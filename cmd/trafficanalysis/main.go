package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"trafficanalysis/internal/capture"
	"trafficanalysis/internal/config"
	"trafficanalysis/internal/httpapi"
	"trafficanalysis/internal/store"
	"trafficanalysis/internal/telegrambot"
	"trafficanalysis/internal/traffic"
	"trafficanalysis/internal/wanip"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "init-config":
		return runInitConfig(args[1:])
	case "capture":
		return runCapture(args[1:])
	case "read-pcap":
		return runReadPCAP(args[1:])
	case "query":
		return runQuery(args[1:])
	case "serve":
		return runServe(args[1:])
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInitConfig(args []string) error {
	fs := flag.NewFlagSet("init-config", flag.ExitOnError)
	out := fs.String("out", "config.json", "config file path to write")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Default()
	cfg.Interface = "eth1"

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(*out, data, 0644)
}

func runCapture(args []string) error {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	configPath := fs.String("config", "config.json", "config file path")
	live := fs.Bool("live", true, "print live traffic stats while capturing")
	quiet := fs.Bool("quiet", false, "disable live traffic stats")
	liveInterval := fs.String("live-interval", "", "live stats interval, such as 2s or 10s")
	webAddr := fs.String("web-addr", "", "optional HTTP listen address for Web UI and /api/live SSE, such as :8080")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if err := cfg.ValidateForCapture(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	output, err := resolveCaptureOutputConfig(captureOutputConfig{
		live:         *live,
		quiet:        *quiet,
		liveInterval: *liveInterval,
		configPeriod: cfg.LiveInterval(),
	})
	if err != nil {
		return err
	}

	var lanRunner captureRunner
	if cfg.LANInterface != "" {
		lanRunner = func(ctx context.Context, handler capture.PacketHandler) error {
			return capture.RunLive(ctx, capture.Options{
				Interface:   cfg.LANInterface,
				BPF:         cfg.BPF,
				SnapshotLen: cfg.SnapshotLen,
				Promiscuous: cfg.Promiscuous,
			}, handler)
		}
	}

	return runCaptureToStore(ctx, cfg, output, func(ctx context.Context, handler capture.PacketHandler) error {
		return capture.RunLive(ctx, capture.Options{
			Interface:   cfg.Interface,
			BPF:         cfg.BPF,
			SnapshotLen: cfg.SnapshotLen,
			Promiscuous: cfg.Promiscuous,
		}, handler)
	}, lanRunner, resolveCaptureWebConfig(*webAddr))
}

func runReadPCAP(args []string) error {
	fs := flag.NewFlagSet("read-pcap", flag.ExitOnError)
	configPath := fs.String("config", "config.json", "config file path")
	pcapPath := fs.String("pcap", "", "pcap file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pcapPath == "" {
		return errors.New("-pcap is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	output, err := resolveCaptureOutputConfig(captureOutputConfig{
		live:         false,
		configPeriod: cfg.LiveInterval(),
	})
	if err != nil {
		return err
	}

	return runCaptureToStore(context.Background(), cfg, output, func(ctx context.Context, handler capture.PacketHandler) error {
		return capture.RunFile(ctx, *pcapPath, cfg.BPF, handler)
	}, nil, resolvedCaptureWebConfig{})
}

type captureRunner func(context.Context, capture.PacketHandler) error

type captureOutputConfig struct {
	live         bool
	quiet        bool
	liveInterval string
	configPeriod time.Duration
}

type resolvedCaptureOutputConfig struct {
	enabled  bool
	interval time.Duration
}

type resolvedCaptureWebConfig struct {
	enabled      bool
	addr         string
	liveInterval time.Duration
}

func resolveCaptureOutputConfig(cfg captureOutputConfig) (resolvedCaptureOutputConfig, error) {
	if cfg.quiet || !cfg.live {
		return resolvedCaptureOutputConfig{enabled: false}, nil
	}

	interval := cfg.configPeriod
	if cfg.liveInterval != "" {
		parsed, err := time.ParseDuration(cfg.liveInterval)
		if err != nil {
			return resolvedCaptureOutputConfig{}, err
		}
		interval = parsed
	}
	if interval <= 0 {
		return resolvedCaptureOutputConfig{enabled: false}, nil
	}
	return resolvedCaptureOutputConfig{enabled: true, interval: interval}, nil
}

func resolveCaptureWebConfig(addr string) resolvedCaptureWebConfig {
	if addr == "" {
		return resolvedCaptureWebConfig{}
	}
	return resolvedCaptureWebConfig{
		enabled:      true,
		addr:         addr,
		liveInterval: time.Second,
	}
}

func runCaptureToStore(ctx context.Context, cfg config.Config, output resolvedCaptureOutputConfig, wanRunner captureRunner, lanRunner captureRunner, web resolvedCaptureWebConfig) error {
	st, err := store.OpenSQLite(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer st.Close()

	manager, err := buildWANIPManager(cfg)
	if err != nil {
		return err
	}
	if err := manager.Refresh(ctx); err != nil {
		return fmt.Errorf("initial WAN IP refresh: %w", err)
	}
	go manager.Run(ctx, cfg.WANIPRefreshInterval())

	localNetworks, err := config.ParseLocalNetworks(cfg.LocalNetworks)
	if err != nil {
		return err
	}
	classifier := traffic.NewWANClassifierWithLocalNetworks(manager.Current, localNetworks)
	aggregator := traffic.NewAggregator(cfg.BucketDuration())
	clientClassifier := traffic.NewLANClientClassifier(localNetworks)
	clientAggregator := traffic.NewClientAggregator(cfg.BucketDuration())
	endpointAggregator := traffic.NewEndpointAggregator(cfg.BucketDuration())

	var consoleMeter *traffic.Meter
	if output.enabled {
		consoleMeter = traffic.NewMeter()
	}
	var webMeter *traffic.Meter
	var webClientMeter *traffic.ClientMeter
	var liveHub *httpapi.LiveHub
	var webErrCh <-chan error
	nameCache := newClientNameCache()
	if err := startTelegramBot(ctx, cfg, st); err != nil {
		return err
	}
	if web.enabled {
		webMeter = traffic.NewMeter()
		webClientMeter = traffic.NewClientMeter()
		liveHub = httpapi.NewLiveHub()
		server := &http.Server{
			Addr: web.addr,
			Handler: httpapi.NewHandler(st, httpapi.Options{
				LiveSource: liveHub,
			}),
		}
		errCh := make(chan error, 1)
		webErrCh = errCh
		go func() {
			errCh <- server.ListenAndServe()
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()
		fmt.Printf("web UI listening on http://%s live_sse=/api/live\n", displayListenAddr(web.addr))
	}

	runCtx, cancelRunners := context.WithCancel(ctx)
	defer cancelRunners()

	errCh := make(chan error, 1)
	go func() {
		errCh <- wanRunner(runCtx, func(packet traffic.Packet) {
			manager.ObservePacket(packet.SrcIP, packet.DstIP)
			direction := classifier.Classify(packet)
			if shouldTriggerWANRefresh(packet, direction) {
				manager.RequestRefresh()
			}
			if consoleMeter != nil {
				consoleMeter.AddPacket(direction, packet)
			}
			if webMeter != nil {
				webMeter.AddPacket(direction, packet)
			}
			if direction == traffic.DirectionLAN && cfg.IgnoreLAN {
				return
			}
			aggregator.Add(packet, direction)
		})
	}()
	if lanRunner != nil {
		go func() {
			errCh <- lanRunner(runCtx, func(packet traffic.Packet) {
				if len(packet.NameObservations) > 0 {
					nameCache.Observe(packet.NameObservations)
					_ = st.UpsertClientNames(context.Background(), packet.NameObservations)
				}
				if client, ok := clientClassifier.Classify(packet); ok {
					clientAggregator.Add(packet, client)
					endpointAggregator.Add(packet, client)
					if webClientMeter != nil {
						webClientMeter.AddPacket(client, packet)
					}
				}
			})
		}()
	}

	flushTicker := time.NewTicker(cfg.FlushInterval())
	defer flushTicker.Stop()

	retentionTicker := time.NewTicker(cfg.Retention.CompactInterval())
	defer retentionTicker.Stop()
	retentionPolicy := store.RetentionPolicy{
		MinuteRetention: cfg.Retention.MinuteDuration(),
		HourlyRetention: cfg.Retention.HourlyDuration(),
	}

	var liveTicker *time.Ticker
	var liveC <-chan time.Time
	if output.enabled {
		liveTicker = time.NewTicker(output.interval)
		defer liveTicker.Stop()
		liveC = liveTicker.C
		fmt.Printf("capture started: interface=%s lan_interface=%s database=%s live_interval=%s\n", cfg.Interface, cfg.LANInterface, cfg.Database, output.interval)
	}

	var webLiveTicker *time.Ticker
	var webLiveC <-chan time.Time
	if web.enabled {
		webLiveTicker = time.NewTicker(web.liveInterval)
		defer webLiveTicker.Stop()
		webLiveC = webLiveTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			cancelRunners()
			return flushAll(context.Background(), st, aggregator, clientAggregator, endpointAggregator)
		case err := <-errCh:
			cancelRunners()
			if flushErr := flushAll(context.Background(), st, aggregator, clientAggregator, endpointAggregator); flushErr != nil {
				return flushErr
			}
			return err
		case err := <-webErrCh:
			if errors.Is(err, http.ErrServerClosed) {
				continue
			}
			cancelRunners()
			if flushErr := flushAll(context.Background(), st, aggregator, clientAggregator, endpointAggregator); flushErr != nil {
				return flushErr
			}
			return err
		case <-flushTicker.C:
			if err := flushCompleteBuckets(ctx, st, aggregator, clientAggregator, endpointAggregator, cfg.BucketDuration()); err != nil {
				return err
			}
		case now := <-retentionTicker.C:
			if err := st.CompactAndPrune(ctx, now.UTC(), retentionPolicy); err != nil {
				return err
			}
		case now := <-liveC:
			wanIP, ok := manager.Current()
			fmt.Println(formatLiveSnapshot(now.UTC(), wanIP, ok, output.interval, consoleMeter.SnapshotAndResetDetailed(3)))
		case now := <-webLiveC:
			wanIP, ok := manager.Current()
			liveHub.Publish(buildHTTPLiveSnapshot(
				now.UTC(),
				wanIP,
				ok,
				web.liveInterval,
				webMeter.SnapshotAndResetDetailed(0),
				webClientMeter.SnapshotAndReset(100),
				liveClientNameResolver(context.Background(), st, nameCache),
			))
		}
	}
}

func buildWANIPManager(cfg config.Config) (*wanip.Manager, error) {
	var providers []wanip.Provider
	if cfg.WANIP.HTTPURL != "" {
		providers = append(providers, wanip.NewHTTPProvider(cfg.WANIP.HTTPURL))
	}
	if cfg.WANIP.Static != "" {
		provider, err := wanip.NewStaticProvider(cfg.WANIP.Static)
		if err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}
	if len(providers) == 0 {
		return nil, errors.New("configure wan_ip.http_url or wan_ip.static")
	}

	return wanip.NewManager(wanip.NewChainProvider(providers...), cfg.WANIPRefreshInterval()), nil
}

func flushCompleteBuckets(ctx context.Context, st *store.SQLiteStore, aggregator *traffic.Aggregator, clientAggregator *traffic.ClientAggregator, endpointAggregator *traffic.EndpointAggregator, bucketDuration time.Duration) error {
	cutoff := time.Now().UTC().Truncate(bucketDuration)
	if err := st.UpsertBuckets(ctx, aggregator.DrainBefore(cutoff)); err != nil {
		return err
	}
	if err := st.UpsertClientBuckets(ctx, clientAggregator.DrainBefore(cutoff)); err != nil {
		return err
	}
	return st.UpsertEndpointBuckets(ctx, endpointAggregator.DrainBefore(cutoff))
}

func flushAll(ctx context.Context, st *store.SQLiteStore, aggregator *traffic.Aggregator, clientAggregator *traffic.ClientAggregator, endpointAggregator *traffic.EndpointAggregator) error {
	if err := st.UpsertBuckets(ctx, aggregator.DrainAll()); err != nil {
		return err
	}
	if err := st.UpsertClientBuckets(ctx, clientAggregator.DrainAll()); err != nil {
		return err
	}
	return st.UpsertEndpointBuckets(ctx, endpointAggregator.DrainAll())
}

func runQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	dbPath := fs.String("db", "traffic.db", "sqlite database path")
	dateText := fs.String("date", "", "local date to query, YYYY-MM-DD")
	monthText := fs.String("month", "", "local month to query, YYYY-MM")
	fromText := fs.String("from", "", "start time: RFC3339, YYYY-MM-DD, or YYYY-MM-DD HH:MM")
	toText := fs.String("to", "", "end time: RFC3339, YYYY-MM-DD, or YYYY-MM-DD HH:MM")
	lastText := fs.String("last", "1h", "relative range ending now, such as 15m, 24h, or 7d")
	if err := fs.Parse(args); err != nil {
		return err
	}

	from, to, err := parseQueryRange(queryRangeOptions{
		date:  *dateText,
		month: *monthText,
		from:  *fromText,
		to:    *toText,
		last:  *lastText,
	})
	if err != nil {
		return err
	}

	ctx := context.Background()
	st, err := store.OpenSQLite(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	rows, err := st.QueryBuckets(ctx, from, to)
	if err != nil {
		return err
	}

	printRows(rows)
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "config.json", "config file path")
	dbPath := fs.String("db", "", "sqlite database path override")
	addr := fs.String("addr", ":8080", "HTTP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolved, err := resolveServeConfig(serveConfigOptions{
		configPath: *configPath,
		dbPath:     *dbPath,
		addr:       *addr,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.OpenSQLite(ctx, resolved.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := startTelegramBot(ctx, resolved.cfg, st); err != nil {
		return err
	}

	server := &http.Server{
		Addr:    resolved.addr,
		Handler: httpapi.NewHandler(st, httpapi.Options{}),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	fmt.Printf("web UI listening on http://%s\n", displayListenAddr(resolved.addr))

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

type serveConfigOptions struct {
	configPath string
	dbPath     string
	addr       string
}

type resolvedServeConfig struct {
	cfg    config.Config
	dbPath string
	addr   string
}

func resolveServeConfig(options serveConfigOptions) (resolvedServeConfig, error) {
	cfg, err := config.Load(options.configPath)
	if err != nil {
		return resolvedServeConfig{}, err
	}

	dbPath := options.dbPath
	if dbPath == "" {
		dbPath = cfg.Database
	}
	addr := options.addr
	if addr == "" {
		addr = ":8080"
	}
	cfg.Database = dbPath
	return resolvedServeConfig{cfg: cfg, dbPath: dbPath, addr: addr}, nil
}

func startTelegramBot(ctx context.Context, cfg config.Config, st *store.SQLiteStore) error {
	if !cfg.Telegram.Enabled {
		return nil
	}
	if err := cfg.ValidateForTelegram(); err != nil {
		return err
	}
	location, err := cfg.Telegram.Location()
	if err != nil {
		return err
	}
	client := telegrambot.NewHTTPClient(cfg.Telegram.BotToken)
	bot := telegrambot.New(telegrambot.Config{
		ChatIDs:      cfg.Telegram.ChatIDs,
		PollInterval: cfg.Telegram.PollInterval(),
		DailyTime:    cfg.Telegram.DailyTime,
		Location:     location,
	}, st, client)
	go func() {
		if err := bot.Run(ctx, client); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "telegram bot error: %v\n", err)
		}
	}()
	fmt.Printf("telegram bot enabled: chats=%d daily_time=%s timezone=%s\n", len(cfg.Telegram.ChatIDs), cfg.Telegram.DailyTime, cfg.Telegram.Timezone)
	return nil
}

func displayListenAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "0.0.0.0" + addr
	}
	return addr
}

type queryRangeOptions struct {
	date  string
	month string
	from  string
	to    string
	last  string
}

func parseQueryRange(options queryRangeOptions) (time.Time, time.Time, error) {
	return parseQueryRangeWithClock(options, time.Now().UTC(), time.Local)
}

func parseQueryRangeWithClock(options queryRangeOptions, now time.Time, location *time.Location) (time.Time, time.Time, error) {
	if location == nil {
		location = time.Local
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if options.date != "" {
		start, err := time.ParseInLocation("2006-01-02", options.date, location)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		return validateQueryRange(start.UTC(), start.AddDate(0, 0, 1).UTC())
	}

	if options.month != "" {
		start, err := time.ParseInLocation("2006-01", options.month, location)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		return validateQueryRange(start.UTC(), start.AddDate(0, 1, 0).UTC())
	}

	to := now
	var err error
	if options.to != "" {
		to, err = parseQueryTime(options.to, location)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
	}

	var from time.Time
	if options.from != "" {
		from, err = parseQueryTime(options.from, location)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
	} else {
		lastText := options.last
		if lastText == "" {
			lastText = "1h"
		}
		last, err := parseQueryDuration(lastText)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		from = to.Add(-last)
	}

	return validateQueryRange(from.UTC(), to.UTC())
}

func validateQueryRange(from, to time.Time) (time.Time, time.Time, error) {
	if !from.Before(to) {
		return time.Time{}, time.Time{}, errors.New("from must be before to")
	}
	return from, to, nil
}

func parseQueryTime(text string, location *time.Location) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, text); err == nil {
		return parsed.UTC(), nil
	}

	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(layout, text, location)
		if err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time %q; use YYYY-MM-DD, YYYY-MM-DD HH:MM, or RFC3339", text)
}

func parseQueryDuration(text string) (time.Duration, error) {
	if strings.HasSuffix(text, "d") {
		daysText := strings.TrimSuffix(text, "d")
		days, err := strconv.Atoi(daysText)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(text)
}

func printRows(rows []store.BucketRow) {
	fmt.Printf("%-20s %-9s %-8s %14s %10s\n", "bucket_start", "direction", "protocol", "bytes", "packets")

	var uploadBytes int64
	var downloadBytes int64
	var lanBytes int64
	var otherBytes int64
	for _, row := range rows {
		fmt.Printf(
			"%-20s %-9s %-8s %14d %10d\n",
			row.Key.Start.Format(time.RFC3339),
			row.Key.Direction,
			row.Key.Protocol,
			row.Value.Bytes,
			row.Value.Packets,
		)
		switch row.Key.Direction {
		case traffic.DirectionUpload:
			uploadBytes += row.Value.Bytes
		case traffic.DirectionDownload:
			downloadBytes += row.Value.Bytes
		case traffic.DirectionLAN:
			lanBytes += row.Value.Bytes
		default:
			otherBytes += row.Value.Bytes
		}
	}

	fmt.Println()
	fmt.Printf("upload:   %s\n", formatBytes(uploadBytes))
	fmt.Printf("download: %s\n", formatBytes(downloadBytes))
	if lanBytes > 0 {
		fmt.Printf("lan:      %s\n", formatBytes(lanBytes))
	}
	if otherBytes > 0 {
		fmt.Printf("other:    %s\n", formatBytes(otherBytes))
	}
}

func formatBytes(bytes int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(bytes)
	unit := units[0]
	for _, next := range units[1:] {
		if value < 1024 {
			break
		}
		value /= 1024
		unit = next
	}
	if unit == "B" {
		return fmt.Sprintf("%d %s", bytes, unit)
	}
	return fmt.Sprintf("%.2f %s", value, unit)
}

func formatLiveStats(now time.Time, wanIP netip.Addr, wanOK bool, interval time.Duration, stats map[traffic.Direction]traffic.DirectionCounters) string {
	return formatLiveSnapshot(now, wanIP, wanOK, interval, traffic.MeterSnapshot{Directions: stats})
}

func formatLiveSnapshot(now time.Time, wanIP netip.Addr, wanOK bool, interval time.Duration, snapshot traffic.MeterSnapshot) string {
	stats := snapshot.Directions
	upload := stats[traffic.DirectionUpload]
	download := stats[traffic.DirectionDownload]
	other := stats[traffic.DirectionOther]
	unknown := stats[traffic.DirectionUnknown]
	lan := stats[traffic.DirectionLAN]
	totalPackets := upload.Packets + download.Packets + lan.Packets + other.Packets + unknown.Packets

	wanText := "unavailable"
	if wanOK {
		wanText = wanIP.String()
	}

	line := fmt.Sprintf(
		"%s wan=%s upload=%s download=%s lan=%s other=%s unknown=%s up_rate=%s/s down_rate=%s/s packets=%d",
		now.Format(time.RFC3339),
		wanText,
		formatBytes(upload.Bytes),
		formatBytes(download.Bytes),
		formatBytes(lan.Bytes),
		formatBytes(other.Bytes),
		formatBytes(unknown.Bytes),
		formatBytes(rateBytes(upload.Bytes, interval)),
		formatBytes(rateBytes(download.Bytes, interval)),
		totalPackets,
	)
	if top := formatTopConversations(snapshot.Conversations[traffic.DirectionOther]); top != "" {
		line += " other_top=" + top
	}
	if top := formatTopConversations(snapshot.Conversations[traffic.DirectionLAN]); top != "" {
		line += " lan_top=" + top
	}
	if top := formatTopConversations(snapshot.Conversations[traffic.DirectionUnknown]); top != "" {
		line += " unknown_top=" + top
	}
	return line
}

func buildHTTPLiveSnapshot(
	now time.Time,
	wanIP netip.Addr,
	wanOK bool,
	interval time.Duration,
	snapshot traffic.MeterSnapshot,
	clientSnapshot traffic.ClientMeterSnapshot,
	resolveClientName func(netip.Addr, string) (string, string),
) httpapi.LiveSnapshot {
	stats := snapshot.Directions
	upload := stats[traffic.DirectionUpload]
	download := stats[traffic.DirectionDownload]
	lan := stats[traffic.DirectionLAN]
	other := stats[traffic.DirectionOther]
	unknown := stats[traffic.DirectionUnknown]

	wanText := ""
	if wanOK {
		wanText = wanIP.String()
	}

	result := httpapi.LiveSnapshot{
		Timestamp:       now.UTC().Format(time.RFC3339),
		WANIP:           wanText,
		WANAvailable:    wanOK,
		IntervalSeconds: interval.Seconds(),
		Totals: httpapi.LiveTotals{
			UploadBytes:   upload.Bytes,
			DownloadBytes: download.Bytes,
			LANBytes:      lan.Bytes,
			OtherBytes:    other.Bytes,
			UnknownBytes:  unknown.Bytes,
			Packets:       upload.Packets + download.Packets + lan.Packets + other.Packets + unknown.Packets,
		},
		Rates: httpapi.LiveRates{
			UploadBPS:   rateBytes(upload.Bytes, interval),
			DownloadBPS: rateBytes(download.Bytes, interval),
		},
	}

	for _, client := range clientSnapshot.Clients {
		name := ""
		if resolveClientName != nil {
			name, _ = resolveClientName(client.ClientIP, client.ClientMAC)
		}
		result.Clients = append(result.Clients, httpapi.LiveClient{
			DisplayName:   displayClientName(name, client.ClientIP.String(), client.ClientMAC),
			ClientIP:      client.ClientIP.String(),
			ClientMAC:     client.ClientMAC,
			UploadBPS:     rateBytes(client.UploadBytes, interval),
			DownloadBPS:   rateBytes(client.DownloadBytes, interval),
			UploadBytes:   client.UploadBytes,
			DownloadBytes: client.DownloadBytes,
			Packets:       client.Packets,
		})
	}
	return result
}

func formatTopConversations(conversations []traffic.ConversationCounters) string {
	if len(conversations) == 0 {
		return ""
	}

	parts := make([]string, 0, len(conversations))
	for _, conversation := range conversations {
		parts = append(parts, fmt.Sprintf(
			"%s->%s/%s:%s",
			formatEndpoint(conversation.Key.SrcIP, conversation.Key.SrcPort),
			formatEndpoint(conversation.Key.DstIP, conversation.Key.DstPort),
			conversation.Key.Protocol,
			formatBytes(conversation.Bytes),
		))
	}
	return strings.Join(parts, ",")
}

func formatEndpoint(addr netip.Addr, port uint16) string {
	if port == 0 {
		return addr.String()
	}
	if addr.Is6() {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

type cachedClientName struct {
	name   string
	source string
}

type clientAliasResolver interface {
	ResolveClientAlias(ctx context.Context, clientIP, clientMAC string) (string, error)
}

type clientNameCache struct {
	mu    sync.RWMutex
	names map[string]cachedClientName
}

func newClientNameCache() *clientNameCache {
	return &clientNameCache{names: make(map[string]cachedClientName)}
}

func (c *clientNameCache) Observe(observations []traffic.NameObservation) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, observation := range observations {
		if !observation.IP.IsValid() || observation.MAC == "" || observation.Name == "" {
			continue
		}
		c.names[clientNameKey(observation.IP, observation.MAC)] = cachedClientName{
			name:   observation.Name,
			source: observation.Source,
		}
	}
}

func (c *clientNameCache) Resolve(ip netip.Addr, mac string) (string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	name := c.names[clientNameKey(ip, mac)]
	return name.name, name.source
}

func liveClientNameResolver(ctx context.Context, aliases clientAliasResolver, names *clientNameCache) func(netip.Addr, string) (string, string) {
	return func(ip netip.Addr, mac string) (string, string) {
		if aliases != nil {
			alias, err := aliases.ResolveClientAlias(ctx, ip.String(), mac)
			if err == nil && strings.TrimSpace(alias) != "" {
				return alias, "alias"
			}
		}
		if names == nil {
			return "", ""
		}
		return names.Resolve(ip, mac)
	}
}

func clientNameKey(ip netip.Addr, mac string) string {
	return ip.String() + "\x00" + mac
}

func displayClientName(name, clientIP, clientMAC string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	if clientMAC != "" {
		return clientMAC
	}
	return clientIP
}

func shouldTriggerWANRefresh(packet traffic.Packet, direction traffic.Direction) bool {
	if direction != traffic.DirectionOther {
		return false
	}
	return isPublicAddress(packet.SrcIP) || isPublicAddress(packet.DstIP)
}

func isPublicAddress(addr netip.Addr) bool {
	return addr.IsValid() &&
		addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast()
}

func rateBytes(bytes int64, interval time.Duration) int64 {
	if interval <= 0 {
		return 0
	}
	return int64(float64(bytes) / interval.Seconds())
}

func printUsage() {
	commands := []string{
		"trafficanalysis init-config -out config.json",
		"trafficanalysis capture -config config.json",
		"trafficanalysis capture -config config.json -quiet",
		"trafficanalysis capture -config config.json -live-interval 2s",
		"trafficanalysis capture -config config.json -web-addr :8080",
		"trafficanalysis read-pcap -config config.json -pcap sample.pcap",
		"trafficanalysis query -db traffic.db -last 1h",
		"trafficanalysis query -db traffic.db -date 2026-04-17",
		"trafficanalysis query -db traffic.db -month 2026-04",
		"trafficanalysis query -db traffic.db -from \"2026-04-17 00:00\" -to \"2026-04-18 00:00\"",
		"trafficanalysis serve -config config.json -addr :8080",
	}
	fmt.Println(strings.Join(commands, "\n"))
}
