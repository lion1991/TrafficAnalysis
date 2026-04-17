package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"trafficanalysis/internal/capture"
	"trafficanalysis/internal/config"
	"trafficanalysis/internal/store"
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

	return runCaptureToStore(ctx, cfg, output, func(ctx context.Context, handler capture.PacketHandler) error {
		return capture.RunLive(ctx, capture.Options{
			Interface:   cfg.Interface,
			BPF:         cfg.BPF,
			SnapshotLen: cfg.SnapshotLen,
			Promiscuous: cfg.Promiscuous,
		}, handler)
	})
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
	})
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

func runCaptureToStore(ctx context.Context, cfg config.Config, output resolvedCaptureOutputConfig, runner captureRunner) error {
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

	classifier := traffic.NewWANClassifier(manager.Current)
	aggregator := traffic.NewAggregator(cfg.BucketDuration())
	meter := traffic.NewMeter()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runner(ctx, func(packet traffic.Packet) {
			direction := classifier.Classify(packet)
			aggregator.Add(packet, direction)
			meter.AddPacket(direction, packet)
		})
	}()

	flushTicker := time.NewTicker(cfg.FlushInterval())
	defer flushTicker.Stop()

	var liveTicker *time.Ticker
	var liveC <-chan time.Time
	if output.enabled {
		liveTicker = time.NewTicker(output.interval)
		defer liveTicker.Stop()
		liveC = liveTicker.C
		fmt.Printf("capture started: interface=%s database=%s live_interval=%s\n", cfg.Interface, cfg.Database, output.interval)
	}

	for {
		select {
		case <-ctx.Done():
			return flushAll(context.Background(), st, aggregator)
		case err := <-errCh:
			if flushErr := flushAll(context.Background(), st, aggregator); flushErr != nil {
				return flushErr
			}
			return err
		case <-flushTicker.C:
			if err := flushCompleteBuckets(ctx, st, aggregator, cfg.BucketDuration()); err != nil {
				return err
			}
		case now := <-liveC:
			wanIP, ok := manager.Current()
			fmt.Println(formatLiveSnapshot(now.UTC(), wanIP, ok, output.interval, meter.SnapshotAndResetDetailed(3)))
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

func flushCompleteBuckets(ctx context.Context, st *store.SQLiteStore, aggregator *traffic.Aggregator, bucketDuration time.Duration) error {
	cutoff := time.Now().UTC().Truncate(bucketDuration)
	return st.UpsertBuckets(ctx, aggregator.DrainBefore(cutoff))
}

func flushAll(ctx context.Context, st *store.SQLiteStore, aggregator *traffic.Aggregator) error {
	return st.UpsertBuckets(ctx, aggregator.DrainAll())
}

func runQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	dbPath := fs.String("db", "traffic.db", "sqlite database path")
	fromText := fs.String("from", "", "start time, RFC3339")
	toText := fs.String("to", "", "end time, RFC3339")
	lastText := fs.String("last", "1h", "relative range ending now, such as 15m or 24h")
	if err := fs.Parse(args); err != nil {
		return err
	}

	from, to, err := parseQueryRange(*fromText, *toText, *lastText)
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

func parseQueryRange(fromText, toText, lastText string) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	to := now
	var err error
	if toText != "" {
		to, err = time.Parse(time.RFC3339, toText)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		to = to.UTC()
	}

	var from time.Time
	if fromText != "" {
		from, err = time.Parse(time.RFC3339, fromText)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		from = from.UTC()
	} else {
		last, err := time.ParseDuration(lastText)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		from = to.Add(-last)
	}

	if !from.Before(to) {
		return time.Time{}, time.Time{}, errors.New("from must be before to")
	}
	return from, to, nil
}

func printRows(rows []store.BucketRow) {
	fmt.Printf("%-20s %-9s %-8s %14s %10s\n", "bucket_start", "direction", "protocol", "bytes", "packets")

	var uploadBytes int64
	var downloadBytes int64
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
		default:
			otherBytes += row.Value.Bytes
		}
	}

	fmt.Println()
	fmt.Printf("upload:   %s\n", formatBytes(uploadBytes))
	fmt.Printf("download: %s\n", formatBytes(downloadBytes))
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
	totalPackets := upload.Packets + download.Packets + other.Packets + unknown.Packets

	wanText := "unavailable"
	if wanOK {
		wanText = wanIP.String()
	}

	line := fmt.Sprintf(
		"%s wan=%s upload=%s download=%s other=%s unknown=%s up_rate=%s/s down_rate=%s/s packets=%d",
		now.Format(time.RFC3339),
		wanText,
		formatBytes(upload.Bytes),
		formatBytes(download.Bytes),
		formatBytes(other.Bytes),
		formatBytes(unknown.Bytes),
		formatBytes(rateBytes(upload.Bytes, interval)),
		formatBytes(rateBytes(download.Bytes, interval)),
		totalPackets,
	)
	if top := formatTopConversations(snapshot.Conversations[traffic.DirectionOther]); top != "" {
		line += " other_top=" + top
	}
	if top := formatTopConversations(snapshot.Conversations[traffic.DirectionUnknown]); top != "" {
		line += " unknown_top=" + top
	}
	return line
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
		"trafficanalysis read-pcap -config config.json -pcap sample.pcap",
		"trafficanalysis query -db traffic.db -last 1h",
		"trafficanalysis query -db traffic.db -from 2026-04-17T00:00:00Z -to 2026-04-17T01:00:00Z",
	}
	fmt.Println(strings.Join(commands, "\n"))
}
