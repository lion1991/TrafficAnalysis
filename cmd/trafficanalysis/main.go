package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

	return runCaptureToStore(ctx, cfg, func(ctx context.Context, handler capture.PacketHandler) error {
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

	return runCaptureToStore(context.Background(), cfg, func(ctx context.Context, handler capture.PacketHandler) error {
		return capture.RunFile(ctx, *pcapPath, cfg.BPF, handler)
	})
}

type captureRunner func(context.Context, capture.PacketHandler) error

func runCaptureToStore(ctx context.Context, cfg config.Config, runner captureRunner) error {
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

	errCh := make(chan error, 1)
	go func() {
		errCh <- runner(ctx, func(packet traffic.Packet) {
			aggregator.Add(packet, classifier.Classify(packet))
		})
	}()

	ticker := time.NewTicker(cfg.FlushInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return flushAll(context.Background(), st, aggregator)
		case err := <-errCh:
			if flushErr := flushAll(context.Background(), st, aggregator); flushErr != nil {
				return flushErr
			}
			return err
		case <-ticker.C:
			if err := flushCompleteBuckets(ctx, st, aggregator, cfg.BucketDuration()); err != nil {
				return err
			}
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

func printUsage() {
	commands := []string{
		"trafficanalysis init-config -out config.json",
		"trafficanalysis capture -config config.json",
		"trafficanalysis read-pcap -config config.json -pcap sample.pcap",
		"trafficanalysis query -db traffic.db -last 1h",
		"trafficanalysis query -db traffic.db -from 2026-04-17T00:00:00Z -to 2026-04-17T01:00:00Z",
	}
	fmt.Println(strings.Join(commands, "\n"))
}
