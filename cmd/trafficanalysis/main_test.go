package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"trafficanalysis/internal/traffic"
)

func TestFormatLiveStatsIncludesRatesDirectionsAndWANIP(t *testing.T) {
	line := formatLiveStats(
		time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
		netip.MustParseAddr("203.0.113.10"),
		true,
		5*time.Second,
		map[traffic.Direction]traffic.DirectionCounters{
			traffic.DirectionUpload:   {Bytes: 10 * 1024, Packets: 3},
			traffic.DirectionDownload: {Bytes: 20 * 1024, Packets: 4},
			traffic.DirectionUnknown:  {Bytes: 512, Packets: 1},
		},
	)

	for _, want := range []string{
		"2026-04-17T12:00:00Z",
		"wan=203.0.113.10",
		"upload=10.00 KiB",
		"download=20.00 KiB",
		"unknown=512 B",
		"up_rate=2.00 KiB/s",
		"down_rate=4.00 KiB/s",
		"packets=8",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected line to contain %q, got %q", want, line)
		}
	}
}

func TestFormatLiveSnapshotIncludesOtherTopConversations(t *testing.T) {
	line := formatLiveSnapshot(
		time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
		netip.MustParseAddr("203.0.113.10"),
		true,
		time.Second,
		traffic.MeterSnapshot{
			Directions: map[traffic.Direction]traffic.DirectionCounters{
				traffic.DirectionOther: {Bytes: 1200, Packets: 1},
			},
			Conversations: map[traffic.Direction][]traffic.ConversationCounters{
				traffic.DirectionOther: {
					{
						Key: traffic.ConversationKey{
							SrcIP:    netip.MustParseAddr("2001:db8::10"),
							DstIP:    netip.MustParseAddr("2001:db8::20"),
							SrcPort:  443,
							DstPort:  53000,
							Protocol: "tcp",
						},
						Bytes:   1200,
						Packets: 1,
					},
				},
			},
		},
	)

	for _, want := range []string{
		"other=1.17 KiB",
		"other_top=[2001:db8::10]:443->[2001:db8::20]:53000/tcp:1.17 KiB",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected line to contain %q, got %q", want, line)
		}
	}
}

func TestResolveLiveOutputOptionsHonorsQuietAndIntervalOverride(t *testing.T) {
	cfg := captureOutputConfig{
		live:         true,
		quiet:        true,
		configPeriod: 5 * time.Second,
	}

	resolved, err := resolveCaptureOutputConfig(cfg)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resolved.enabled {
		t.Fatal("expected quiet mode to disable live output")
	}

	cfg = captureOutputConfig{
		live:         true,
		quiet:        false,
		liveInterval: "2s",
		configPeriod: 5 * time.Second,
	}
	resolved, err = resolveCaptureOutputConfig(cfg)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if !resolved.enabled || resolved.interval != 2*time.Second {
		t.Fatalf("unexpected live output config: %#v", resolved)
	}
}
