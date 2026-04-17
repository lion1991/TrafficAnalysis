package main

import (
	"net/netip"
	"os"
	"path/filepath"
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

func TestFormatLiveSnapshotIncludesLANTraffic(t *testing.T) {
	line := formatLiveSnapshot(
		time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
		netip.MustParseAddr("42.103.52.33"),
		true,
		time.Second,
		traffic.MeterSnapshot{
			Directions: map[traffic.Direction]traffic.DirectionCounters{
				traffic.DirectionLAN: {Bytes: 1024, Packets: 2},
			},
			Conversations: map[traffic.Direction][]traffic.ConversationCounters{
				traffic.DirectionLAN: {
					{
						Key: traffic.ConversationKey{
							SrcIP:    netip.MustParseAddr("192.168.252.1"),
							DstIP:    netip.MustParseAddr("239.255.255.250"),
							SrcPort:  1900,
							DstPort:  1900,
							Protocol: "udp",
						},
						Bytes:   1024,
						Packets: 2,
					},
				},
			},
		},
	)

	for _, want := range []string{
		"lan=1.00 KiB",
		"lan_top=192.168.252.1:1900->239.255.255.250:1900/udp:1.00 KiB",
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

func TestResolveCaptureWebConfigEnablesSSEAtOneSecondInterval(t *testing.T) {
	resolved := resolveCaptureWebConfig("")
	if resolved.enabled {
		t.Fatal("expected empty web address to disable capture web UI")
	}

	resolved = resolveCaptureWebConfig(":8080")
	if !resolved.enabled {
		t.Fatal("expected web address to enable capture web UI")
	}
	if resolved.addr != ":8080" {
		t.Fatalf("unexpected addr: %s", resolved.addr)
	}
	if resolved.liveInterval != time.Second {
		t.Fatalf("unexpected live interval: %s", resolved.liveInterval)
	}
}

func TestParseQueryRangeSupportsDateShortcut(t *testing.T) {
	location := time.FixedZone("TEST", 8*60*60)
	from, to, err := parseQueryRangeWithClock(queryRangeOptions{date: "2026-04-17"}, time.Time{}, location)
	if err != nil {
		t.Fatalf("parse query range: %v", err)
	}

	if from != time.Date(2026, 4, 16, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected from: %s", from)
	}
	if to != time.Date(2026, 4, 17, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected to: %s", to)
	}
}

func TestParseQueryRangeSupportsMonthShortcut(t *testing.T) {
	location := time.FixedZone("TEST", 8*60*60)
	from, to, err := parseQueryRangeWithClock(queryRangeOptions{month: "2026-04"}, time.Time{}, location)
	if err != nil {
		t.Fatalf("parse query range: %v", err)
	}

	if from != time.Date(2026, 3, 31, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected from: %s", from)
	}
	if to != time.Date(2026, 4, 30, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected to: %s", to)
	}
}

func TestParseQueryRangeSupportsLocalTimeRangeWithoutRFC3339(t *testing.T) {
	location := time.FixedZone("TEST", 8*60*60)
	from, to, err := parseQueryRangeWithClock(queryRangeOptions{
		from: "2026-04-17 00:00",
		to:   "2026-04-18 00:00",
	}, time.Time{}, location)
	if err != nil {
		t.Fatalf("parse query range: %v", err)
	}

	if from != time.Date(2026, 4, 16, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected from: %s", from)
	}
	if to != time.Date(2026, 4, 17, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected to: %s", to)
	}
}

func TestParseQueryRangeSupportsDayDurations(t *testing.T) {
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	from, to, err := parseQueryRangeWithClock(queryRangeOptions{last: "7d"}, now, time.UTC)
	if err != nil {
		t.Fatalf("parse query range: %v", err)
	}

	if to != now {
		t.Fatalf("unexpected to: %s", to)
	}
	if from != now.Add(-7*24*time.Hour) {
		t.Fatalf("unexpected from: %s", from)
	}
}

func TestShouldTriggerWANRefreshForOtherPublicTraffic(t *testing.T) {
	packet := traffic.Packet{
		SrcIP: netip.MustParseAddr("42.103.52.50"),
		DstIP: netip.MustParseAddr("124.222.87.165"),
	}
	if !shouldTriggerWANRefresh(packet, traffic.DirectionOther) {
		t.Fatal("expected public other traffic to trigger WAN refresh")
	}
}

func TestShouldNotTriggerWANRefreshForLANOrPrivateTraffic(t *testing.T) {
	packet := traffic.Packet{
		SrcIP: netip.MustParseAddr("192.168.252.1"),
		DstIP: netip.MustParseAddr("239.255.255.250"),
	}
	if shouldTriggerWANRefresh(packet, traffic.DirectionLAN) {
		t.Fatal("expected LAN traffic not to trigger WAN refresh")
	}
	if shouldTriggerWANRefresh(packet, traffic.DirectionOther) {
		t.Fatal("expected private/multicast traffic not to trigger WAN refresh")
	}
}

func TestBuildHTTPLiveSnapshotIncludesWANRatesAndCounters(t *testing.T) {
	snapshot := buildHTTPLiveSnapshot(
		time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
		netip.MustParseAddr("42.103.52.33"),
		true,
		2*time.Second,
		traffic.MeterSnapshot{
			Directions: map[traffic.Direction]traffic.DirectionCounters{
				traffic.DirectionUpload:   {Bytes: 2048, Packets: 2},
				traffic.DirectionDownload: {Bytes: 4096, Packets: 3},
				traffic.DirectionOther:    {Bytes: 128, Packets: 1},
			},
		},
	)

	if snapshot.Timestamp != "2026-04-17T12:00:00Z" {
		t.Fatalf("unexpected timestamp: %s", snapshot.Timestamp)
	}
	if snapshot.WANIP != "42.103.52.33" || !snapshot.WANAvailable {
		t.Fatalf("unexpected WAN fields: %#v", snapshot)
	}
	if snapshot.Totals.UploadBytes != 2048 || snapshot.Totals.DownloadBytes != 4096 || snapshot.Totals.OtherBytes != 128 {
		t.Fatalf("unexpected totals: %#v", snapshot.Totals)
	}
	if snapshot.Totals.Packets != 6 {
		t.Fatalf("unexpected packets: %d", snapshot.Totals.Packets)
	}
	if snapshot.Rates.UploadBPS != 1024 || snapshot.Rates.DownloadBPS != 2048 {
		t.Fatalf("unexpected rates: %#v", snapshot.Rates)
	}
}

func TestResolveServeConfigUsesConfigDatabaseAndOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("TZ", "UTC")

	err := os.WriteFile(configPath, []byte(`{
  "database": "from-config.db"
}`), 0644)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	resolved, err := resolveServeConfig(serveConfigOptions{
		configPath: configPath,
		addr:       ":9090",
		dbPath:     "override.db",
	})
	if err != nil {
		t.Fatalf("resolve serve config: %v", err)
	}

	if resolved.addr != ":9090" {
		t.Fatalf("unexpected addr: %s", resolved.addr)
	}
	if resolved.dbPath != "override.db" {
		t.Fatalf("unexpected db path: %s", resolved.dbPath)
	}

	resolved, err = resolveServeConfig(serveConfigOptions{
		configPath: configPath,
		addr:       ":9090",
	})
	if err != nil {
		t.Fatalf("resolve serve config: %v", err)
	}
	if resolved.dbPath != "from-config.db" {
		t.Fatalf("expected config database, got %s", resolved.dbPath)
	}
}
