package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"trafficanalysis/internal/traffic"
)

func TestSQLiteStoreUpsertsAndQueriesBuckets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	key := traffic.BucketKey{
		Start:     start,
		Direction: traffic.DirectionUpload,
		Protocol:  "tcp",
	}

	err = store.UpsertBuckets(ctx, map[traffic.BucketKey]traffic.BucketValue{
		key: {Bytes: 1000, Packets: 2},
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	err = store.UpsertBuckets(ctx, map[traffic.BucketKey]traffic.BucketValue{
		key: {Bytes: 2500, Packets: 3},
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	rows, err := store.QueryBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %#v", len(rows), rows)
	}
	if rows[0].Key != key {
		t.Fatalf("unexpected key: %#v", rows[0].Key)
	}
	if rows[0].Value.Bytes != 3500 || rows[0].Value.Packets != 5 {
		t.Fatalf("unexpected aggregate: %#v", rows[0].Value)
	}
}

func TestSQLiteStoreEnablesConcurrentReadFriendlyPragmas(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	var journalMode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&journalMode); err != nil {
		t.Fatalf("query journal mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("expected WAL journal mode, got %q", journalMode)
	}

	var busyTimeout int
	if err := store.db.QueryRowContext(ctx, "PRAGMA busy_timeout;").Scan(&busyTimeout); err != nil {
		t.Fatalf("query busy timeout: %v", err)
	}
	if busyTimeout < 5000 {
		t.Fatalf("expected busy timeout >= 5000ms, got %d", busyTimeout)
	}
}

func TestSQLiteStoreUpsertsAndQueriesClientBuckets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	clientIP := netip.MustParseAddr("192.168.248.22")
	key := traffic.ClientBucketKey{
		Start:     start,
		ClientIP:  clientIP,
		ClientMAC: "00:11:22:33:44:55",
		Direction: traffic.DirectionDownload,
		Protocol:  "tcp",
	}

	err = store.UpsertClientBuckets(ctx, map[traffic.ClientBucketKey]traffic.BucketValue{
		key: {Bytes: 4096, Packets: 4},
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	err = store.UpsertClientBuckets(ctx, map[traffic.ClientBucketKey]traffic.BucketValue{
		key: {Bytes: 2048, Packets: 2},
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	rows, err := store.QueryClientBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute), "")
	if err != nil {
		t.Fatalf("query all clients: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %#v", len(rows), rows)
	}
	if rows[0].Key != key {
		t.Fatalf("unexpected key: %#v", rows[0].Key)
	}
	if rows[0].Value.Bytes != 6144 || rows[0].Value.Packets != 6 {
		t.Fatalf("unexpected aggregate: %#v", rows[0].Value)
	}

	filtered, err := store.QueryClientBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute), clientIP.String())
	if err != nil {
		t.Fatalf("query filtered clients: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected filtered row, got %d: %#v", len(filtered), filtered)
	}

	filtered, err = store.QueryClientBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute), "192.168.248.99")
	if err != nil {
		t.Fatalf("query absent client: %v", err)
	}
	if len(filtered) != 0 {
		t.Fatalf("expected no filtered rows, got %#v", filtered)
	}
}

func TestSQLiteStoreUpsertsAndQueriesEndpointBuckets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	clientIP := netip.MustParseAddr("192.168.248.22")
	remoteIP := netip.MustParseAddr("203.0.113.9")
	key := traffic.EndpointBucketKey{
		Start:      start,
		ClientIP:   clientIP,
		ClientMAC:  "00:11:22:33:44:55",
		RemoteIP:   remoteIP,
		RemotePort: 443,
		Direction:  traffic.DirectionUpload,
		Protocol:   "tcp",
	}

	err = store.UpsertEndpointBuckets(ctx, map[traffic.EndpointBucketKey]traffic.BucketValue{
		key: {Bytes: 4096, Packets: 4},
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	err = store.UpsertEndpointBuckets(ctx, map[traffic.EndpointBucketKey]traffic.BucketValue{
		key: {Bytes: 2048, Packets: 2},
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	rows, err := store.QueryEndpointBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute))
	if err != nil {
		t.Fatalf("query endpoints: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %#v", len(rows), rows)
	}
	if rows[0].Key != key {
		t.Fatalf("unexpected key: %#v", rows[0].Key)
	}
	if rows[0].Value.Bytes != 6144 || rows[0].Value.Packets != 6 {
		t.Fatalf("unexpected aggregate: %#v", rows[0].Value)
	}
}

func TestSQLiteStoreUpsertsAndQueriesWANEndpointBuckets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	remoteIP := netip.MustParseAddr("203.0.113.9")
	key := traffic.WANEndpointBucketKey{
		Start:      start,
		RemoteIP:   remoteIP,
		RemotePort: 443,
		Direction:  traffic.DirectionUpload,
		Protocol:   "udp",
	}

	err = store.UpsertWANEndpointBuckets(ctx, map[traffic.WANEndpointBucketKey]traffic.BucketValue{
		key: {Bytes: 4096, Packets: 4},
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	err = store.UpsertWANEndpointBuckets(ctx, map[traffic.WANEndpointBucketKey]traffic.BucketValue{
		key: {Bytes: 2048, Packets: 2},
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	rows, err := store.QueryWANEndpointBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute))
	if err != nil {
		t.Fatalf("query WAN endpoints: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %#v", len(rows), rows)
	}
	if rows[0].Key != key {
		t.Fatalf("unexpected key: %#v", rows[0].Key)
	}
	if rows[0].Value.Bytes != 6144 || rows[0].Value.Packets != 6 {
		t.Fatalf("unexpected aggregate: %#v", rows[0].Value)
	}
}

func TestSQLiteStoreStoresClientNamesAndReturnsThemWithClientBuckets(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	clientIP := netip.MustParseAddr("192.168.248.22")
	clientMAC := "00:11:22:33:44:55"

	err = store.UpsertClientNames(ctx, []traffic.NameObservation{
		{
			Timestamp: start,
			IP:        clientIP,
			MAC:       clientMAC,
			Name:      "nas-box",
			Source:    "dhcp",
		},
	})
	if err != nil {
		t.Fatalf("upsert client name: %v", err)
	}

	err = store.UpsertClientBuckets(ctx, map[traffic.ClientBucketKey]traffic.BucketValue{
		{
			Start:     start,
			ClientIP:  clientIP,
			ClientMAC: clientMAC,
			Direction: traffic.DirectionUpload,
			Protocol:  "tcp",
		}: {Bytes: 1024, Packets: 1},
	})
	if err != nil {
		t.Fatalf("upsert client bucket: %v", err)
	}

	rows, err := store.QueryClientBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute), "")
	if err != nil {
		t.Fatalf("query client buckets: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d: %#v", len(rows), rows)
	}
	if rows[0].Name != "nas-box" || rows[0].NameSource != "dhcp" {
		t.Fatalf("expected client name from dhcp, got name=%q source=%q", rows[0].Name, rows[0].NameSource)
	}
}

func TestSQLiteStoreClientAliasOverridesLearnedName(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	clientIP := netip.MustParseAddr("192.168.248.22")
	clientMAC := "00:11:22:33:44:55"

	err = store.UpsertClientNames(ctx, []traffic.NameObservation{
		{Timestamp: start, IP: clientIP, MAC: clientMAC, Name: "nas-box", Source: "dhcp"},
	})
	if err != nil {
		t.Fatalf("upsert client name: %v", err)
	}
	err = store.UpsertClientAlias(ctx, clientIP.String(), clientMAC, "书房 NAS")
	if err != nil {
		t.Fatalf("upsert client alias: %v", err)
	}
	err = store.UpsertClientBuckets(ctx, map[traffic.ClientBucketKey]traffic.BucketValue{
		{
			Start:     start,
			ClientIP:  clientIP,
			ClientMAC: clientMAC,
			Direction: traffic.DirectionDownload,
			Protocol:  "tcp",
		}: {Bytes: 2048, Packets: 2},
	})
	if err != nil {
		t.Fatalf("upsert client bucket: %v", err)
	}

	rows, err := store.QueryClientBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute), "")
	if err != nil {
		t.Fatalf("query client buckets: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d: %#v", len(rows), rows)
	}
	if rows[0].Alias != "书房 NAS" || rows[0].Name != "nas-box" {
		t.Fatalf("expected alias and learned name, got alias=%q name=%q", rows[0].Alias, rows[0].Name)
	}

	err = store.UpsertClientAlias(ctx, clientIP.String(), clientMAC, "")
	if err != nil {
		t.Fatalf("clear client alias: %v", err)
	}
	rows, err = store.QueryClientBuckets(ctx, start.Add(-time.Minute), start.Add(time.Minute), "")
	if err != nil {
		t.Fatalf("query client buckets after clear: %v", err)
	}
	if rows[0].Alias != "" {
		t.Fatalf("expected alias to clear, got %q", rows[0].Alias)
	}
}

func TestSQLiteStoreResolvesClientAliasForLiveTraffic(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	if err := store.UpsertClientAlias(ctx, "192.168.248.22", "00:11:22:33:44:55", "书房 NAS"); err != nil {
		t.Fatalf("upsert mac alias: %v", err)
	}
	alias, err := store.ResolveClientAlias(ctx, "192.168.248.22", "00:11:22:33:44:55")
	if err != nil {
		t.Fatalf("resolve mac alias: %v", err)
	}
	if alias != "书房 NAS" {
		t.Fatalf("expected alias by mac, got %q", alias)
	}

	alias, err = store.ResolveClientAlias(ctx, "192.168.248.22", "")
	if err != nil {
		t.Fatalf("resolve ip fallback alias: %v", err)
	}
	if alias != "书房 NAS" {
		t.Fatalf("expected live traffic without mac to fall back to ip alias, got %q", alias)
	}
}

func TestSQLiteStoreCompactsMinuteBucketsToHourlyWithoutLosingTotals(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	oldHour := now.Add(-40 * 24 * time.Hour).Truncate(time.Hour)
	clientIP := netip.MustParseAddr("192.168.248.22")
	clientMAC := "00:11:22:33:44:55"

	if err := store.UpsertBuckets(ctx, map[traffic.BucketKey]traffic.BucketValue{
		{Start: oldHour.Add(5 * time.Minute), Direction: traffic.DirectionUpload, Protocol: "tcp"}:    {Bytes: 1000, Packets: 2},
		{Start: oldHour.Add(15 * time.Minute), Direction: traffic.DirectionUpload, Protocol: "tcp"}:   {Bytes: 2500, Packets: 3},
		{Start: oldHour.Add(25 * time.Minute), Direction: traffic.DirectionDownload, Protocol: "udp"}: {Bytes: 4096, Packets: 4},
	}); err != nil {
		t.Fatalf("upsert traffic buckets: %v", err)
	}
	if err := store.UpsertClientBuckets(ctx, map[traffic.ClientBucketKey]traffic.BucketValue{
		{Start: oldHour.Add(5 * time.Minute), ClientIP: clientIP, ClientMAC: clientMAC, Direction: traffic.DirectionUpload, Protocol: "tcp"}:    {Bytes: 1000, Packets: 2},
		{Start: oldHour.Add(15 * time.Minute), ClientIP: clientIP, ClientMAC: clientMAC, Direction: traffic.DirectionUpload, Protocol: "tcp"}:   {Bytes: 2500, Packets: 3},
		{Start: oldHour.Add(25 * time.Minute), ClientIP: clientIP, ClientMAC: clientMAC, Direction: traffic.DirectionDownload, Protocol: "udp"}: {Bytes: 4096, Packets: 4},
	}); err != nil {
		t.Fatalf("upsert client buckets: %v", err)
	}
	if err := store.UpsertClientNames(ctx, []traffic.NameObservation{
		{Timestamp: oldHour, IP: clientIP, MAC: clientMAC, Name: "nas-box", Source: "dhcp"},
	}); err != nil {
		t.Fatalf("upsert client name: %v", err)
	}
	if err := store.UpsertClientAlias(ctx, clientIP.String(), clientMAC, "书房 NAS"); err != nil {
		t.Fatalf("upsert alias: %v", err)
	}

	err = store.CompactAndPrune(ctx, now, RetentionPolicy{
		MinuteRetention: 30 * 24 * time.Hour,
		HourlyRetention: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("compact and prune: %v", err)
	}

	var minuteRows int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_buckets;`).Scan(&minuteRows); err != nil {
		t.Fatalf("count minute traffic rows: %v", err)
	}
	if minuteRows != 0 {
		t.Fatalf("expected compacted minute traffic rows to be deleted, got %d", minuteRows)
	}

	rows, err := store.QueryBuckets(ctx, oldHour, oldHour.Add(time.Hour))
	if err != nil {
		t.Fatalf("query compacted traffic: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected two hourly traffic rows, got %d: %#v", len(rows), rows)
	}
	if rows[0].Key.Start != oldHour || rows[0].Value.Bytes != 4096 || rows[0].Value.Packets != 4 {
		t.Fatalf("unexpected first compacted traffic row: %#v", rows[0])
	}
	if rows[1].Key.Start != oldHour || rows[1].Value.Bytes != 3500 || rows[1].Value.Packets != 5 {
		t.Fatalf("unexpected second compacted traffic row: %#v", rows[1])
	}

	clientRows, err := store.QueryClientBuckets(ctx, oldHour, oldHour.Add(time.Hour), clientIP.String())
	if err != nil {
		t.Fatalf("query compacted clients: %v", err)
	}
	if len(clientRows) != 2 {
		t.Fatalf("expected two hourly client rows, got %d: %#v", len(clientRows), clientRows)
	}
	if clientRows[0].Alias != "书房 NAS" || clientRows[0].Name != "nas-box" {
		t.Fatalf("expected alias and learned name after compaction, got %#v", clientRows[0])
	}
	var totalBytes int64
	var totalPackets int64
	for _, row := range clientRows {
		totalBytes += row.Value.Bytes
		totalPackets += row.Value.Packets
	}
	if totalBytes != 7596 || totalPackets != 9 {
		t.Fatalf("expected client totals to survive compaction, got bytes=%d packets=%d", totalBytes, totalPackets)
	}
}

func TestSQLiteStoreArchivesHourlyBucketsOlderThanRetention(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	tooOld := now.Add(-400 * 24 * time.Hour).Truncate(time.Hour)
	keep := now.Add(-200 * 24 * time.Hour).Truncate(time.Hour)
	clientIP := "192.168.248.22"
	clientMAC := "00:11:22:33:44:55"

	for _, start := range []time.Time{tooOld, keep} {
		if _, err := store.db.ExecContext(ctx, `
INSERT INTO traffic_hourly_buckets (bucket_start, direction, protocol, bytes, packets)
VALUES (?, ?, ?, ?, ?);
`, start.Unix(), string(traffic.DirectionDownload), "tcp", 1000, 1); err != nil {
			t.Fatalf("insert hourly traffic: %v", err)
		}
		if _, err := store.db.ExecContext(ctx, `
INSERT INTO client_hourly_buckets (bucket_start, client_ip, client_mac, direction, protocol, bytes, packets)
VALUES (?, ?, ?, ?, ?, ?, ?);
`, start.Unix(), clientIP, clientMAC, string(traffic.DirectionDownload), "tcp", 1000, 1); err != nil {
			t.Fatalf("insert hourly client: %v", err)
		}
	}

	err = store.CompactAndPrune(ctx, now, RetentionPolicy{
		MinuteRetention: 30 * 24 * time.Hour,
		HourlyRetention: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("compact and prune: %v", err)
	}

	rows, err := store.QueryBuckets(ctx, tooOld.Add(-time.Hour), keep.Add(time.Hour))
	if err != nil {
		t.Fatalf("query hourly traffic: %v", err)
	}
	if len(rows) != 1 || rows[0].Key.Start != keep {
		t.Fatalf("expected only retained hourly traffic row, got %#v", rows)
	}

	var archivedTrafficBytes int64
	var archivedTrafficPackets int64
	if err := store.db.QueryRowContext(ctx, `
SELECT bytes, packets
FROM traffic_archive_buckets
WHERE direction = ? AND protocol = ?;
`, string(traffic.DirectionDownload), "tcp").Scan(&archivedTrafficBytes, &archivedTrafficPackets); err != nil {
		t.Fatalf("query archived traffic: %v", err)
	}
	if archivedTrafficBytes != 1000 || archivedTrafficPackets != 1 {
		t.Fatalf("expected old hourly traffic to be archived, got bytes=%d packets=%d", archivedTrafficBytes, archivedTrafficPackets)
	}

	clientRows, err := store.QueryClientBuckets(ctx, tooOld.Add(-time.Hour), keep.Add(time.Hour), clientIP)
	if err != nil {
		t.Fatalf("query hourly clients: %v", err)
	}
	if len(clientRows) != 1 || clientRows[0].Key.Start != keep {
		t.Fatalf("expected only retained hourly client row, got %#v", clientRows)
	}

	var archivedClientBytes int64
	var archivedClientPackets int64
	if err := store.db.QueryRowContext(ctx, `
SELECT bytes, packets
FROM client_archive_buckets
WHERE client_ip = ? AND client_mac = ? AND direction = ? AND protocol = ?;
`, clientIP, clientMAC, string(traffic.DirectionDownload), "tcp").Scan(&archivedClientBytes, &archivedClientPackets); err != nil {
		t.Fatalf("query archived client: %v", err)
	}
	if archivedClientBytes != 1000 || archivedClientPackets != 1 {
		t.Fatalf("expected old hourly client traffic to be archived, got bytes=%d packets=%d", archivedClientBytes, archivedClientPackets)
	}
}

func TestSQLiteStoreStoresAndQueriesAnalysisObservationsAndSessions(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	observedAt := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	clientIP := netip.MustParseAddr("192.168.248.22")
	remoteIP := netip.MustParseAddr("203.0.113.9")

	err = store.UpsertDNSObservations(ctx, []traffic.DNSObservation{
		{
			ObservedAt: observedAt,
			ClientIP:   clientIP,
			ClientMAC:  "00:11:22:33:44:55",
			Name:       "api.example.com",
			RecordType: "A",
			AnswerIP:   remoteIP,
			TTL:        300,
			Source:     "dns",
		},
	})
	if err != nil {
		t.Fatalf("upsert dns observations: %v", err)
	}

	err = store.UpsertTLSObservations(ctx, []traffic.TLSObservation{
		{
			ObservedAt: observedAt.Add(2 * time.Second),
			Viewpoint:  traffic.ViewpointLAN,
			ClientIP:   clientIP,
			ClientMAC:  "00:11:22:33:44:55",
			RemoteIP:   remoteIP,
			RemotePort: 443,
			ServerName: "api.example.com",
			ALPN:       "h2",
			Protocol:   "tcp",
			Source:     "tls_client_hello",
		},
	})
	if err != nil {
		t.Fatalf("upsert tls observations: %v", err)
	}

	sessionID, err := store.InsertFlowSession(ctx, traffic.FlowSession{
		Viewpoint:      traffic.ViewpointLAN,
		Protocol:       "tcp",
		LocalIP:        clientIP,
		LocalPort:      53000,
		RemoteIP:       remoteIP,
		RemotePort:     443,
		ClientIP:       clientIP,
		ClientMAC:      "00:11:22:33:44:55",
		FirstSeen:      observedAt,
		LastSeen:       observedAt.Add(15 * time.Second),
		UploadBytes:    4096,
		DownloadBytes:  2048,
		Packets:        12,
		SYNSeen:        true,
		HasDNSEvidence: true,
		HasTLSEvidence: true,
	})
	if err != nil {
		t.Fatalf("insert flow session: %v", err)
	}

	dnsRows, err := store.QueryDNSObservations(ctx, observedAt.Add(-time.Minute), observedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("query dns observations: %v", err)
	}
	if len(dnsRows) != 1 || dnsRows[0].Name != "api.example.com" || dnsRows[0].AnswerIP != remoteIP {
		t.Fatalf("unexpected dns rows: %#v", dnsRows)
	}

	tlsRows, err := store.QueryTLSObservations(ctx, observedAt.Add(-time.Minute), observedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("query tls observations: %v", err)
	}
	if len(tlsRows) != 1 || tlsRows[0].ServerName != "api.example.com" || tlsRows[0].ALPN != "h2" {
		t.Fatalf("unexpected tls rows: %#v", tlsRows)
	}

	sessions, err := store.QueryFlowSessions(ctx, observedAt.Add(-time.Minute), observedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("query flow sessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != sessionID {
		t.Fatalf("unexpected flow sessions: %#v", sessions)
	}
	if sessions[0].UploadBytes != 4096 || !sessions[0].HasDNSEvidence || !sessions[0].HasTLSEvidence {
		t.Fatalf("unexpected flow session payload: %#v", sessions[0])
	}
}

func TestSQLiteStoreQueryFlowSessionsToleratesHistoricalInvalidIPSentinel(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "traffic.db")

	store, err := OpenSQLite(ctx, dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	start := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO flow_sessions (
	viewpoint, protocol, local_ip, local_port, remote_ip, remote_port, client_ip, client_mac,
	first_seen, last_seen, upload_bytes, download_bytes, packets, syn_seen, fin_seen, rst_seen,
	has_dns_evidence, has_tls_evidence
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`, "wan", "udp", "198.51.100.10", 52000, "203.0.113.9", 3478, "invalid IP", "", start.Unix(), start.Add(10*time.Second).Unix(), 1000, 2000, 3, 0, 0, 0, 0, 0); err != nil {
		t.Fatalf("insert historical invalid row: %v", err)
	}

	rows, err := store.QueryFlowSessions(ctx, start.Add(-time.Minute), start.Add(time.Minute))
	if err != nil {
		t.Fatalf("query flow sessions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one flow session, got %#v", rows)
	}
	if rows[0].ClientIP.IsValid() {
		t.Fatalf("expected invalid IP sentinel to decode as zero address, got %#v", rows[0])
	}
}
