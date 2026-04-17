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
