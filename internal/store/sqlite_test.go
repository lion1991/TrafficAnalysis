package store

import (
	"context"
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
