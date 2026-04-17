package store

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"trafficanalysis/internal/traffic"
)

type BucketRow struct {
	Key   traffic.BucketKey
	Value traffic.BucketValue
}

type SQLiteStore struct {
	db *sql.DB
}

func OpenSQLite(ctx context.Context, path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	store := &SQLiteStore{db: db}
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) configure(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
PRAGMA busy_timeout = 5000;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
`)
	return err
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS traffic_buckets (
	bucket_start INTEGER NOT NULL,
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (bucket_start, direction, protocol)
);
CREATE INDEX IF NOT EXISTS idx_traffic_buckets_start ON traffic_buckets(bucket_start);
`)
	return err
}

func (s *SQLiteStore) UpsertBuckets(ctx context.Context, buckets map[traffic.BucketKey]traffic.BucketValue) error {
	if len(buckets) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_buckets (bucket_start, direction, protocol, bytes, packets)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(bucket_start, direction, protocol) DO UPDATE SET
	bytes = bytes + excluded.bytes,
	packets = packets + excluded.packets;
`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for key, value := range buckets {
		_, err := stmt.ExecContext(
			ctx,
			key.Start.UTC().Unix(),
			string(key.Direction),
			key.Protocol,
			value.Bytes,
			value.Packets,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStore) QueryBuckets(ctx context.Context, from, to time.Time) ([]BucketRow, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT bucket_start, direction, protocol, bytes, packets
FROM traffic_buckets
WHERE bucket_start >= ? AND bucket_start < ?
ORDER BY bucket_start ASC, direction ASC, protocol ASC;
`, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []BucketRow
	for rows.Next() {
		var startUnix int64
		var direction string
		var protocol string
		var bytes int64
		var packets int64
		if err := rows.Scan(&startUnix, &direction, &protocol, &bytes, &packets); err != nil {
			return nil, err
		}

		result = append(result, BucketRow{
			Key: traffic.BucketKey{
				Start:     time.Unix(startUnix, 0).UTC(),
				Direction: traffic.Direction(direction),
				Protocol:  protocol,
			},
			Value: traffic.BucketValue{
				Bytes:   bytes,
				Packets: packets,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
