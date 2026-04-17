package store

import (
	"context"
	"database/sql"
	"net/netip"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"trafficanalysis/internal/traffic"
)

type BucketRow struct {
	Key   traffic.BucketKey
	Value traffic.BucketValue
}

type ClientBucketRow struct {
	Key        traffic.ClientBucketKey
	Value      traffic.BucketValue
	Name       string
	NameSource string
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
CREATE TABLE IF NOT EXISTS client_buckets (
	bucket_start INTEGER NOT NULL,
	client_ip TEXT NOT NULL,
	client_mac TEXT NOT NULL,
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (bucket_start, client_ip, client_mac, direction, protocol)
);
CREATE INDEX IF NOT EXISTS idx_client_buckets_start ON client_buckets(bucket_start);
CREATE INDEX IF NOT EXISTS idx_client_buckets_client_ip ON client_buckets(client_ip, bucket_start);
CREATE TABLE IF NOT EXISTS client_names (
	client_ip TEXT NOT NULL,
	client_mac TEXT NOT NULL,
	name TEXT NOT NULL,
	source TEXT NOT NULL,
	first_seen INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	PRIMARY KEY (client_ip, client_mac)
);
CREATE INDEX IF NOT EXISTS idx_client_names_mac ON client_names(client_mac);
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

func (s *SQLiteStore) UpsertClientBuckets(ctx context.Context, buckets map[traffic.ClientBucketKey]traffic.BucketValue) error {
	if len(buckets) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO client_buckets (bucket_start, client_ip, client_mac, direction, protocol, bytes, packets)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(bucket_start, client_ip, client_mac, direction, protocol) DO UPDATE SET
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
			key.ClientIP.String(),
			key.ClientMAC,
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

func (s *SQLiteStore) UpsertClientNames(ctx context.Context, names []traffic.NameObservation) error {
	if len(names) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO client_names (client_ip, client_mac, name, source, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(client_ip, client_mac) DO UPDATE SET
	name = excluded.name,
	source = excluded.source,
	last_seen = MAX(client_names.last_seen, excluded.last_seen);
`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, name := range names {
		if !name.IP.IsValid() || name.MAC == "" || name.Name == "" {
			continue
		}
		timestamp := name.Timestamp.UTC()
		if timestamp.IsZero() {
			timestamp = time.Now().UTC()
		}
		_, err := stmt.ExecContext(
			ctx,
			name.IP.String(),
			name.MAC,
			name.Name,
			name.Source,
			timestamp.Unix(),
			timestamp.Unix(),
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

func (s *SQLiteStore) QueryClientBuckets(ctx context.Context, from, to time.Time, clientIP string) ([]ClientBucketRow, error) {
	const queryAll = `
SELECT cb.bucket_start, cb.client_ip, cb.client_mac, cb.direction, cb.protocol, cb.bytes, cb.packets,
       COALESCE(cn.name, ''), COALESCE(cn.source, '')
FROM client_buckets cb
LEFT JOIN client_names cn ON cn.client_ip = cb.client_ip AND cn.client_mac = cb.client_mac
WHERE cb.bucket_start >= ? AND cb.bucket_start < ?
ORDER BY cb.bucket_start ASC, cb.client_ip ASC, cb.client_mac ASC, cb.direction ASC, cb.protocol ASC;
`
	const queryClient = `
SELECT cb.bucket_start, cb.client_ip, cb.client_mac, cb.direction, cb.protocol, cb.bytes, cb.packets,
       COALESCE(cn.name, ''), COALESCE(cn.source, '')
FROM client_buckets cb
LEFT JOIN client_names cn ON cn.client_ip = cb.client_ip AND cn.client_mac = cb.client_mac
WHERE cb.bucket_start >= ? AND cb.bucket_start < ? AND cb.client_ip = ?
ORDER BY cb.bucket_start ASC, cb.client_ip ASC, cb.client_mac ASC, cb.direction ASC, cb.protocol ASC;
`

	var rows *sql.Rows
	var err error
	if clientIP == "" {
		rows, err = s.db.QueryContext(ctx, queryAll, from.UTC().Unix(), to.UTC().Unix())
	} else {
		rows, err = s.db.QueryContext(ctx, queryClient, from.UTC().Unix(), to.UTC().Unix(), clientIP)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ClientBucketRow
	for rows.Next() {
		var startUnix int64
		var clientIPText string
		var clientMAC string
		var direction string
		var protocol string
		var bytes int64
		var packets int64
		var name string
		var nameSource string
		if err := rows.Scan(&startUnix, &clientIPText, &clientMAC, &direction, &protocol, &bytes, &packets, &name, &nameSource); err != nil {
			return nil, err
		}

		clientAddr, err := netip.ParseAddr(clientIPText)
		if err != nil {
			return nil, err
		}
		result = append(result, ClientBucketRow{
			Key: traffic.ClientBucketKey{
				Start:     time.Unix(startUnix, 0).UTC(),
				ClientIP:  clientAddr,
				ClientMAC: clientMAC,
				Direction: traffic.Direction(direction),
				Protocol:  protocol,
			},
			Value: traffic.BucketValue{
				Bytes:   bytes,
				Packets: packets,
			},
			Name:       name,
			NameSource: nameSource,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
