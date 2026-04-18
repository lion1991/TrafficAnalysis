package store

import (
	"context"
	"database/sql"
	"net/netip"
	"strings"
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
	Alias      string
	Name       string
	NameSource string
}

type EndpointBucketRow struct {
	Key   traffic.EndpointBucketKey
	Value traffic.BucketValue
}

type RetentionPolicy struct {
	MinuteRetention time.Duration
	HourlyRetention time.Duration
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
CREATE TABLE IF NOT EXISTS traffic_hourly_buckets (
	bucket_start INTEGER NOT NULL,
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (bucket_start, direction, protocol)
);
CREATE INDEX IF NOT EXISTS idx_traffic_hourly_buckets_start ON traffic_hourly_buckets(bucket_start);
CREATE TABLE IF NOT EXISTS traffic_archive_buckets (
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (direction, protocol)
);
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
CREATE TABLE IF NOT EXISTS client_hourly_buckets (
	bucket_start INTEGER NOT NULL,
	client_ip TEXT NOT NULL,
	client_mac TEXT NOT NULL,
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (bucket_start, client_ip, client_mac, direction, protocol)
);
CREATE INDEX IF NOT EXISTS idx_client_hourly_buckets_start ON client_hourly_buckets(bucket_start);
CREATE INDEX IF NOT EXISTS idx_client_hourly_buckets_client_ip ON client_hourly_buckets(client_ip, bucket_start);
CREATE TABLE IF NOT EXISTS client_archive_buckets (
	client_ip TEXT NOT NULL,
	client_mac TEXT NOT NULL,
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (client_ip, client_mac, direction, protocol)
);
CREATE TABLE IF NOT EXISTS endpoint_buckets (
	bucket_start INTEGER NOT NULL,
	client_ip TEXT NOT NULL,
	client_mac TEXT NOT NULL,
	remote_ip TEXT NOT NULL,
	remote_port INTEGER NOT NULL,
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_buckets_start ON endpoint_buckets(bucket_start);
CREATE INDEX IF NOT EXISTS idx_endpoint_buckets_remote ON endpoint_buckets(remote_ip, bucket_start);
CREATE TABLE IF NOT EXISTS endpoint_hourly_buckets (
	bucket_start INTEGER NOT NULL,
	client_ip TEXT NOT NULL,
	client_mac TEXT NOT NULL,
	remote_ip TEXT NOT NULL,
	remote_port INTEGER NOT NULL,
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_hourly_buckets_start ON endpoint_hourly_buckets(bucket_start);
CREATE INDEX IF NOT EXISTS idx_endpoint_hourly_buckets_remote ON endpoint_hourly_buckets(remote_ip, bucket_start);
CREATE TABLE IF NOT EXISTS endpoint_archive_buckets (
	client_ip TEXT NOT NULL,
	client_mac TEXT NOT NULL,
	remote_ip TEXT NOT NULL,
	remote_port INTEGER NOT NULL,
	direction TEXT NOT NULL,
	protocol TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	packets INTEGER NOT NULL,
	PRIMARY KEY (client_ip, client_mac, remote_ip, remote_port, direction, protocol)
);
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
CREATE TABLE IF NOT EXISTS client_aliases (
	client_key TEXT NOT NULL PRIMARY KEY,
	client_ip TEXT NOT NULL,
	client_mac TEXT NOT NULL,
	alias TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_client_aliases_mac ON client_aliases(client_mac);
CREATE INDEX IF NOT EXISTS idx_client_aliases_ip ON client_aliases(client_ip);
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

func (s *SQLiteStore) UpsertEndpointBuckets(ctx context.Context, buckets map[traffic.EndpointBucketKey]traffic.BucketValue) error {
	if len(buckets) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO endpoint_buckets (bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol, bytes, packets)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol) DO UPDATE SET
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
			key.RemoteIP.String(),
			int(key.RemotePort),
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

func (s *SQLiteStore) UpsertClientAlias(ctx context.Context, clientIP, clientMAC, alias string) error {
	clientIP = strings.TrimSpace(clientIP)
	clientMAC = normalizeMAC(clientMAC)
	alias = strings.TrimSpace(alias)
	if clientIP == "" && clientMAC == "" {
		return nil
	}
	clientKey := clientAliasKey(clientIP, clientMAC)
	if alias == "" {
		_, err := s.db.ExecContext(ctx, `
DELETE FROM client_aliases
WHERE client_key = ?;
`, clientKey)
		return err
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO client_aliases (client_key, client_ip, client_mac, alias, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(client_key) DO UPDATE SET
	client_ip = excluded.client_ip,
	client_mac = excluded.client_mac,
	alias = excluded.alias,
	updated_at = excluded.updated_at;
`, clientKey, clientIP, clientMAC, alias, time.Now().UTC().Unix())
	return err
}

func clientAliasKey(clientIP, clientMAC string) string {
	clientMAC = normalizeMAC(clientMAC)
	if clientMAC != "" {
		return clientMAC
	}
	return strings.TrimSpace(clientIP)
}

func normalizeMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}

func (s *SQLiteStore) ResolveClientAlias(ctx context.Context, clientIP, clientMAC string) (string, error) {
	clientIP = strings.TrimSpace(clientIP)
	clientMAC = normalizeMAC(clientMAC)
	if clientIP == "" && clientMAC == "" {
		return "", nil
	}

	if clientMAC != "" {
		alias, err := s.resolveClientAliasByMAC(ctx, clientMAC)
		if err != nil || alias != "" {
			return alias, err
		}
	}
	if clientIP == "" {
		return "", nil
	}

	var alias string
	err := s.db.QueryRowContext(ctx, `
SELECT alias
FROM client_aliases
WHERE client_ip = ?
ORDER BY updated_at DESC
LIMIT 1;
`, clientIP).Scan(&alias)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return alias, err
}

func (s *SQLiteStore) resolveClientAliasByMAC(ctx context.Context, clientMAC string) (string, error) {
	var alias string
	err := s.db.QueryRowContext(ctx, `
SELECT alias
FROM client_aliases
WHERE client_key = ? OR client_mac = ?
ORDER BY updated_at DESC
LIMIT 1;
`, clientMAC, clientMAC).Scan(&alias)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return alias, err
}

func (s *SQLiteStore) QueryBuckets(ctx context.Context, from, to time.Time) ([]BucketRow, error) {
	rows, err := s.db.QueryContext(ctx, `
WITH combined AS (
SELECT bucket_start, direction, protocol, bytes, packets
FROM traffic_buckets
WHERE bucket_start >= ? AND bucket_start < ?
UNION ALL
SELECT bucket_start, direction, protocol, bytes, packets
FROM traffic_hourly_buckets
WHERE bucket_start >= ? AND bucket_start < ?
)
SELECT bucket_start, direction, protocol, bytes, packets
FROM combined
ORDER BY bucket_start ASC, direction ASC, protocol ASC;
`, from.UTC().Unix(), to.UTC().Unix(), from.UTC().Unix(), to.UTC().Unix())
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
WITH combined AS (
SELECT bucket_start, client_ip, client_mac, direction, protocol, bytes, packets
FROM client_buckets
WHERE bucket_start >= ? AND bucket_start < ?
UNION ALL
SELECT bucket_start, client_ip, client_mac, direction, protocol, bytes, packets
FROM client_hourly_buckets
WHERE bucket_start >= ? AND bucket_start < ?
)
SELECT cb.bucket_start, cb.client_ip, cb.client_mac, cb.direction, cb.protocol, cb.bytes, cb.packets,
       COALESCE((
          SELECT alias
          FROM (
             SELECT ca.alias, ca.updated_at,
                    CASE
                       WHEN cb.client_mac != '' AND ca.client_key = cb.client_mac THEN 0
                       WHEN cb.client_mac != '' AND ca.client_mac = cb.client_mac THEN 1
                       WHEN ca.client_ip = cb.client_ip THEN 2
                       ELSE 3
                    END AS alias_priority
             FROM client_aliases ca
             WHERE (cb.client_mac != '' AND (ca.client_key = cb.client_mac OR ca.client_mac = cb.client_mac))
                OR ca.client_ip = cb.client_ip
          )
          ORDER BY alias_priority ASC, updated_at DESC
          LIMIT 1
       ), ''),
       COALESCE(cn.name, ''), COALESCE(cn.source, '')
FROM combined cb
LEFT JOIN client_names cn ON cn.client_ip = cb.client_ip AND cn.client_mac = cb.client_mac
ORDER BY cb.bucket_start ASC, cb.client_ip ASC, cb.client_mac ASC, cb.direction ASC, cb.protocol ASC;
`
	const queryClient = `
WITH combined AS (
SELECT bucket_start, client_ip, client_mac, direction, protocol, bytes, packets
FROM client_buckets
WHERE bucket_start >= ? AND bucket_start < ? AND client_ip = ?
UNION ALL
SELECT bucket_start, client_ip, client_mac, direction, protocol, bytes, packets
FROM client_hourly_buckets
WHERE bucket_start >= ? AND bucket_start < ? AND client_ip = ?
)
SELECT cb.bucket_start, cb.client_ip, cb.client_mac, cb.direction, cb.protocol, cb.bytes, cb.packets,
       COALESCE((
          SELECT alias
          FROM (
             SELECT ca.alias, ca.updated_at,
                    CASE
                       WHEN cb.client_mac != '' AND ca.client_key = cb.client_mac THEN 0
                       WHEN cb.client_mac != '' AND ca.client_mac = cb.client_mac THEN 1
                       WHEN ca.client_ip = cb.client_ip THEN 2
                       ELSE 3
                    END AS alias_priority
             FROM client_aliases ca
             WHERE (cb.client_mac != '' AND (ca.client_key = cb.client_mac OR ca.client_mac = cb.client_mac))
                OR ca.client_ip = cb.client_ip
          )
          ORDER BY alias_priority ASC, updated_at DESC
          LIMIT 1
       ), ''),
       COALESCE(cn.name, ''), COALESCE(cn.source, '')
FROM combined cb
LEFT JOIN client_names cn ON cn.client_ip = cb.client_ip AND cn.client_mac = cb.client_mac
ORDER BY cb.bucket_start ASC, cb.client_ip ASC, cb.client_mac ASC, cb.direction ASC, cb.protocol ASC;
`

	var rows *sql.Rows
	var err error
	if clientIP == "" {
		rows, err = s.db.QueryContext(ctx, queryAll, from.UTC().Unix(), to.UTC().Unix(), from.UTC().Unix(), to.UTC().Unix())
	} else {
		rows, err = s.db.QueryContext(ctx, queryClient, from.UTC().Unix(), to.UTC().Unix(), clientIP, from.UTC().Unix(), to.UTC().Unix(), clientIP)
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
		var alias string
		var name string
		var nameSource string
		if err := rows.Scan(&startUnix, &clientIPText, &clientMAC, &direction, &protocol, &bytes, &packets, &alias, &name, &nameSource); err != nil {
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
			Alias:      alias,
			Name:       name,
			NameSource: nameSource,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SQLiteStore) QueryEndpointBuckets(ctx context.Context, from, to time.Time) ([]EndpointBucketRow, error) {
	rows, err := s.db.QueryContext(ctx, `
WITH combined AS (
SELECT bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol, bytes, packets
FROM endpoint_buckets
WHERE bucket_start >= ? AND bucket_start < ?
UNION ALL
SELECT bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol, bytes, packets
FROM endpoint_hourly_buckets
WHERE bucket_start >= ? AND bucket_start < ?
)
SELECT bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol, bytes, packets
FROM combined
ORDER BY bucket_start ASC, remote_ip ASC, remote_port ASC, client_ip ASC, client_mac ASC, direction ASC, protocol ASC;
`, from.UTC().Unix(), to.UTC().Unix(), from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []EndpointBucketRow
	for rows.Next() {
		var startUnix int64
		var clientIPText string
		var clientMAC string
		var remoteIPText string
		var remotePort int
		var direction string
		var protocol string
		var bytes int64
		var packets int64
		if err := rows.Scan(&startUnix, &clientIPText, &clientMAC, &remoteIPText, &remotePort, &direction, &protocol, &bytes, &packets); err != nil {
			return nil, err
		}

		clientAddr, err := netip.ParseAddr(clientIPText)
		if err != nil {
			return nil, err
		}
		remoteAddr, err := netip.ParseAddr(remoteIPText)
		if err != nil {
			return nil, err
		}
		result = append(result, EndpointBucketRow{
			Key: traffic.EndpointBucketKey{
				Start:      time.Unix(startUnix, 0).UTC(),
				ClientIP:   clientAddr,
				ClientMAC:  clientMAC,
				RemoteIP:   remoteAddr,
				RemotePort: uint16(remotePort),
				Direction:  traffic.Direction(direction),
				Protocol:   protocol,
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

func (s *SQLiteStore) CompactAndPrune(ctx context.Context, now time.Time, policy RetentionPolicy) error {
	if policy.MinuteRetention <= 0 && policy.HourlyRetention <= 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if policy.MinuteRetention > 0 {
		minuteCutoff := now.UTC().Add(-policy.MinuteRetention).Truncate(time.Hour).Unix()
		if err := compactMinuteBuckets(ctx, tx, minuteCutoff); err != nil {
			return err
		}
	}
	if policy.HourlyRetention > 0 {
		hourlyCutoff := now.UTC().Add(-policy.HourlyRetention).Truncate(time.Hour).Unix()
		if err := archiveHourlyBuckets(ctx, tx, hourlyCutoff); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func compactMinuteBuckets(ctx context.Context, tx *sql.Tx, cutoffUnix int64) error {
	statements := []string{
		`
INSERT INTO traffic_hourly_buckets (bucket_start, direction, protocol, bytes, packets)
SELECT (bucket_start / 3600) * 3600, direction, protocol, SUM(bytes), SUM(packets)
FROM traffic_buckets
WHERE bucket_start < ?
GROUP BY (bucket_start / 3600) * 3600, direction, protocol
ON CONFLICT(bucket_start, direction, protocol) DO UPDATE SET
	bytes = bytes + excluded.bytes,
	packets = packets + excluded.packets;
`,
		`
INSERT INTO client_hourly_buckets (bucket_start, client_ip, client_mac, direction, protocol, bytes, packets)
SELECT (bucket_start / 3600) * 3600, client_ip, client_mac, direction, protocol, SUM(bytes), SUM(packets)
FROM client_buckets
WHERE bucket_start < ?
GROUP BY (bucket_start / 3600) * 3600, client_ip, client_mac, direction, protocol
ON CONFLICT(bucket_start, client_ip, client_mac, direction, protocol) DO UPDATE SET
	bytes = bytes + excluded.bytes,
	packets = packets + excluded.packets;
`,
		`
INSERT INTO endpoint_hourly_buckets (bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol, bytes, packets)
SELECT (bucket_start / 3600) * 3600, client_ip, client_mac, remote_ip, remote_port, direction, protocol, SUM(bytes), SUM(packets)
FROM endpoint_buckets
WHERE bucket_start < ?
GROUP BY (bucket_start / 3600) * 3600, client_ip, client_mac, remote_ip, remote_port, direction, protocol
ON CONFLICT(bucket_start, client_ip, client_mac, remote_ip, remote_port, direction, protocol) DO UPDATE SET
	bytes = bytes + excluded.bytes,
	packets = packets + excluded.packets;
`,
		`DELETE FROM traffic_buckets WHERE bucket_start < ?;`,
		`DELETE FROM client_buckets WHERE bucket_start < ?;`,
		`DELETE FROM endpoint_buckets WHERE bucket_start < ?;`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement, cutoffUnix); err != nil {
			return err
		}
	}
	return nil
}

func archiveHourlyBuckets(ctx context.Context, tx *sql.Tx, cutoffUnix int64) error {
	statements := []string{
		`
INSERT INTO traffic_archive_buckets (direction, protocol, bytes, packets)
SELECT direction, protocol, SUM(bytes), SUM(packets)
FROM traffic_hourly_buckets
WHERE bucket_start < ?
GROUP BY direction, protocol
ON CONFLICT(direction, protocol) DO UPDATE SET
	bytes = bytes + excluded.bytes,
	packets = packets + excluded.packets;
`,
		`
INSERT INTO client_archive_buckets (client_ip, client_mac, direction, protocol, bytes, packets)
SELECT client_ip, client_mac, direction, protocol, SUM(bytes), SUM(packets)
FROM client_hourly_buckets
WHERE bucket_start < ?
GROUP BY client_ip, client_mac, direction, protocol
ON CONFLICT(client_ip, client_mac, direction, protocol) DO UPDATE SET
	bytes = bytes + excluded.bytes,
	packets = packets + excluded.packets;
`,
		`
INSERT INTO endpoint_archive_buckets (client_ip, client_mac, remote_ip, remote_port, direction, protocol, bytes, packets)
SELECT client_ip, client_mac, remote_ip, remote_port, direction, protocol, SUM(bytes), SUM(packets)
FROM endpoint_hourly_buckets
WHERE bucket_start < ?
GROUP BY client_ip, client_mac, remote_ip, remote_port, direction, protocol
ON CONFLICT(client_ip, client_mac, remote_ip, remote_port, direction, protocol) DO UPDATE SET
	bytes = bytes + excluded.bytes,
	packets = packets + excluded.packets;
`,
		`DELETE FROM traffic_hourly_buckets WHERE bucket_start < ?;`,
		`DELETE FROM client_hourly_buckets WHERE bucket_start < ?;`,
		`DELETE FROM endpoint_hourly_buckets WHERE bucket_start < ?;`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement, cutoffUnix); err != nil {
			return err
		}
	}
	return nil
}
