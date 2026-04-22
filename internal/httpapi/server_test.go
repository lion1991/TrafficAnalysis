package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"trafficanalysis/internal/store"
	"trafficanalysis/internal/traffic"
)

type fakeBucketQueryer struct {
	from            time.Time
	to              time.Time
	clientIP        string
	aliasIP         string
	aliasMAC        string
	aliasName       string
	rows            []store.BucketRow
	clientRows      []store.ClientBucketRow
	endpointRows    []store.EndpointBucketRow
	wanEndpointRows []store.WANEndpointBucketRow
	dnsRows         []traffic.DNSObservation
	tlsRows         []traffic.TLSObservation
	flowSessions    []traffic.FlowSession
	bucketQueries   int
	clientQueries   int
	endpointQueries int
	wanQueries      int
	dnsQueries      int
	tlsQueries      int
	flowQueries     int
}

type fakeAnalysisOverviewQueryer struct {
	*fakeBucketQueryer
	analysisOverview store.AnalysisOverview
	overviewQueries  int
}

func (f *fakeBucketQueryer) QueryBuckets(ctx context.Context, from, to time.Time) ([]store.BucketRow, error) {
	f.from = from
	f.to = to
	f.bucketQueries++
	return f.rows, nil
}

func (f *fakeBucketQueryer) QueryClientBuckets(ctx context.Context, from, to time.Time, clientIP string) ([]store.ClientBucketRow, error) {
	f.from = from
	f.to = to
	f.clientIP = clientIP
	f.clientQueries++
	return f.clientRows, nil
}

func (f *fakeBucketQueryer) QueryEndpointBuckets(ctx context.Context, from, to time.Time) ([]store.EndpointBucketRow, error) {
	f.from = from
	f.to = to
	f.endpointQueries++
	return f.endpointRows, nil
}

func (f *fakeBucketQueryer) QueryWANEndpointBuckets(ctx context.Context, from, to time.Time) ([]store.WANEndpointBucketRow, error) {
	f.from = from
	f.to = to
	f.wanQueries++
	return f.wanEndpointRows, nil
}

func (f *fakeBucketQueryer) UpsertClientAlias(ctx context.Context, clientIP, clientMAC, alias string) error {
	f.aliasIP = clientIP
	f.aliasMAC = clientMAC
	f.aliasName = alias
	return nil
}

func (f *fakeBucketQueryer) QueryDNSObservations(ctx context.Context, from, to time.Time) ([]traffic.DNSObservation, error) {
	f.from = from
	f.to = to
	f.dnsQueries++
	return f.dnsRows, nil
}

func (f *fakeBucketQueryer) QueryTLSObservations(ctx context.Context, from, to time.Time) ([]traffic.TLSObservation, error) {
	f.from = from
	f.to = to
	f.tlsQueries++
	return f.tlsRows, nil
}

func (f *fakeBucketQueryer) QueryFlowSessions(ctx context.Context, from, to time.Time) ([]traffic.FlowSession, error) {
	f.from = from
	f.to = to
	f.flowQueries++
	return f.flowSessions, nil
}

func (f *fakeBucketQueryer) QueryFlowSessionByID(ctx context.Context, id int64) (traffic.FlowSession, error) {
	for _, session := range f.flowSessions {
		if session.ID == id {
			return session, nil
		}
	}
	return traffic.FlowSession{}, os.ErrNotExist
}

func (f *fakeAnalysisOverviewQueryer) QueryAnalysisOverview(ctx context.Context, from, to time.Time, topClientLimit, topEndpointLimit int) (store.AnalysisOverview, error) {
	f.from = from
	f.to = to
	f.overviewQueries++
	return f.analysisOverview, nil
}

func TestTrafficAPIReturnsTotalsSeriesAndBreakdown(t *testing.T) {
	queryer := &fakeBucketQueryer{
		rows: []store.BucketRow{
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 1200, Packets: 3},
			},
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					Direction: traffic.DirectionDownload,
					Protocol:  "udp",
				},
				Value: traffic.BucketValue{Bytes: 3400, Packets: 4},
			},
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 10, 1, 0, 0, time.UTC),
					Direction: traffic.DirectionDownload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 5600, Packets: 5},
			},
		},
	}
	handler := NewHandler(queryer, Options{Location: time.UTC})

	req := httptest.NewRequest(http.MethodGet, "/api/traffic?from=2026-04-17%2010:00&to=2026-04-17%2010:03", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if queryer.from != time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected query from: %s", queryer.from)
	}
	if queryer.to != time.Date(2026, 4, 17, 10, 3, 0, 0, time.UTC) {
		t.Fatalf("unexpected query to: %s", queryer.to)
	}

	var body trafficResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Range.From != "2026-04-17T10:00:00Z" || body.Range.To != "2026-04-17T10:03:00Z" {
		t.Fatalf("unexpected range: %#v", body.Range)
	}
	if body.Totals.UploadBytes != 1200 || body.Totals.DownloadBytes != 9000 || body.Totals.Packets != 12 {
		t.Fatalf("unexpected totals: %#v", body.Totals)
	}
	if len(body.Series) != 2 {
		t.Fatalf("expected 2 series points, got %d: %#v", len(body.Series), body.Series)
	}
	if body.Series[0].UploadBytes != 1200 || body.Series[0].DownloadBytes != 3400 {
		t.Fatalf("unexpected first series point: %#v", body.Series[0])
	}
	if len(body.Breakdown) != 3 {
		t.Fatalf("expected 3 breakdown rows, got %d: %#v", len(body.Breakdown), body.Breakdown)
	}
}

func TestTrafficAPISupportsLastDateAndMonthShortcuts(t *testing.T) {
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	queryer := &fakeBucketQueryer{}
	handler := NewHandler(queryer, Options{
		Location: time.UTC,
		Now:      func() time.Time { return now },
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/traffic?last=7d", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected last query to pass, got %d", rec.Code)
	}
	if queryer.from != now.Add(-7*24*time.Hour) || queryer.to != now {
		t.Fatalf("unexpected last range: from=%s to=%s", queryer.from, queryer.to)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/traffic?date=2026-04-17", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected date query to pass, got %d", rec.Code)
	}
	if queryer.from != time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC) || queryer.to != time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected date range: from=%s to=%s", queryer.from, queryer.to)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/traffic?month=2026-04", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected month query to pass, got %d", rec.Code)
	}
	if queryer.from != time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC) || queryer.to != time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected month range: from=%s to=%s", queryer.from, queryer.to)
	}
}

func TestTrafficAPIRejectsInvalidRanges(t *testing.T) {
	handler := NewHandler(&fakeBucketQueryer{}, Options{Location: time.UTC})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/traffic?from=2026-04-18&to=2026-04-17", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "from must be before to") {
		t.Fatalf("expected validation message, got %q", rec.Body.String())
	}
}

func TestClientsAPIReturnsClientTotalsAndBreakdown(t *testing.T) {
	queryer := &fakeBucketQueryer{
		clientRows: []store.ClientBucketRow{
			{
				Key: traffic.ClientBucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					ClientIP:  trafficMustAddr("192.168.248.22"),
					ClientMAC: "00:11:22:33:44:55",
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value:      traffic.BucketValue{Bytes: 1200, Packets: 3},
				Alias:      "书房 NAS",
				Name:       "nas-box",
				NameSource: "dhcp",
			},
			{
				Key: traffic.ClientBucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					ClientIP:  trafficMustAddr("192.168.248.22"),
					ClientMAC: "00:11:22:33:44:55",
					Direction: traffic.DirectionDownload,
					Protocol:  "udp",
				},
				Value:      traffic.BucketValue{Bytes: 3400, Packets: 4},
				Alias:      "书房 NAS",
				Name:       "nas-box",
				NameSource: "dhcp",
			},
			{
				Key: traffic.ClientBucketKey{
					Start:     time.Date(2026, 4, 17, 10, 1, 0, 0, time.UTC),
					ClientIP:  trafficMustAddr("192.168.248.23"),
					ClientMAC: "66:77:88:99:aa:bb",
					Direction: traffic.DirectionDownload,
					Protocol:  "tcp",
				},
				Value:      traffic.BucketValue{Bytes: 5600, Packets: 5},
				Name:       "laptop",
				NameSource: "mdns",
			},
		},
	}
	handler := NewHandler(queryer, Options{Location: time.UTC})

	req := httptest.NewRequest(http.MethodGet, "/api/clients?from=2026-04-17%2010:00&to=2026-04-17%2010:03&client_ip=192.168.248.22", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if queryer.clientIP != "192.168.248.22" {
		t.Fatalf("expected client filter to be passed through, got %q", queryer.clientIP)
	}

	var body clientsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d: %#v", len(body.Clients), body.Clients)
	}
	if body.Clients[0].ClientIP != "192.168.248.23" || body.Clients[0].DownloadBytes != 5600 {
		t.Fatalf("expected clients sorted by total bytes descending, got %#v", body.Clients)
	}
	if body.Clients[0].DisplayName != "laptop" || body.Clients[0].NameSource != "mdns" {
		t.Fatalf("expected client display name from mdns, got %#v", body.Clients[0])
	}
	if body.Clients[1].ClientIP != "192.168.248.22" || body.Clients[1].UploadBytes != 1200 || body.Clients[1].DownloadBytes != 3400 {
		t.Fatalf("unexpected second client: %#v", body.Clients[1])
	}
	if body.Clients[1].DisplayName != "书房 NAS" || body.Clients[1].NameSource != "alias" || body.Clients[1].LearnedName != "nas-box" {
		t.Fatalf("expected client display name from alias, got %#v", body.Clients[1])
	}
	if len(body.Breakdown) != 3 {
		t.Fatalf("expected 3 breakdown rows, got %d: %#v", len(body.Breakdown), body.Breakdown)
	}
}

func TestAnalysisAPIReturnsTrafficSignalsAndTopClients(t *testing.T) {
	queryer := &fakeBucketQueryer{
		rows: []store.BucketRow{
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 1200, Packets: 3},
			},
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 10, 1, 0, 0, time.UTC),
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 4200, Packets: 4},
			},
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 10, 1, 0, 0, time.UTC),
					Direction: traffic.DirectionDownload,
					Protocol:  "udp",
				},
				Value: traffic.BucketValue{Bytes: 2100, Packets: 5},
			},
		},
		clientRows: []store.ClientBucketRow{
			{
				Key: traffic.ClientBucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					ClientIP:  trafficMustAddr("192.168.248.22"),
					ClientMAC: "00:11:22:33:44:55",
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value:      traffic.BucketValue{Bytes: 5000, Packets: 7},
				Alias:      "书房 NAS",
				Name:       "nas-box",
				NameSource: "dhcp",
			},
			{
				Key: traffic.ClientBucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					ClientIP:  trafficMustAddr("192.168.248.23"),
					ClientMAC: "66:77:88:99:aa:bb",
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 2000, Packets: 2},
			},
		},
		endpointRows: []store.EndpointBucketRow{
			{
				Key: traffic.EndpointBucketKey{
					Start:      time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					ClientIP:   trafficMustAddr("192.168.248.22"),
					ClientMAC:  "00:11:22:33:44:55",
					RemoteIP:   trafficMustAddr("203.0.113.9"),
					RemotePort: 443,
					Direction:  traffic.DirectionUpload,
					Protocol:   "tcp",
				},
				Value: traffic.BucketValue{Bytes: 4096, Packets: 4},
			},
			{
				Key: traffic.EndpointBucketKey{
					Start:      time.Date(2026, 4, 17, 10, 1, 0, 0, time.UTC),
					ClientIP:   trafficMustAddr("192.168.248.23"),
					ClientMAC:  "66:77:88:99:aa:bb",
					RemoteIP:   trafficMustAddr("203.0.113.9"),
					RemotePort: 443,
					Direction:  traffic.DirectionDownload,
					Protocol:   "tcp",
				},
				Value: traffic.BucketValue{Bytes: 2048, Packets: 2},
			},
		},
		wanEndpointRows: []store.WANEndpointBucketRow{
			{
				Key: traffic.WANEndpointBucketKey{
					Start:      time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					RemoteIP:   trafficMustAddr("198.51.100.8"),
					RemotePort: 3478,
					Direction:  traffic.DirectionUpload,
					Protocol:   "udp",
				},
				Value: traffic.BucketValue{Bytes: 8192, Packets: 8},
			},
			{
				Key: traffic.WANEndpointBucketKey{
					Start:      time.Date(2026, 4, 17, 10, 1, 0, 0, time.UTC),
					RemoteIP:   trafficMustAddr("198.51.100.8"),
					RemotePort: 3478,
					Direction:  traffic.DirectionDownload,
					Protocol:   "udp",
				},
				Value: traffic.BucketValue{Bytes: 1024, Packets: 1},
			},
		},
	}
	handler := NewHandler(queryer, Options{Location: time.UTC})

	req := httptest.NewRequest(http.MethodGet, "/api/analysis?from=2026-04-17%2010:00&to=2026-04-17%2010:03", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if queryer.from != time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected query from: %s", queryer.from)
	}
	if queryer.to != time.Date(2026, 4, 17, 10, 3, 0, 0, time.UTC) {
		t.Fatalf("unexpected query to: %s", queryer.to)
	}
	if queryer.clientIP != "" {
		t.Fatalf("expected analysis to query all clients, got filter %q", queryer.clientIP)
	}

	var body struct {
		Range  responseRange `json:"range"`
		Totals struct {
			UploadBytes       int64   `json:"upload_bytes"`
			DownloadBytes     int64   `json:"download_bytes"`
			UploadShare       float64 `json:"upload_share"`
			PeakUploadBytes   int64   `json:"peak_upload_bytes"`
			PeakUploadBucket  string  `json:"peak_upload_bucket"`
			ActiveClientCount int     `json:"active_client_count"`
		} `json:"totals"`
		TopUploadClients []clientSummaryRow `json:"top_upload_clients"`
		RemoteEndpoints  []struct {
			RemoteIP      string `json:"remote_ip"`
			RemotePort    uint16 `json:"remote_port"`
			Protocol      string `json:"protocol"`
			UploadBytes   int64  `json:"upload_bytes"`
			DownloadBytes int64  `json:"download_bytes"`
			ClientCount   int    `json:"client_count"`
		} `json:"remote_endpoints"`
		WANRemoteEndpoints []struct {
			RemoteIP      string `json:"remote_ip"`
			RemotePort    uint16 `json:"remote_port"`
			Protocol      string `json:"protocol"`
			UploadBytes   int64  `json:"upload_bytes"`
			DownloadBytes int64  `json:"download_bytes"`
			Packets       int64  `json:"packets"`
		} `json:"wan_remote_endpoints"`
		WANUDPRemoteEndpoints []struct {
			RemoteIP      string `json:"remote_ip"`
			RemotePort    uint16 `json:"remote_port"`
			Protocol      string `json:"protocol"`
			UploadBytes   int64  `json:"upload_bytes"`
			DownloadBytes int64  `json:"download_bytes"`
			Packets       int64  `json:"packets"`
		} `json:"wan_udp_remote_endpoints"`
		WANUDPClientGaps []struct {
			RemoteIP                  string `json:"remote_ip"`
			RemotePort                uint16 `json:"remote_port"`
			Protocol                  string `json:"protocol"`
			WANUploadBytes            int64  `json:"wan_upload_bytes"`
			WANDownloadBytes          int64  `json:"wan_download_bytes"`
			ClientUploadBytes         int64  `json:"client_upload_bytes"`
			ClientDownloadBytes       int64  `json:"client_download_bytes"`
			UnattributedUploadBytes   int64  `json:"unattributed_upload_bytes"`
			UnattributedDownloadBytes int64  `json:"unattributed_download_bytes"`
			ClientCount               int    `json:"client_count"`
		} `json:"wan_udp_client_gaps"`
		Signals []struct {
			Label string `json:"label"`
			Level string `json:"level"`
			Value string `json:"value"`
		} `json:"signals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Totals.UploadBytes != 5400 || body.Totals.DownloadBytes != 2100 {
		t.Fatalf("unexpected totals: %#v", body.Totals)
	}
	if body.Totals.PeakUploadBytes != 4200 || body.Totals.PeakUploadBucket != "2026-04-17T10:01:00Z" {
		t.Fatalf("unexpected upload peak: %#v", body.Totals)
	}
	if body.Totals.ActiveClientCount != 2 {
		t.Fatalf("unexpected active client count: %d", body.Totals.ActiveClientCount)
	}
	if len(body.TopUploadClients) != 2 || body.TopUploadClients[0].DisplayName != "书房 NAS" || body.TopUploadClients[0].UploadBytes != 5000 {
		t.Fatalf("unexpected top upload clients: %#v", body.TopUploadClients)
	}
	if len(body.RemoteEndpoints) != 1 {
		t.Fatalf("expected one aggregated remote endpoint, got %#v", body.RemoteEndpoints)
	}
	if body.RemoteEndpoints[0].RemoteIP != "203.0.113.9" || body.RemoteEndpoints[0].RemotePort != 443 || body.RemoteEndpoints[0].UploadBytes != 4096 || body.RemoteEndpoints[0].DownloadBytes != 2048 || body.RemoteEndpoints[0].ClientCount != 2 {
		t.Fatalf("unexpected remote endpoint summary: %#v", body.RemoteEndpoints[0])
	}
	if len(body.WANRemoteEndpoints) != 1 {
		t.Fatalf("expected one aggregated WAN remote endpoint, got %#v", body.WANRemoteEndpoints)
	}
	if body.WANRemoteEndpoints[0].RemoteIP != "198.51.100.8" || body.WANRemoteEndpoints[0].RemotePort != 3478 || body.WANRemoteEndpoints[0].Protocol != "udp" || body.WANRemoteEndpoints[0].UploadBytes != 8192 || body.WANRemoteEndpoints[0].DownloadBytes != 1024 || body.WANRemoteEndpoints[0].Packets != 9 {
		t.Fatalf("unexpected WAN remote endpoint summary: %#v", body.WANRemoteEndpoints[0])
	}
	if len(body.WANUDPRemoteEndpoints) != 1 {
		t.Fatalf("expected one aggregated WAN UDP remote endpoint, got %#v", body.WANUDPRemoteEndpoints)
	}
	if body.WANUDPRemoteEndpoints[0].RemoteIP != "198.51.100.8" || body.WANUDPRemoteEndpoints[0].RemotePort != 3478 || body.WANUDPRemoteEndpoints[0].Protocol != "udp" || body.WANUDPRemoteEndpoints[0].UploadBytes != 8192 || body.WANUDPRemoteEndpoints[0].DownloadBytes != 1024 || body.WANUDPRemoteEndpoints[0].Packets != 9 {
		t.Fatalf("unexpected WAN UDP remote endpoint summary: %#v", body.WANUDPRemoteEndpoints[0])
	}
	if len(body.WANUDPClientGaps) != 1 {
		t.Fatalf("expected one WAN UDP/client gap row, got %#v", body.WANUDPClientGaps)
	}
	if body.WANUDPClientGaps[0].RemoteIP != "198.51.100.8" || body.WANUDPClientGaps[0].RemotePort != 3478 || body.WANUDPClientGaps[0].WANUploadBytes != 8192 || body.WANUDPClientGaps[0].WANDownloadBytes != 1024 || body.WANUDPClientGaps[0].ClientUploadBytes != 0 || body.WANUDPClientGaps[0].ClientDownloadBytes != 0 || body.WANUDPClientGaps[0].UnattributedUploadBytes != 8192 || body.WANUDPClientGaps[0].UnattributedDownloadBytes != 1024 || body.WANUDPClientGaps[0].ClientCount != 0 {
		t.Fatalf("unexpected WAN UDP/client gap summary: %#v", body.WANUDPClientGaps[0])
	}
	if len(body.Signals) == 0 || body.Signals[0].Label == "" || body.Signals[0].Level == "" {
		t.Fatalf("expected analysis signals, got %#v", body.Signals)
	}
}

func TestClientAliasAPIStoresAlias(t *testing.T) {
	queryer := &fakeBucketQueryer{}
	handler := NewHandler(queryer, Options{Location: time.UTC})

	req := httptest.NewRequest(http.MethodPut, "/api/clients/alias", strings.NewReader(`{
		"client_ip": "192.168.248.22",
		"client_mac": "00:11:22:33:44:55",
		"alias": "书房 NAS"
	}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if queryer.aliasIP != "192.168.248.22" || queryer.aliasMAC != "00:11:22:33:44:55" || queryer.aliasName != "书房 NAS" {
		t.Fatalf("unexpected alias write: ip=%q mac=%q alias=%q", queryer.aliasIP, queryer.aliasMAC, queryer.aliasName)
	}
}

func trafficMustAddr(value string) netip.Addr {
	return netip.MustParseAddr(value)
}

func TestStaticUIIsServedAtRoot(t *testing.T) {
	handler := NewHandler(&fakeBucketQueryer{}, Options{Location: time.UTC})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("expected html content type, got %q", contentType)
	}
	if !strings.Contains(rec.Body.String(), "TrafficAnalysis") {
		t.Fatalf("expected UI shell, got %q", rec.Body.String())
	}
}

func TestLiveSSEStreamsPublishedSnapshots(t *testing.T) {
	hub := NewLiveHub()
	handler := NewHandler(&fakeBucketQueryer{}, Options{
		Location:   time.UTC,
		LiveSource: hub,
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/live", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("connect live SSE: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if contentType := resp.Header.Get("Content-Type"); !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("expected event stream, got %q", contentType)
	}

	hub.Publish(LiveSnapshot{
		Timestamp:       "2026-04-17T12:00:00Z",
		WANIP:           "42.103.52.33",
		WANAvailable:    true,
		IntervalSeconds: 1,
		Totals: LiveTotals{
			UploadBytes:   1024,
			DownloadBytes: 2048,
			Packets:       3,
		},
		Rates: LiveRates{
			UploadBPS:   1024,
			DownloadBPS: 2048,
		},
		Clients: []LiveClient{
			{
				DisplayName: "nas-box",
				ClientIP:    "192.168.248.22",
				ClientMAC:   "00:11:22:33:44:55",
				UploadBPS:   512,
				DownloadBPS: 1024,
				Packets:     2,
			},
		},
	})

	scanner := bufio.NewScanner(resp.Body)
	var dataLine string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if dataLine == "" {
		t.Fatal("expected SSE data line")
	}

	var snapshot LiveSnapshot
	if err := json.Unmarshal([]byte(dataLine), &snapshot); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snapshot.WANIP != "42.103.52.33" || snapshot.Totals.UploadBytes != 1024 || snapshot.Rates.DownloadBPS != 2048 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if len(snapshot.Clients) != 1 || snapshot.Clients[0].DisplayName != "nas-box" || snapshot.Clients[0].DownloadBPS != 1024 {
		t.Fatalf("unexpected live clients: %#v", snapshot.Clients)
	}
}

func TestLiveSSESendsHeartbeatEvents(t *testing.T) {
	data, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}

	for _, want := range []string{"liveHeartbeatInterval", "time.NewTicker(liveHeartbeatInterval)", `"event: heartbeat\ndata: {}\n\n"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("expected live SSE handler to keep connections warm with %q", want)
		}
	}
}

func TestLiveSSEReturnsUnavailableWithoutLiveSource(t *testing.T) {
	handler := NewHandler(&fakeBucketQueryer{}, Options{Location: time.UTC})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/live", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestAnalysisObjectsAPIReturnsAttributedObjects(t *testing.T) {
	queryer := &fakeBucketQueryer{
		dnsRows: []traffic.DNSObservation{
			{
				ObservedAt: time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
				ClientIP:   trafficMustAddr("192.168.248.22"),
				ClientMAC:  "00:11:22:33:44:55",
				Name:       "api.example.com",
				RecordType: "A",
				AnswerIP:   trafficMustAddr("203.0.113.9"),
				TTL:        300,
				Source:     "dns",
			},
		},
		tlsRows: []traffic.TLSObservation{
			{
				ObservedAt: time.Date(2026, 4, 17, 10, 0, 2, 0, time.UTC),
				Viewpoint:  traffic.ViewpointLAN,
				ClientIP:   trafficMustAddr("192.168.248.22"),
				ClientMAC:  "00:11:22:33:44:55",
				RemoteIP:   trafficMustAddr("203.0.113.9"),
				RemotePort: 443,
				ServerName: "api.example.com",
				ALPN:       "h2",
				Protocol:   "tcp",
				Source:     "tls_client_hello",
			},
		},
		flowSessions: []traffic.FlowSession{
			{
				ID:            1,
				Viewpoint:     traffic.ViewpointLAN,
				Protocol:      "tcp",
				LocalIP:       trafficMustAddr("192.168.248.22"),
				LocalPort:     53000,
				RemoteIP:      trafficMustAddr("203.0.113.9"),
				RemotePort:    443,
				ClientIP:      trafficMustAddr("192.168.248.22"),
				ClientMAC:     "00:11:22:33:44:55",
				FirstSeen:     time.Date(2026, 4, 17, 10, 0, 1, 0, time.UTC),
				LastSeen:      time.Date(2026, 4, 17, 10, 0, 20, 0, time.UTC),
				UploadBytes:   4096,
				DownloadBytes: 2048,
				Packets:       12,
			},
		},
	}
	handler := NewHandler(queryer, Options{Location: time.UTC})

	req := httptest.NewRequest(http.MethodGet, "/api/analysis/objects?from=2026-04-17%2010:00&to=2026-04-17%2010:10", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Objects []struct {
			Label         string  `json:"label"`
			LabelSource   string  `json:"label_source"`
			Confidence    float64 `json:"confidence"`
			UploadBytes   int64   `json:"upload_bytes"`
			DownloadBytes int64   `json:"download_bytes"`
			ClientCount   int     `json:"client_count"`
			SessionCount  int     `json:"session_count"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode objects response: %v", err)
	}
	if len(body.Objects) != 1 {
		t.Fatalf("expected one attributed object, got %#v", body.Objects)
	}
	if body.Objects[0].Label != "api.example.com" || body.Objects[0].LabelSource != "tls_sni" {
		t.Fatalf("unexpected object label: %#v", body.Objects[0])
	}
	if body.Objects[0].UploadBytes != 4096 || body.Objects[0].DownloadBytes != 2048 || body.Objects[0].ClientCount != 1 || body.Objects[0].SessionCount != 1 {
		t.Fatalf("unexpected object counters: %#v", body.Objects[0])
	}
}

func TestAnalysisReconcileAPIReturnsMatchedAndUnmatchedSessions(t *testing.T) {
	queryer := &fakeBucketQueryer{
		flowSessions: []traffic.FlowSession{
			{
				ID:            1,
				Viewpoint:     traffic.ViewpointWAN,
				Protocol:      "tcp",
				LocalIP:       trafficMustAddr("198.51.100.10"),
				LocalPort:     53000,
				RemoteIP:      trafficMustAddr("203.0.113.9"),
				RemotePort:    443,
				FirstSeen:     time.Date(2026, 4, 17, 10, 0, 1, 0, time.UTC),
				LastSeen:      time.Date(2026, 4, 17, 10, 0, 20, 0, time.UTC),
				UploadBytes:   4096,
				DownloadBytes: 2048,
				Packets:       12,
			},
			{
				ID:            2,
				Viewpoint:     traffic.ViewpointLAN,
				Protocol:      "tcp",
				LocalIP:       trafficMustAddr("192.168.248.22"),
				LocalPort:     53000,
				RemoteIP:      trafficMustAddr("203.0.113.9"),
				RemotePort:    443,
				ClientIP:      trafficMustAddr("192.168.248.22"),
				ClientMAC:     "00:11:22:33:44:55",
				FirstSeen:     time.Date(2026, 4, 17, 10, 0, 2, 0, time.UTC),
				LastSeen:      time.Date(2026, 4, 17, 10, 0, 19, 0, time.UTC),
				UploadBytes:   4000,
				DownloadBytes: 2048,
				Packets:       11,
			},
			{
				ID:            3,
				Viewpoint:     traffic.ViewpointWAN,
				Protocol:      "udp",
				LocalIP:       trafficMustAddr("198.51.100.10"),
				LocalPort:     52000,
				RemoteIP:      trafficMustAddr("198.51.100.8"),
				RemotePort:    3478,
				FirstSeen:     time.Date(2026, 4, 17, 10, 1, 0, 0, time.UTC),
				LastSeen:      time.Date(2026, 4, 17, 10, 1, 30, 0, time.UTC),
				UploadBytes:   8192,
				DownloadBytes: 1024,
				Packets:       13,
			},
		},
	}
	handler := NewHandler(queryer, Options{Location: time.UTC})

	req := httptest.NewRequest(http.MethodGet, "/api/analysis/reconcile?from=2026-04-17%2010:00&to=2026-04-17%2010:10", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Rows []struct {
			WANSessionID              int64   `json:"wan_session_id"`
			LANSessionID              int64   `json:"lan_session_id"`
			Status                    string  `json:"status"`
			Reason                    string  `json:"reason"`
			Confidence                float64 `json:"confidence"`
			UnattributedUploadBytes   int64   `json:"unattributed_upload_bytes"`
			UnattributedDownloadBytes int64   `json:"unattributed_download_bytes"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode reconcile response: %v", err)
	}
	if len(body.Rows) != 2 {
		t.Fatalf("expected two reconcile rows, got %#v", body.Rows)
	}
	rowsByWAN := make(map[int64]struct {
		WANSessionID              int64   `json:"wan_session_id"`
		LANSessionID              int64   `json:"lan_session_id"`
		Status                    string  `json:"status"`
		Reason                    string  `json:"reason"`
		Confidence                float64 `json:"confidence"`
		UnattributedUploadBytes   int64   `json:"unattributed_upload_bytes"`
		UnattributedDownloadBytes int64   `json:"unattributed_download_bytes"`
	}, len(body.Rows))
	for _, row := range body.Rows {
		rowsByWAN[row.WANSessionID] = row
	}
	if matched := rowsByWAN[1]; matched.LANSessionID != 2 || matched.Status != "matched" {
		t.Fatalf("unexpected matched row: %#v", matched)
	}
	if unmatched := rowsByWAN[3]; unmatched.Status != "unmatched" || unmatched.Reason == "" {
		t.Fatalf("unexpected unmatched row: %#v", unmatched)
	}
}

func TestBuildObjectsResponseLimitsRowsToTopTotals(t *testing.T) {
	const limit = 200
	start := time.Date(2026, 4, 21, 10, 0, 0, 0, time.UTC)
	sessions := make([]traffic.FlowSession, 0, limit+5)
	for i := 0; i < limit+5; i++ {
		sessions = append(sessions, traffic.FlowSession{
			ID:            int64(i + 1),
			Viewpoint:     traffic.ViewpointLAN,
			Protocol:      "tcp",
			LocalIP:       trafficMustAddr("192.168.248.22"),
			LocalPort:     uint16(40000 + i),
			RemoteIP:      trafficMustAddr("203.0.113.9"),
			RemotePort:    uint16(10000 + i),
			ClientIP:      trafficMustAddr("192.168.248.22"),
			ClientMAC:     "00:11:22:33:44:55",
			FirstSeen:     start.Add(time.Duration(i) * time.Second),
			LastSeen:      start.Add(time.Duration(i)*time.Second + 5*time.Second),
			UploadBytes:   int64(i + 1),
			DownloadBytes: 0,
			Packets:       1,
		})
	}

	response := buildObjectsResponse(start, start.Add(time.Hour), sessions, nil, nil)
	if len(response.Objects) != limit {
		t.Fatalf("expected %d object rows after limiting, got %d", limit, len(response.Objects))
	}
	if response.Objects[0].UploadBytes != limit+5 {
		t.Fatalf("expected largest object total first, got %#v", response.Objects[0])
	}
	if response.Objects[len(response.Objects)-1].UploadBytes != 6 {
		t.Fatalf("expected smallest retained object total to be 6, got %#v", response.Objects[len(response.Objects)-1])
	}
}

func TestBuildReconcileResponseLimitsRowsToLargestUnattributedTotals(t *testing.T) {
	const limit = 200
	start := time.Date(2026, 4, 21, 10, 0, 0, 0, time.UTC)
	wanSessions := make([]traffic.FlowSession, 0, limit+5)
	for i := 0; i < limit+5; i++ {
		wanSessions = append(wanSessions, traffic.FlowSession{
			ID:            int64(i + 1),
			Viewpoint:     traffic.ViewpointWAN,
			Protocol:      "udp",
			LocalIP:       trafficMustAddr("198.51.100.10"),
			LocalPort:     uint16(50000 + i),
			RemoteIP:      trafficMustAddr("198.51.100.8"),
			RemotePort:    uint16(20000 + i),
			FirstSeen:     start.Add(time.Duration(i) * time.Second),
			LastSeen:      start.Add(time.Duration(i)*time.Second + 5*time.Second),
			UploadBytes:   int64(i + 1),
			DownloadBytes: 0,
			Packets:       1,
		})
	}

	response := buildReconcileResponse(start, start.Add(time.Hour), wanSessions, nil)
	if len(response.Rows) != limit {
		t.Fatalf("expected %d reconcile rows after limiting, got %d", limit, len(response.Rows))
	}
	if response.Rows[0].WANSessionID != limit+5 {
		t.Fatalf("expected largest unattributed row first, got %#v", response.Rows[0])
	}
	if response.Rows[len(response.Rows)-1].WANSessionID != 6 {
		t.Fatalf("expected smallest retained reconcile row to be WAN session 6, got %#v", response.Rows[len(response.Rows)-1])
	}
}

func TestAnalysisEndpointCachesRepeatedRangeRequests(t *testing.T) {
	queryer := &fakeBucketQueryer{
		rows: []store.BucketRow{
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 1200, Packets: 3},
			},
		},
		clientRows: []store.ClientBucketRow{
			{
				Key: traffic.ClientBucketKey{
					Start:     time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
					ClientIP:  trafficMustAddr("192.168.248.22"),
					ClientMAC: "00:11:22:33:44:55",
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 1200, Packets: 3},
			},
		},
	}
	now := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	handler := NewHandler(queryer, Options{
		Location: time.UTC,
		Now:      func() time.Time { return now },
	})

	req := httptest.NewRequest(http.MethodGet, "/api/analysis?last=1h", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d: %s", rec1.Code, rec1.Body.String())
	}

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/analysis?last=1h", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected second request 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	if rec1.Body.String() != rec2.Body.String() {
		t.Fatalf("expected cached analysis response to be reused")
	}
	if queryer.bucketQueries != 1 || queryer.clientQueries != 1 || queryer.endpointQueries != 1 || queryer.wanQueries != 1 {
		t.Fatalf("expected analysis cache to avoid repeated source queries, got buckets=%d clients=%d endpoints=%d wan=%d",
			queryer.bucketQueries, queryer.clientQueries, queryer.endpointQueries, queryer.wanQueries)
	}
}

func TestAnalysisEndpointPrefersOverviewQueryerFastPath(t *testing.T) {
	now := time.Date(2026, 4, 17, 11, 0, 0, 0, time.UTC)
	queryer := &fakeAnalysisOverviewQueryer{
		fakeBucketQueryer: &fakeBucketQueryer{},
		analysisOverview: store.AnalysisOverview{
			Totals: store.AnalysisOverviewTotals{
				UploadBytes:      1200,
				DownloadBytes:    3400,
				Packets:          7,
				PeakUploadBytes:  1200,
				PeakUploadBucket: time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC),
			},
			Clients: []store.AnalysisClientSummary{
				{
					ClientIP:      trafficMustAddr("192.168.248.22"),
					ClientMAC:     "00:11:22:33:44:55",
					UploadBytes:   1200,
					DownloadBytes: 3400,
					Packets:       7,
				},
			},
		},
	}
	handler := NewHandler(queryer, Options{
		Location: time.UTC,
		Now:      func() time.Time { return now },
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/analysis?last=1h", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if queryer.overviewQueries != 1 {
		t.Fatalf("expected overview fast path to be used once, got %d", queryer.overviewQueries)
	}
	if queryer.bucketQueries != 0 || queryer.clientQueries != 0 || queryer.endpointQueries != 0 || queryer.wanQueries != 0 {
		t.Fatalf("expected overview fast path to skip raw bucket scans, got buckets=%d clients=%d endpoints=%d wan=%d",
			queryer.bucketQueries, queryer.clientQueries, queryer.endpointQueries, queryer.wanQueries)
	}
}

func TestWebAppStartsLiveStreamOnLoad(t *testing.T) {
	data, err := embeddedStatic.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}

	if !strings.Contains(string(data), "syncControls();\nstartLiveStream();\nloadTraffic();") {
		t.Fatal("expected web app to connect /api/live when the page loads")
	}
}

func TestClientsPageIsServed(t *testing.T) {
	handler := NewHandler(&fakeBucketQueryer{}, Options{Location: time.UTC})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/clients.html", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "客户端流量") {
		t.Fatalf("expected clients page, got %q", rec.Body.String())
	}
}

func TestAnalysisPageIsServedAndFetchesAnalysisAPI(t *testing.T) {
	handler := NewHandler(&fakeBucketQueryer{}, Options{Location: time.UTC})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/analysis.html", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "流量分析") {
		t.Fatalf("expected analysis page, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "远程 IP") {
		t.Fatalf("expected analysis page to show remote IP transfer section")
	}

	js, err := embeddedStatic.ReadFile("static/analysis.js")
	if err != nil {
		t.Fatalf("read analysis.js: %v", err)
	}
	for _, want := range []string{"/api/analysis", "loadAnalysis", "renderSignals", "top_upload_clients", "remote_endpoints", "renderRemoteEndpoints"} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected analysis script to contain %q", want)
		}
	}
	for _, want := range []string{"WAN UDP", "wan_udp_remote_endpoints", "wanUDPRemoteEndpointsBody", "wan_udp_client_gaps", "wanUDPClientGapsBody"} {
		if !strings.Contains(rec.Body.String()+string(js), want) {
			t.Fatalf("expected analysis assets to contain %q", want)
		}
	}
}

func TestNavigationLinksIncludeAnalysisPage(t *testing.T) {
	for _, path := range []string{"static/index.html", "static/clients.html", "static/analysis.html"} {
		html, err := embeddedStatic.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(html), `href="/analysis.html"`) {
			t.Fatalf("expected %s to link to analysis page", path)
		}
	}
}

func TestClientsPageIntegratesLiveRatesIntoSummaryTable(t *testing.T) {
	html, err := embeddedStatic.ReadFile("static/clients.html")
	if err != nil {
		t.Fatalf("read clients.html: %v", err)
	}
	js, err := embeddedStatic.ReadFile("static/clients.js")
	if err != nil {
		t.Fatalf("read clients.js: %v", err)
	}

	if strings.Contains(string(html), "liveClientsBody") {
		t.Fatal("expected clients page to avoid a separate realtime clients table")
	}
	for _, want := range []string{"实时上传", "实时下载", "别名"} {
		if !strings.Contains(string(html), want) {
			t.Fatalf("expected clients page to contain %q", want)
		}
	}
	for _, want := range []string{"mergeLiveClients", "saveAlias", "/api/clients/alias"} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected clients script to contain %q", want)
		}
	}
}

func TestClientsPageUsesStableDefaultSortAndSortableHeaders(t *testing.T) {
	html, err := embeddedStatic.ReadFile("static/clients.html")
	if err != nil {
		t.Fatalf("read clients.html: %v", err)
	}
	js, err := embeddedStatic.ReadFile("static/clients.js")
	if err != nil {
		t.Fatalf("read clients.js: %v", err)
	}
	css, err := embeddedStatic.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}

	for _, want := range []string{`data-sort="display_name"`, `data-sort="upload_bytes"`, `data-sort="download_bps"`} {
		if !strings.Contains(string(html), want) {
			t.Fatalf("expected clients page to contain sortable header %q", want)
		}
	}
	for _, want := range []string{"sortState = { field: \"total_bytes\", direction: \"desc\" }", "function setSort", "function compareClientRows"} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected clients script to contain %q", want)
		}
	}
	for _, want := range []string{".bytesCol", ".rateCol", "font-variant-numeric: tabular-nums", "table-layout: fixed"} {
		if !strings.Contains(string(css), want) {
			t.Fatalf("expected CSS to stabilize traffic columns with %q", want)
		}
	}
}

func TestClientsPagePreservesAliasDraftsDuringLiveRefresh(t *testing.T) {
	js, err := embeddedStatic.ReadFile("static/clients.js")
	if err != nil {
		t.Fatalf("read clients.js: %v", err)
	}

	for _, want := range []string{"function captureAliasDrafts", "function restoreAliasDrafts", "document.activeElement", "data-alias-input-key"} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected clients script to preserve alias edits during realtime refresh with %q", want)
		}
	}
}

func TestClientsPageDoesNotReplaceLearnedNameWithLiveFallback(t *testing.T) {
	js, err := embeddedStatic.ReadFile("static/clients.js")
	if err != nil {
		t.Fatalf("read clients.js: %v", err)
	}

	for _, want := range []string{"function liveDisplayName", "existing.learned_name || liveDisplayName(row, existing)", "return existing.display_name || row.display_name || row.client_ip || row.client_mac"} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected live refresh to keep learned client names before fallback display names with %q", want)
		}
	}
}

func TestWebPagesUseTimezoneSafeDateRangeHelpers(t *testing.T) {
	for _, path := range []string{"static/app.js", "static/clients.js", "static/analysis.js"} {
		js, err := embeddedStatic.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(js)
		for _, want := range []string{"Date.UTC(year, month - 1, day)", "date.setUTCDate(date.getUTCDate() + days)", "return formatDateInputValue(date);"} {
			if !strings.Contains(text, want) {
				t.Fatalf("expected %s to add date-range days without local timezone drift using %q", path, want)
			}
		}
		if strings.Contains(text, "return d.toISOString().slice(0, 10);") {
			t.Fatalf("expected %s not to convert date-range day arithmetic through UTC ISO strings", path)
		}
	}
}

func TestWebPagesMigrateSavedDatetimePrefs(t *testing.T) {
	for _, path := range []string{"static/app.js", "static/clients.js", "static/analysis.js"} {
		js, err := embeddedStatic.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, want := range []string{"function normalizeDatetimeLocalPref", `.replace(" ", "T")`, "normalizeDatetimeLocalPref(savedPrefs.from)", "normalizeDatetimeLocalPref(savedPrefs.to)"} {
			if !strings.Contains(string(js), want) {
				t.Fatalf("expected %s to migrate saved datetime-local preferences with %q", path, want)
			}
		}
	}
}

func TestWebCSSHonorsHiddenControls(t *testing.T) {
	css, err := embeddedStatic.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	if !strings.Contains(string(css), "[hidden]") || !strings.Contains(string(css), "display: none !important;") {
		t.Fatal("expected CSS to hide inactive range controls even when label display styles are applied")
	}
}

func TestWebPagesUseSharedControlSizing(t *testing.T) {
	css, err := embeddedStatic.ReadFile("static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	for _, want := range []string{"--control-preset-width", "--control-action-width", ".controlPreset", ".controlAction"} {
		if !strings.Contains(string(css), want) {
			t.Fatalf("expected shared control sizing CSS to contain %q", want)
		}
	}

	for _, path := range []string{"static/index.html", "static/clients.html", "static/analysis.html"} {
		html, err := embeddedStatic.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, want := range []string{`class="controlPreset"`, `class="controlAction"`, `class="controlAction btnReset"`} {
			if !strings.Contains(string(html), want) {
				t.Fatalf("expected %s to use shared control sizing class %q", path, want)
			}
		}
	}
}

func TestOverviewPageSupportsSpecifiedDateRange(t *testing.T) {
	html, err := embeddedStatic.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	for _, want := range []string{`<option value="date">指定日期</option>`, `<input id="date" type="date" />`} {
		if !strings.Contains(string(html), want) {
			t.Fatalf("expected overview page to contain specified-date control %q", want)
		}
	}

	js, err := embeddedStatic.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	for _, want := range []string{`date: document.querySelector("#date")`, `params.set("date", elements.date.value || todayText());`, `elements.date.closest("label").hidden = !isDate`} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected overview script to support specified-date range with %q", want)
		}
	}
}

func TestWebPagesCloseLiveStreamsWhenNavigatingAway(t *testing.T) {
	for _, path := range []string{"static/app.js", "static/clients.js"} {
		js, err := embeddedStatic.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, want := range []string{"function cleanupPage", `window.addEventListener("pagehide", cleanupPage)`, `window.addEventListener("beforeunload", cleanupPage)`} {
			if !strings.Contains(string(js), want) {
				t.Fatalf("expected %s to close live streams during navigation with %q", path, want)
			}
		}
	}
}

func TestWebPagesReconnectLiveStreamsAfterErrors(t *testing.T) {
	for _, path := range []string{"static/app.js", "static/clients.js"} {
		js, err := embeddedStatic.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, want := range []string{"const LIVE_RECONNECT_DELAY_MS", "const LIVE_STALE_TIMEOUT_MS", "let liveReconnectTimer", "let liveWatchdogTimer", "function markLiveMessage", "function startLiveWatchdog", "setTimeout(startLiveStream, LIVE_RECONNECT_DELAY_MS)", "scheduleLiveReconnect();"} {
			if !strings.Contains(string(js), want) {
				t.Fatalf("expected %s to reconnect live streams after SSE errors with %q", path, want)
			}
		}
	}
}

func TestAnalysisPageSupportsPerTableColumnSorting(t *testing.T) {
	html, err := embeddedStatic.ReadFile("static/analysis.html")
	if err != nil {
		t.Fatalf("read analysis.html: %v", err)
	}
	for _, want := range []string{
		`data-sort-table="uploadClients"`,
		`data-sort-table="downloadClients"`,
		`data-sort-table="objects"`,
		`data-sort-table="reconcile"`,
	} {
		if !strings.Contains(string(html), want) {
			t.Fatalf("expected analysis page to expose sortable table headers with %q", want)
		}
	}

	js, err := embeddedStatic.ReadFile("static/analysis.js")
	if err != nil {
		t.Fatalf("read analysis.js: %v", err)
	}
	for _, want := range []string{
		"const defaultSortStates = {",
		"function sortRows(table, rows)",
		"function setSort(table, field)",
		`document.querySelectorAll("[data-sort-table][data-sort-field]")`,
	} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected analysis script to support per-table sorting with %q", want)
		}
	}
}

func TestAnalysisPageRendersBaseResultsBeforeAuxiliaryTables(t *testing.T) {
	js, err := embeddedStatic.ReadFile("static/analysis.js")
	if err != nil {
		t.Fatalf("read analysis.js: %v", err)
	}
	for _, want := range []string{
		"const analysis = await fetchJSON(buildAnalysisURL(), requestController.signal);",
		"latestAnalysis = analysis;",
		"renderLoadedRows();",
		"const [objectsResult, reconcileResult] = await Promise.allSettled([",
		`elements.status.textContent = "基础结果已更新，正在补充访问对象和 WAN/LAN 对账";`,
	} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected analysis page to render base results before slower auxiliary fetches with %q", want)
		}
	}
}

func TestAnalysisPageLimitsHeavyAuxiliaryTables(t *testing.T) {
	js, err := embeddedStatic.ReadFile("static/analysis.js")
	if err != nil {
		t.Fatalf("read analysis.js: %v", err)
	}
	for _, want := range []string{
		"const MAX_OBJECT_ROWS = 200;",
		"const MAX_RECONCILE_ROWS = 200;",
		"rows = limitRows(sortRows(\"objects\", rows), MAX_OBJECT_ROWS);",
		"rows = limitRows(sortRows(\"reconcile\", rows), MAX_RECONCILE_ROWS);",
	} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected analysis page to clamp heavy auxiliary tables with %q", want)
		}
	}
}

func TestAnalysisPageSortsUsingLoadedRowsWithoutReloading(t *testing.T) {
	js, err := embeddedStatic.ReadFile("static/analysis.js")
	if err != nil {
		t.Fatalf("read analysis.js: %v", err)
	}
	for _, want := range []string{
		"let latestAnalysis = null;",
		"let latestObjects = [];",
		"let latestReconcile = [];",
		"renderLoadedRows();",
	} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected analysis page sorting to reuse loaded rows with %q", want)
		}
	}
	if strings.Contains(string(js), "savePrefs();\n  renderSortHeaders();\n  loadAnalysis();\n}") {
		t.Fatal("expected sort changes to avoid reloading the analysis endpoint")
	}
}

func TestAnalysisPageKeepsAuxiliaryTablesVisibleWhileRefreshing(t *testing.T) {
	js, err := embeddedStatic.ReadFile("static/analysis.js")
	if err != nil {
		t.Fatalf("read analysis.js: %v", err)
	}
	for _, want := range []string{
		`latestObjects = objectsResult.status === "fulfilled" ? (objectsResult.value.objects || []) : latestObjects;`,
		`latestReconcile = reconcileResult.status === "fulfilled" ? (reconcileResult.value.rows || []) : latestReconcile;`,
	} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected analysis page to preserve auxiliary rows while refreshing with %q", want)
		}
	}
	for _, unwanted := range []string{
		"\n  latestObjects = [];\n",
		"\n  latestReconcile = [];\n",
	} {
		if strings.Contains(string(js), unwanted) {
			t.Fatalf("expected analysis page to avoid clearing auxiliary rows before refresh with %q", unwanted)
		}
	}
}

func TestAnalysisPageAbortsInFlightFetchesWhenNavigatingAway(t *testing.T) {
	js, err := embeddedStatic.ReadFile("static/analysis.js")
	if err != nil {
		t.Fatalf("read analysis.js: %v", err)
	}
	for _, want := range []string{
		"let activeRequestController = null;",
		"function abortActiveRequest()",
		"activeRequestController.abort();",
		"new AbortController()",
		"if (error?.name === \"AbortError\")",
		"function cleanupPage()",
	} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("expected analysis page to abort in-flight fetches during navigation with %q", want)
		}
	}
}
