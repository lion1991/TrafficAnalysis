package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"trafficanalysis/internal/store"
	"trafficanalysis/internal/traffic"
)

type fakeBucketQueryer struct {
	from       time.Time
	to         time.Time
	clientIP   string
	aliasIP    string
	aliasMAC   string
	aliasName  string
	rows       []store.BucketRow
	clientRows []store.ClientBucketRow
}

func (f *fakeBucketQueryer) QueryBuckets(ctx context.Context, from, to time.Time) ([]store.BucketRow, error) {
	f.from = from
	f.to = to
	return f.rows, nil
}

func (f *fakeBucketQueryer) QueryClientBuckets(ctx context.Context, from, to time.Time, clientIP string) ([]store.ClientBucketRow, error) {
	f.from = from
	f.to = to
	f.clientIP = clientIP
	return f.clientRows, nil
}

func (f *fakeBucketQueryer) UpsertClientAlias(ctx context.Context, clientIP, clientMAC, alias string) error {
	f.aliasIP = clientIP
	f.aliasMAC = clientMAC
	f.aliasName = alias
	return nil
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

func TestLiveSSEReturnsUnavailableWithoutLiveSource(t *testing.T) {
	handler := NewHandler(&fakeBucketQueryer{}, Options{Location: time.UTC})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/live", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
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
