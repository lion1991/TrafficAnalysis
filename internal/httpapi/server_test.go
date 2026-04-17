package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trafficanalysis/internal/store"
	"trafficanalysis/internal/traffic"
)

type fakeBucketQueryer struct {
	from time.Time
	to   time.Time
	rows []store.BucketRow
}

func (f *fakeBucketQueryer) QueryBuckets(ctx context.Context, from, to time.Time) ([]store.BucketRow, error) {
	f.from = from
	f.to = to
	return f.rows, nil
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
