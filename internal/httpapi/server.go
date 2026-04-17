package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"trafficanalysis/internal/store"
	"trafficanalysis/internal/traffic"
)

//go:embed static/*
var embeddedStatic embed.FS

type BucketQueryer interface {
	QueryBuckets(ctx context.Context, from, to time.Time) ([]store.BucketRow, error)
}

type Options struct {
	Location *time.Location
	Now      func() time.Time
}

type server struct {
	queryer  BucketQueryer
	location *time.Location
	now      func() time.Time
}

func NewHandler(queryer BucketQueryer, options Options) http.Handler {
	location := options.Location
	if location == nil {
		location = time.Local
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	srv := server{
		queryer:  queryer,
		location: location,
		now:      now,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/traffic", srv.handleTraffic)
	mux.Handle("/", srv.staticHandler())
	return mux
}

func (s server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	from, to, err := parseRangeFromRequest(r, s.now(), s.location)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rows, err := s.queryer.QueryBuckets(r.Context(), from, to)
	if err != nil {
		http.Error(w, "query traffic buckets", http.StatusInternalServerError)
		return
	}

	response := buildTrafficResponse(from, to, rows)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

func (s server) staticHandler() http.Handler {
	staticFS, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(staticFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFileFS(w, r, staticFS, "index.html")
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

type trafficResponse struct {
	Range     responseRange  `json:"range"`
	Totals    responseTotals `json:"totals"`
	Series    []seriesPoint  `json:"series"`
	Breakdown []breakdownRow `json:"breakdown"`
}

type responseRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type responseTotals struct {
	UploadBytes   int64 `json:"upload_bytes"`
	DownloadBytes int64 `json:"download_bytes"`
	LANBytes      int64 `json:"lan_bytes"`
	OtherBytes    int64 `json:"other_bytes"`
	UnknownBytes  int64 `json:"unknown_bytes"`
	Packets       int64 `json:"packets"`
}

type seriesPoint struct {
	BucketStart   string `json:"bucket_start"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	LANBytes      int64  `json:"lan_bytes"`
	OtherBytes    int64  `json:"other_bytes"`
	UnknownBytes  int64  `json:"unknown_bytes"`
	Packets       int64  `json:"packets"`
}

type breakdownRow struct {
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	Bytes     int64  `json:"bytes"`
	Packets   int64  `json:"packets"`
}

func buildTrafficResponse(from, to time.Time, rows []store.BucketRow) trafficResponse {
	response := trafficResponse{
		Range: responseRange{
			From: from.UTC().Format(time.RFC3339),
			To:   to.UTC().Format(time.RFC3339),
		},
		Series:    []seriesPoint{},
		Breakdown: []breakdownRow{},
	}

	seriesByStart := make(map[time.Time]*seriesPoint)
	breakdownByKey := make(map[string]*breakdownRow)

	for _, row := range rows {
		addDirectionBytes(&response.Totals, row.Key.Direction, row.Value.Bytes)
		response.Totals.Packets += row.Value.Packets

		start := row.Key.Start.UTC()
		point := seriesByStart[start]
		if point == nil {
			point = &seriesPoint{BucketStart: start.Format(time.RFC3339)}
			seriesByStart[start] = point
		}
		addPointDirectionBytes(point, row.Key.Direction, row.Value.Bytes)
		point.Packets += row.Value.Packets

		key := string(row.Key.Direction) + "\x00" + row.Key.Protocol
		breakdown := breakdownByKey[key]
		if breakdown == nil {
			breakdown = &breakdownRow{
				Direction: string(row.Key.Direction),
				Protocol:  row.Key.Protocol,
			}
			breakdownByKey[key] = breakdown
		}
		breakdown.Bytes += row.Value.Bytes
		breakdown.Packets += row.Value.Packets
	}

	starts := make([]time.Time, 0, len(seriesByStart))
	for start := range seriesByStart {
		starts = append(starts, start)
	}
	sort.Slice(starts, func(i, j int) bool {
		return starts[i].Before(starts[j])
	})
	for _, start := range starts {
		response.Series = append(response.Series, *seriesByStart[start])
	}

	breakdownKeys := make([]string, 0, len(breakdownByKey))
	for key := range breakdownByKey {
		breakdownKeys = append(breakdownKeys, key)
	}
	sort.Strings(breakdownKeys)
	for _, key := range breakdownKeys {
		response.Breakdown = append(response.Breakdown, *breakdownByKey[key])
	}

	return response
}

func addDirectionBytes(totals *responseTotals, direction traffic.Direction, bytes int64) {
	switch direction {
	case traffic.DirectionUpload:
		totals.UploadBytes += bytes
	case traffic.DirectionDownload:
		totals.DownloadBytes += bytes
	case traffic.DirectionLAN:
		totals.LANBytes += bytes
	case traffic.DirectionUnknown:
		totals.UnknownBytes += bytes
	default:
		totals.OtherBytes += bytes
	}
}

func addPointDirectionBytes(point *seriesPoint, direction traffic.Direction, bytes int64) {
	switch direction {
	case traffic.DirectionUpload:
		point.UploadBytes += bytes
	case traffic.DirectionDownload:
		point.DownloadBytes += bytes
	case traffic.DirectionLAN:
		point.LANBytes += bytes
	case traffic.DirectionUnknown:
		point.UnknownBytes += bytes
	default:
		point.OtherBytes += bytes
	}
}

func parseRangeFromRequest(r *http.Request, now time.Time, location *time.Location) (time.Time, time.Time, error) {
	query := r.URL.Query()
	return parseQueryRange(queryRangeOptions{
		date:  query.Get("date"),
		month: query.Get("month"),
		from:  query.Get("from"),
		to:    query.Get("to"),
		last:  query.Get("last"),
	}, now, location)
}

type queryRangeOptions struct {
	date  string
	month string
	from  string
	to    string
	last  string
}

func parseQueryRange(options queryRangeOptions, now time.Time, location *time.Location) (time.Time, time.Time, error) {
	if location == nil {
		location = time.Local
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if options.date != "" {
		start, err := time.ParseInLocation("2006-01-02", options.date, location)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		return validateQueryRange(start.UTC(), start.AddDate(0, 0, 1).UTC())
	}

	if options.month != "" {
		start, err := time.ParseInLocation("2006-01", options.month, location)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		return validateQueryRange(start.UTC(), start.AddDate(0, 1, 0).UTC())
	}

	to := now.UTC()
	var err error
	if options.to != "" {
		to, err = parseQueryTime(options.to, location)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
	}

	var from time.Time
	if options.from != "" {
		from, err = parseQueryTime(options.from, location)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
	} else {
		lastText := options.last
		if lastText == "" {
			lastText = "1h"
		}
		last, err := parseQueryDuration(lastText)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		from = to.Add(-last)
	}

	return validateQueryRange(from.UTC(), to.UTC())
}

func validateQueryRange(from, to time.Time) (time.Time, time.Time, error) {
	if !from.Before(to) {
		return time.Time{}, time.Time{}, errors.New("from must be before to")
	}
	return from, to, nil
}

func parseQueryTime(text string, location *time.Location) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, text); err == nil {
		return parsed.UTC(), nil
	}

	layouts := []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(layout, text, location)
		if err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time %q; use YYYY-MM-DD, YYYY-MM-DD HH:MM, or RFC3339", text)
}

func parseQueryDuration(text string) (time.Duration, error) {
	if strings.HasSuffix(text, "d") {
		daysText := strings.TrimSuffix(text, "d")
		days, err := strconv.Atoi(daysText)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(text)
}
