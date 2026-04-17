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

type ClientBucketQueryer interface {
	QueryClientBuckets(ctx context.Context, from, to time.Time, clientIP string) ([]store.ClientBucketRow, error)
}

type ClientAliasWriter interface {
	UpsertClientAlias(ctx context.Context, clientIP, clientMAC, alias string) error
}

type Options struct {
	Location   *time.Location
	Now        func() time.Time
	LiveSource LiveSource
}

type server struct {
	queryer       BucketQueryer
	clientQueryer ClientBucketQueryer
	aliasWriter   ClientAliasWriter
	location      *time.Location
	now           func() time.Time
	liveSource    LiveSource
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
		queryer:       queryer,
		clientQueryer: clientBucketQueryer(queryer),
		aliasWriter:   clientAliasWriter(queryer),
		location:      location,
		now:           now,
		liveSource:    options.LiveSource,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/traffic", srv.handleTraffic)
	mux.HandleFunc("/api/clients", srv.handleClients)
	mux.HandleFunc("/api/clients/alias", srv.handleClientAlias)
	mux.HandleFunc("/api/live", srv.handleLive)
	mux.Handle("/", srv.staticHandler())
	return mux
}

func clientAliasWriter(queryer BucketQueryer) ClientAliasWriter {
	aliasWriter, ok := queryer.(ClientAliasWriter)
	if !ok {
		return nil
	}
	return aliasWriter
}

func clientBucketQueryer(queryer BucketQueryer) ClientBucketQueryer {
	clientQueryer, ok := queryer.(ClientBucketQueryer)
	if !ok {
		return nil
	}
	return clientQueryer
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

func (s server) handleLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.liveSource == nil {
		http.Error(w, "live stream is only available from a capture process", http.StatusServiceUnavailable)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	events, cancel := s.liveSource.Subscribe(r.Context())
	defer cancel()

	if _, err := fmt.Fprint(w, ": connected\n\n"); err != nil {
		return
	}
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case snapshot, ok := <-events:
			if !ok {
				return
			}
			data, err := json.Marshal(snapshot)
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s server) handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.clientQueryer == nil {
		http.Error(w, "client traffic buckets are unavailable", http.StatusNotImplemented)
		return
	}

	from, to, err := parseRangeFromRequest(r, s.now(), s.location)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientIP := strings.TrimSpace(r.URL.Query().Get("client_ip"))
	rows, err := s.clientQueryer.QueryClientBuckets(r.Context(), from, to, clientIP)
	if err != nil {
		http.Error(w, "query client traffic buckets", http.StatusInternalServerError)
		return
	}

	response := buildClientsResponse(from, to, rows)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

func (s server) handleClientAlias(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.aliasWriter == nil {
		http.Error(w, "client aliases are unavailable", http.StatusNotImplemented)
		return
	}

	var request struct {
		ClientIP  string `json:"client_ip"`
		ClientMAC string `json:"client_mac"`
		Alias     string `json:"alias"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	request.ClientIP = strings.TrimSpace(request.ClientIP)
	request.ClientMAC = strings.TrimSpace(request.ClientMAC)
	request.Alias = strings.TrimSpace(request.Alias)
	if request.ClientIP == "" && request.ClientMAC == "" {
		http.Error(w, "client_ip or client_mac is required", http.StatusBadRequest)
		return
	}
	if err := s.aliasWriter.UpsertClientAlias(r.Context(), request.ClientIP, request.ClientMAC, request.Alias); err != nil {
		http.Error(w, "store client alias", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

type clientsResponse struct {
	Range     responseRange        `json:"range"`
	Clients   []clientSummaryRow   `json:"clients"`
	Breakdown []clientBreakdownRow `json:"breakdown"`
}

type clientSummaryRow struct {
	DisplayName   string `json:"display_name"`
	NameSource    string `json:"name_source"`
	Alias         string `json:"alias"`
	LearnedName   string `json:"learned_name"`
	ClientIP      string `json:"client_ip"`
	ClientMAC     string `json:"client_mac"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	Packets       int64  `json:"packets"`
}

type clientBreakdownRow struct {
	ClientIP  string `json:"client_ip"`
	ClientMAC string `json:"client_mac"`
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

func buildClientsResponse(from, to time.Time, rows []store.ClientBucketRow) clientsResponse {
	response := clientsResponse{
		Range: responseRange{
			From: from.UTC().Format(time.RFC3339),
			To:   to.UTC().Format(time.RFC3339),
		},
		Clients:   []clientSummaryRow{},
		Breakdown: []clientBreakdownRow{},
	}

	summaryByClient := make(map[string]*clientSummaryRow)
	breakdownByKey := make(map[string]*clientBreakdownRow)

	for _, row := range rows {
		clientIP := row.Key.ClientIP.String()
		clientKey := clientIP + "\x00" + row.Key.ClientMAC
		summary := summaryByClient[clientKey]
		if summary == nil {
			displayName, source := displayClientName(row.Alias, row.Name, row.NameSource, clientIP, row.Key.ClientMAC)
			summary = &clientSummaryRow{
				DisplayName: displayName,
				NameSource:  source,
				Alias:       row.Alias,
				LearnedName: row.Name,
				ClientIP:    clientIP,
				ClientMAC:   row.Key.ClientMAC,
			}
			summaryByClient[clientKey] = summary
		}
		switch row.Key.Direction {
		case traffic.DirectionUpload:
			summary.UploadBytes += row.Value.Bytes
		case traffic.DirectionDownload:
			summary.DownloadBytes += row.Value.Bytes
		}
		summary.Packets += row.Value.Packets

		breakdownKey := clientKey + "\x00" + string(row.Key.Direction) + "\x00" + row.Key.Protocol
		breakdown := breakdownByKey[breakdownKey]
		if breakdown == nil {
			breakdown = &clientBreakdownRow{
				ClientIP:  clientIP,
				ClientMAC: row.Key.ClientMAC,
				Direction: string(row.Key.Direction),
				Protocol:  row.Key.Protocol,
			}
			breakdownByKey[breakdownKey] = breakdown
		}
		breakdown.Bytes += row.Value.Bytes
		breakdown.Packets += row.Value.Packets
	}

	clientKeys := make([]string, 0, len(summaryByClient))
	for key := range summaryByClient {
		clientKeys = append(clientKeys, key)
	}
	sort.Slice(clientKeys, func(i, j int) bool {
		left := summaryByClient[clientKeys[i]]
		right := summaryByClient[clientKeys[j]]
		leftTotal := left.UploadBytes + left.DownloadBytes
		rightTotal := right.UploadBytes + right.DownloadBytes
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		if left.ClientIP != right.ClientIP {
			return left.ClientIP < right.ClientIP
		}
		return left.ClientMAC < right.ClientMAC
	})
	for _, key := range clientKeys {
		response.Clients = append(response.Clients, *summaryByClient[key])
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

func displayClientName(alias, learnedName, learnedSource, clientIP, clientMAC string) (string, string) {
	alias = strings.TrimSpace(alias)
	if alias != "" {
		return alias, "alias"
	}
	learnedName = strings.TrimSpace(learnedName)
	if learnedName != "" {
		return learnedName, learnedSource
	}
	if clientMAC != "" {
		return clientMAC, ""
	}
	return clientIP, ""
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
