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

const liveHeartbeatInterval = 15 * time.Second

type BucketQueryer interface {
	QueryBuckets(ctx context.Context, from, to time.Time) ([]store.BucketRow, error)
}

type ClientBucketQueryer interface {
	QueryClientBuckets(ctx context.Context, from, to time.Time, clientIP string) ([]store.ClientBucketRow, error)
}

type EndpointBucketQueryer interface {
	QueryEndpointBuckets(ctx context.Context, from, to time.Time) ([]store.EndpointBucketRow, error)
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
	queryer         BucketQueryer
	clientQueryer   ClientBucketQueryer
	endpointQueryer EndpointBucketQueryer
	aliasWriter     ClientAliasWriter
	location        *time.Location
	now             func() time.Time
	liveSource      LiveSource
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
		queryer:         queryer,
		clientQueryer:   clientBucketQueryer(queryer),
		endpointQueryer: endpointBucketQueryer(queryer),
		aliasWriter:     clientAliasWriter(queryer),
		location:        location,
		now:             now,
		liveSource:      options.LiveSource,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/traffic", srv.handleTraffic)
	mux.HandleFunc("/api/clients", srv.handleClients)
	mux.HandleFunc("/api/analysis", srv.handleAnalysis)
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

func endpointBucketQueryer(queryer BucketQueryer) EndpointBucketQueryer {
	endpointQueryer, ok := queryer.(EndpointBucketQueryer)
	if !ok {
		return nil
	}
	return endpointQueryer
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

	heartbeat := time.NewTicker(liveHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, "event: heartbeat\ndata: {}\n\n"); err != nil {
				return
			}
			flusher.Flush()
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

func (s server) handleAnalysis(w http.ResponseWriter, r *http.Request) {
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

	trafficRows, err := s.queryer.QueryBuckets(r.Context(), from, to)
	if err != nil {
		http.Error(w, "query traffic buckets", http.StatusInternalServerError)
		return
	}

	var clientRows []store.ClientBucketRow
	if s.clientQueryer != nil {
		clientRows, err = s.clientQueryer.QueryClientBuckets(r.Context(), from, to, "")
		if err != nil {
			http.Error(w, "query client traffic buckets", http.StatusInternalServerError)
			return
		}
	}
	var endpointRows []store.EndpointBucketRow
	if s.endpointQueryer != nil {
		endpointRows, err = s.endpointQueryer.QueryEndpointBuckets(r.Context(), from, to)
		if err != nil {
			http.Error(w, "query endpoint traffic buckets", http.StatusInternalServerError)
			return
		}
	}

	response := buildAnalysisResponse(from, to, trafficRows, clientRows, endpointRows)
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

type analysisResponse struct {
	Range              responseRange       `json:"range"`
	Totals             analysisTotals      `json:"totals"`
	TopUploadClients   []clientSummaryRow  `json:"top_upload_clients"`
	TopDownloadClients []clientSummaryRow  `json:"top_download_clients"`
	RemoteEndpoints    []remoteEndpointRow `json:"remote_endpoints"`
	Signals            []analysisSignal    `json:"signals"`
	Limitations        []string            `json:"limitations"`
}

type analysisTotals struct {
	UploadBytes       int64   `json:"upload_bytes"`
	DownloadBytes     int64   `json:"download_bytes"`
	LANBytes          int64   `json:"lan_bytes"`
	OtherBytes        int64   `json:"other_bytes"`
	UnknownBytes      int64   `json:"unknown_bytes"`
	Packets           int64   `json:"packets"`
	UploadShare       float64 `json:"upload_share"`
	PeakUploadBytes   int64   `json:"peak_upload_bytes"`
	PeakUploadBucket  string  `json:"peak_upload_bucket"`
	ActiveClientCount int     `json:"active_client_count"`
	UploadClientCount int     `json:"upload_client_count"`
}

type analysisSignal struct {
	Label string `json:"label"`
	Level string `json:"level"`
	Value string `json:"value"`
	Note  string `json:"note"`
}

type remoteEndpointRow struct {
	RemoteIP      string `json:"remote_ip"`
	RemotePort    uint16 `json:"remote_port"`
	Protocol      string `json:"protocol"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	Packets       int64  `json:"packets"`
	ClientCount   int    `json:"client_count"`
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

func buildAnalysisResponse(from, to time.Time, trafficRows []store.BucketRow, clientRows []store.ClientBucketRow, endpointRows []store.EndpointBucketRow) analysisResponse {
	traffic := buildTrafficResponse(from, to, trafficRows)
	clients := buildClientsResponse(from, to, clientRows)
	response := analysisResponse{
		Range: traffic.Range,
		Totals: analysisTotals{
			UploadBytes:       traffic.Totals.UploadBytes,
			DownloadBytes:     traffic.Totals.DownloadBytes,
			LANBytes:          traffic.Totals.LANBytes,
			OtherBytes:        traffic.Totals.OtherBytes,
			UnknownBytes:      traffic.Totals.UnknownBytes,
			Packets:           traffic.Totals.Packets,
			ActiveClientCount: len(clients.Clients),
		},
		TopUploadClients:   topClientsBy(clients.Clients, "upload", 8),
		TopDownloadClients: topClientsBy(clients.Clients, "download", 8),
		RemoteEndpoints:    buildRemoteEndpointRows(endpointRows, 20),
		Limitations: []string{
			"当前分析基于已落库的时间 bucket 和客户端汇总。",
			"远端 IP/端口维度来自 LAN 镜像口捕获到的客户端公网流量。",
		},
	}

	totalWAN := response.Totals.UploadBytes + response.Totals.DownloadBytes
	if totalWAN > 0 {
		response.Totals.UploadShare = float64(response.Totals.UploadBytes) / float64(totalWAN)
	}

	for _, point := range traffic.Series {
		if point.UploadBytes > response.Totals.PeakUploadBytes {
			response.Totals.PeakUploadBytes = point.UploadBytes
			response.Totals.PeakUploadBucket = point.BucketStart
		}
	}
	for _, client := range clients.Clients {
		if client.UploadBytes > 0 {
			response.Totals.UploadClientCount++
		}
	}

	response.Signals = buildAnalysisSignals(response.Totals, response.TopUploadClients)
	return response
}

type remoteEndpointAccumulator struct {
	row     remoteEndpointRow
	clients map[string]struct{}
}

func buildRemoteEndpointRows(rows []store.EndpointBucketRow, limit int) []remoteEndpointRow {
	if len(rows) == 0 || limit <= 0 {
		return []remoteEndpointRow{}
	}
	byEndpoint := make(map[string]*remoteEndpointAccumulator)
	for _, row := range rows {
		key := row.Key.RemoteIP.String() + "\x00" + strconv.Itoa(int(row.Key.RemotePort)) + "\x00" + row.Key.Protocol
		acc := byEndpoint[key]
		if acc == nil {
			acc = &remoteEndpointAccumulator{
				row: remoteEndpointRow{
					RemoteIP:   row.Key.RemoteIP.String(),
					RemotePort: row.Key.RemotePort,
					Protocol:   row.Key.Protocol,
				},
				clients: make(map[string]struct{}),
			}
			byEndpoint[key] = acc
		}
		switch row.Key.Direction {
		case traffic.DirectionUpload:
			acc.row.UploadBytes += row.Value.Bytes
		case traffic.DirectionDownload:
			acc.row.DownloadBytes += row.Value.Bytes
		}
		acc.row.Packets += row.Value.Packets
		clientKey := row.Key.ClientIP.String() + "\x00" + row.Key.ClientMAC
		acc.clients[clientKey] = struct{}{}
	}

	result := make([]remoteEndpointRow, 0, len(byEndpoint))
	for _, acc := range byEndpoint {
		acc.row.ClientCount = len(acc.clients)
		result = append(result, acc.row)
	}
	sort.Slice(result, func(i, j int) bool {
		leftTotal := result[i].UploadBytes + result[i].DownloadBytes
		rightTotal := result[j].UploadBytes + result[j].DownloadBytes
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		if result[i].RemoteIP != result[j].RemoteIP {
			return result[i].RemoteIP < result[j].RemoteIP
		}
		if result[i].RemotePort != result[j].RemotePort {
			return result[i].RemotePort < result[j].RemotePort
		}
		return result[i].Protocol < result[j].Protocol
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func topClientsBy(clients []clientSummaryRow, field string, limit int) []clientSummaryRow {
	if limit <= 0 || len(clients) == 0 {
		return []clientSummaryRow{}
	}
	result := append([]clientSummaryRow(nil), clients...)
	sort.Slice(result, func(i, j int) bool {
		left := clientByteValue(result[i], field)
		right := clientByteValue(result[j], field)
		if left != right {
			return left > right
		}
		if result[i].DisplayName != result[j].DisplayName {
			return result[i].DisplayName < result[j].DisplayName
		}
		return result[i].ClientIP < result[j].ClientIP
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func clientByteValue(row clientSummaryRow, field string) int64 {
	switch field {
	case "download":
		return row.DownloadBytes
	default:
		return row.UploadBytes
	}
}

func buildAnalysisSignals(totals analysisTotals, topUploadClients []clientSummaryRow) []analysisSignal {
	signals := []analysisSignal{
		{
			Label: "上传占比",
			Level: uploadShareLevel(totals.UploadShare),
			Value: formatPercent(totals.UploadShare),
			Note:  "上传占比越高，越需要结合客户端排行和业务场景判断。",
		},
		{
			Label: "上传峰值",
			Level: uploadPeakLevel(totals.PeakUploadBytes, totals.UploadBytes),
			Value: formatByteCount(totals.PeakUploadBytes),
			Note:  "峰值来自单个落库时间 bucket，用于定位异常时间点。",
		},
		{
			Label: "活跃客户端",
			Level: clientCoverageLevel(totals.ActiveClientCount),
			Value: strconv.Itoa(totals.ActiveClientCount),
			Note:  "需要配置 LAN 镜像口和 local_networks 才能获得客户端维度。",
		},
		{
			Label: "数据维度",
			Level: "info",
			Value: "bucket / client / remote",
			Note:  "远端 IP/端口维度需要 LAN 镜像口数据。",
		},
	}

	if len(topUploadClients) > 0 && totals.UploadBytes > 0 {
		top := topUploadClients[0]
		share := float64(top.UploadBytes) / float64(totals.UploadBytes)
		signals = append(signals, analysisSignal{
			Label: "最高上传客户端",
			Level: topClientShareLevel(share),
			Value: top.DisplayName,
			Note:  fmt.Sprintf("%s，占上传总量 %s", formatByteCount(top.UploadBytes), formatPercent(share)),
		})
	}

	return signals
}

func uploadShareLevel(share float64) string {
	switch {
	case share >= 0.80:
		return "watch"
	case share >= 0.55:
		return "notice"
	default:
		return "normal"
	}
}

func uploadPeakLevel(peakBytes, totalUploadBytes int64) string {
	if peakBytes <= 0 || totalUploadBytes <= 0 {
		return "normal"
	}
	share := float64(peakBytes) / float64(totalUploadBytes)
	switch {
	case share >= 0.75:
		return "watch"
	case share >= 0.45:
		return "notice"
	default:
		return "normal"
	}
}

func clientCoverageLevel(count int) string {
	if count == 0 {
		return "notice"
	}
	return "normal"
}

func topClientShareLevel(share float64) string {
	switch {
	case share >= 0.85:
		return "watch"
	case share >= 0.60:
		return "notice"
	default:
		return "normal"
	}
}

func formatPercent(value float64) string {
	return strconv.FormatFloat(value*100, 'f', 1, 64) + "%"
}

func formatByteCount(bytes int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(bytes)
	unit := units[0]
	for index := 1; index < len(units) && value >= 1024; index++ {
		value /= 1024
		unit = units[index]
	}
	if unit == "B" {
		return strconv.FormatInt(bytes, 10) + " B"
	}
	return strconv.FormatFloat(value, 'f', 2, 64) + " " + unit
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
