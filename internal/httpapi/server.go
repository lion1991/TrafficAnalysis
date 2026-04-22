package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
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

type WANEndpointBucketQueryer interface {
	QueryWANEndpointBuckets(ctx context.Context, from, to time.Time) ([]store.WANEndpointBucketRow, error)
}

type ClientAliasWriter interface {
	UpsertClientAlias(ctx context.Context, clientIP, clientMAC, alias string) error
}

type DNSObservationQueryer interface {
	QueryDNSObservations(ctx context.Context, from, to time.Time) ([]traffic.DNSObservation, error)
}

type TLSObservationQueryer interface {
	QueryTLSObservations(ctx context.Context, from, to time.Time) ([]traffic.TLSObservation, error)
}

type FlowSessionQueryer interface {
	QueryFlowSessions(ctx context.Context, from, to time.Time) ([]traffic.FlowSession, error)
	QueryFlowSessionByID(ctx context.Context, id int64) (traffic.FlowSession, error)
}

type ViewpointTLSObservationQueryer interface {
	QueryTLSObservationsByViewpoint(ctx context.Context, from, to time.Time, viewpoint traffic.Viewpoint) ([]traffic.TLSObservation, error)
}

type ViewpointFlowSessionQueryer interface {
	QueryFlowSessionsByViewpoint(ctx context.Context, from, to time.Time, viewpoint traffic.Viewpoint) ([]traffic.FlowSession, error)
}

type Options struct {
	Location   *time.Location
	Now        func() time.Time
	LiveSource LiveSource
}

type server struct {
	queryer              BucketQueryer
	clientQueryer        ClientBucketQueryer
	endpointQueryer      EndpointBucketQueryer
	wanEndpointQueryer   WANEndpointBucketQueryer
	aliasWriter          ClientAliasWriter
	dnsQueryer           DNSObservationQueryer
	tlsQueryer           TLSObservationQueryer
	flowSessionQueryer   FlowSessionQueryer
	viewpointTLSQueryer  ViewpointTLSObservationQueryer
	viewpointFlowQueryer ViewpointFlowSessionQueryer
	location             *time.Location
	now                  func() time.Time
	liveSource           LiveSource
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
		queryer:              queryer,
		clientQueryer:        clientBucketQueryer(queryer),
		endpointQueryer:      endpointBucketQueryer(queryer),
		wanEndpointQueryer:   wanEndpointBucketQueryer(queryer),
		aliasWriter:          clientAliasWriter(queryer),
		dnsQueryer:           dnsObservationQueryer(queryer),
		tlsQueryer:           tlsObservationQueryer(queryer),
		flowSessionQueryer:   flowSessionQueryer(queryer),
		viewpointTLSQueryer:  viewpointTLSObservationQueryer(queryer),
		viewpointFlowQueryer: viewpointFlowSessionQueryer(queryer),
		location:             location,
		now:                  now,
		liveSource:           options.LiveSource,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/traffic", srv.handleTraffic)
	mux.HandleFunc("/api/clients", srv.handleClients)
	mux.HandleFunc("/api/analysis", srv.handleAnalysis)
	mux.HandleFunc("/api/analysis/objects", srv.handleAnalysisObjects)
	mux.HandleFunc("/api/analysis/reconcile", srv.handleAnalysisReconcile)
	mux.HandleFunc("/api/analysis/session", srv.handleAnalysisSession)
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

func wanEndpointBucketQueryer(queryer BucketQueryer) WANEndpointBucketQueryer {
	wanEndpointQueryer, ok := queryer.(WANEndpointBucketQueryer)
	if !ok {
		return nil
	}
	return wanEndpointQueryer
}

func dnsObservationQueryer(queryer BucketQueryer) DNSObservationQueryer {
	dnsQueryer, ok := queryer.(DNSObservationQueryer)
	if !ok {
		return nil
	}
	return dnsQueryer
}

func tlsObservationQueryer(queryer BucketQueryer) TLSObservationQueryer {
	tlsQueryer, ok := queryer.(TLSObservationQueryer)
	if !ok {
		return nil
	}
	return tlsQueryer
}

func flowSessionQueryer(queryer BucketQueryer) FlowSessionQueryer {
	sessionQueryer, ok := queryer.(FlowSessionQueryer)
	if !ok {
		return nil
	}
	return sessionQueryer
}

func viewpointTLSObservationQueryer(queryer BucketQueryer) ViewpointTLSObservationQueryer {
	filtered, ok := queryer.(ViewpointTLSObservationQueryer)
	if !ok {
		return nil
	}
	return filtered
}

func viewpointFlowSessionQueryer(queryer BucketQueryer) ViewpointFlowSessionQueryer {
	filtered, ok := queryer.(ViewpointFlowSessionQueryer)
	if !ok {
		return nil
	}
	return filtered
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
	var wanEndpointRows []store.WANEndpointBucketRow
	if s.wanEndpointQueryer != nil {
		wanEndpointRows, err = s.wanEndpointQueryer.QueryWANEndpointBuckets(r.Context(), from, to)
		if err != nil {
			http.Error(w, "query WAN endpoint traffic buckets", http.StatusInternalServerError)
			return
		}
	}

	response := buildAnalysisResponse(from, to, trafficRows, clientRows, endpointRows, wanEndpointRows)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}

func (s server) handleAnalysisObjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.flowSessionQueryer == nil {
		http.Error(w, "flow sessions are unavailable", http.StatusNotImplemented)
		return
	}

	from, to, err := parseRangeFromRequest(r, s.now(), s.location)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sessions, err := s.queryFlowSessionsByViewpoint(r.Context(), from, to, traffic.ViewpointLAN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dnsRows, err := s.queryDNSObservations(r.Context(), from, to)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tlsRows, err := s.queryTLSObservationsByViewpoint(r.Context(), from, to, traffic.ViewpointLAN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := buildObjectsResponse(from, to, sessions, dnsRows, tlsRows)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s server) handleAnalysisReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.flowSessionQueryer == nil {
		http.Error(w, "flow sessions are unavailable", http.StatusNotImplemented)
		return
	}

	from, to, err := parseRangeFromRequest(r, s.now(), s.location)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wanSessions, err := s.queryFlowSessionsByViewpoint(r.Context(), from, to, traffic.ViewpointWAN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lanSessions, err := s.queryFlowSessionsByViewpoint(r.Context(), from, to, traffic.ViewpointLAN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := buildReconcileResponse(from, to, wanSessions, lanSessions)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s server) handleAnalysisSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.flowSessionQueryer == nil {
		http.Error(w, "flow sessions are unavailable", http.StatusNotImplemented)
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid session id", http.StatusBadRequest)
		return
	}

	session, err := s.flowSessionQueryer.QueryFlowSessionByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		http.Error(w, "query flow session", http.StatusInternalServerError)
		return
	}

	windowFrom := session.FirstSeen.Add(-5 * time.Minute)
	windowTo := session.LastSeen.Add(5 * time.Minute)
	sessions, dnsRows, tlsRows, err := s.loadAnalysisEvidence(r.Context(), windowFrom, windowTo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	label, source, confidence := attributeSession(session, dnsRows, tlsRows)
	response := buildSessionResponse(session, label, source, confidence, dnsRows, tlsRows, buildReconcileRows(sessions))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s server) loadAnalysisEvidence(ctx context.Context, from, to time.Time) ([]traffic.FlowSession, []traffic.DNSObservation, []traffic.TLSObservation, error) {
	sessions, err := s.flowSessionQueryer.QueryFlowSessions(ctx, from, to)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("query flow sessions")
	}
	var dnsRows []traffic.DNSObservation
	if s.dnsQueryer != nil {
		dnsRows, err = s.dnsQueryer.QueryDNSObservations(ctx, from, to)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("query dns observations")
		}
	}
	var tlsRows []traffic.TLSObservation
	if s.tlsQueryer != nil {
		tlsRows, err = s.tlsQueryer.QueryTLSObservations(ctx, from, to)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("query tls observations")
		}
	}
	return sessions, dnsRows, tlsRows, nil
}

func (s server) queryDNSObservations(ctx context.Context, from, to time.Time) ([]traffic.DNSObservation, error) {
	if s.dnsQueryer == nil {
		return nil, nil
	}
	rows, err := s.dnsQueryer.QueryDNSObservations(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("query dns observations")
	}
	return rows, nil
}

func (s server) queryTLSObservationsByViewpoint(ctx context.Context, from, to time.Time, viewpoint traffic.Viewpoint) ([]traffic.TLSObservation, error) {
	if s.viewpointTLSQueryer != nil {
		rows, err := s.viewpointTLSQueryer.QueryTLSObservationsByViewpoint(ctx, from, to, viewpoint)
		if err != nil {
			return nil, fmt.Errorf("query tls observations")
		}
		return rows, nil
	}
	if s.tlsQueryer == nil {
		return nil, nil
	}
	rows, err := s.tlsQueryer.QueryTLSObservations(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("query tls observations")
	}
	filtered := make([]traffic.TLSObservation, 0, len(rows))
	for _, row := range rows {
		if row.Viewpoint == viewpoint {
			filtered = append(filtered, row)
		}
	}
	return filtered, nil
}

func (s server) queryFlowSessionsByViewpoint(ctx context.Context, from, to time.Time, viewpoint traffic.Viewpoint) ([]traffic.FlowSession, error) {
	if s.viewpointFlowQueryer != nil {
		rows, err := s.viewpointFlowQueryer.QueryFlowSessionsByViewpoint(ctx, from, to, viewpoint)
		if err != nil {
			return nil, fmt.Errorf("query flow sessions")
		}
		return rows, nil
	}
	rows, err := s.flowSessionQueryer.QueryFlowSessions(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("query flow sessions")
	}
	filtered := make([]traffic.FlowSession, 0, len(rows))
	for _, row := range rows {
		if row.Viewpoint == viewpoint {
			filtered = append(filtered, row)
		}
	}
	return filtered, nil
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
	Range              responseRange          `json:"range"`
	Totals             analysisTotals         `json:"totals"`
	TopUploadClients   []clientSummaryRow     `json:"top_upload_clients"`
	TopDownloadClients []clientSummaryRow     `json:"top_download_clients"`
	RemoteEndpoints    []remoteEndpointRow    `json:"remote_endpoints"`
	WANRemoteEndpoints []wanRemoteEndpointRow `json:"wan_remote_endpoints"`
	WANUDPRemoteEnds   []wanRemoteEndpointRow `json:"wan_udp_remote_endpoints"`
	WANUDPClientGaps   []wanUDPClientGapRow   `json:"wan_udp_client_gaps"`
	Signals            []analysisSignal       `json:"signals"`
	Limitations        []string               `json:"limitations"`
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

const (
	maxAnalysisObjectRows    = 200
	maxAnalysisReconcileRows = 200
)

type objectsResponse struct {
	Range   responseRange       `json:"range"`
	Objects []analysisObjectRow `json:"objects"`
}

type analysisObjectRow struct {
	Label         string  `json:"label"`
	LabelSource   string  `json:"label_source"`
	Confidence    float64 `json:"confidence"`
	Protocol      string  `json:"protocol"`
	RemoteIP      string  `json:"remote_ip"`
	RemotePort    uint16  `json:"remote_port"`
	UploadBytes   int64   `json:"upload_bytes"`
	DownloadBytes int64   `json:"download_bytes"`
	SessionCount  int     `json:"session_count"`
	ClientCount   int     `json:"client_count"`
}

type reconcileResponse struct {
	Range responseRange  `json:"range"`
	Rows  []reconcileRow `json:"rows"`
}

type reconcileRow struct {
	WANSessionID              int64   `json:"wan_session_id"`
	LANSessionID              int64   `json:"lan_session_id"`
	Status                    string  `json:"status"`
	Reason                    string  `json:"reason"`
	Confidence                float64 `json:"confidence"`
	RemoteIP                  string  `json:"remote_ip"`
	RemotePort                uint16  `json:"remote_port"`
	Protocol                  string  `json:"protocol"`
	UnattributedUploadBytes   int64   `json:"unattributed_upload_bytes"`
	UnattributedDownloadBytes int64   `json:"unattributed_download_bytes"`
}

type sessionResponse struct {
	Session   sessionDetailResponse    `json:"session"`
	DNS       []traffic.DNSObservation `json:"dns_observations"`
	TLS       []traffic.TLSObservation `json:"tls_observations"`
	Reconcile *reconcileRow            `json:"reconcile,omitempty"`
}

type sessionDetailResponse struct {
	ID            int64   `json:"id"`
	Viewpoint     string  `json:"viewpoint"`
	Protocol      string  `json:"protocol"`
	LocalIP       string  `json:"local_ip"`
	LocalPort     uint16  `json:"local_port"`
	RemoteIP      string  `json:"remote_ip"`
	RemotePort    uint16  `json:"remote_port"`
	ClientIP      string  `json:"client_ip"`
	ClientMAC     string  `json:"client_mac"`
	FirstSeen     string  `json:"first_seen"`
	LastSeen      string  `json:"last_seen"`
	UploadBytes   int64   `json:"upload_bytes"`
	DownloadBytes int64   `json:"download_bytes"`
	Packets       int64   `json:"packets"`
	Label         string  `json:"label"`
	LabelSource   string  `json:"label_source"`
	Confidence    float64 `json:"confidence"`
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

type wanRemoteEndpointRow struct {
	RemoteIP      string `json:"remote_ip"`
	RemotePort    uint16 `json:"remote_port"`
	Protocol      string `json:"protocol"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	Packets       int64  `json:"packets"`
}

type wanUDPClientGapRow struct {
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

func buildAnalysisResponse(from, to time.Time, trafficRows []store.BucketRow, clientRows []store.ClientBucketRow, endpointRows []store.EndpointBucketRow, wanEndpointRows []store.WANEndpointBucketRow) analysisResponse {
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
		WANRemoteEndpoints: buildWANRemoteEndpointRows(wanEndpointRows, 20),
		WANUDPRemoteEnds:   buildWANRemoteEndpointRows(filterWANEndpointRowsByProtocol(wanEndpointRows, "udp"), 20),
		WANUDPClientGaps:   buildWANUDPClientGapRows(endpointRows, wanEndpointRows, 20),
		Limitations: []string{
			"当前分析基于已落库的时间 bucket 和客户端汇总。",
			"客户端远端 IP/端口维度来自 LAN 镜像口捕获到的客户端公网流量。",
			"WAN 远端排行来自 WAN 镜像口，能定位 NAT 后未归属到客户端的公网流量。",
			"WAN UDP 远端排行只展示 UDP，会补足综合排行里被 TCP Top 项挤掉的长期 UDP 观察。",
			"WAN UDP 对照表按同一远端 IP、端口、协议比较 WAN 与客户端侧统计，用于定位未归属流量。",
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
	result := aggregateRemoteEndpointRows(rows)
	if len(result) == 0 || limit <= 0 {
		return []remoteEndpointRow{}
	}
	sortRemoteEndpointRows(result)
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func aggregateRemoteEndpointRows(rows []store.EndpointBucketRow) []remoteEndpointRow {
	if len(rows) == 0 {
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
	return result
}

func buildWANRemoteEndpointRows(rows []store.WANEndpointBucketRow, limit int) []wanRemoteEndpointRow {
	result := aggregateWANRemoteEndpointRows(rows)
	if len(result) == 0 || limit <= 0 {
		return []wanRemoteEndpointRow{}
	}
	sortWANRemoteEndpointRows(result)
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func aggregateWANRemoteEndpointRows(rows []store.WANEndpointBucketRow) []wanRemoteEndpointRow {
	if len(rows) == 0 {
		return []wanRemoteEndpointRow{}
	}
	byEndpoint := make(map[string]*wanRemoteEndpointRow)
	for _, row := range rows {
		key := row.Key.RemoteIP.String() + "\x00" + strconv.Itoa(int(row.Key.RemotePort)) + "\x00" + row.Key.Protocol
		acc := byEndpoint[key]
		if acc == nil {
			acc = &wanRemoteEndpointRow{
				RemoteIP:   row.Key.RemoteIP.String(),
				RemotePort: row.Key.RemotePort,
				Protocol:   row.Key.Protocol,
			}
			byEndpoint[key] = acc
		}
		switch row.Key.Direction {
		case traffic.DirectionUpload:
			acc.UploadBytes += row.Value.Bytes
		case traffic.DirectionDownload:
			acc.DownloadBytes += row.Value.Bytes
		}
		acc.Packets += row.Value.Packets
	}

	result := make([]wanRemoteEndpointRow, 0, len(byEndpoint))
	for _, row := range byEndpoint {
		result = append(result, *row)
	}
	return result
}

func sortRemoteEndpointRows(rows []remoteEndpointRow) {
	sort.Slice(rows, func(i, j int) bool {
		leftTotal := rows[i].UploadBytes + rows[i].DownloadBytes
		rightTotal := rows[j].UploadBytes + rows[j].DownloadBytes
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		if rows[i].RemoteIP != rows[j].RemoteIP {
			return rows[i].RemoteIP < rows[j].RemoteIP
		}
		if rows[i].RemotePort != rows[j].RemotePort {
			return rows[i].RemotePort < rows[j].RemotePort
		}
		return rows[i].Protocol < rows[j].Protocol
	})
}

func sortWANRemoteEndpointRows(rows []wanRemoteEndpointRow) {
	sort.Slice(rows, func(i, j int) bool {
		leftTotal := rows[i].UploadBytes + rows[i].DownloadBytes
		rightTotal := rows[j].UploadBytes + rows[j].DownloadBytes
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		if rows[i].RemoteIP != rows[j].RemoteIP {
			return rows[i].RemoteIP < rows[j].RemoteIP
		}
		if rows[i].RemotePort != rows[j].RemotePort {
			return rows[i].RemotePort < rows[j].RemotePort
		}
		return rows[i].Protocol < rows[j].Protocol
	})
}

func filterWANEndpointRowsByProtocol(rows []store.WANEndpointBucketRow, protocol string) []store.WANEndpointBucketRow {
	if len(rows) == 0 {
		return nil
	}
	filtered := make([]store.WANEndpointBucketRow, 0, len(rows))
	for _, row := range rows {
		if row.Key.Protocol == protocol {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func filterEndpointRowsByProtocol(rows []store.EndpointBucketRow, protocol string) []store.EndpointBucketRow {
	if len(rows) == 0 {
		return nil
	}
	filtered := make([]store.EndpointBucketRow, 0, len(rows))
	for _, row := range rows {
		if row.Key.Protocol == protocol {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func buildWANUDPClientGapRows(endpointRows []store.EndpointBucketRow, wanEndpointRows []store.WANEndpointBucketRow, limit int) []wanUDPClientGapRow {
	if limit <= 0 {
		return []wanUDPClientGapRow{}
	}
	clientRows := aggregateRemoteEndpointRows(filterEndpointRowsByProtocol(endpointRows, "udp"))
	wanRows := aggregateWANRemoteEndpointRows(filterWANEndpointRowsByProtocol(wanEndpointRows, "udp"))
	if len(wanRows) == 0 {
		return []wanUDPClientGapRow{}
	}

	clientByKey := make(map[string]remoteEndpointRow, len(clientRows))
	for _, row := range clientRows {
		key := row.RemoteIP + "\x00" + strconv.Itoa(int(row.RemotePort)) + "\x00" + row.Protocol
		clientByKey[key] = row
	}

	result := make([]wanUDPClientGapRow, 0, len(wanRows))
	for _, wan := range wanRows {
		key := wan.RemoteIP + "\x00" + strconv.Itoa(int(wan.RemotePort)) + "\x00" + wan.Protocol
		client := clientByKey[key]
		result = append(result, wanUDPClientGapRow{
			RemoteIP:                  wan.RemoteIP,
			RemotePort:                wan.RemotePort,
			Protocol:                  wan.Protocol,
			WANUploadBytes:            wan.UploadBytes,
			WANDownloadBytes:          wan.DownloadBytes,
			ClientUploadBytes:         client.UploadBytes,
			ClientDownloadBytes:       client.DownloadBytes,
			UnattributedUploadBytes:   positiveDelta(wan.UploadBytes, client.UploadBytes),
			UnattributedDownloadBytes: positiveDelta(wan.DownloadBytes, client.DownloadBytes),
			ClientCount:               client.ClientCount,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		leftGap := result[i].UnattributedUploadBytes + result[i].UnattributedDownloadBytes
		rightGap := result[j].UnattributedUploadBytes + result[j].UnattributedDownloadBytes
		if leftGap != rightGap {
			return leftGap > rightGap
		}
		leftWAN := result[i].WANUploadBytes + result[i].WANDownloadBytes
		rightWAN := result[j].WANUploadBytes + result[j].WANDownloadBytes
		if leftWAN != rightWAN {
			return leftWAN > rightWAN
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

func positiveDelta(left, right int64) int64 {
	if left <= right {
		return 0
	}
	return left - right
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

func buildObjectsResponse(from, to time.Time, sessions []traffic.FlowSession, dnsRows []traffic.DNSObservation, tlsRows []traffic.TLSObservation) objectsResponse {
	response := objectsResponse{
		Range: responseRange{
			From: from.UTC().Format(time.RFC3339),
			To:   to.UTC().Format(time.RFC3339),
		},
		Objects: []analysisObjectRow{},
	}

	type accumulator struct {
		row     analysisObjectRow
		clients map[string]struct{}
	}

	index := newEvidenceIndex(dnsRows, tlsRows)
	byObject := make(map[string]*accumulator)
	for _, session := range sessions {
		label, source, confidence := attributeSessionWithIndex(session, index)
		key := label + "\x00" + source + "\x00" + session.Protocol
		acc := byObject[key]
		if acc == nil {
			acc = &accumulator{
				row: analysisObjectRow{
					Label:       label,
					LabelSource: source,
					Confidence:  confidence,
					Protocol:    session.Protocol,
					RemoteIP:    session.RemoteIP.String(),
					RemotePort:  session.RemotePort,
				},
				clients: make(map[string]struct{}),
			}
			byObject[key] = acc
		}
		acc.row.UploadBytes += session.UploadBytes
		acc.row.DownloadBytes += session.DownloadBytes
		acc.row.SessionCount++
		if confidence > acc.row.Confidence {
			acc.row.Confidence = confidence
		}
		clientKey := session.ClientIP.String() + "\x00" + session.ClientMAC
		acc.clients[clientKey] = struct{}{}
	}

	for _, acc := range byObject {
		acc.row.ClientCount = len(acc.clients)
		response.Objects = append(response.Objects, acc.row)
	}
	sort.Slice(response.Objects, func(i, j int) bool {
		leftTotal := response.Objects[i].UploadBytes + response.Objects[i].DownloadBytes
		rightTotal := response.Objects[j].UploadBytes + response.Objects[j].DownloadBytes
		if leftTotal != rightTotal {
			return leftTotal > rightTotal
		}
		return response.Objects[i].Label < response.Objects[j].Label
	})
	if len(response.Objects) > maxAnalysisObjectRows {
		response.Objects = response.Objects[:maxAnalysisObjectRows]
	}
	return response
}

func buildReconcileResponse(from, to time.Time, wanSessions []traffic.FlowSession, lanSessions []traffic.FlowSession) reconcileResponse {
	return reconcileResponse{
		Range: responseRange{
			From: from.UTC().Format(time.RFC3339),
			To:   to.UTC().Format(time.RFC3339),
		},
		Rows: limitReconcileRows(buildReconcileRowsFromSets(wanSessions, lanSessions), maxAnalysisReconcileRows),
	}
}

func buildReconcileRows(sessions []traffic.FlowSession) []reconcileRow {
	var wanSessions []traffic.FlowSession
	var lanSessions []traffic.FlowSession
	for _, session := range sessions {
		switch session.Viewpoint {
		case traffic.ViewpointWAN:
			wanSessions = append(wanSessions, session)
		case traffic.ViewpointLAN:
			lanSessions = append(lanSessions, session)
		}
	}
	return buildReconcileRowsFromSets(wanSessions, lanSessions)
}

func buildReconcileRowsFromSets(wanSessions []traffic.FlowSession, lanSessions []traffic.FlowSession) []reconcileRow {
	sort.Slice(wanSessions, func(i, j int) bool {
		if !wanSessions[i].FirstSeen.Equal(wanSessions[j].FirstSeen) {
			return wanSessions[i].FirstSeen.Before(wanSessions[j].FirstSeen)
		}
		return wanSessions[i].ID < wanSessions[j].ID
	})

	lanIndex := buildLANSessionIndex(lanSessions)
	usedLAN := make(map[int64]struct{})
	rows := make([]reconcileRow, 0, len(wanSessions))
	for _, wan := range wanSessions {
		best, ok := findBestLANMatch(wan, lanIndex[reconcileMatchKey(wan)], usedLAN)
		row := reconcileRow{
			WANSessionID: wan.ID,
			RemoteIP:     wan.RemoteIP.String(),
			RemotePort:   wan.RemotePort,
			Protocol:     wan.Protocol,
		}
		if !ok {
			row.Status = "unmatched"
			row.Reason = "no_lan_candidate"
			row.Confidence = 0.2
			row.UnattributedUploadBytes = wan.UploadBytes
			row.UnattributedDownloadBytes = wan.DownloadBytes
			rows = append(rows, row)
			continue
		}

		usedLAN[best.ID] = struct{}{}
		row.LANSessionID = best.ID
		row.UnattributedUploadBytes = positiveDelta(wan.UploadBytes, best.UploadBytes)
		row.UnattributedDownloadBytes = positiveDelta(wan.DownloadBytes, best.DownloadBytes)
		row.Confidence = matchConfidence(wan, best)

		totalGap := row.UnattributedUploadBytes + row.UnattributedDownloadBytes
		wanTotal := wan.UploadBytes + wan.DownloadBytes
		threshold := wanTotal / 5
		if threshold < 1024 {
			threshold = 1024
		}
		if totalGap <= threshold {
			row.Status = "matched"
			row.Reason = "remote_time_overlap"
		} else {
			row.Status = "partial"
			row.Reason = "byte_gap"
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		leftGap := rows[i].UnattributedUploadBytes + rows[i].UnattributedDownloadBytes
		rightGap := rows[j].UnattributedUploadBytes + rows[j].UnattributedDownloadBytes
		if leftGap != rightGap {
			return leftGap > rightGap
		}
		if rows[i].Confidence != rows[j].Confidence {
			return rows[i].Confidence < rows[j].Confidence
		}
		return rows[i].WANSessionID > rows[j].WANSessionID
	})
	return rows
}

func limitReconcileRows(rows []reconcileRow, limit int) []reconcileRow {
	if limit <= 0 || len(rows) <= limit {
		return rows
	}
	return rows[:limit]
}

func buildSessionResponse(session traffic.FlowSession, label, source string, confidence float64, dnsRows []traffic.DNSObservation, tlsRows []traffic.TLSObservation, reconcileRows []reconcileRow) sessionResponse {
	response := sessionResponse{
		Session: sessionDetailResponse{
			ID:            session.ID,
			Viewpoint:     string(session.Viewpoint),
			Protocol:      session.Protocol,
			LocalIP:       session.LocalIP.String(),
			LocalPort:     session.LocalPort,
			RemoteIP:      session.RemoteIP.String(),
			RemotePort:    session.RemotePort,
			ClientIP:      session.ClientIP.String(),
			ClientMAC:     session.ClientMAC,
			FirstSeen:     session.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:      session.LastSeen.UTC().Format(time.RFC3339),
			UploadBytes:   session.UploadBytes,
			DownloadBytes: session.DownloadBytes,
			Packets:       session.Packets,
			Label:         label,
			LabelSource:   source,
			Confidence:    confidence,
		},
		DNS: filterDNSObservationsForSession(session, dnsRows),
		TLS: filterTLSObservationsForSession(session, tlsRows),
	}
	for _, row := range reconcileRows {
		if row.WANSessionID == session.ID || row.LANSessionID == session.ID {
			matched := row
			response.Reconcile = &matched
			break
		}
	}
	return response
}

func attributeSession(session traffic.FlowSession, dnsRows []traffic.DNSObservation, tlsRows []traffic.TLSObservation) (string, string, float64) {
	return attributeSessionWithIndex(session, newEvidenceIndex(dnsRows, tlsRows))
}

type evidenceIndex struct {
	dnsByClientRemote map[string][]traffic.DNSObservation
	tlsByClientRemote map[string][]traffic.TLSObservation
}

func newEvidenceIndex(dnsRows []traffic.DNSObservation, tlsRows []traffic.TLSObservation) evidenceIndex {
	index := evidenceIndex{
		dnsByClientRemote: make(map[string][]traffic.DNSObservation),
		tlsByClientRemote: make(map[string][]traffic.TLSObservation),
	}
	for _, row := range dnsRows {
		key := evidenceDNSKey(row.ClientIP, row.AnswerIP)
		index.dnsByClientRemote[key] = append(index.dnsByClientRemote[key], row)
	}
	for _, row := range tlsRows {
		key := evidenceTLSKey(row.ClientIP, row.RemoteIP, row.RemotePort, row.Protocol)
		index.tlsByClientRemote[key] = append(index.tlsByClientRemote[key], row)
	}
	return index
}

func attributeSessionWithIndex(session traffic.FlowSession, index evidenceIndex) (string, string, float64) {
	if observation, ok := findBestTLSObservationWithIndex(session, index); ok {
		return observation.ServerName, "tls_sni", 0.95
	}
	if observation, ok := findBestDNSObservationWithIndex(session, index); ok {
		return observation.Name, "dns_answer", 0.75
	}
	return remoteLabel(session.RemoteIP, session.RemotePort), "remote_endpoint", 0.3
}

func evidenceDNSKey(clientIP, remoteIP netip.Addr) string {
	return clientIP.String() + "\x00" + remoteIP.String()
}

func evidenceTLSKey(clientIP, remoteIP netip.Addr, remotePort uint16, protocol string) string {
	return clientIP.String() + "\x00" + remoteIP.String() + "\x00" + strconv.Itoa(int(remotePort)) + "\x00" + protocol
}

func findBestTLSObservation(session traffic.FlowSession, observations []traffic.TLSObservation) (traffic.TLSObservation, bool) {
	return findBestTLSObservationWithIndex(session, newEvidenceIndex(nil, observations))
}

func findBestTLSObservationWithIndex(session traffic.FlowSession, index evidenceIndex) (traffic.TLSObservation, bool) {
	var best traffic.TLSObservation
	bestFound := false
	for _, observation := range index.tlsByClientRemote[evidenceTLSKey(session.ClientIP, session.RemoteIP, session.RemotePort, session.Protocol)] {
		if observation.ObservedAt.Before(session.FirstSeen.Add(-2*time.Minute)) || observation.ObservedAt.After(session.LastSeen.Add(2*time.Minute)) {
			continue
		}
		if !bestFound || observation.ObservedAt.After(best.ObservedAt) {
			best = observation
			bestFound = true
		}
	}
	return best, bestFound
}

func findBestDNSObservation(session traffic.FlowSession, observations []traffic.DNSObservation) (traffic.DNSObservation, bool) {
	return findBestDNSObservationWithIndex(session, newEvidenceIndex(observations, nil))
}

func findBestDNSObservationWithIndex(session traffic.FlowSession, index evidenceIndex) (traffic.DNSObservation, bool) {
	var best traffic.DNSObservation
	bestFound := false
	for _, observation := range index.dnsByClientRemote[evidenceDNSKey(session.ClientIP, session.RemoteIP)] {
		if observation.ObservedAt.Before(session.FirstSeen.Add(-10*time.Minute)) || observation.ObservedAt.After(session.LastSeen.Add(1*time.Minute)) {
			continue
		}
		if !bestFound || observation.ObservedAt.After(best.ObservedAt) {
			best = observation
			bestFound = true
		}
	}
	return best, bestFound
}

func filterDNSObservationsForSession(session traffic.FlowSession, observations []traffic.DNSObservation) []traffic.DNSObservation {
	filtered := make([]traffic.DNSObservation, 0)
	for _, observation := range observations {
		if observation.AnswerIP != session.RemoteIP {
			continue
		}
		if session.ClientIP.IsValid() && observation.ClientIP.IsValid() && observation.ClientIP != session.ClientIP {
			continue
		}
		filtered = append(filtered, observation)
	}
	return filtered
}

func filterTLSObservationsForSession(session traffic.FlowSession, observations []traffic.TLSObservation) []traffic.TLSObservation {
	filtered := make([]traffic.TLSObservation, 0)
	for _, observation := range observations {
		if observation.RemoteIP != session.RemoteIP || observation.RemotePort != session.RemotePort {
			continue
		}
		if session.ClientIP.IsValid() && observation.ClientIP.IsValid() && observation.ClientIP != session.ClientIP {
			continue
		}
		filtered = append(filtered, observation)
	}
	return filtered
}

func reconcileMatchKey(session traffic.FlowSession) string {
	return session.Protocol + "\x00" + session.RemoteIP.String() + "\x00" + strconv.Itoa(int(session.RemotePort))
}

func buildLANSessionIndex(lanSessions []traffic.FlowSession) map[string][]traffic.FlowSession {
	index := make(map[string][]traffic.FlowSession)
	for _, session := range lanSessions {
		index[reconcileMatchKey(session)] = append(index[reconcileMatchKey(session)], session)
	}
	return index
}

func findBestLANMatch(wan traffic.FlowSession, lanSessions []traffic.FlowSession, usedLAN map[int64]struct{}) (traffic.FlowSession, bool) {
	bestFound := false
	var best traffic.FlowSession
	var bestGap time.Duration
	var bestDelta int64
	for _, candidate := range lanSessions {
		if _, alreadyUsed := usedLAN[candidate.ID]; alreadyUsed {
			continue
		}
		if candidate.Protocol != wan.Protocol || candidate.RemoteIP != wan.RemoteIP || candidate.RemotePort != wan.RemotePort {
			continue
		}
		gap := sessionGap(wan, candidate)
		if gap > 15*time.Second {
			continue
		}
		delta := abs64((wan.UploadBytes + wan.DownloadBytes) - (candidate.UploadBytes + candidate.DownloadBytes))
		if !bestFound || gap < bestGap || (gap == bestGap && delta < bestDelta) {
			best = candidate
			bestGap = gap
			bestDelta = delta
			bestFound = true
		}
	}
	return best, bestFound
}

func sessionGap(left, right traffic.FlowSession) time.Duration {
	if left.LastSeen.Before(right.FirstSeen) {
		return right.FirstSeen.Sub(left.LastSeen)
	}
	if right.LastSeen.Before(left.FirstSeen) {
		return left.FirstSeen.Sub(right.LastSeen)
	}
	return 0
}

func matchConfidence(wan, lan traffic.FlowSession) float64 {
	gap := sessionGap(wan, lan)
	if gap == 0 {
		return 0.9
	}
	if gap <= 5*time.Second {
		return 0.75
	}
	return 0.6
}

func remoteLabel(ip netip.Addr, port uint16) string {
	if !ip.IsValid() {
		return "-"
	}
	if port == 0 {
		return ip.String()
	}
	return ip.String() + ":" + strconv.Itoa(int(port))
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
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
