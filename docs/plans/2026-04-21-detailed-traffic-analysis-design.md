# Detailed Traffic Analysis Design

## Goal

Extend TrafficAnalysis from bucket-level traffic summaries into object attribution and WAN/LAN reconciliation without changing the existing capture and bucket query workflow.

## Phase 1 Scope

- Parse and persist DNS answer observations.
- Parse and persist TLS ClientHello SNI/ALPN observations.
- Build lightweight LAN/WAN flow sessions with byte counters and TCP flag summaries.
- Expose new HTTP APIs for:
  - attributed access objects
  - WAN/LAN reconciliation
  - per-session evidence lookup
- Extend `analysis.html` with minimal views for object attribution and reconciliation.

## Data Model

- `dns_observations`
  - time, client identity, qname, rrtype, answer IP, ttl, source
- `tls_observations`
  - time, viewpoint, client identity, remote endpoint, SNI, ALPN, protocol, source
- `flow_sessions`
  - viewpoint, protocol, local endpoint, remote endpoint, client identity, first/last seen, upload/download bytes, packets, TCP flag summaries, evidence flags

## Runtime Flow

1. `capture.ExtractPacket` extracts DNS and TLS observations in addition to existing name observations.
2. LAN packet handling writes DNS/TLS observations and updates LAN flow sessions.
3. WAN packet handling writes TLS observations and updates WAN flow sessions.
4. Periodic flush persists complete traffic buckets plus expired flow sessions to SQLite.
5. `/api/analysis/objects` attributes LAN sessions with TLS SNI first, then DNS answers.
6. `/api/analysis/reconcile` matches WAN sessions to LAN sessions by remote endpoint, protocol, and time overlap.

## Boundaries

- QUIC SNI extraction is not in this phase.
- No full DPI, HTTP content parsing, or long-term packet retention.
- Reconciliation is heuristic, not a strict NAT/session reassembly engine.

## Verification

- Unit tests for packet parsing, SQLite persistence, HTTP APIs, and flow tracking.
- `go test ./...`
- `node --check internal/httpapi/static/analysis.js`
- `git diff --check`
