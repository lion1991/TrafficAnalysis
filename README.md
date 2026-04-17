# TrafficAnalysis

Linux WAN mirror traffic analyzer written in Go.

It is designed for this topology:

```text
router WAN port -- mirrored traffic --> Linux capture interface
```

Because packets are mirrored from the router WAN side, NAT has already happened. The analyzer cannot see LAN client IPs in this mode. Upload and download are classified using the router's current WAN IP:

- `src == current WAN IP`: upload
- `dst == current WAN IP`: download
- no current WAN IP: unknown
- neither side is current WAN IP: other

The WAN IP can be refreshed automatically from an HTTP endpoint, with an optional static fallback.

## Build

```bash
go build -o trafficanalysis ./cmd/trafficanalysis
```

Linux live capture requires `libpcap` and capture permission. Common options:

```bash
sudo ./trafficanalysis capture -config config.json
```

or grant packet capture capability to the binary:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./trafficanalysis
```

## Configure

Generate a starter config:

```bash
./trafficanalysis init-config -out config.json
```

Example:

```json
{
  "interface": "eth1",
  "database": "traffic.db",
  "bpf": "",
  "snapshot_len": 262144,
  "promiscuous": true,
  "bucket_seconds": 60,
  "flush_seconds": 10,
  "live_seconds": 5,
  "local_networks": [
    "192.168.248.0/21"
  ],
  "ignore_lan_traffic": true,
  "wan_ip": {
    "http_url": "https://api.ipify.org",
    "static": "",
    "refresh_seconds": 300
  }
}
```

`wan_ip.http_url` should return a plain IP address. This works when the analyzer's management network exits through the same router WAN IP that is being mirrored. If the analyzer uses a different Internet exit path, set `wan_ip.static` or replace the HTTP URL with an internal endpoint that returns the router WAN IP.

WAN IP refresh is adaptive. After a successful refresh, the analyzer keeps the IP valid while packets continue to contain that IP, so it does not call the HTTP endpoint on every interval during active traffic. If traffic no longer matches the cached WAN IP and public `other` traffic appears, the analyzer requests an immediate refresh with a short debounce. The configured `refresh_seconds` remains the fallback check interval for idle or stale periods.

## Capture

Start live capture:

```bash
sudo ./trafficanalysis capture -config config.json
```

During capture, the process prints a live line every `live_seconds` by default:

```text
2026-04-17T12:00:00Z wan=203.0.113.10 upload=10.00 KiB download=20.00 KiB other=0 B unknown=0 B up_rate=2.00 KiB/s down_rate=4.00 KiB/s packets=7
```

Use command flags to control display mode:

```bash
sudo ./trafficanalysis capture -config config.json -quiet
sudo ./trafficanalysis capture -config config.json -live=false
sudo ./trafficanalysis capture -config config.json -live-interval 2s
```

Set `"live_seconds": 0` to make config-based live output silent by default.

The default `bpf` is empty so PPPoE or VLAN-encapsulated WAN traffic is not filtered out before decoding. If you need a filter, set it explicitly after confirming the capture format with tcpdump.

Set `local_networks` to your LAN CIDRs. Packets matching those CIDRs are shown as `lan` in live output. With `ignore_lan_traffic: true`, they are not written into the WAN traffic database.

Import a pcap file for offline testing:

```bash
./trafficanalysis read-pcap -config config.json -pcap sample.pcap
```

## Query

Last hour:

```bash
./trafficanalysis query -db traffic.db -last 1h
```

Last seven days:

```bash
./trafficanalysis query -db traffic.db -last 7d
```

One local day:

```bash
./trafficanalysis query -db traffic.db -date 2026-04-17
```

One local month:

```bash
./trafficanalysis query -db traffic.db -month 2026-04
```

Explicit local range:

```bash
./trafficanalysis query -db traffic.db \
  -from "2026-04-17 00:00" \
  -to "2026-04-18 00:00"
```

Explicit RFC3339 range also works:

```bash
./trafficanalysis query -db traffic.db \
  -from 2026-04-17T00:00:00Z \
  -to 2026-04-17T01:00:00Z
```

Data is stored as time buckets in SQLite. The first version stores totals by bucket, direction, and protocol.

## Web UI and HTTP API

Start the built-in Web UI:

```bash
./trafficanalysis serve -config config.json -addr :8080
```

Then open:

```text
http://127.0.0.1:8080
```

The Web UI is embedded into the Go binary, so it does not require a separate Node.js frontend server. It reads the same SQLite database used by capture and query commands. You can override the database path:

```bash
./trafficanalysis serve -config config.json -db traffic.db -addr :8080
```

HTTP API:

```text
GET /api/traffic?last=1h
GET /api/traffic?last=7d
GET /api/traffic?date=2026-04-17
GET /api/traffic?month=2026-04
GET /api/traffic?from=2026-04-17%2000:00&to=2026-04-18%2000:00
```

Response contains:

- `range`: UTC query range
- `totals`: upload/download/lan/other/unknown bytes and packet total
- `series`: bucketed upload/download/lan/other/unknown values for charting
- `breakdown`: totals by direction and protocol

The Web UI can auto-refresh by polling the API. This is suitable for watching recently flushed SQLite bucket data. It is not a true live stream from the capture process memory; for sub-second live display, add a capture-side SSE or WebSocket endpoint.
