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
  "bpf": "ip or ip6",
  "snapshot_len": 262144,
  "promiscuous": true,
  "bucket_seconds": 60,
  "flush_seconds": 10,
  "wan_ip": {
    "http_url": "https://api.ipify.org",
    "static": "",
    "refresh_seconds": 300
  }
}
```

`wan_ip.http_url` should return a plain IP address. This works when the analyzer's management network exits through the same router WAN IP that is being mirrored. If the analyzer uses a different Internet exit path, set `wan_ip.static` or replace the HTTP URL with an internal endpoint that returns the router WAN IP.

## Capture

Start live capture:

```bash
sudo ./trafficanalysis capture -config config.json
```

Import a pcap file for offline testing:

```bash
./trafficanalysis read-pcap -config config.json -pcap sample.pcap
```

## Query

Last hour:

```bash
./trafficanalysis query -db traffic.db -last 1h
```

Explicit range:

```bash
./trafficanalysis query -db traffic.db \
  -from 2026-04-17T00:00:00Z \
  -to 2026-04-17T01:00:00Z
```

Data is stored as time buckets in SQLite. The first version stores totals by bucket, direction, and protocol.

