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
