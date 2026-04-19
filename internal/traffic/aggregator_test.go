package traffic

import (
	"net/netip"
	"testing"
	"time"
)

func TestEndpointAggregatorUsesRemoteSideForUploadAndDownload(t *testing.T) {
	aggregator := NewEndpointAggregator(time.Minute)
	clientIP := netip.MustParseAddr("192.168.248.22")
	clientMAC := "00:11:22:33:44:55"
	remoteIP := netip.MustParseAddr("203.0.113.9")
	start := time.Date(2026, 4, 17, 11, 12, 13, 0, time.UTC)

	aggregator.Add(Packet{
		Timestamp: start,
		SrcIP:     clientIP,
		DstIP:     remoteIP,
		SrcPort:   55321,
		DstPort:   443,
		Protocol:  "tcp",
		Bytes:     1500,
	}, ClientTraffic{
		ClientIP:  clientIP,
		ClientMAC: clientMAC,
		Direction: DirectionUpload,
	})
	aggregator.Add(Packet{
		Timestamp: start.Add(10 * time.Second),
		SrcIP:     remoteIP,
		DstIP:     clientIP,
		SrcPort:   443,
		DstPort:   55321,
		Protocol:  "tcp",
		Bytes:     900,
	}, ClientTraffic{
		ClientIP:  clientIP,
		ClientMAC: clientMAC,
		Direction: DirectionDownload,
	})

	buckets := aggregator.DrainAll()
	if len(buckets) != 2 {
		t.Fatalf("expected upload and download endpoint buckets, got %d: %#v", len(buckets), buckets)
	}

	uploadKey := EndpointBucketKey{
		Start:      start.Truncate(time.Minute),
		ClientIP:   clientIP,
		ClientMAC:  clientMAC,
		RemoteIP:   remoteIP,
		RemotePort: 443,
		Direction:  DirectionUpload,
		Protocol:   "tcp",
	}
	if buckets[uploadKey].Bytes != 1500 || buckets[uploadKey].Packets != 1 {
		t.Fatalf("unexpected upload bucket: %#v", buckets[uploadKey])
	}

	downloadKey := EndpointBucketKey{
		Start:      start.Truncate(time.Minute),
		ClientIP:   clientIP,
		ClientMAC:  clientMAC,
		RemoteIP:   remoteIP,
		RemotePort: 443,
		Direction:  DirectionDownload,
		Protocol:   "tcp",
	}
	if buckets[downloadKey].Bytes != 900 || buckets[downloadKey].Packets != 1 {
		t.Fatalf("unexpected download bucket: %#v", buckets[downloadKey])
	}
}

func TestWANEndpointAggregatorTracksRemoteSideWithoutClientAttribution(t *testing.T) {
	aggregator := NewWANEndpointAggregator(time.Minute)
	wanIP := netip.MustParseAddr("42.103.52.33")
	remoteIP := netip.MustParseAddr("203.0.113.9")
	start := time.Date(2026, 4, 17, 11, 12, 13, 0, time.UTC)

	aggregator.Add(Packet{
		Timestamp: start,
		SrcIP:     wanIP,
		DstIP:     remoteIP,
		SrcPort:   55321,
		DstPort:   443,
		Protocol:  "udp",
		Bytes:     1500,
	}, DirectionUpload)
	aggregator.Add(Packet{
		Timestamp: start.Add(10 * time.Second),
		SrcIP:     remoteIP,
		DstIP:     wanIP,
		SrcPort:   443,
		DstPort:   55321,
		Protocol:  "udp",
		Bytes:     900,
	}, DirectionDownload)
	aggregator.Add(Packet{
		Timestamp: start.Add(20 * time.Second),
		SrcIP:     netip.MustParseAddr("198.51.100.20"),
		DstIP:     netip.MustParseAddr("198.51.100.30"),
		Protocol:  "udp",
		Bytes:     700,
	}, DirectionOther)

	buckets := aggregator.DrainAll()
	if len(buckets) != 2 {
		t.Fatalf("expected upload and download WAN endpoint buckets, got %d: %#v", len(buckets), buckets)
	}

	uploadKey := WANEndpointBucketKey{
		Start:      start.Truncate(time.Minute),
		RemoteIP:   remoteIP,
		RemotePort: 443,
		Direction:  DirectionUpload,
		Protocol:   "udp",
	}
	if buckets[uploadKey].Bytes != 1500 || buckets[uploadKey].Packets != 1 {
		t.Fatalf("unexpected upload bucket: %#v", buckets[uploadKey])
	}

	downloadKey := WANEndpointBucketKey{
		Start:      start.Truncate(time.Minute),
		RemoteIP:   remoteIP,
		RemotePort: 443,
		Direction:  DirectionDownload,
		Protocol:   "udp",
	}
	if buckets[downloadKey].Bytes != 900 || buckets[downloadKey].Packets != 1 {
		t.Fatalf("unexpected download bucket: %#v", buckets[downloadKey])
	}
}
