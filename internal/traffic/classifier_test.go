package traffic

import (
	"net/netip"
	"testing"
	"time"
)

func TestWANIPClassifierClassifiesUploadAndDownload(t *testing.T) {
	wan := netip.MustParseAddr("203.0.113.10")
	classifier := NewWANClassifier(func() (netip.Addr, bool) {
		return wan, true
	})

	upload := classifier.Classify(Packet{
		Timestamp: time.Unix(100, 0),
		SrcIP:     wan,
		DstIP:     netip.MustParseAddr("8.8.8.8"),
		Bytes:     1200,
	})
	if upload != DirectionUpload {
		t.Fatalf("expected upload, got %s", upload)
	}

	download := classifier.Classify(Packet{
		Timestamp: time.Unix(101, 0),
		SrcIP:     netip.MustParseAddr("1.1.1.1"),
		DstIP:     wan,
		Bytes:     900,
	})
	if download != DirectionDownload {
		t.Fatalf("expected download, got %s", download)
	}
}

func TestWANIPClassifierReturnsUnknownWhenWANIPUnavailable(t *testing.T) {
	classifier := NewWANClassifier(func() (netip.Addr, bool) {
		return netip.Addr{}, false
	})

	direction := classifier.Classify(Packet{
		Timestamp: time.Unix(100, 0),
		SrcIP:     netip.MustParseAddr("203.0.113.10"),
		DstIP:     netip.MustParseAddr("8.8.8.8"),
		Bytes:     1200,
	})
	if direction != DirectionUnknown {
		t.Fatalf("expected unknown when WAN IP is unavailable, got %s", direction)
	}
}

func TestWANIPClassifierClassifiesConfiguredLocalNetworkTrafficAsLAN(t *testing.T) {
	wan := netip.MustParseAddr("42.103.52.33")
	local := netip.MustParsePrefix("192.168.248.0/21")
	classifier := NewWANClassifierWithLocalNetworks(func() (netip.Addr, bool) {
		return wan, true
	}, []netip.Prefix{local})

	direction := classifier.Classify(Packet{
		Timestamp: time.Unix(100, 0),
		SrcIP:     netip.MustParseAddr("192.168.252.1"),
		DstIP:     netip.MustParseAddr("239.255.255.250"),
		SrcPort:   1900,
		DstPort:   1900,
		Protocol:  "udp",
		Bytes:     1024,
	})
	if direction != DirectionLAN {
		t.Fatalf("expected lan, got %s", direction)
	}

	upload := classifier.Classify(Packet{
		Timestamp: time.Unix(101, 0),
		SrcIP:     wan,
		DstIP:     netip.MustParseAddr("8.8.8.8"),
		Bytes:     1200,
	})
	if upload != DirectionUpload {
		t.Fatalf("expected WAN IP to still classify as upload, got %s", upload)
	}
}

func TestAggregatorBucketsTrafficByTimeDirectionAndProtocol(t *testing.T) {
	aggregator := NewAggregator(time.Minute)
	base := time.Date(2026, 4, 17, 10, 7, 30, 0, time.UTC)

	aggregator.Add(Packet{Timestamp: base, Protocol: "tcp", Bytes: 1000}, DirectionUpload)
	aggregator.Add(Packet{Timestamp: base.Add(10 * time.Second), Protocol: "tcp", Bytes: 2500}, DirectionUpload)
	aggregator.Add(Packet{Timestamp: base.Add(80 * time.Second), Protocol: "udp", Bytes: 700}, DirectionDownload)

	buckets := aggregator.Snapshot()
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d: %#v", len(buckets), buckets)
	}

	first := BucketKey{
		Start:     time.Date(2026, 4, 17, 10, 7, 0, 0, time.UTC),
		Direction: DirectionUpload,
		Protocol:  "tcp",
	}
	if buckets[first].Bytes != 3500 || buckets[first].Packets != 2 {
		t.Fatalf("unexpected first bucket: %#v", buckets[first])
	}

	second := BucketKey{
		Start:     time.Date(2026, 4, 17, 10, 8, 0, 0, time.UTC),
		Direction: DirectionDownload,
		Protocol:  "udp",
	}
	if buckets[second].Bytes != 700 || buckets[second].Packets != 1 {
		t.Fatalf("unexpected second bucket: %#v", buckets[second])
	}
}
