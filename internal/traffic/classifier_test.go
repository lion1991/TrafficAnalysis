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

func TestLANClientClassifierClassifiesPublicTrafficByClient(t *testing.T) {
	local := netip.MustParsePrefix("192.168.248.0/21")
	classifier := NewLANClientClassifier([]netip.Prefix{local})

	upload, ok := classifier.Classify(Packet{
		Timestamp: time.Unix(100, 0),
		SrcIP:     netip.MustParseAddr("192.168.248.22"),
		DstIP:     netip.MustParseAddr("8.8.8.8"),
		SrcMAC:    "00:11:22:33:44:55",
		DstMAC:    "aa:bb:cc:dd:ee:ff",
		Protocol:  "tcp",
		Bytes:     1200,
	})
	if !ok {
		t.Fatal("expected upload packet to classify")
	}
	if upload.ClientIP != netip.MustParseAddr("192.168.248.22") || upload.ClientMAC != "00:11:22:33:44:55" || upload.Direction != DirectionUpload {
		t.Fatalf("unexpected upload classification: %#v", upload)
	}

	download, ok := classifier.Classify(Packet{
		Timestamp: time.Unix(101, 0),
		SrcIP:     netip.MustParseAddr("1.1.1.1"),
		DstIP:     netip.MustParseAddr("192.168.248.22"),
		SrcMAC:    "aa:bb:cc:dd:ee:ff",
		DstMAC:    "00:11:22:33:44:55",
		Protocol:  "udp",
		Bytes:     900,
	})
	if !ok {
		t.Fatal("expected download packet to classify")
	}
	if download.ClientIP != netip.MustParseAddr("192.168.248.22") || download.ClientMAC != "00:11:22:33:44:55" || download.Direction != DirectionDownload {
		t.Fatalf("unexpected download classification: %#v", download)
	}
}

func TestLANClientClassifierIgnoresPrivateBroadcastAndMulticastTraffic(t *testing.T) {
	local := netip.MustParsePrefix("192.168.248.0/21")
	classifier := NewLANClientClassifier([]netip.Prefix{local})

	cases := []Packet{
		{
			SrcIP: netip.MustParseAddr("192.168.248.22"),
			DstIP: netip.MustParseAddr("192.168.248.23"),
			Bytes: 100,
		},
		{
			SrcIP: netip.MustParseAddr("192.168.248.22"),
			DstIP: netip.MustParseAddr("239.255.255.250"),
			Bytes: 100,
		},
		{
			SrcIP: netip.MustParseAddr("192.168.248.22"),
			DstIP: netip.MustParseAddr("192.168.255.255"),
			Bytes: 100,
		},
	}

	for _, packet := range cases {
		if classified, ok := classifier.Classify(packet); ok {
			t.Fatalf("expected packet to be ignored, got %#v", classified)
		}
	}
}

func TestClientAggregatorBucketsTrafficByClientDirectionAndProtocol(t *testing.T) {
	aggregator := NewClientAggregator(time.Minute)
	base := time.Date(2026, 4, 17, 10, 7, 30, 0, time.UTC)
	clientIP := netip.MustParseAddr("192.168.248.22")

	aggregator.Add(Packet{Timestamp: base, Protocol: "tcp", Bytes: 1000}, ClientTraffic{
		ClientIP:  clientIP,
		ClientMAC: "00:11:22:33:44:55",
		Direction: DirectionUpload,
	})
	aggregator.Add(Packet{Timestamp: base.Add(10 * time.Second), Protocol: "tcp", Bytes: 2500}, ClientTraffic{
		ClientIP:  clientIP,
		ClientMAC: "00:11:22:33:44:55",
		Direction: DirectionUpload,
	})
	aggregator.Add(Packet{Timestamp: base, Protocol: "udp", Bytes: 900}, ClientTraffic{
		ClientIP:  clientIP,
		ClientMAC: "00:11:22:33:44:55",
		Direction: DirectionDownload,
	})

	buckets := aggregator.Snapshot()
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d: %#v", len(buckets), buckets)
	}

	uploadKey := ClientBucketKey{
		Start:     time.Date(2026, 4, 17, 10, 7, 0, 0, time.UTC),
		ClientIP:  clientIP,
		ClientMAC: "00:11:22:33:44:55",
		Direction: DirectionUpload,
		Protocol:  "tcp",
	}
	if buckets[uploadKey].Bytes != 3500 || buckets[uploadKey].Packets != 2 {
		t.Fatalf("unexpected upload bucket: %#v", buckets[uploadKey])
	}

	downloadKey := ClientBucketKey{
		Start:     time.Date(2026, 4, 17, 10, 7, 0, 0, time.UTC),
		ClientIP:  clientIP,
		ClientMAC: "00:11:22:33:44:55",
		Direction: DirectionDownload,
		Protocol:  "udp",
	}
	if buckets[downloadKey].Bytes != 900 || buckets[downloadKey].Packets != 1 {
		t.Fatalf("unexpected download bucket: %#v", buckets[downloadKey])
	}
}
