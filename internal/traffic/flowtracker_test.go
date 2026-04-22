package traffic

import (
	"net/netip"
	"testing"
	"time"
)

func TestFlowTrackerBuildsLANSessionWithDNSAndTLSHints(t *testing.T) {
	tracker := NewFlowTracker(30 * time.Second)
	base := time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)
	client := ClientTraffic{
		ClientIP:  netip.MustParseAddr("192.168.248.22"),
		ClientMAC: "00:11:22:33:44:55",
		Direction: DirectionUpload,
	}

	tracker.AddLANPacket(Packet{
		Timestamp: base,
		SrcIP:     netip.MustParseAddr("192.168.248.1"),
		DstIP:     client.ClientIP,
		SrcMAC:    "aa:bb:cc:dd:ee:ff",
		DstMAC:    client.ClientMAC,
		SrcPort:   53,
		DstPort:   53000,
		Protocol:  "udp",
		Bytes:     180,
		DNSObservations: []DNSObservation{
			{
				ObservedAt: base,
				ClientIP:   client.ClientIP,
				ClientMAC:  client.ClientMAC,
				Name:       "api.example.com",
				RecordType: "A",
				AnswerIP:   netip.MustParseAddr("203.0.113.9"),
				TTL:        300,
				Source:     "dns",
			},
		},
	}, ClientTraffic{
		ClientIP:  client.ClientIP,
		ClientMAC: client.ClientMAC,
		Direction: DirectionDownload,
	})

	tracker.AddLANPacket(Packet{
		Timestamp: base.Add(2 * time.Second),
		SrcIP:     client.ClientIP,
		DstIP:     netip.MustParseAddr("203.0.113.9"),
		SrcMAC:    client.ClientMAC,
		DstMAC:    "aa:bb:cc:dd:ee:ff",
		SrcPort:   53000,
		DstPort:   443,
		Protocol:  "tcp",
		Bytes:     512,
		TCPSYN:    true,
		TLSObservations: []TLSObservation{
			{
				ObservedAt: base.Add(2 * time.Second),
				ClientIP:   client.ClientIP,
				ClientMAC:  client.ClientMAC,
				RemoteIP:   netip.MustParseAddr("203.0.113.9"),
				RemotePort: 443,
				ServerName: "api.example.com",
				ALPN:       "h2",
				Protocol:   "tcp",
				Source:     "tls_client_hello",
			},
		},
	}, client)

	tracker.AddLANPacket(Packet{
		Timestamp: base.Add(4 * time.Second),
		SrcIP:     netip.MustParseAddr("203.0.113.9"),
		DstIP:     client.ClientIP,
		SrcMAC:    "aa:bb:cc:dd:ee:ff",
		DstMAC:    client.ClientMAC,
		SrcPort:   443,
		DstPort:   53000,
		Protocol:  "tcp",
		Bytes:     1024,
	}, ClientTraffic{
		ClientIP:  client.ClientIP,
		ClientMAC: client.ClientMAC,
		Direction: DirectionDownload,
	})

	sessions := tracker.DrainExpired(base.Add(40 * time.Second))
	if len(sessions) != 2 {
		t.Fatalf("expected dns session and tcp session, got %#v", sessions)
	}

	var tcpSession FlowSession
	for _, session := range sessions {
		if session.Protocol == "tcp" {
			tcpSession = session
			break
		}
	}
	if tcpSession.Viewpoint != ViewpointLAN || tcpSession.RemoteIP != netip.MustParseAddr("203.0.113.9") || tcpSession.RemotePort != 443 {
		t.Fatalf("unexpected LAN session identity: %#v", tcpSession)
	}
	if tcpSession.UploadBytes != 512 || tcpSession.DownloadBytes != 1024 || !tcpSession.SYNSeen {
		t.Fatalf("unexpected LAN session counters: %#v", tcpSession)
	}
	if !tcpSession.HasDNSEvidence || !tcpSession.HasTLSEvidence {
		t.Fatalf("expected DNS and TLS evidence flags, got %#v", tcpSession)
	}
}

func TestFlowTrackerBuildsWANSession(t *testing.T) {
	tracker := NewFlowTracker(30 * time.Second)
	base := time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC)

	tracker.AddWANPacket(Packet{
		Timestamp: base,
		SrcIP:     netip.MustParseAddr("198.51.100.10"),
		DstIP:     netip.MustParseAddr("203.0.113.9"),
		SrcPort:   52000,
		DstPort:   443,
		Protocol:  "tcp",
		Bytes:     2048,
		TCPSYN:    true,
	}, DirectionUpload)
	tracker.AddWANPacket(Packet{
		Timestamp: base.Add(2 * time.Second),
		SrcIP:     netip.MustParseAddr("203.0.113.9"),
		DstIP:     netip.MustParseAddr("198.51.100.10"),
		SrcPort:   443,
		DstPort:   52000,
		Protocol:  "tcp",
		Bytes:     1024,
	}, DirectionDownload)

	sessions := tracker.DrainExpired(base.Add(40 * time.Second))
	if len(sessions) != 1 {
		t.Fatalf("expected one WAN session, got %#v", sessions)
	}
	if sessions[0].Viewpoint != ViewpointWAN || sessions[0].LocalIP != netip.MustParseAddr("198.51.100.10") || sessions[0].RemoteIP != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("unexpected WAN session identity: %#v", sessions[0])
	}
	if sessions[0].UploadBytes != 2048 || sessions[0].DownloadBytes != 1024 || !sessions[0].SYNSeen {
		t.Fatalf("unexpected WAN session payload: %#v", sessions[0])
	}
}
