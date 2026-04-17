package capture

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestExtractPacketParsesIPv4TCPPacket(t *testing.T) {
	tcp := &layers.TCP{
		SrcPort: 443,
		DstPort: 53000,
		SYN:     true,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{203, 0, 113, 10},
		DstIP:    net.IP{198, 51, 100, 8},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
			DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
			EthernetType: layers.EthernetTypeIPv4,
		},
		ip,
		tcp,
	)
	if err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo.Timestamp = time.Unix(100, 0)
	packet.Metadata().CaptureInfo.Length = len(buffer.Bytes())

	parsed, ok := ExtractPacket(packet)
	if !ok {
		t.Fatal("expected packet to parse")
	}
	if parsed.SrcIP != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("unexpected src IP: %s", parsed.SrcIP)
	}
	if parsed.DstIP != netip.MustParseAddr("198.51.100.8") {
		t.Fatalf("unexpected dst IP: %s", parsed.DstIP)
	}
	if parsed.SrcPort != 443 || parsed.DstPort != 53000 {
		t.Fatalf("unexpected ports: %d -> %d", parsed.SrcPort, parsed.DstPort)
	}
	if parsed.Protocol != "tcp" {
		t.Fatalf("unexpected protocol: %s", parsed.Protocol)
	}
	if parsed.Bytes != len(buffer.Bytes()) {
		t.Fatalf("unexpected byte length: %d", parsed.Bytes)
	}
}
