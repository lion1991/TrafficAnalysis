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
	if parsed.SrcMAC != "00:01:02:03:04:05" {
		t.Fatalf("unexpected src MAC: %s", parsed.SrcMAC)
	}
	if parsed.DstMAC != "06:07:08:09:0a:0b" {
		t.Fatalf("unexpected dst MAC: %s", parsed.DstMAC)
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

func TestExtractPacketLearnsDHCPHostname(t *testing.T) {
	srcMAC := net.HardwareAddr{0, 17, 34, 51, 68, 85}
	udp := &layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 248, 22},
		DstIP:    net.IP{255, 255, 255, 255},
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum layer: %v", err)
	}

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0x12345678,
		ClientIP:     net.IP{192, 168, 248, 22},
		ClientHWAddr: srcMAC,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}),
			layers.NewDHCPOption(layers.DHCPOptHostname, []byte("nas-box")),
		},
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       net.HardwareAddr{255, 255, 255, 255, 255, 255},
			EthernetType: layers.EthernetTypeIPv4,
		},
		ip,
		udp,
		dhcp,
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
	if len(parsed.NameObservations) != 1 {
		t.Fatalf("expected one name observation, got %#v", parsed.NameObservations)
	}
	observation := parsed.NameObservations[0]
	if observation.Name != "nas-box" || observation.Source != "dhcp" {
		t.Fatalf("unexpected observation name/source: %#v", observation)
	}
	if observation.IP != netip.MustParseAddr("192.168.248.22") || observation.MAC != "00:11:22:33:44:55" {
		t.Fatalf("unexpected observation identity: %#v", observation)
	}
}

func TestExtractPacketLearnsMDNSARecordName(t *testing.T) {
	srcMAC := net.HardwareAddr{0, 17, 34, 51, 68, 85}
	udp := &layers.UDP{
		SrcPort: 5353,
		DstPort: 5353,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 248, 22},
		DstIP:    net.IP{224, 0, 0, 251},
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum layer: %v", err)
	}

	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("nas-box.local"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   120,
				IP:    net.IP{192, 168, 248, 22},
			},
		},
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       net.HardwareAddr{1, 0, 94, 0, 0, 251},
			EthernetType: layers.EthernetTypeIPv4,
		},
		ip,
		udp,
		dns,
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
	if len(parsed.NameObservations) != 1 {
		t.Fatalf("expected one name observation, got %#v", parsed.NameObservations)
	}
	observation := parsed.NameObservations[0]
	if observation.Name != "nas-box" || observation.Source != "mdns" {
		t.Fatalf("unexpected observation: %#v", observation)
	}
}
