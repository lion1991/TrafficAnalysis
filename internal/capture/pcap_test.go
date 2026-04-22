package capture

import (
	"bytes"
	"encoding/binary"
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

func TestExtractPacketCapturesDNSAnswerObservations(t *testing.T) {
	srcMAC := net.HardwareAddr{0, 17, 34, 51, 68, 85}
	udp := &layers.UDP{
		SrcPort: 53,
		DstPort: 53000,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 248, 1},
		DstIP:    net.IP{192, 168, 248, 22},
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum layer: %v", err)
	}

	dns := &layers.DNS{
		ID:      0x1234,
		QR:      true,
		RD:      true,
		RA:      true,
		QDCount: 1,
		ANCount: 1,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("api.example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("api.example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   300,
				IP:    net.IP{203, 0, 113, 9},
			},
		},
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
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
	if len(parsed.DNSObservations) != 1 {
		t.Fatalf("expected one DNS observation, got %#v", parsed.DNSObservations)
	}
	observation := parsed.DNSObservations[0]
	if observation.ClientIP != netip.MustParseAddr("192.168.248.22") || observation.ClientMAC != "06:07:08:09:0a:0b" {
		t.Fatalf("unexpected DNS client identity: %#v", observation)
	}
	if observation.Name != "api.example.com" || observation.AnswerIP != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("unexpected DNS observation payload: %#v", observation)
	}
	if observation.TTL != 300 || observation.Source != "dns" {
		t.Fatalf("unexpected DNS observation metadata: %#v", observation)
	}
}

func TestExtractPacketCapturesTLSSNIAndALPN(t *testing.T) {
	tcp := &layers.TCP{
		SrcPort: 53000,
		DstPort: 443,
		ACK:     true,
		PSH:     true,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 248, 22},
		DstIP:    net.IP{203, 0, 113, 9},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum layer: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 17, 34, 51, 68, 85},
			DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
			EthernetType: layers.EthernetTypeIPv4,
		},
		ip,
		tcp,
		gopacket.Payload(testTLSClientHello("api.example.com", "h2")),
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
	if len(parsed.TLSObservations) != 1 {
		t.Fatalf("expected one TLS observation, got %#v", parsed.TLSObservations)
	}
	observation := parsed.TLSObservations[0]
	if observation.ServerName != "api.example.com" || observation.ALPN != "h2" {
		t.Fatalf("unexpected TLS observation: %#v", observation)
	}
	if observation.RemoteIP != netip.MustParseAddr("203.0.113.9") || observation.RemotePort != 443 {
		t.Fatalf("unexpected TLS remote endpoint: %#v", observation)
	}
}

func testTLSClientHello(serverName, alpn string) []byte {
	serverNameBytes := []byte(serverName)
	alpnBytes := []byte(alpn)

	var sniBody bytes.Buffer
	_ = binary.Write(&sniBody, binary.BigEndian, uint16(len(serverNameBytes)+3))
	sniBody.WriteByte(0)
	_ = binary.Write(&sniBody, binary.BigEndian, uint16(len(serverNameBytes)))
	sniBody.Write(serverNameBytes)
	sniData := sniBody.Bytes()

	var sniExt bytes.Buffer
	_ = binary.Write(&sniExt, binary.BigEndian, uint16(0))
	_ = binary.Write(&sniExt, binary.BigEndian, uint16(len(sniData)))
	sniExt.Write(sniData)

	var alpnData bytes.Buffer
	_ = binary.Write(&alpnData, binary.BigEndian, uint16(len(alpnBytes)+1))
	alpnData.WriteByte(byte(len(alpnBytes)))
	alpnData.Write(alpnBytes)

	var alpnExt bytes.Buffer
	_ = binary.Write(&alpnExt, binary.BigEndian, uint16(16))
	_ = binary.Write(&alpnExt, binary.BigEndian, uint16(alpnData.Len()))
	alpnExt.Write(alpnData.Bytes())

	extensions := append(sniExt.Bytes(), alpnExt.Bytes()...)

	var hello bytes.Buffer
	hello.Write([]byte{0x03, 0x03})
	hello.Write(bytes.Repeat([]byte{0x01}, 32))
	hello.WriteByte(0)
	_ = binary.Write(&hello, binary.BigEndian, uint16(2))
	hello.Write([]byte{0x13, 0x01})
	hello.WriteByte(1)
	hello.WriteByte(0)
	_ = binary.Write(&hello, binary.BigEndian, uint16(len(extensions)))
	hello.Write(extensions)

	helloBytes := hello.Bytes()

	var handshake bytes.Buffer
	handshake.WriteByte(0x01)
	handshake.Write([]byte{byte(len(helloBytes) >> 16), byte(len(helloBytes) >> 8), byte(len(helloBytes))})
	handshake.Write(helloBytes)

	handshakeBytes := handshake.Bytes()

	var record bytes.Buffer
	record.WriteByte(0x16)
	record.Write([]byte{0x03, 0x01})
	_ = binary.Write(&record, binary.BigEndian, uint16(len(handshakeBytes)))
	record.Write(handshakeBytes)
	return record.Bytes()
}
