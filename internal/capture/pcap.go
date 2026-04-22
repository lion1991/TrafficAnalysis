package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"trafficanalysis/internal/traffic"
)

type PacketHandler func(traffic.Packet)

type Options struct {
	Interface   string
	BPF         string
	SnapshotLen int
	Promiscuous bool
}

func RunLive(ctx context.Context, opts Options, handler PacketHandler) error {
	snapshotLen := int32(opts.SnapshotLen)
	if snapshotLen <= 0 {
		snapshotLen = 262144
	}

	handle, err := pcap.OpenLive(opts.Interface, snapshotLen, opts.Promiscuous, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	return runHandle(ctx, handle, opts.BPF, handler)
}

func RunFile(ctx context.Context, path string, bpf string, handler PacketHandler) error {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	return runHandle(ctx, handle, bpf, handler)
}

func runHandle(ctx context.Context, handle *pcap.Handle, bpf string, handler PacketHandler) error {
	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			return err
		}
	}

	go func() {
		<-ctx.Done()
		handle.Close()
	}()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		parsed, ok := ExtractPacket(packet)
		if ok {
			handler(parsed)
		}
	}

	if err := handle.Error(); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func ExtractPacket(packet gopacket.Packet) (traffic.Packet, bool) {
	network := packet.NetworkLayer()
	if network == nil {
		return traffic.Packet{}, false
	}

	srcIP, err := netip.ParseAddr(network.NetworkFlow().Src().String())
	if err != nil {
		return traffic.Packet{}, false
	}
	dstIP, err := netip.ParseAddr(network.NetworkFlow().Dst().String())
	if err != nil {
		return traffic.Packet{}, false
	}

	captureInfo := packet.Metadata().CaptureInfo
	timestamp := captureInfo.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	packetLen := captureInfo.Length
	if packetLen <= 0 {
		packetLen = len(packet.Data())
	}

	result := traffic.Packet{
		Timestamp: timestamp.UTC(),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Protocol:  protocolName(packet),
		Bytes:     packetLen,
	}

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		ethernet := ethernetLayer.(*layers.Ethernet)
		result.SrcMAC = ethernet.SrcMAC.String()
		result.DstMAC = ethernet.DstMAC.String()
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		result.SrcPort = uint16(tcp.SrcPort)
		result.DstPort = uint16(tcp.DstPort)
		result.TCPSYN = tcp.SYN
		result.TCPFIN = tcp.FIN
		result.TCPRST = tcp.RST
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		result.SrcPort = uint16(udp.SrcPort)
		result.DstPort = uint16(udp.DstPort)
	}
	result.NameObservations = extractNameObservations(packet, result)
	result.DNSObservations = extractDNSObservations(packet, result)
	result.TLSObservations = extractTLSObservations(packet, result)

	return result, true
}

func extractNameObservations(packet gopacket.Packet, parsed traffic.Packet) []traffic.NameObservation {
	var observations []traffic.NameObservation
	if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
		if observation, ok := extractDHCPHostname(dhcpLayer.(*layers.DHCPv4), parsed); ok {
			observations = append(observations, observation)
		}
	}
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		observations = append(observations, extractDNSNames(dnsLayer.(*layers.DNS), parsed)...)
	} else if parsed.SrcPort == 5353 || parsed.DstPort == 5353 || parsed.SrcPort == 5355 || parsed.DstPort == 5355 {
		if app := packet.ApplicationLayer(); app != nil {
			var dns layers.DNS
			if err := dns.DecodeFromBytes(app.Payload(), gopacket.NilDecodeFeedback); err == nil {
				observations = append(observations, extractDNSNames(&dns, parsed)...)
			}
		}
	}
	return observations
}

func extractDHCPHostname(dhcp *layers.DHCPv4, packet traffic.Packet) (traffic.NameObservation, bool) {
	var hostname string
	for _, option := range dhcp.Options {
		if option.Type == layers.DHCPOptHostname {
			hostname = cleanDeviceName(string(option.Data))
			break
		}
	}
	if hostname == "" {
		return traffic.NameObservation{}, false
	}

	ip := addrFromNetIP(dhcp.ClientIP)
	if !ip.IsValid() {
		ip = addrFromNetIP(dhcp.YourClientIP)
	}
	if !ip.IsValid() {
		ip = packet.SrcIP
	}
	mac := dhcp.ClientHWAddr.String()
	if mac == "" {
		mac = packet.SrcMAC
	}

	return traffic.NameObservation{
		Timestamp: packet.Timestamp,
		IP:        ip,
		MAC:       mac,
		Name:      hostname,
		Source:    "dhcp",
	}, ip.IsValid() && mac != ""
}

func extractDNSNames(dns *layers.DNS, packet traffic.Packet) []traffic.NameObservation {
	if packet.SrcPort != 5353 && packet.DstPort != 5353 && packet.SrcPort != 5355 && packet.DstPort != 5355 {
		return nil
	}

	source := "mdns"
	if packet.SrcPort == 5355 || packet.DstPort == 5355 {
		source = "llmnr"
	}

	var observations []traffic.NameObservation
	for _, record := range append(append(dns.Answers, dns.Authorities...), dns.Additionals...) {
		if record.Type != layers.DNSTypeA && record.Type != layers.DNSTypeAAAA {
			continue
		}
		ip := addrFromNetIP(record.IP)
		name := cleanDeviceName(string(record.Name))
		if !ip.IsValid() || name == "" {
			continue
		}

		mac := ""
		switch ip {
		case packet.SrcIP:
			mac = packet.SrcMAC
		case packet.DstIP:
			mac = packet.DstMAC
		}
		if mac == "" {
			continue
		}
		observations = append(observations, traffic.NameObservation{
			Timestamp: packet.Timestamp,
			IP:        ip,
			MAC:       mac,
			Name:      name,
			Source:    source,
		})
	}
	return observations
}

func extractDNSObservations(packet gopacket.Packet, parsed traffic.Packet) []traffic.DNSObservation {
	var dns *layers.DNS
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns = dnsLayer.(*layers.DNS)
	} else if (parsed.SrcPort == 53 || parsed.DstPort == 53) && packet.ApplicationLayer() != nil {
		decoded := &layers.DNS{}
		if err := decoded.DecodeFromBytes(packet.ApplicationLayer().Payload(), gopacket.NilDecodeFeedback); err == nil {
			dns = decoded
		}
	}
	if dns == nil || !dns.QR {
		return nil
	}

	clientIP := parsed.DstIP
	clientMAC := parsed.DstMAC
	if !clientIP.IsValid() || clientMAC == "" {
		return nil
	}

	observations := make([]traffic.DNSObservation, 0, len(dns.Answers))
	for _, answer := range dns.Answers {
		if answer.Type != layers.DNSTypeA && answer.Type != layers.DNSTypeAAAA {
			continue
		}
		answerIP := addrFromNetIP(answer.IP)
		name := cleanDeviceName(string(answer.Name))
		if !answerIP.IsValid() || name == "" {
			continue
		}
		observations = append(observations, traffic.DNSObservation{
			ObservedAt: parsed.Timestamp,
			ClientIP:   clientIP,
			ClientMAC:  clientMAC,
			Name:       name,
			RecordType: answer.Type.String(),
			AnswerIP:   answerIP,
			TTL:        answer.TTL,
			Source:     "dns",
		})
	}
	return observations
}

func extractTLSObservations(packet gopacket.Packet, parsed traffic.Packet) []traffic.TLSObservation {
	if parsed.Protocol != "tcp" {
		return nil
	}
	app := packet.ApplicationLayer()
	if app == nil {
		return nil
	}
	serverName, alpn, err := parseTLSClientHello(app.Payload())
	if err != nil || serverName == "" {
		return nil
	}

	remoteIP := parsed.DstIP
	remotePort := parsed.DstPort
	clientIP := parsed.SrcIP
	clientMAC := parsed.SrcMAC
	if parsed.SrcPort == 443 {
		remoteIP = parsed.SrcIP
		remotePort = parsed.SrcPort
		clientIP = parsed.DstIP
		clientMAC = parsed.DstMAC
	}
	return []traffic.TLSObservation{{
		ObservedAt: parsed.Timestamp,
		ClientIP:   clientIP,
		ClientMAC:  clientMAC,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		ServerName: serverName,
		ALPN:       alpn,
		Protocol:   parsed.Protocol,
		Source:     "tls_client_hello",
	}}
}

func parseTLSClientHello(payload []byte) (string, string, error) {
	if len(payload) < 5 || payload[0] != 0x16 {
		return "", "", errors.New("not a tls handshake record")
	}
	recordLength := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLength {
		return "", "", errors.New("short tls record")
	}
	handshake := payload[5 : 5+recordLength]
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return "", "", errors.New("not a client hello")
	}
	messageLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+messageLength {
		return "", "", errors.New("short client hello")
	}
	body := handshake[4 : 4+messageLength]
	if len(body) < 34 {
		return "", "", errors.New("short client hello body")
	}

	offset := 34
	sessionIDLen := int(body[offset])
	offset++
	if len(body) < offset+sessionIDLen+2 {
		return "", "", errors.New("short session id")
	}
	offset += sessionIDLen

	cipherSuitesLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body) < offset+cipherSuitesLen+1 {
		return "", "", errors.New("short cipher suites")
	}
	offset += cipherSuitesLen

	compressionMethodsLen := int(body[offset])
	offset++
	if len(body) < offset+compressionMethodsLen+2 {
		return "", "", errors.New("short compression methods")
	}
	offset += compressionMethodsLen

	extensionsLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body) < offset+extensionsLen {
		return "", "", errors.New("short extensions")
	}
	extensions := body[offset : offset+extensionsLen]

	var serverName string
	var alpn string
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[0:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			return "", "", errors.New("short extension payload")
		}
		extData := extensions[:extLen]
		extensions = extensions[extLen:]

		switch extType {
		case 0:
			name, err := parseTLSServerName(extData)
			if err == nil {
				serverName = name
			}
		case 16:
			value, err := parseTLSALPN(extData)
			if err == nil {
				alpn = value
			}
		}
	}
	if serverName == "" {
		return "", "", errors.New("no server name")
	}
	return serverName, alpn, nil
}

func parseTLSServerName(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("short sni extension")
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+listLen || listLen < 3 {
		return "", errors.New("short sni list")
	}
	entry := data[2 : 2+listLen]
	if entry[0] != 0 {
		return "", errors.New("unsupported sni name type")
	}
	nameLen := int(binary.BigEndian.Uint16(entry[1:3]))
	if len(entry) < 3+nameLen {
		return "", errors.New("short sni name")
	}
	return string(entry[3 : 3+nameLen]), nil
}

func parseTLSALPN(data []byte) (string, error) {
	if len(data) < 3 {
		return "", errors.New("short alpn extension")
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+listLen {
		return "", errors.New("short alpn list")
	}
	list := data[2 : 2+listLen]
	if len(list) < 1 {
		return "", errors.New("empty alpn list")
	}
	valueLen := int(list[0])
	if len(list) < 1+valueLen {
		return "", errors.New("short alpn value")
	}
	return string(bytes.TrimSpace(list[1 : 1+valueLen])), nil
}

func addrFromNetIP(ip []byte) netip.Addr {
	if len(ip) == 0 {
		return netip.Addr{}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func cleanDeviceName(name string) string {
	name = strings.TrimSpace(strings.Trim(name, "."))
	if strings.HasSuffix(name, ".local") {
		name = strings.TrimSuffix(name, ".local")
	}
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}

func protocolName(packet gopacket.Packet) string {
	if transport := packet.TransportLayer(); transport != nil {
		return strings.ToLower(transport.LayerType().String())
	}
	switch {
	case packet.Layer(layers.LayerTypeICMPv4) != nil:
		return "icmpv4"
	case packet.Layer(layers.LayerTypeICMPv6) != nil:
		return "icmpv6"
	default:
		return "unknown"
	}
}
