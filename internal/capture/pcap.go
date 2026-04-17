package capture

import (
	"context"
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
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		result.SrcPort = uint16(udp.SrcPort)
		result.DstPort = uint16(udp.DstPort)
	}
	result.NameObservations = extractNameObservations(packet, result)

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
