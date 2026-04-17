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

	return result, true
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
