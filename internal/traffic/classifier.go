package traffic

import "net/netip"

type WANIPSource func() (netip.Addr, bool)

type WANClassifier struct {
	currentWANIP WANIPSource
	localNets    []netip.Prefix
}

func NewWANClassifier(currentWANIP WANIPSource) WANClassifier {
	return WANClassifier{currentWANIP: currentWANIP}
}

func NewWANClassifierWithLocalNetworks(currentWANIP WANIPSource, localNets []netip.Prefix) WANClassifier {
	return WANClassifier{
		currentWANIP: currentWANIP,
		localNets:    localNets,
	}
}

func (c WANClassifier) Classify(packet Packet) Direction {
	if c.currentWANIP != nil {
		wanIP, ok := c.currentWANIP()
		if ok && wanIP.IsValid() {
			switch {
			case packet.SrcIP == wanIP && packet.DstIP != wanIP:
				return DirectionUpload
			case packet.DstIP == wanIP && packet.SrcIP != wanIP:
				return DirectionDownload
			case packet.SrcIP == wanIP && packet.DstIP == wanIP:
				return DirectionOther
			}
		}
	}

	if c.isLocal(packet.SrcIP) || c.isLocal(packet.DstIP) {
		return DirectionLAN
	}

	if c.currentWANIP == nil {
		return DirectionUnknown
	}

	wanIP, ok := c.currentWANIP()
	if !ok || !wanIP.IsValid() {
		return DirectionUnknown
	}

	return DirectionOther
}

func (c WANClassifier) isLocal(addr netip.Addr) bool {
	for _, prefix := range c.localNets {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type ClientTraffic struct {
	ClientIP  netip.Addr
	ClientMAC string
	Direction Direction
}

type LANClientClassifier struct {
	localNets []netip.Prefix
}

func NewLANClientClassifier(localNets []netip.Prefix) LANClientClassifier {
	return LANClientClassifier{localNets: localNets}
}

func (c LANClientClassifier) Classify(packet Packet) (ClientTraffic, bool) {
	srcLocal := c.isLocal(packet.SrcIP)
	dstLocal := c.isLocal(packet.DstIP)

	switch {
	case srcLocal && !dstLocal && isPublicAddress(packet.DstIP):
		return ClientTraffic{
			ClientIP:  packet.SrcIP,
			ClientMAC: packet.SrcMAC,
			Direction: DirectionUpload,
		}, true
	case dstLocal && !srcLocal && isPublicAddress(packet.SrcIP):
		return ClientTraffic{
			ClientIP:  packet.DstIP,
			ClientMAC: packet.DstMAC,
			Direction: DirectionDownload,
		}, true
	default:
		return ClientTraffic{}, false
	}
}

func (c LANClientClassifier) isLocal(addr netip.Addr) bool {
	for _, prefix := range c.localNets {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isPublicAddress(addr netip.Addr) bool {
	return addr.IsValid() &&
		addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast()
}
