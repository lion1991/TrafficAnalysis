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
