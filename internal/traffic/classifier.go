package traffic

import "net/netip"

type WANIPSource func() (netip.Addr, bool)

type WANClassifier struct {
	currentWANIP WANIPSource
}

func NewWANClassifier(currentWANIP WANIPSource) WANClassifier {
	return WANClassifier{currentWANIP: currentWANIP}
}

func (c WANClassifier) Classify(packet Packet) Direction {
	if c.currentWANIP == nil {
		return DirectionUnknown
	}

	wanIP, ok := c.currentWANIP()
	if !ok || !wanIP.IsValid() {
		return DirectionUnknown
	}

	switch {
	case packet.SrcIP == wanIP && packet.DstIP != wanIP:
		return DirectionUpload
	case packet.DstIP == wanIP && packet.SrcIP != wanIP:
		return DirectionDownload
	case packet.SrcIP == wanIP && packet.DstIP == wanIP:
		return DirectionOther
	default:
		return DirectionOther
	}
}
