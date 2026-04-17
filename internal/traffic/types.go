package traffic

import (
	"net/netip"
	"time"
)

type Direction string

const (
	DirectionUpload   Direction = "upload"
	DirectionDownload Direction = "download"
	DirectionLAN      Direction = "lan"
	DirectionOther    Direction = "other"
	DirectionUnknown  Direction = "unknown"
)

type Packet struct {
	Timestamp        time.Time
	SrcIP            netip.Addr
	DstIP            netip.Addr
	SrcMAC           string
	DstMAC           string
	SrcPort          uint16
	DstPort          uint16
	Protocol         string
	Bytes            int
	NameObservations []NameObservation
}

type NameObservation struct {
	Timestamp time.Time
	IP        netip.Addr
	MAC       string
	Name      string
	Source    string
}
