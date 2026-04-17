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
	Timestamp time.Time
	SrcIP     netip.Addr
	DstIP     netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Bytes     int
}
