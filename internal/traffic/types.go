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
	DNSObservations  []DNSObservation
	TLSObservations  []TLSObservation
	TCPSYN           bool
	TCPFIN           bool
	TCPRST           bool
}

type NameObservation struct {
	Timestamp time.Time
	IP        netip.Addr
	MAC       string
	Name      string
	Source    string
}

type Viewpoint string

const (
	ViewpointLAN Viewpoint = "lan"
	ViewpointWAN Viewpoint = "wan"
)

type DNSObservation struct {
	ObservedAt time.Time
	ClientIP   netip.Addr
	ClientMAC  string
	Name       string
	RecordType string
	AnswerIP   netip.Addr
	TTL        uint32
	Source     string
}

type TLSObservation struct {
	ObservedAt time.Time
	Viewpoint  Viewpoint
	ClientIP   netip.Addr
	ClientMAC  string
	RemoteIP   netip.Addr
	RemotePort uint16
	ServerName string
	ALPN       string
	Protocol   string
	Source     string
}

type FlowSession struct {
	ID             int64
	Viewpoint      Viewpoint
	Protocol       string
	LocalIP        netip.Addr
	LocalPort      uint16
	RemoteIP       netip.Addr
	RemotePort     uint16
	ClientIP       netip.Addr
	ClientMAC      string
	FirstSeen      time.Time
	LastSeen       time.Time
	UploadBytes    int64
	DownloadBytes  int64
	Packets        int64
	SYNSeen        bool
	FINSeen        bool
	RSTSeen        bool
	HasDNSEvidence bool
	HasTLSEvidence bool
}
