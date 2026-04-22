package traffic

import (
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type flowKey struct {
	viewpoint  Viewpoint
	protocol   string
	localIP    netip.Addr
	localPort  uint16
	remoteIP   netip.Addr
	remotePort uint16
	clientIP   netip.Addr
	clientMAC  string
}

type dnsEvidence struct {
	expiresAt time.Time
}

type FlowTracker struct {
	mu              sync.Mutex
	inactivity      time.Duration
	sessions        map[flowKey]*FlowSession
	dnsEvidenceByIP map[string]dnsEvidence
}

func NewFlowTracker(inactivity time.Duration) *FlowTracker {
	if inactivity <= 0 {
		inactivity = 30 * time.Second
	}
	return &FlowTracker{
		inactivity:      inactivity,
		sessions:        make(map[flowKey]*FlowSession),
		dnsEvidenceByIP: make(map[string]dnsEvidence),
	}
}

func (t *FlowTracker) AddWANPacket(packet Packet, direction Direction) {
	if direction != DirectionUpload && direction != DirectionDownload {
		return
	}

	localIP := packet.SrcIP
	localPort := packet.SrcPort
	remoteIP := packet.DstIP
	remotePort := packet.DstPort
	if direction == DirectionDownload {
		localIP = packet.DstIP
		localPort = packet.DstPort
		remoteIP = packet.SrcIP
		remotePort = packet.SrcPort
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	key := flowKey{
		viewpoint:  ViewpointWAN,
		protocol:   packet.Protocol,
		localIP:    localIP,
		localPort:  localPort,
		remoteIP:   remoteIP,
		remotePort: remotePort,
	}
	session := t.getOrCreateSession(key, packet.Timestamp)
	applyPacketToSession(session, packet, direction)
}

func (t *FlowTracker) AddLANPacket(packet Packet, client ClientTraffic) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.observeDNSEvidence(packet)

	localIP := client.ClientIP
	localPort := packet.SrcPort
	remoteIP := packet.DstIP
	remotePort := packet.DstPort
	if client.Direction == DirectionDownload {
		localPort = packet.DstPort
		remoteIP = packet.SrcIP
		remotePort = packet.SrcPort
	}

	key := flowKey{
		viewpoint:  ViewpointLAN,
		protocol:   packet.Protocol,
		localIP:    localIP,
		localPort:  localPort,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		clientIP:   client.ClientIP,
		clientMAC:  client.ClientMAC,
	}
	session := t.getOrCreateSession(key, packet.Timestamp)
	session.ClientIP = client.ClientIP
	session.ClientMAC = client.ClientMAC
	if t.hasDNSEvidence(client.ClientIP, remoteIP, packet.Timestamp) {
		session.HasDNSEvidence = true
	}
	if len(packet.TLSObservations) > 0 {
		session.HasTLSEvidence = true
	}
	applyPacketToSession(session, packet, client.Direction)
}

func (t *FlowTracker) DrainExpired(now time.Time) []FlowSession {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pruneDNSEvidence(now)

	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-t.inactivity)
	drained := make([]FlowSession, 0)
	for key, session := range t.sessions {
		if session.LastSeen.After(cutoff) {
			continue
		}
		drained = append(drained, *session)
		delete(t.sessions, key)
	}
	return drained
}

func (t *FlowTracker) DrainAll() []FlowSession {
	t.mu.Lock()
	defer t.mu.Unlock()

	drained := make([]FlowSession, 0, len(t.sessions))
	for key, session := range t.sessions {
		drained = append(drained, *session)
		delete(t.sessions, key)
	}
	return drained
}

func (t *FlowTracker) getOrCreateSession(key flowKey, timestamp time.Time) *FlowSession {
	session := t.sessions[key]
	if session == nil {
		session = &FlowSession{
			Viewpoint:  key.viewpoint,
			Protocol:   key.protocol,
			LocalIP:    key.localIP,
			LocalPort:  key.localPort,
			RemoteIP:   key.remoteIP,
			RemotePort: key.remotePort,
			ClientIP:   key.clientIP,
			ClientMAC:  key.clientMAC,
			FirstSeen:  timestamp.UTC(),
			LastSeen:   timestamp.UTC(),
		}
		t.sessions[key] = session
	}
	return session
}

func (t *FlowTracker) observeDNSEvidence(packet Packet) {
	for _, observation := range packet.DNSObservations {
		if !observation.ClientIP.IsValid() || !observation.AnswerIP.IsValid() {
			continue
		}
		expiresAt := observation.ObservedAt.UTC().Add(time.Duration(observation.TTL) * time.Second)
		if expiresAt.IsZero() || !expiresAt.After(observation.ObservedAt.UTC()) {
			expiresAt = observation.ObservedAt.UTC().Add(5 * time.Minute)
		}
		t.dnsEvidenceByIP[dnsEvidenceKey(observation.ClientIP, observation.AnswerIP)] = dnsEvidence{
			expiresAt: expiresAt,
		}
	}
}

func (t *FlowTracker) hasDNSEvidence(clientIP, remoteIP netip.Addr, now time.Time) bool {
	evidence, ok := t.dnsEvidenceByIP[dnsEvidenceKey(clientIP, remoteIP)]
	return ok && evidence.expiresAt.After(now.UTC())
}

func (t *FlowTracker) pruneDNSEvidence(now time.Time) {
	for key, evidence := range t.dnsEvidenceByIP {
		if !evidence.expiresAt.After(now.UTC()) {
			delete(t.dnsEvidenceByIP, key)
		}
	}
}

func dnsEvidenceKey(clientIP, remoteIP netip.Addr) string {
	return clientIP.String() + "\x00" + remoteIP.String()
}

func applyPacketToSession(session *FlowSession, packet Packet, direction Direction) {
	if packet.Timestamp.Before(session.FirstSeen) {
		session.FirstSeen = packet.Timestamp.UTC()
	}
	if packet.Timestamp.After(session.LastSeen) {
		session.LastSeen = packet.Timestamp.UTC()
	}
	switch direction {
	case DirectionUpload:
		session.UploadBytes += int64(packet.Bytes)
	case DirectionDownload:
		session.DownloadBytes += int64(packet.Bytes)
	}
	session.Packets++
	session.SYNSeen = session.SYNSeen || packet.TCPSYN
	session.FINSeen = session.FINSeen || packet.TCPFIN
	session.RSTSeen = session.RSTSeen || packet.TCPRST
}

func (k flowKey) String() string {
	return string(k.viewpoint) + ":" + k.protocol + ":" + k.localIP.String() + ":" + strconv.Itoa(int(k.localPort)) + ":" + k.remoteIP.String() + ":" + strconv.Itoa(int(k.remotePort))
}
