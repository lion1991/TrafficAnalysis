package traffic

import (
	"net/netip"
	"sort"
	"sync"
)

type DirectionCounters struct {
	Bytes   int64
	Packets int64
}

type ConversationKey struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

type ConversationCounters struct {
	Key     ConversationKey
	Bytes   int64
	Packets int64
}

type MeterSnapshot struct {
	Directions    map[Direction]DirectionCounters
	Conversations map[Direction][]ConversationCounters
}

type Meter struct {
	mu            sync.Mutex
	counters      map[Direction]DirectionCounters
	conversations map[Direction]map[ConversationKey]DirectionCounters
}

func NewMeter() *Meter {
	return &Meter{
		counters:      make(map[Direction]DirectionCounters),
		conversations: make(map[Direction]map[ConversationKey]DirectionCounters),
	}
}

func (m *Meter) Add(direction Direction, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.add(direction, bytes)
}

func (m *Meter) AddPacket(direction Direction, packet Packet) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.add(direction, packet.Bytes)

	if _, ok := m.conversations[direction]; !ok {
		m.conversations[direction] = make(map[ConversationKey]DirectionCounters)
	}
	key := ConversationKey{
		SrcIP:    packet.SrcIP,
		DstIP:    packet.DstIP,
		SrcPort:  packet.SrcPort,
		DstPort:  packet.DstPort,
		Protocol: packet.Protocol,
	}
	counters := m.conversations[direction][key]
	counters.Bytes += int64(packet.Bytes)
	counters.Packets++
	m.conversations[direction][key] = counters
}

func (m *Meter) SnapshotAndReset() map[Direction]DirectionCounters {
	return m.SnapshotAndResetDetailed(0).Directions
}

func (m *Meter) SnapshotAndResetDetailed(topN int) MeterSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	directions := make(map[Direction]DirectionCounters, len(m.counters))
	for direction, counters := range m.counters {
		directions[direction] = counters
	}

	conversations := make(map[Direction][]ConversationCounters, len(m.conversations))
	for direction, directionConversations := range m.conversations {
		rows := make([]ConversationCounters, 0, len(directionConversations))
		for key, counters := range directionConversations {
			rows = append(rows, ConversationCounters{
				Key:     key,
				Bytes:   counters.Bytes,
				Packets: counters.Packets,
			})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Bytes != rows[j].Bytes {
				return rows[i].Bytes > rows[j].Bytes
			}
			return rows[i].Packets > rows[j].Packets
		})
		if topN > 0 && len(rows) > topN {
			rows = rows[:topN]
		}
		conversations[direction] = rows
	}

	m.counters = make(map[Direction]DirectionCounters)
	m.conversations = make(map[Direction]map[ConversationKey]DirectionCounters)

	return MeterSnapshot{
		Directions:    directions,
		Conversations: conversations,
	}
}

func (m *Meter) add(direction Direction, bytes int) {
	counters := m.counters[direction]
	counters.Bytes += int64(bytes)
	counters.Packets++
	m.counters[direction] = counters
}

type ClientCounters struct {
	ClientIP      netip.Addr
	ClientMAC     string
	UploadBytes   int64
	DownloadBytes int64
	Packets       int64
}

type ClientMeterSnapshot struct {
	Clients []ClientCounters
}

type clientMeterKey struct {
	ip  netip.Addr
	mac string
}

type ClientMeter struct {
	mu       sync.Mutex
	counters map[clientMeterKey]ClientCounters
}

func NewClientMeter() *ClientMeter {
	return &ClientMeter{
		counters: make(map[clientMeterKey]ClientCounters),
	}
}

func (m *ClientMeter) AddPacket(client ClientTraffic, packet Packet) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := clientMeterKey{ip: client.ClientIP, mac: client.ClientMAC}
	counters := m.counters[key]
	counters.ClientIP = client.ClientIP
	counters.ClientMAC = client.ClientMAC
	switch client.Direction {
	case DirectionUpload:
		counters.UploadBytes += int64(packet.Bytes)
	case DirectionDownload:
		counters.DownloadBytes += int64(packet.Bytes)
	}
	counters.Packets++
	m.counters[key] = counters
}

func (m *ClientMeter) SnapshotAndReset(topN int) ClientMeterSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	rows := make([]ClientCounters, 0, len(m.counters))
	for _, counters := range m.counters {
		rows = append(rows, counters)
	}
	sort.Slice(rows, func(i, j int) bool {
		left := rows[i].UploadBytes + rows[i].DownloadBytes
		right := rows[j].UploadBytes + rows[j].DownloadBytes
		if left != right {
			return left > right
		}
		if rows[i].ClientIP != rows[j].ClientIP {
			return rows[i].ClientIP.Less(rows[j].ClientIP)
		}
		return rows[i].ClientMAC < rows[j].ClientMAC
	})
	if topN > 0 && len(rows) > topN {
		rows = rows[:topN]
	}

	m.counters = make(map[clientMeterKey]ClientCounters)
	return ClientMeterSnapshot{Clients: rows}
}
