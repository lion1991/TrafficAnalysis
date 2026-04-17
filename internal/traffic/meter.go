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
