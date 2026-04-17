package traffic

import "sync"

type DirectionCounters struct {
	Bytes   int64
	Packets int64
}

type Meter struct {
	mu       sync.Mutex
	counters map[Direction]DirectionCounters
}

func NewMeter() *Meter {
	return &Meter{counters: make(map[Direction]DirectionCounters)}
}

func (m *Meter) Add(direction Direction, bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	counters := m.counters[direction]
	counters.Bytes += int64(bytes)
	counters.Packets++
	m.counters[direction] = counters
}

func (m *Meter) SnapshotAndReset() map[Direction]DirectionCounters {
	m.mu.Lock()
	defer m.mu.Unlock()

	snapshot := make(map[Direction]DirectionCounters, len(m.counters))
	for direction, counters := range m.counters {
		snapshot[direction] = counters
	}
	m.counters = make(map[Direction]DirectionCounters)
	return snapshot
}
