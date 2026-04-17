package traffic

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

type BucketKey struct {
	Start     time.Time
	Direction Direction
	Protocol  string
}

type ClientBucketKey struct {
	Start     time.Time
	ClientIP  netip.Addr
	ClientMAC string
	Direction Direction
	Protocol  string
}

type BucketValue struct {
	Bytes   int64
	Packets int64
}

type Aggregator struct {
	mu       sync.Mutex
	interval time.Duration
	buckets  map[BucketKey]BucketValue
}

func NewAggregator(interval time.Duration) *Aggregator {
	if interval <= 0 {
		interval = time.Minute
	}
	return &Aggregator{
		interval: interval,
		buckets:  make(map[BucketKey]BucketValue),
	}
}

func (a *Aggregator) Add(packet Packet, direction Direction) {
	a.mu.Lock()
	defer a.mu.Unlock()

	protocol := packet.Protocol
	if protocol == "" {
		protocol = "unknown"
	}

	key := BucketKey{
		Start:     packet.Timestamp.Truncate(a.interval).UTC(),
		Direction: direction,
		Protocol:  protocol,
	}
	value := a.buckets[key]
	value.Bytes += int64(packet.Bytes)
	value.Packets++
	a.buckets[key] = value
}

func (a *Aggregator) Snapshot() map[BucketKey]BucketValue {
	a.mu.Lock()
	defer a.mu.Unlock()

	snapshot := make(map[BucketKey]BucketValue, len(a.buckets))
	for key, value := range a.buckets {
		snapshot[key] = value
	}
	return snapshot
}

func (a *Aggregator) DrainBefore(cutoff time.Time) map[BucketKey]BucketValue {
	a.mu.Lock()
	defer a.mu.Unlock()

	drained := make(map[BucketKey]BucketValue)
	for key, value := range a.buckets {
		if key.Start.Before(cutoff) {
			drained[key] = value
			delete(a.buckets, key)
		}
	}
	return drained
}

func (a *Aggregator) DrainAll() map[BucketKey]BucketValue {
	a.mu.Lock()
	defer a.mu.Unlock()

	drained := a.buckets
	a.buckets = make(map[BucketKey]BucketValue)
	return drained
}

func SortedBucketKeys(buckets map[BucketKey]BucketValue) []BucketKey {
	keys := make([]BucketKey, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if !keys[i].Start.Equal(keys[j].Start) {
			return keys[i].Start.Before(keys[j].Start)
		}
		if keys[i].Direction != keys[j].Direction {
			return keys[i].Direction < keys[j].Direction
		}
		return keys[i].Protocol < keys[j].Protocol
	})
	return keys
}

type ClientAggregator struct {
	mu       sync.Mutex
	interval time.Duration
	buckets  map[ClientBucketKey]BucketValue
}

func NewClientAggregator(interval time.Duration) *ClientAggregator {
	if interval <= 0 {
		interval = time.Minute
	}
	return &ClientAggregator{
		interval: interval,
		buckets:  make(map[ClientBucketKey]BucketValue),
	}
}

func (a *ClientAggregator) Add(packet Packet, client ClientTraffic) {
	a.mu.Lock()
	defer a.mu.Unlock()

	protocol := packet.Protocol
	if protocol == "" {
		protocol = "unknown"
	}

	key := ClientBucketKey{
		Start:     packet.Timestamp.Truncate(a.interval).UTC(),
		ClientIP:  client.ClientIP,
		ClientMAC: client.ClientMAC,
		Direction: client.Direction,
		Protocol:  protocol,
	}
	value := a.buckets[key]
	value.Bytes += int64(packet.Bytes)
	value.Packets++
	a.buckets[key] = value
}

func (a *ClientAggregator) Snapshot() map[ClientBucketKey]BucketValue {
	a.mu.Lock()
	defer a.mu.Unlock()

	snapshot := make(map[ClientBucketKey]BucketValue, len(a.buckets))
	for key, value := range a.buckets {
		snapshot[key] = value
	}
	return snapshot
}

func (a *ClientAggregator) DrainBefore(cutoff time.Time) map[ClientBucketKey]BucketValue {
	a.mu.Lock()
	defer a.mu.Unlock()

	drained := make(map[ClientBucketKey]BucketValue)
	for key, value := range a.buckets {
		if key.Start.Before(cutoff) {
			drained[key] = value
			delete(a.buckets, key)
		}
	}
	return drained
}

func (a *ClientAggregator) DrainAll() map[ClientBucketKey]BucketValue {
	a.mu.Lock()
	defer a.mu.Unlock()

	drained := a.buckets
	a.buckets = make(map[ClientBucketKey]BucketValue)
	return drained
}
