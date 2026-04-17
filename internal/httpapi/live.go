package httpapi

import (
	"context"
	"sync"
)

type LiveTotals struct {
	UploadBytes   int64 `json:"upload_bytes"`
	DownloadBytes int64 `json:"download_bytes"`
	LANBytes      int64 `json:"lan_bytes"`
	OtherBytes    int64 `json:"other_bytes"`
	UnknownBytes  int64 `json:"unknown_bytes"`
	Packets       int64 `json:"packets"`
}

type LiveRates struct {
	UploadBPS   int64 `json:"upload_bps"`
	DownloadBPS int64 `json:"download_bps"`
}

type LiveSnapshot struct {
	Timestamp       string     `json:"timestamp"`
	WANIP           string     `json:"wan_ip"`
	WANAvailable    bool       `json:"wan_available"`
	IntervalSeconds float64    `json:"interval_seconds"`
	Totals          LiveTotals `json:"totals"`
	Rates           LiveRates  `json:"rates"`
}

type LiveSource interface {
	Subscribe(ctx context.Context) (<-chan LiveSnapshot, func())
}

type LiveHub struct {
	mu          sync.Mutex
	subscribers map[chan LiveSnapshot]struct{}
	last        *LiveSnapshot
}

func NewLiveHub() *LiveHub {
	return &LiveHub{
		subscribers: make(map[chan LiveSnapshot]struct{}),
	}
}

func (h *LiveHub) Publish(snapshot LiveSnapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.last = &snapshot
	for subscriber := range h.subscribers {
		select {
		case subscriber <- snapshot:
		default:
		}
	}
}

func (h *LiveHub) Subscribe(ctx context.Context) (<-chan LiveSnapshot, func()) {
	ch := make(chan LiveSnapshot, 1)

	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	if h.last != nil {
		ch <- *h.last
	}
	h.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subscribers, ch)
			close(ch)
			h.mu.Unlock()
		})
	}

	go func() {
		<-ctx.Done()
		cancel()
	}()

	return ch, cancel
}
