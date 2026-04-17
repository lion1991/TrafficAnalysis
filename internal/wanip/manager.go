package wanip

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

type Provider interface {
	CurrentIP(context.Context) (netip.Addr, error)
}

type ProviderFunc func(context.Context) (netip.Addr, error)

func (f ProviderFunc) CurrentIP(ctx context.Context) (netip.Addr, error) {
	return f(ctx)
}

type Manager struct {
	mu         sync.RWMutex
	provider   Provider
	refreshTTL time.Duration
	current    netip.Addr
	updatedAt  time.Time
}

func NewManager(provider Provider, refreshTTL time.Duration) *Manager {
	if refreshTTL <= 0 {
		refreshTTL = 5 * time.Minute
	}
	return &Manager{provider: provider, refreshTTL: refreshTTL}
}

func (m *Manager) Refresh(ctx context.Context) error {
	addr, err := m.provider.CurrentIP(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = addr
	m.updatedAt = time.Now()
	return nil
}

func (m *Manager) Current() (netip.Addr, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.current.IsValid() {
		return netip.Addr{}, false
	}
	if m.updatedAt.IsZero() || time.Since(m.updatedAt) > m.refreshTTL {
		return m.current, false
	}
	return m.current, true
}

func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = m.refreshTTL / 2
	}
	if interval <= 0 {
		interval = time.Minute
	}

	_ = m.Refresh(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = m.Refresh(ctx)
		}
	}
}
