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
	mu             sync.RWMutex
	provider       Provider
	refreshTTL     time.Duration
	current        netip.Addr
	updatedAt      time.Time
	lastSeenAt     time.Time
	lastAttemptAt  time.Time
	refreshRequest chan struct{}
	now            func() time.Time
}

func NewManager(provider Provider, refreshTTL time.Duration) *Manager {
	if refreshTTL <= 0 {
		refreshTTL = 5 * time.Minute
	}
	return &Manager{
		provider:       provider,
		refreshTTL:     refreshTTL,
		refreshRequest: make(chan struct{}, 1),
		now:            time.Now,
	}
}

func (m *Manager) Refresh(ctx context.Context) error {
	m.mu.Lock()
	m.lastAttemptAt = m.now()
	m.mu.Unlock()

	addr, err := m.provider.CurrentIP(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = addr
	m.updatedAt = m.now()
	m.lastSeenAt = time.Time{}
	return nil
}

func (m *Manager) RefreshIfNeeded(ctx context.Context) (bool, error) {
	m.mu.RLock()
	shouldSkip := m.current.IsValid() && !m.lastSeenAt.IsZero() && m.now().Sub(m.lastSeenAt) <= m.refreshTTL
	m.mu.RUnlock()
	if shouldSkip {
		return false, nil
	}

	if err := m.Refresh(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) ObservePacket(src, dst netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.current.IsValid() {
		return
	}
	if src == m.current || dst == m.current {
		m.lastSeenAt = m.now()
	}
}

func (m *Manager) RequestRefresh() {
	select {
	case m.refreshRequest <- struct{}{}:
	default:
	}
}

func (m *Manager) Current() (netip.Addr, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.current.IsValid() {
		return netip.Addr{}, false
	}
	lastValidAt := m.updatedAt
	if m.lastSeenAt.After(lastValidAt) {
		lastValidAt = m.lastSeenAt
	}
	if lastValidAt.IsZero() || m.now().Sub(lastValidAt) > m.refreshTTL {
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
		case <-m.refreshRequest:
			_, _ = m.RefreshIfAttemptAllowed(ctx, 5*time.Second)
		case <-ticker.C:
			_, _ = m.RefreshIfNeeded(ctx)
		}
	}
}

func (m *Manager) RefreshIfAttemptAllowed(ctx context.Context, minInterval time.Duration) (bool, error) {
	m.mu.RLock()
	if minInterval > 0 && !m.lastAttemptAt.IsZero() && m.now().Sub(m.lastAttemptAt) < minInterval {
		m.mu.RUnlock()
		return false, nil
	}
	m.mu.RUnlock()

	if err := m.Refresh(ctx); err != nil {
		return false, err
	}
	return true, nil
}
