package wanip

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestManagerRefreshesWANIPFromProvider(t *testing.T) {
	provider := ProviderFunc(func(context.Context) (netip.Addr, error) {
		return netip.MustParseAddr("203.0.113.77"), nil
	})
	manager := NewManager(provider, time.Minute)

	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	addr, ok := manager.Current()
	if !ok {
		t.Fatal("expected WAN IP to be available")
	}
	if addr.String() != "203.0.113.77" {
		t.Fatalf("unexpected WAN IP: %s", addr)
	}
}

func TestManagerKeepsCurrentIPValidWhenObservedInTraffic(t *testing.T) {
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	provider := ProviderFunc(func(context.Context) (netip.Addr, error) {
		return netip.MustParseAddr("203.0.113.77"), nil
	})
	manager := NewManager(provider, time.Minute)
	manager.now = func() time.Time { return now }

	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	now = now.Add(2 * time.Minute)
	manager.ObservePacket(netip.MustParseAddr("203.0.113.77"), netip.MustParseAddr("8.8.8.8"))

	now = now.Add(30 * time.Second)
	addr, ok := manager.Current()
	if !ok {
		t.Fatal("expected WAN IP to stay valid after seeing it in traffic")
	}
	if addr.String() != "203.0.113.77" {
		t.Fatalf("unexpected WAN IP: %s", addr)
	}
}

func TestManagerSkipsScheduledRefreshWhenCurrentIPWasRecentlyObserved(t *testing.T) {
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	var calls int
	provider := ProviderFunc(func(context.Context) (netip.Addr, error) {
		calls++
		return netip.MustParseAddr("203.0.113.77"), nil
	})
	manager := NewManager(provider, time.Minute)
	manager.now = func() time.Time { return now }

	if err := manager.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	manager.ObservePacket(netip.MustParseAddr("203.0.113.77"), netip.MustParseAddr("8.8.8.8"))

	now = now.Add(30 * time.Second)
	refreshed, err := manager.RefreshIfNeeded(context.Background())
	if err != nil {
		t.Fatalf("refresh if needed failed: %v", err)
	}
	if refreshed {
		t.Fatal("expected scheduled refresh to be skipped")
	}
	if calls != 1 {
		t.Fatalf("expected provider to be called once, got %d", calls)
	}
}

func TestHTTPProviderParsesPlainTextIP(t *testing.T) {
	provider := NewHTTPProvider("http://127.0.0.1/")
	addr, err := provider.parse([]byte(" 198.51.100.44\n"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if addr.String() != "198.51.100.44" {
		t.Fatalf("unexpected parsed IP: %s", addr)
	}
}
