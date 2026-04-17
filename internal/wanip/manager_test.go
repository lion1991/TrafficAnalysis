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
