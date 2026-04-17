package config

import (
	"net/netip"
	"testing"
)

func TestParseLocalNetworksParsesCIDRs(t *testing.T) {
	prefixes, err := ParseLocalNetworks([]string{"192.168.248.0/21"})
	if err != nil {
		t.Fatalf("parse local networks: %v", err)
	}
	if len(prefixes) != 1 {
		t.Fatalf("expected 1 prefix, got %d", len(prefixes))
	}
	if !prefixes[0].Contains(netip.MustParseAddr("192.168.252.1")) {
		t.Fatalf("expected prefix to contain LAN IP: %s", prefixes[0])
	}
}
