package wanip

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

type StaticProvider struct {
	addr netip.Addr
}

func NewStaticProvider(ip string) (StaticProvider, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return StaticProvider{}, err
	}
	return StaticProvider{addr: addr}, nil
}

func (p StaticProvider) CurrentIP(context.Context) (netip.Addr, error) {
	return p.addr, nil
}

type ChainProvider struct {
	providers []Provider
}

func NewChainProvider(providers ...Provider) ChainProvider {
	return ChainProvider{providers: providers}
}

func (p ChainProvider) CurrentIP(ctx context.Context) (netip.Addr, error) {
	var errs []error
	for _, provider := range p.providers {
		if provider == nil {
			continue
		}
		addr, err := provider.CurrentIP(ctx)
		if err == nil && addr.IsValid() {
			return addr, nil
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return netip.Addr{}, errors.New("no WAN IP providers configured")
	}
	return netip.Addr{}, fmt.Errorf("all WAN IP providers failed: %w", errors.Join(errs...))
}
