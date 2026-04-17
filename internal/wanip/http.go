package wanip

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"
)

type HTTPProvider struct {
	url    string
	client *http.Client
}

func NewHTTPProvider(url string) *HTTPProvider {
	return &HTTPProvider{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (p *HTTPProvider) CurrentIP(ctx context.Context) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return netip.Addr{}, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return netip.Addr{}, fmt.Errorf("WAN IP endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return netip.Addr{}, err
	}
	return p.parse(body)
}

func (p *HTTPProvider) parse(body []byte) (netip.Addr, error) {
	text := string(bytes.TrimSpace(body))
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse WAN IP %q: %w", text, err)
	}
	return addr, nil
}
