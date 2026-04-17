package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"
)

type Config struct {
	Interface     string      `json:"interface"`
	LANInterface  string      `json:"lan_interface"`
	Database      string      `json:"database"`
	BPF           string      `json:"bpf"`
	SnapshotLen   int         `json:"snapshot_len"`
	Promiscuous   bool        `json:"promiscuous"`
	BucketSeconds int         `json:"bucket_seconds"`
	FlushSeconds  int         `json:"flush_seconds"`
	LiveSeconds   int         `json:"live_seconds"`
	LocalNetworks []string    `json:"local_networks"`
	IgnoreLAN     bool        `json:"ignore_lan_traffic"`
	WANIP         WANIPConfig `json:"wan_ip"`
	Retention     Retention   `json:"retention"`
}

type WANIPConfig struct {
	HTTPURL        string `json:"http_url"`
	Static         string `json:"static"`
	RefreshSeconds int    `json:"refresh_seconds"`
}

type Retention struct {
	MinuteDays     int `json:"minute_days"`
	HourlyDays     int `json:"hourly_days"`
	CompactSeconds int `json:"compact_seconds"`
}

func Default() Config {
	return Config{
		Database:      "traffic.db",
		BPF:           "",
		SnapshotLen:   262144,
		Promiscuous:   true,
		BucketSeconds: 60,
		FlushSeconds:  10,
		LiveSeconds:   5,
		IgnoreLAN:     true,
		WANIP: WANIPConfig{
			HTTPURL:        "https://api.ipify.org",
			RefreshSeconds: 300,
		},
		Retention: Retention{
			MinuteDays:     30,
			HourlyDays:     365,
			CompactSeconds: 3600,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) applyDefaults() {
	defaults := Default()
	if c.Database == "" {
		c.Database = defaults.Database
	}
	if c.SnapshotLen <= 0 {
		c.SnapshotLen = defaults.SnapshotLen
	}
	if c.BucketSeconds <= 0 {
		c.BucketSeconds = defaults.BucketSeconds
	}
	if c.FlushSeconds <= 0 {
		c.FlushSeconds = defaults.FlushSeconds
	}
	if c.LiveSeconds < 0 {
		c.LiveSeconds = defaults.LiveSeconds
	}
	if c.WANIP.RefreshSeconds <= 0 {
		c.WANIP.RefreshSeconds = defaults.WANIP.RefreshSeconds
	}
	if c.Retention.MinuteDays <= 0 {
		c.Retention.MinuteDays = defaults.Retention.MinuteDays
	}
	if c.Retention.HourlyDays <= 0 {
		c.Retention.HourlyDays = defaults.Retention.HourlyDays
	}
	if c.Retention.CompactSeconds <= 0 {
		c.Retention.CompactSeconds = defaults.Retention.CompactSeconds
	}
}

func (c Config) ValidateForCapture() error {
	if c.Interface == "" {
		return errors.New("interface is required for live capture")
	}
	return nil
}

func (c Config) BucketDuration() time.Duration {
	return time.Duration(c.BucketSeconds) * time.Second
}

func (c Config) FlushInterval() time.Duration {
	return time.Duration(c.FlushSeconds) * time.Second
}

func (c Config) LiveInterval() time.Duration {
	return time.Duration(c.LiveSeconds) * time.Second
}

func (c Config) WANIPRefreshInterval() time.Duration {
	return time.Duration(c.WANIP.RefreshSeconds) * time.Second
}

func (r Retention) MinuteDuration() time.Duration {
	return time.Duration(r.MinuteDays) * 24 * time.Hour
}

func (r Retention) HourlyDuration() time.Duration {
	return time.Duration(r.HourlyDays) * 24 * time.Hour
}

func (r Retention) CompactInterval() time.Duration {
	return time.Duration(r.CompactSeconds) * time.Second
}

func ParseLocalNetworks(networks []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(networks))
	for _, network := range networks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil {
			return nil, fmt.Errorf("parse local_networks entry %q: %w", network, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
