package config

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

type Config struct {
	Interface     string      `json:"interface"`
	Database      string      `json:"database"`
	BPF           string      `json:"bpf"`
	SnapshotLen   int         `json:"snapshot_len"`
	Promiscuous   bool        `json:"promiscuous"`
	BucketSeconds int         `json:"bucket_seconds"`
	FlushSeconds  int         `json:"flush_seconds"`
	LiveSeconds   int         `json:"live_seconds"`
	WANIP         WANIPConfig `json:"wan_ip"`
}

type WANIPConfig struct {
	HTTPURL        string `json:"http_url"`
	Static         string `json:"static"`
	RefreshSeconds int    `json:"refresh_seconds"`
}

func Default() Config {
	return Config{
		Database:      "traffic.db",
		BPF:           "ip or ip6",
		SnapshotLen:   262144,
		Promiscuous:   true,
		BucketSeconds: 60,
		FlushSeconds:  10,
		LiveSeconds:   5,
		WANIP: WANIPConfig{
			HTTPURL:        "https://api.ipify.org",
			RefreshSeconds: 300,
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
	if c.BPF == "" {
		c.BPF = defaults.BPF
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
