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
	Telegram      Telegram    `json:"telegram"`
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

type Telegram struct {
	Enabled     bool     `json:"enabled"`
	BotToken    string   `json:"bot_token"`
	ChatIDs     []string `json:"chat_ids"`
	PollSeconds int      `json:"poll_seconds"`
	DailyTime   string   `json:"daily_time"`
	Timezone    string   `json:"timezone"`
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
		Telegram: Telegram{
			PollSeconds: 30,
			DailyTime:   "08:00",
			Timezone:    "Local",
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
	if c.Telegram.PollSeconds <= 0 {
		c.Telegram.PollSeconds = defaults.Telegram.PollSeconds
	}
	if c.Telegram.DailyTime == "" {
		c.Telegram.DailyTime = defaults.Telegram.DailyTime
	}
	if c.Telegram.Timezone == "" {
		c.Telegram.Timezone = defaults.Telegram.Timezone
	}
}

func (c Config) ValidateForCapture() error {
	if c.Interface == "" {
		return errors.New("interface is required for live capture")
	}
	return nil
}

func (c Config) ValidateForTelegram() error {
	if !c.Telegram.Enabled {
		return nil
	}
	if c.Telegram.BotToken == "" {
		return errors.New("telegram.bot_token is required when telegram.enabled is true")
	}
	if len(c.Telegram.ChatIDs) == 0 {
		return errors.New("telegram.chat_ids is required when telegram.enabled is true")
	}
	if _, err := time.Parse("15:04", c.Telegram.DailyTime); err != nil {
		return fmt.Errorf("parse telegram.daily_time: %w", err)
	}
	if c.Telegram.Timezone != "Local" {
		if _, err := time.LoadLocation(c.Telegram.Timezone); err != nil {
			return fmt.Errorf("load telegram.timezone: %w", err)
		}
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

func (t Telegram) PollInterval() time.Duration {
	return time.Duration(t.PollSeconds) * time.Second
}

func (t Telegram) Location() (*time.Location, error) {
	if t.Timezone == "" || t.Timezone == "Local" {
		return time.Local, nil
	}
	return time.LoadLocation(t.Timezone)
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
