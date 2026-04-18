package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestDefaultRetentionPolicyCompactsAndArchivesLongRunningData(t *testing.T) {
	cfg := Default()

	if cfg.Retention.MinuteDays != 30 {
		t.Fatalf("expected 30 day minute retention, got %d", cfg.Retention.MinuteDays)
	}
	if cfg.Retention.HourlyDays != 365 {
		t.Fatalf("expected 365 day hourly retention, got %d", cfg.Retention.HourlyDays)
	}
	if cfg.Retention.CompactSeconds != 3600 {
		t.Fatalf("expected hourly compaction, got %d", cfg.Retention.CompactSeconds)
	}
	if cfg.Retention.MinuteDuration() != 30*24*time.Hour {
		t.Fatalf("unexpected minute retention duration: %s", cfg.Retention.MinuteDuration())
	}
}

func TestLoadAppliesRetentionDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"database":"traffic.db"}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Retention.MinuteDays != 30 || cfg.Retention.HourlyDays != 365 || cfg.Retention.CompactSeconds != 3600 {
		t.Fatalf("expected retention defaults, got %#v", cfg.Retention)
	}
}

func TestLoadAppliesTelegramDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"database":"traffic.db","telegram":{"enabled":true,"bot_token":"123:abc","chat_ids":["1001"]}}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.Telegram.Enabled {
		t.Fatal("expected telegram to be enabled")
	}
	if cfg.Telegram.PollSeconds != 30 {
		t.Fatalf("expected default telegram poll interval, got %d", cfg.Telegram.PollSeconds)
	}
	if cfg.Telegram.DailyTime != "08:00" {
		t.Fatalf("expected default daily time, got %q", cfg.Telegram.DailyTime)
	}
	if cfg.Telegram.Timezone != "Local" {
		t.Fatalf("expected default timezone, got %q", cfg.Telegram.Timezone)
	}
}

func TestValidateForTelegramRequiresTokenAndChatIDsWhenEnabled(t *testing.T) {
	cfg := Default()
	cfg.Telegram.Enabled = true

	err := cfg.ValidateForTelegram()
	if err == nil {
		t.Fatal("expected missing telegram token/chat id to fail")
	}

	cfg.Telegram.BotToken = "123:abc"
	cfg.Telegram.ChatIDs = []string{"1001"}
	if err := cfg.ValidateForTelegram(); err != nil {
		t.Fatalf("expected valid telegram config, got %v", err)
	}
}
