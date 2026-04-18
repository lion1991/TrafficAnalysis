package telegrambot

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"trafficanalysis/internal/store"
	"trafficanalysis/internal/traffic"
)

type fakeStore struct {
	from         time.Time
	to           time.Time
	trafficRows  []store.BucketRow
	clientRows   []store.ClientBucketRow
	endpointRows []store.EndpointBucketRow
}

func (f *fakeStore) QueryBuckets(ctx context.Context, from, to time.Time) ([]store.BucketRow, error) {
	f.from = from
	f.to = to
	return f.trafficRows, nil
}

func (f *fakeStore) QueryClientBuckets(ctx context.Context, from, to time.Time, clientIP string) ([]store.ClientBucketRow, error) {
	f.from = from
	f.to = to
	return f.clientRows, nil
}

func (f *fakeStore) QueryEndpointBuckets(ctx context.Context, from, to time.Time) ([]store.EndpointBucketRow, error) {
	f.from = from
	f.to = to
	return f.endpointRows, nil
}

type fakeSender struct {
	chatID string
	text   string
}

func (f *fakeSender) SendMessage(ctx context.Context, chatID, text string) error {
	f.chatID = chatID
	f.text = text
	return nil
}

func TestHandleYesterdayCommandSendsPreviousLocalDaySummary(t *testing.T) {
	location := time.FixedZone("UTC+8", 8*60*60)
	fakeStore := &fakeStore{
		trafficRows: []store.BucketRow{
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 1, 0, 0, 0, time.UTC),
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 2048, Packets: 2},
			},
			{
				Key: traffic.BucketKey{
					Start:     time.Date(2026, 4, 17, 1, 0, 0, 0, time.UTC),
					Direction: traffic.DirectionDownload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 4096, Packets: 4},
			},
		},
		clientRows: []store.ClientBucketRow{
			{
				Key: traffic.ClientBucketKey{
					Start:     time.Date(2026, 4, 17, 1, 0, 0, 0, time.UTC),
					ClientIP:  netip.MustParseAddr("192.168.248.22"),
					ClientMAC: "00:11:22:33:44:55",
					Direction: traffic.DirectionUpload,
					Protocol:  "tcp",
				},
				Value: traffic.BucketValue{Bytes: 2048, Packets: 2},
				Alias: "书房 NAS",
			},
		},
		endpointRows: []store.EndpointBucketRow{
			{
				Key: traffic.EndpointBucketKey{
					Start:      time.Date(2026, 4, 17, 1, 0, 0, 0, time.UTC),
					ClientIP:   netip.MustParseAddr("192.168.248.22"),
					ClientMAC:  "00:11:22:33:44:55",
					RemoteIP:   netip.MustParseAddr("203.0.113.9"),
					RemotePort: 443,
					Direction:  traffic.DirectionUpload,
					Protocol:   "tcp",
				},
				Value: traffic.BucketValue{Bytes: 1024, Packets: 1},
			},
		},
	}
	sender := &fakeSender{}
	bot := New(Config{
		ChatIDs:  []string{"1001"},
		Location: location,
		Now:      func() time.Time { return time.Date(2026, 4, 18, 9, 30, 0, 0, location) },
	}, fakeStore, sender)

	if err := bot.HandleText(context.Background(), "1001", "/yesterday"); err != nil {
		t.Fatalf("handle command: %v", err)
	}

	if sender.chatID != "1001" {
		t.Fatalf("unexpected chat id: %q", sender.chatID)
	}
	if fakeStore.from != time.Date(2026, 4, 16, 16, 0, 0, 0, time.UTC) || fakeStore.to != time.Date(2026, 4, 17, 16, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected query range: from=%s to=%s", fakeStore.from, fakeStore.to)
	}
	for _, want := range []string{"2026-04-17", "上传 2.00 KiB", "下载 4.00 KiB", "书房 NAS", "203.0.113.9:443/tcp"} {
		if !strings.Contains(sender.text, want) {
			t.Fatalf("expected message to contain %q, got %q", want, sender.text)
		}
	}
}

func TestHandleTextRejectsUnauthorizedChat(t *testing.T) {
	bot := New(Config{ChatIDs: []string{"1001"}}, &fakeStore{}, &fakeSender{})

	if err := bot.HandleText(context.Background(), "2002", "/today"); err != nil {
		t.Fatalf("handle unauthorized command: %v", err)
	}
}

func TestNextDailyRunUsesConfiguredLocalTime(t *testing.T) {
	location := time.FixedZone("UTC+8", 8*60*60)
	now := time.Date(2026, 4, 18, 7, 30, 0, 0, location)
	next, err := NextDailyRun(now, "08:00", location)
	if err != nil {
		t.Fatalf("next run: %v", err)
	}
	if next != time.Date(2026, 4, 18, 8, 0, 0, 0, location) {
		t.Fatalf("unexpected same-day run: %s", next)
	}

	next, err = NextDailyRun(time.Date(2026, 4, 18, 8, 30, 0, 0, location), "08:00", location)
	if err != nil {
		t.Fatalf("next run after configured time: %v", err)
	}
	if next != time.Date(2026, 4, 19, 8, 0, 0, 0, location) {
		t.Fatalf("unexpected next-day run: %s", next)
	}
}
