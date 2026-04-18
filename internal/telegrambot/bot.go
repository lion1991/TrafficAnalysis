package telegrambot

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"trafficanalysis/internal/store"
	"trafficanalysis/internal/traffic"
)

type TrafficStore interface {
	QueryBuckets(ctx context.Context, from, to time.Time) ([]store.BucketRow, error)
	QueryClientBuckets(ctx context.Context, from, to time.Time, clientIP string) ([]store.ClientBucketRow, error)
	QueryEndpointBuckets(ctx context.Context, from, to time.Time) ([]store.EndpointBucketRow, error)
}

type Sender interface {
	SendMessage(ctx context.Context, chatID, text string) error
}

type Config struct {
	ChatIDs      []string
	PollInterval time.Duration
	DailyTime    string
	Location     *time.Location
	Now          func() time.Time
}

type Bot struct {
	cfg     Config
	store   TrafficStore
	sender  Sender
	allowed map[string]struct{}
}

func New(cfg Config, st TrafficStore, sender Sender) *Bot {
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.DailyTime == "" {
		cfg.DailyTime = "08:00"
	}
	allowed := make(map[string]struct{}, len(cfg.ChatIDs))
	for _, chatID := range cfg.ChatIDs {
		chatID = strings.TrimSpace(chatID)
		if chatID != "" {
			allowed[chatID] = struct{}{}
		}
	}
	return &Bot{
		cfg:     cfg,
		store:   st,
		sender:  sender,
		allowed: allowed,
	}
}

func (b *Bot) HandleText(ctx context.Context, chatID, text string) error {
	if !b.isAllowed(chatID) {
		return nil
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	var (
		title string
		from  time.Time
		to    time.Time
		err   error
	)
	now := b.cfg.Now().In(b.cfg.Location)
	parts := strings.Fields(strings.TrimPrefix(text, "/"))
	command := strings.ToLower(strings.TrimPrefix(parts[0], "/"))
	if at := strings.Index(command, "@"); at >= 0 {
		command = command[:at]
	}

	switch command {
	case "help", "start":
		return b.sender.SendMessage(ctx, chatID, helpText())
	case "traffic", "today":
		start := beginningOfLocalDay(now, b.cfg.Location)
		from, to = start.UTC(), now.UTC()
		title = "今日流量"
	case "yesterday":
		day := beginningOfLocalDay(now, b.cfg.Location).AddDate(0, 0, -1)
		from, to = day.UTC(), day.AddDate(0, 0, 1).UTC()
		title = day.Format("2006-01-02") + " 流量"
	case "last":
		durationText := "24h"
		if len(parts) > 1 {
			durationText = parts[1]
		}
		duration, parseErr := parseDurationArg(durationText)
		if parseErr != nil {
			return b.sender.SendMessage(ctx, chatID, "无法识别时间范围。示例：/last 1h、/last 24h、/last 7d")
		}
		from, to = now.Add(-duration).UTC(), now.UTC()
		title = "最近 " + durationText + " 流量"
	default:
		return b.sender.SendMessage(ctx, chatID, helpText())
	}
	if err != nil {
		return err
	}

	message, err := b.buildSummary(ctx, title, from, to)
	if err != nil {
		return err
	}
	return b.sender.SendMessage(ctx, chatID, message)
}

func (b *Bot) SendYesterdaySummary(ctx context.Context, chatID string, now time.Time) error {
	if !b.isAllowed(chatID) {
		return nil
	}
	localNow := now.In(b.cfg.Location)
	day := beginningOfLocalDay(localNow, b.cfg.Location).AddDate(0, 0, -1)
	message, err := b.buildSummary(ctx, day.Format("2006-01-02")+" 流量", day.UTC(), day.AddDate(0, 0, 1).UTC())
	if err != nil {
		return err
	}
	return b.sender.SendMessage(ctx, chatID, message)
}

func (b *Bot) Run(ctx context.Context, receiver Receiver) error {
	go b.runDaily(ctx)

	offset := 0
	timeoutSeconds := int(b.cfg.PollInterval.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		updates, err := receiver.GetUpdates(ctx, offset, timeoutSeconds)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			wait := b.cfg.PollInterval
			if wait > 10*time.Second {
				wait = 10 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
				continue
			}
		}

		for _, update := range updates {
			if update.ID >= offset {
				offset = update.ID + 1
			}
			if update.Message.Text == "" || update.Message.Chat.ID == "" {
				continue
			}
			_ = b.HandleText(ctx, update.Message.Chat.ID, update.Message.Text)
		}
	}
}

func (b *Bot) runDaily(ctx context.Context) {
	for {
		now := time.Now().In(b.cfg.Location)
		next, err := NextDailyRun(now, b.cfg.DailyTime, b.cfg.Location)
		if err != nil {
			return
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case runAt := <-timer.C:
			for _, chatID := range b.cfg.ChatIDs {
				_ = b.SendYesterdaySummary(ctx, chatID, runAt)
			}
		}
	}
}

func (b *Bot) buildSummary(ctx context.Context, title string, from, to time.Time) (string, error) {
	trafficRows, err := b.store.QueryBuckets(ctx, from, to)
	if err != nil {
		return "", err
	}
	clientRows, err := b.store.QueryClientBuckets(ctx, from, to, "")
	if err != nil {
		return "", err
	}
	endpointRows, err := b.store.QueryEndpointBuckets(ctx, from, to)
	if err != nil {
		return "", err
	}

	totals := summarizeTraffic(trafficRows)
	clients := topClientUploads(clientRows, 5)
	endpoints := topRemoteEndpoints(endpointRows, 5)

	var builder strings.Builder
	builder.WriteString(title)
	builder.WriteByte('\n')
	builder.WriteString(fmt.Sprintf("范围 %s 到 %s\n", formatLocalTime(from, b.cfg.Location), formatLocalTime(to, b.cfg.Location)))
	builder.WriteString(fmt.Sprintf("上传 %s，下载 %s，包 %s\n", formatBytes(totals.upload), formatBytes(totals.download), strconv.FormatInt(totals.packets, 10)))
	if totals.upload+totals.download > 0 {
		builder.WriteString(fmt.Sprintf("上传占比 %s\n", formatPercent(float64(totals.upload)/float64(totals.upload+totals.download))))
	}

	builder.WriteString("\n上传客户端 Top 5\n")
	if len(clients) == 0 {
		builder.WriteString("暂无客户端数据\n")
	} else {
		for index, client := range clients {
			builder.WriteString(fmt.Sprintf("%d. %s %s\n", index+1, client.name, formatBytes(client.upload)))
		}
	}

	builder.WriteString("\n远程 IP Top 5\n")
	if len(endpoints) == 0 {
		builder.WriteString("暂无远程 IP 数据\n")
	} else {
		for index, endpoint := range endpoints {
			builder.WriteString(fmt.Sprintf("%d. %s:%d/%s 上传 %s 下载 %s\n", index+1, endpoint.remoteIP, endpoint.remotePort, endpoint.protocol, formatBytes(endpoint.upload), formatBytes(endpoint.download)))
		}
	}

	return builder.String(), nil
}

func (b *Bot) isAllowed(chatID string) bool {
	_, ok := b.allowed[strings.TrimSpace(chatID)]
	return ok
}

func helpText() string {
	return strings.Join([]string{
		"TrafficAnalysis 快速查询",
		"/traffic 或 /today：今日流量",
		"/yesterday：昨天流量",
		"/last 1h：最近 1 小时",
		"/last 24h：最近 24 小时",
		"/last 7d：最近 7 天",
	}, "\n")
}

type trafficTotals struct {
	upload   int64
	download int64
	packets  int64
}

func summarizeTraffic(rows []store.BucketRow) trafficTotals {
	var totals trafficTotals
	for _, row := range rows {
		switch row.Key.Direction {
		case traffic.DirectionUpload:
			totals.upload += row.Value.Bytes
		case traffic.DirectionDownload:
			totals.download += row.Value.Bytes
		}
		totals.packets += row.Value.Packets
	}
	return totals
}

type clientUpload struct {
	name   string
	upload int64
}

func topClientUploads(rows []store.ClientBucketRow, limit int) []clientUpload {
	byClient := make(map[string]clientUpload)
	for _, row := range rows {
		if row.Key.Direction != traffic.DirectionUpload {
			continue
		}
		clientKey := row.Key.ClientIP.String() + "\x00" + row.Key.ClientMAC
		current := byClient[clientKey]
		if current.name == "" {
			current.name = displayClientName(row)
		}
		current.upload += row.Value.Bytes
		byClient[clientKey] = current
	}
	result := make([]clientUpload, 0, len(byClient))
	for _, row := range byClient {
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].upload != result[j].upload {
			return result[i].upload > result[j].upload
		}
		return result[i].name < result[j].name
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func displayClientName(row store.ClientBucketRow) string {
	if strings.TrimSpace(row.Alias) != "" {
		return strings.TrimSpace(row.Alias)
	}
	if strings.TrimSpace(row.Name) != "" {
		return strings.TrimSpace(row.Name)
	}
	if row.Key.ClientMAC != "" {
		return row.Key.ClientMAC
	}
	return row.Key.ClientIP.String()
}

type remoteEndpoint struct {
	remoteIP   string
	remotePort uint16
	protocol   string
	upload     int64
	download   int64
}

func topRemoteEndpoints(rows []store.EndpointBucketRow, limit int) []remoteEndpoint {
	byEndpoint := make(map[string]remoteEndpoint)
	for _, row := range rows {
		key := row.Key.RemoteIP.String() + "\x00" + strconv.Itoa(int(row.Key.RemotePort)) + "\x00" + row.Key.Protocol
		current := byEndpoint[key]
		current.remoteIP = row.Key.RemoteIP.String()
		current.remotePort = row.Key.RemotePort
		current.protocol = row.Key.Protocol
		switch row.Key.Direction {
		case traffic.DirectionUpload:
			current.upload += row.Value.Bytes
		case traffic.DirectionDownload:
			current.download += row.Value.Bytes
		}
		byEndpoint[key] = current
	}
	result := make([]remoteEndpoint, 0, len(byEndpoint))
	for _, row := range byEndpoint {
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].upload + result[i].download
		right := result[j].upload + result[j].download
		if left != right {
			return left > right
		}
		if result[i].remoteIP != result[j].remoteIP {
			return result[i].remoteIP < result[j].remoteIP
		}
		if result[i].remotePort != result[j].remotePort {
			return result[i].remotePort < result[j].remotePort
		}
		return result[i].protocol < result[j].protocol
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func parseDurationArg(text string) (time.Duration, error) {
	if strings.HasSuffix(text, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(text, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day duration")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(text)
}

func beginningOfLocalDay(t time.Time, location *time.Location) time.Time {
	local := t.In(location)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location)
}

func formatLocalTime(t time.Time, location *time.Location) string {
	return t.In(location).Format("2006-01-02 15:04")
}

func formatPercent(value float64) string {
	return strconv.FormatFloat(value*100, 'f', 1, 64) + "%"
}

func formatBytes(bytes int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(bytes)
	unit := units[0]
	for index := 1; index < len(units) && value >= 1024; index++ {
		value /= 1024
		unit = units[index]
	}
	if unit == "B" {
		return strconv.FormatInt(bytes, 10) + " B"
	}
	return strconv.FormatFloat(value, 'f', 2, 64) + " " + unit
}

func NextDailyRun(now time.Time, dailyTime string, location *time.Location) (time.Time, error) {
	if location == nil {
		location = time.Local
	}
	parsed, err := time.Parse("15:04", dailyTime)
	if err != nil {
		return time.Time{}, err
	}
	localNow := now.In(location)
	next := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), parsed.Hour(), parsed.Minute(), 0, 0, location)
	if !next.After(localNow) {
		next = next.AddDate(0, 0, 1)
	}
	return next, nil
}
