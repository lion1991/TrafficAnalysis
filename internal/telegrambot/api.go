package telegrambot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Update struct {
	ID      int     `json:"update_id"`
	Message Message `json:"message"`
}

type Message struct {
	Chat Chat   `json:"chat"`
	Text string `json:"text"`
}

type Chat struct {
	ID string `json:"id"`
}

func (c *Chat) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var text string
	if err := json.Unmarshal(raw.ID, &text); err == nil {
		c.ID = text
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(raw.ID, &number); err == nil {
		c.ID = number.String()
		return nil
	}
	return nil
}

type Receiver interface {
	GetUpdates(ctx context.Context, offset int, timeoutSeconds int) ([]Update, error)
}

type HTTPClient struct {
	token      string
	baseURL    string
	httpClient *http.Client
}

func NewHTTPClient(token string) *HTTPClient {
	return &HTTPClient{
		token:   token,
		baseURL: "https://api.telegram.org",
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (c *HTTPClient) SendMessage(ctx context.Context, chatID, text string) error {
	payload := map[string]string{
		"chat_id": chatID,
		"text":    trimTelegramMessage(text),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.methodURL("sendMessage"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TrafficAnalysis Telegram Bot")
	return c.do(req, nil)
}

func (c *HTTPClient) GetUpdates(ctx context.Context, offset int, timeoutSeconds int) ([]Update, error) {
	values := url.Values{}
	if offset > 0 {
		values.Set("offset", strconv.Itoa(offset))
	}
	if timeoutSeconds > 0 {
		values.Set("timeout", strconv.Itoa(timeoutSeconds))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.methodURL("getUpdates")+"?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TrafficAnalysis Telegram Bot")
	var updates []Update
	if err := c.do(req, &updates); err != nil {
		return nil, err
	}
	return updates, nil
}

func (c *HTTPClient) methodURL(method string) string {
	return strings.TrimRight(c.baseURL, "/") + "/bot" + c.token + "/" + method
}

func (c *HTTPClient) do(req *http.Request, result any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var envelope struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	if !envelope.OK {
		if envelope.Description == "" {
			envelope.Description = resp.Status
		}
		return fmt.Errorf("telegram api: %s", envelope.Description)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, result)
}

func trimTelegramMessage(text string) string {
	text = strings.TrimSpace(text)
	if len([]rune(text)) <= 4096 {
		return text
	}
	runes := []rune(text)
	return string(runes[:4090]) + "\n..."
}
