package telegrambot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClientSendMessagePostsJSON(t *testing.T) {
	var requestBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot123:abc/sendMessage" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer server.Close()

	client := NewHTTPClient("123:abc")
	client.baseURL = server.URL
	if err := client.SendMessage(context.Background(), "1001", "hello"); err != nil {
		t.Fatalf("send message: %v", err)
	}
	if requestBody["chat_id"] != "1001" || requestBody["text"] != "hello" {
		t.Fatalf("unexpected request body: %#v", requestBody)
	}
}

func TestHTTPClientGetUpdatesUsesOffsetAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot123:abc/getUpdates" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("offset") != "42" || r.URL.Query().Get("timeout") != "30" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":42,"message":{"chat":{"id":1001},"text":"/today"}}]}`))
	}))
	defer server.Close()

	client := NewHTTPClient("123:abc")
	client.baseURL = server.URL
	updates, err := client.GetUpdates(context.Background(), 42, 30)
	if err != nil {
		t.Fatalf("get updates: %v", err)
	}
	if len(updates) != 1 || updates[0].ID != 42 || updates[0].Message.Text != "/today" || updates[0].Message.Chat.ID != "1001" {
		t.Fatalf("unexpected updates: %#v", updates)
	}
}
