package nexustransport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
)

func TestAuthAndTransportBoundary(t *testing.T) {
	session := ids.New(ids.KindSession)
	for _, a := range []Auth{{}, {Token: "x\n"}, {Token: "nta_fixture", Login: "login"}, {Token: "licence", Session: session}, {Token: "licence", Login: "login", Session: "bad"}} {
		if a.Validate() == nil {
			t.Fatal("accepted invalid auth")
		}
	}
	for _, endpoint := range []string{"http://example.com", "https://user@example.com", "https://example.com?", "https://example.com/#x", "https://example.com/%2f"} {
		if _, err := New(endpoint, Auth{Token: "fixture"}); err == nil {
			t.Fatal(endpoint)
		}
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer licence-fixture" || r.Header.Get("X-Newtype-Login") != "login-fixture" || r.Header.Get("X-Newtype-Session") != session {
			t.Error("auth missing")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	c, err := New(server.URL, Auth{Token: "licence-fixture", Login: "login-fixture", Session: session})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]bool
	if err = c.Do(context.Background(), "POST", "/v1/heartbeat", struct{}{}, &out); err != nil || !out["ok"] {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.Do(ctx, "GET", "/v1/peers", nil, &out) == nil {
		t.Fatal("cancel ignored")
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected request")
	}
}
func TestNoRedirectRetryOrErrorBody(t *testing.T) {
	var leak atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leak.Add(1) }))
	defer target.Close()
	for _, status := range []int{302, 401, 403, 409, 500} {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Location", target.URL)
			w.WriteHeader(status)
			w.Write([]byte("PRIVATE response body"))
		}))
		c, _ := New(server.URL, Auth{Token: "fixture"})
		var out json.RawMessage
		err := c.Do(context.Background(), "POST", "/v1/messages", struct{}{}, &out)
		server.Close()
		if err == nil || strings.Contains(err.Error(), "PRIVATE") || calls.Load() != 1 {
			t.Fatal("error or retry boundary", err)
		}
	}
	if leak.Load() != 0 {
		t.Fatal("redirect followed")
	}
}
func TestEncodedQueryCannotChangeRoute(t *testing.T) {
	value := "recipient&other=x?#/../"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/messages/event" || len(r.URL.Query()) != 1 || r.URL.Query().Get("to") != value {
			t.Error("query changed routing")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client, err := New(server.URL, Auth{Token: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]bool
	if err = client.Query(context.Background(), "/v1/messages/event", url.Values{"to": {value}}, &out); err != nil || !out["ok"] {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/messages/event?to=x", "/v1/../messages", "/other"} {
		if client.Query(context.Background(), path, nil, &out) == nil {
			t.Fatal("invalid route accepted")
		}
	}
}

func TestOversizedResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", (1<<20)+1))) }))
	defer s.Close()
	c, _ := New(s.URL, Auth{Token: "fixture"})
	var out any
	if c.Do(context.Background(), "GET", "/v1/peers", nil, &out) == nil {
		t.Fatal("accepted oversized response")
	}
}

// Self-host G5: http only for loopback development origins.
func TestBaseLoopbackHTTPOnly(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8080", "http://localhost:18480", "http://[::1]:9000"} {
		if _, err := Base(ok); err != nil {
			t.Fatalf("%s refused", ok)
		}
	}
	for _, bad := range []string{"http://example.com", "http://127.0.0.1.evil.com", "http://localhost.evil", "http://10.0.0.1"} {
		if _, err := Base(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}
