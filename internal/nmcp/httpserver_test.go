package nmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/internal/nexusops"
	"github.com/newtype-ai-com/nexus/internal/nexusops/nexusopstest"
)

type httpClient struct {
	t     *testing.T
	url   string
	token string
	sid   string
}

func startHTTP(t *testing.T, tools map[string]Caller) (*httptest.Server, *HTTPHandler) {
	t.Helper()
	h := &HTTPHandler{
		Authenticate: func(r *http.Request) (string, bool) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			_, ok := tools[tok]
			return tok, ok
		},
		Challenge: `Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource/mcp"`,
		NewServer: func(_ context.Context, owner string) (*Server, error) {
			return &Server{Tools: tools[owner], Name: "newtype-nexus", Version: "test", Diag: io.Discard}, nil
		},
		Origins:   []string{"https://claude.ai"},
		Heartbeat: 50 * time.Millisecond,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(func() { h.Close(); srv.Close() })
	return srv, h
}

func (c *httpClient) do(ctx context.Context, method string, body any, hdr map[string]string) *http.Response {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequestWithContext(ctx, method, c.url, rd)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	if c.sid != "" {
		req.Header.Set("Mcp-Session-Id", c.sid)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp
}

// events reads SSE "data:" payloads (one JSON-RPC message each).
func events(resp *http.Response) <-chan map[string]json.RawMessage {
	ch := make(chan map[string]json.RawMessage, 16)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var m map[string]json.RawMessage
				if json.Unmarshal([]byte(v), &m) == nil {
					ch <- m
				}
			}
		}
	}()
	return ch
}

func next(t *testing.T, ch <-chan map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	select {
	case m, ok := <-ch:
		if !ok {
			t.Fatal("stream ended")
		}
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
	}
	return nil
}

func (c *httpClient) initialize(caps map[string]any) {
	c.t.Helper()
	resp := c.do(context.Background(), "POST", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-11-25", "capabilities": caps}}, nil)
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Mcp-Session-Id") == "" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		c.t.Fatalf("initialize %d %v", resp.StatusCode, resp.Header)
	}
	c.sid = resp.Header.Get("Mcp-Session-Id")
	n := c.do(context.Background(), "POST", map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, nil)
	n.Body.Close()
	if n.StatusCode != http.StatusAccepted {
		c.t.Fatalf("notification %d", n.StatusCode)
	}
}

// call sends tools/call and returns the final response (SSE).
func (c *httpClient) call(id int, name, args string) map[string]json.RawMessage {
	c.t.Helper()
	resp := c.do(context.Background(), "POST", map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": json.RawMessage(args)}}, nil)
	defer resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		c.t.Fatalf("tools/call content type %q", resp.Header.Get("Content-Type"))
	}
	return next(c.t, events(resp))
}

func TestHTTPTransportSameContract(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	c := attach(t, f, "remote-claude", seatRoot)
	other := attach(t, f, "other", seatRoot)
	srv, _ := startHTTP(t, map[string]Caller{"tok-a": c, "tok-b": other})
	cl := &httpClient{t: t, url: srv.URL, token: "tok-a"}

	// unauthenticated → 401 with the resource metadata challenge
	bad := &httpClient{t: t, url: srv.URL, token: "nope"}
	r := bad.do(ctx, "POST", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, nil)
	r.Body.Close()
	if r.StatusCode != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("401 %d %q", r.StatusCode, r.Header.Get("WWW-Authenticate"))
	}
	// a foreign browser origin → 403
	r = cl.do(ctx, "POST", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, map[string]string{"Origin": "https://evil.example"})
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatalf("origin %d", r.StatusCode)
	}

	cl.initialize(map[string]any{})
	if res := cl.call(2, "delegation_info", `{}`); !strings.Contains(string(res["result"]), "session:delegate") {
		t.Fatalf("delegation_info %s", res["result"])
	}
	// another owner cannot use this session ID; an unknown one is 404
	thief := &httpClient{t: t, url: srv.URL, token: "tok-b", sid: cl.sid}
	r = thief.do(ctx, "POST", map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, nil)
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatalf("foreign session %d", r.StatusCode)
	}
	// a message is read only once the SSE response was written
	sent, err := other.Seat.Send(ctx, "remote-claude", "hello over http", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if res := cl.call(4, "nexus_inbox", `{}`); !strings.Contains(string(res["result"]), "hello over http") {
		t.Fatalf("inbox %s", res["result"])
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, read := readAt(t, f, c.Seat.ID, sent.Event); read {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read not recorded after delivery")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// DELETE ends the session
	r = cl.do(ctx, "DELETE", nil, nil)
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", r.StatusCode)
	}
	r = cl.do(ctx, "POST", map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/list"}, nil)
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatalf("after delete %d", r.StatusCode)
	}
}

// A client that leaves while nexus_inbox waits gets no response and nothing
// that arrives afterwards is marked delivered or read.
func TestHTTPDisconnectedCallMarksNothing(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	c := attach(t, f, "remote-claude", seatRoot)
	other := attach(t, f, "other", seatRoot)
	srv, _ := startHTTP(t, map[string]Caller{"tok-a": c})
	cl := &httpClient{t: t, url: srv.URL, token: "tok-a"}
	cl.initialize(map[string]any{})
	callCtx, cancel := context.WithCancel(ctx)
	resp := cl.do(callCtx, "POST", map[string]any{"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": map[string]any{"name": "nexus_inbox", "arguments": map[string]int{"wait_seconds": 30}}}, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("long call did not open its stream: %d", resp.StatusCode)
	}
	go func() { io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	time.Sleep(300 * time.Millisecond)
	sent, err := other.Seat.Send(ctx, "remote-claude", "too late", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if d, r := readAt(t, f, c.Seat.ID, sent.Event); d || r {
		t.Fatalf("disconnected call recorded delivered=%v read=%v", d, r)
	}
}

// Elicitation travels on the POST stream; the client's answer is a POST (202).
func TestHTTPElicitationOnThePostStream(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	c := attach(t, f, "remote-claude", seatRoot)
	srv, _ := startHTTP(t, map[string]Caller{"tok-a": c})
	cl := &httpClient{t: t, url: srv.URL, token: "tok-a"}
	cl.initialize(map[string]any{"elicitation": map[string]any{}})
	resp := cl.do(ctx, "POST", map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": "request_approval", "arguments": map[string]string{"action": "tool:shell", "reason": "build"}}}, nil)
	defer resp.Body.Close()
	ch := events(resp)
	ask := next(t, ch)
	if method(ask) != "elicitation/create" {
		t.Fatalf("expected elicitation, got %v", ask)
	}
	ans := cl.do(ctx, "POST", map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(ask["id"]), "result": map[string]any{"action": "accept", "content": map[string]string{"decision": "once"}}}, nil)
	ans.Body.Close()
	if ans.StatusCode != http.StatusAccepted {
		t.Fatalf("answer %d", ans.StatusCode)
	}
	final := next(t, ch)
	if string(final["id"]) != "7" || !strings.Contains(string(final["result"]), "approved") {
		t.Fatalf("final %v", final)
	}
}

// Notifications with no open POST go to the GET stream and resume by Last-Event-ID.
func TestHTTPGetStreamCarriesInboxUpdates(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	c := attach(t, f, "remote-claude", seatRoot)
	other := attach(t, f, "other", seatRoot)
	srv, _ := startHTTP(t, map[string]Caller{"tok-a": c})
	cl := &httpClient{t: t, url: srv.URL, token: "tok-a"}
	cl.initialize(map[string]any{})
	sub := cl.do(ctx, "POST", map[string]any{"jsonrpc": "2.0", "id": 2, "method": "resources/subscribe", "params": map[string]string{"uri": inboxURI}}, nil)
	sub.Body.Close()
	time.Sleep(200 * time.Millisecond)
	if _, err := other.Seat.Send(ctx, "remote-claude", "ping via stream", false, "", ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // no GET open yet: kept for resume
	getCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g := cl.do(getCtx, "GET", nil, map[string]string{"Accept": "text/event-stream", "Last-Event-ID": "0"})
	defer g.Body.Close()
	m := next(t, events(g))
	if method(m) != "notifications/resources/updated" || strings.Contains(string(m["params"]), "ping via stream") {
		t.Fatalf("update %v", m)
	}
	var _ nexusops.InboxPeek
}
