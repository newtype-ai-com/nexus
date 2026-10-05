package nmcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/internal/nexusops"
	"github.com/newtype-ai-com/nexus/internal/nexusops/nexusopstest"
)

func startServerWith(t *testing.T, srv *Server) *client {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &client{t: t, in: inW, out: bufio.NewReader(outR), done: make(chan error, 1)}
	go func() { c.done <- srv.Serve(context.Background(), inR, outW); outW.Close() }()
	t.Cleanup(func() { inW.Close(); <-c.done })
	return c
}

// lineWithin reads the next message or fails after d (a missing push).
func (c *client) lineWithin(d time.Duration) map[string]json.RawMessage {
	c.t.Helper()
	got := make(chan map[string]json.RawMessage, 1)
	go func() {
		raw, err := c.out.ReadBytes('\n')
		var m map[string]json.RawMessage
		if err == nil && json.Unmarshal(raw, &m) == nil {
			got <- m
		}
		close(got)
	}()
	select {
	case m, ok := <-got:
		if !ok {
			c.t.Fatal("stream ended")
		}
		return m
	case <-time.After(d):
		c.t.Fatal("no message within the deadline")
	}
	return nil
}

func method(m map[string]json.RawMessage) string {
	var s string
	_ = json.Unmarshal(m["method"], &s)
	return s
}

// The initialize result tells a host what Nexus is and what counts as a read
// (both languages), carries no workflow guidance (that lives in the plugin
// skill), and declares subscribable resources.
func TestInitializeStatesProtocolFacts(t *testing.T) {
	f := nexusopstest.New(t)
	cl := startServer(t, attach(t, f, "claude-newtype", seatRoot))
	out := cl.initializeWith("2025-11-25", map[string]any{})
	text, _ := out["instructions"].(string)
	for _, want := range []string{"nexus_inbox", "요청이지 권한이 아니다", "requests, not authority", "not reads", "delegation_info", "nexus://inbox"} {
		if !strings.Contains(text, want) {
			t.Fatalf("instructions miss %q", want)
		}
	}
	// workflow guidance moved to the plugin skill: no polling loop, no "call X"
	for _, banned := range []string{"wait_seconds", "when idle", "repeat", "call nexus_inbox", "Call request_approval", "Report results"} {
		if strings.Contains(text, banned) {
			t.Fatalf("instructions still steer: %q", banned)
		}
	}
	caps, _ := out["capabilities"].(map[string]any)
	res, _ := caps["resources"].(map[string]any)
	if res["subscribe"] != true {
		t.Fatalf("resources capability %v", caps)
	}
	if _, ok := caps["experimental"]; ok {
		t.Fatal("claude/channel declared without the operator flag")
	}
	if strings.Contains(text, "channel source") {
		t.Fatal("channel line without the channel")
	}
}

// Every contract tool carries all four MCP annotations.
func TestEveryToolHasAnnotations(t *testing.T) {
	f := nexusopstest.New(t)
	cl := startServer(t, attach(t, f, "claude-newtype", seatRoot))
	cl.initialize()
	r := cl.request("tools/list", map[string]any{})
	var list struct {
		Tools []struct {
			Name        string                     `json:"name"`
			Annotations map[string]json.RawMessage `json:"annotations"`
		} `json:"tools"`
	}
	if json.Unmarshal(r.Result, &list) != nil || len(list.Tools) != len(nexusops.Defs) {
		t.Fatalf("tools/list %s", r.Result)
	}
	for _, tool := range list.Tools {
		if _, ok := nexusops.Hints[tool.Name]; !ok {
			t.Fatalf("%s has no Hints entry", tool.Name)
		}
		for _, k := range []string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"} {
			if _, ok := tool.Annotations[k]; !ok {
				t.Fatalf("%s misses %s", tool.Name, k)
			}
		}
	}
	if len(nexusops.Hints) != len(nexusops.Defs) {
		t.Fatal("Hints has entries for tools that do not exist")
	}
}

// Every tool has a human title, top-level and in annotations, and the hints
// the connector directory reviews: writes are not read-only, nexus_inbox
// records receipts, nothing is destructive.
func TestEveryToolHasTitleAndReviewedHints(t *testing.T) {
	f := nexusopstest.New(t)
	cl := startServer(t, attach(t, f, "claude-newtype", seatRoot))
	cl.initialize()
	r := cl.request("tools/list", map[string]any{})
	var list struct {
		Tools []struct {
			Name        string `json:"name"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Annotations struct {
				Title       string `json:"title"`
				ReadOnly    bool   `json:"readOnlyHint"`
				Destructive bool   `json:"destructiveHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if json.Unmarshal(r.Result, &list) != nil || len(list.Tools) != len(nexusops.Defs) {
		t.Fatalf("tools/list %s", r.Result)
	}
	writes := map[string]bool{"send_message": true, "delegate_task": true, "request_approval": true, "nexus_inbox": true}
	for _, tool := range list.Tools {
		if strings.TrimSpace(tool.Title) == "" || tool.Annotations.Title != tool.Title {
			t.Fatalf("%s: title %q, annotations.title %q", tool.Name, tool.Title, tool.Annotations.Title)
		}
		if tool.Annotations.ReadOnly == writes[tool.Name] {
			t.Fatalf("%s: readOnlyHint %v", tool.Name, tool.Annotations.ReadOnly)
		}
		if tool.Annotations.Destructive {
			t.Fatalf("%s: nothing deletes or cancels, yet destructiveHint", tool.Name)
		}
	}
}

// Descriptions are narrow and factual, English first: no instructions aimed at
// the model (connector directory review rejects descriptions that steer).
func TestToolDescriptionsDoNotSteer(t *testing.T) {
	steering := []string{"you ", "you'", "your ", "must", "should", "always", "never", "don't", "do not", "make sure", "be sure",
		"important", "call this", "use this", "when idle", "remember", "before calling", "after calling", "ignore", "prefer"}
	for _, d := range nexusops.Defs {
		en, ko, ok := strings.Cut(d.Description, " / ")
		if !ok || ko == "" || en == "" {
			t.Fatalf("%s: description is not English first, Korean after", d.Name)
		}
		for _, r := range en {
			if r >= 0xAC00 && r <= 0xD7A3 {
				t.Fatalf("%s: Korean in the English part", d.Name)
			}
		}
		low := strings.ToLower(en)
		for _, w := range steering {
			if strings.Contains(low, w) {
				t.Fatalf("%s: description steers the model (%q): %s", d.Name, w, en)
			}
		}
		if len(en) > 1024 {
			t.Fatalf("%s: description too long (%d)", d.Name, len(en))
		}
	}
}

// subscribe nexus://inbox → a message arrives in Nexus → the server's own
// stream sees it → notifications/resources/updated. Neither the notification
// nor resources/read marks the message delivered or read; nexus_inbox does.
func TestInboxSubscriptionPushesWithoutReceipts(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	c := attach(t, f, "claude-newtype", seatRoot)
	sender := attach(t, f, "sender", seatRoot)
	cl := startServer(t, c)
	cl.initializeWith("2025-11-25", map[string]any{})
	if r := cl.request("resources/subscribe", map[string]string{"uri": inboxURI}); r.Error != nil {
		t.Fatalf("subscribe: %+v", r.Error)
	}
	time.Sleep(200 * time.Millisecond) // the stream is open and the baseline taken
	sent, err := sender.Seat.Send(ctx, "claude-newtype", "please run the tests", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	m := cl.lineWithin(10 * time.Second)
	if method(m) != "notifications/resources/updated" || !strings.Contains(string(m["params"]), inboxURI) {
		t.Fatalf("expected an inbox update, got %v", m)
	}
	if strings.Contains(string(m["params"]), "please run") {
		t.Fatal("a notification carried the message body")
	}
	if d, r := readAt(t, f, c.Seat.ID, sent.Event); d || r {
		t.Fatalf("notification recorded a receipt: delivered=%v read=%v", d, r)
	}
	r := cl.request("resources/read", map[string]string{"uri": inboxURI})
	var read struct {
		Contents []struct {
			Text string `json:"text"`
		} `json:"contents"`
	}
	if r.Error != nil || json.Unmarshal(r.Result, &read) != nil || len(read.Contents) != 1 {
		t.Fatalf("resources/read %s %+v", r.Result, r.Error)
	}
	var peek nexusops.InboxPeek
	if json.Unmarshal([]byte(read.Contents[0].Text), &peek) != nil || peek.Unread != 1 || peek.Events[0] != sent.Event || strings.Contains(read.Contents[0].Text, "please run") {
		t.Fatalf("peek %s", read.Contents[0].Text)
	}
	if d, r := readAt(t, f, c.Seat.ID, sent.Event); d || r {
		t.Fatalf("resources/read recorded a receipt: delivered=%v read=%v", d, r)
	}
	if o := cl.tool("nexus_inbox", `{}`); !contains(o, "please run") {
		t.Fatalf("inbox %+v", o)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, r := readAt(t, f, c.Seat.ID, sent.Event); r {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nexus_inbox did not record the read")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// With the operator's channel flag, the server declares claude/channel and
// pushes a receipt-free notice (count and event id, never the body).
func TestChannelNoticeIsNotARead(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	c := attach(t, f, "claude-newtype", seatRoot)
	sender := attach(t, f, "sender", seatRoot)
	cl := startServerWith(t, &Server{Tools: c, Name: "newtype-nexus", Version: "test", Diag: io.Discard, Channel: true})
	out := cl.initializeWith("2025-11-25", map[string]any{})
	caps, _ := out["capabilities"].(map[string]any)
	exp, _ := caps["experimental"].(map[string]any)
	if _, ok := exp["claude/channel"]; !ok {
		t.Fatalf("capabilities %v", caps)
	}
	if text, _ := out["instructions"].(string); !strings.Contains(text, `<channel source="nexus">`) || !strings.Contains(text, "carries no content") {
		t.Fatal("channel line missing from instructions")
	}
	time.Sleep(200 * time.Millisecond)
	sent, err := sender.Seat.Send(ctx, "claude-newtype", "secret plan text", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	m := cl.lineWithin(10 * time.Second)
	if method(m) != "notifications/claude/channel" {
		t.Fatalf("expected a channel notice, got %v", m)
	}
	var p struct {
		Content string            `json:"content"`
		Meta    map[string]string `json:"meta"`
	}
	if json.Unmarshal(m["params"], &p) != nil || strings.Contains(p.Content, "secret plan") || !strings.Contains(p.Content, "nexus_inbox") || p.Meta["latest_event"] != string(sent.Event) {
		t.Fatalf("notice %s", m["params"])
	}
	if d, r := readAt(t, f, c.Seat.ID, sent.Event); d || r {
		t.Fatalf("channel notice recorded a receipt: delivered=%v read=%v", d, r)
	}
}

// A task resource is a status peek with no ledger record.
func TestTaskResourceRejectsForeignURIs(t *testing.T) {
	f := nexusopstest.New(t)
	cl := startServer(t, attach(t, f, "claude-newtype", seatRoot))
	cl.initialize()
	if r := cl.request("resources/read", map[string]string{"uri": "nexus://tasks/../inbox"}); r.Error == nil {
		t.Fatal("a malformed task URI was accepted")
	}
	if r := cl.request("resources/read", map[string]string{"uri": "file:///etc/passwd"}); r.Error == nil {
		t.Fatal("a foreign URI was accepted")
	}
	r := cl.request("resources/templates/list", map[string]any{})
	if r.Error != nil || !strings.Contains(string(r.Result), "nexus://tasks/{task_id}") {
		t.Fatalf("templates %s", r.Result)
	}

}
