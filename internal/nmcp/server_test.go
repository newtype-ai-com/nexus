package nmcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/nexusops"
	"github.com/newtype-ai-com/nexus/internal/nexusops/nexusopstest"
	"github.com/newtype-ai-com/nexus/nexus"
)

func readAt(t *testing.T, f *nexusopstest.Fake, to ids.Session, event ids.Event) (delivered, read bool) {
	t.Helper()
	st, err := f.Service.MessageDelivery(context.Background(), f.Person, to, event)
	if err != nil {
		t.Fatal(err)
	}
	return st.DeliveredAt != nil, st.ReadAt != nil
}

// initialize → tools/list → send_message → the TUI side's inbox sees it →
// the TUI replies → nexus_inbox returns the reply → read is recorded only
// after the response was written to the client.
func TestStdioRoundTripReadOnlyAfterReturn(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	tui, tuiP := f.Root(t, "tui-fixture")
	c := attach(t, f, "claude-newtype", seatRoot)
	cl := startServer(t, c)

	cl.initialize()
	list := cl.request("tools/list", map[string]any{})
	var tools struct {
		Tools []struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(list.Result, &tools); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range tools.Tools {
		names = append(names, x.Name)
		if !json.Valid(x.InputSchema) {
			t.Fatalf("%s schema", x.Name)
		}
	}
	want := "delegation_info request_approval delegate_task task_status nexus_peers send_message nexus_inbox nexus_tree nexus_log"
	if strings.Join(names, " ") != want {
		t.Fatalf("tools/list = %v", names)
	}

	sent := cl.tool("send_message", `{"to":"tui-fixture","text":"hello from Claude"}`)
	if sent.IsError {
		t.Fatal(sent.Text)
	}
	var s nexusops.SendResult
	if err := json.Unmarshal([]byte(sent.Text), &s); err != nil || s.To != tui.Session.ID {
		t.Fatalf("send %s", sent.Text)
	}
	mail, _, err := f.Service.Inbox(ctx, tuiP, 0, 0)
	if err != nil || len(mail) != 1 || mail[0].Text != "hello from Claude" || mail[0].From != c.Seat.ID || mail[0].FromTitle != "claude-newtype" {
		t.Fatalf("tui inbox %+v %v", mail, err)
	}
	reply, err := f.Service.Send(ctx, tuiP, nexus.Message{To: c.Seat.ID, Text: "reply from TUI", ReplyTo: s.Event})
	if err != nil {
		t.Fatal(err)
	}

	// The response is not read yet (pipe): delivered may be set, read must not.
	cl.sendRequest("tools/call", map[string]any{"name": "nexus_inbox", "arguments": map[string]any{}})
	time.Sleep(200 * time.Millisecond) // the call has run and blocks writing its response
	if _, read := readAt(t, f, c.Seat.ID, reply.Event); read {
		t.Fatal("read recorded before the result was returned")
	}
	r := cl.read()
	if r.Error != nil || !strings.Contains(string(r.Result), "reply from TUI") {
		t.Fatalf("inbox result %s %+v", r.Result, r.Error)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		delivered, read := readAt(t, f, c.Seat.ID, reply.Event)
		if delivered && read {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read not recorded after return")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A returned message is not returned again.
	if again := cl.tool("nexus_inbox", `{}`); strings.Contains(again.Text, "reply from TUI") {
		t.Fatal("read message returned again")
	}
	// The sender sees sent → delivered → read on its own message too.
	if delivered, _ := readAt(t, f, tui.Session.ID, s.Event); delivered {
		t.Fatal("nobody delivered the TUI's copy yet")
	}

	// every call landed in the session's own ledger (tool name + outcome only)
	events, _, err := f.Service.Events(ctx, f.Person, c.Seat.ID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	for _, e := range events {
		if e.Kind == "tool.call" {
			var p map[string]string
			_ = json.Unmarshal(e.Payload, &p)
			calls[p["tool"]]++
			if strings.Contains(string(e.Payload), "hello") {
				t.Fatal("message text in the call record")
			}
		}
	}
	if calls["send_message"] != 1 || calls["nexus_inbox"] != 2 {
		t.Fatalf("ledger records %v", calls)
	}
}

func TestProtocolErrorsAndAliases(t *testing.T) {
	f := nexusopstest.New(t)
	f.Root(t, "peer-fixture")
	c := attach(t, f, "claude-newtype", seatRoot)
	cl := startServer(t, c)

	if r := cl.request("tools/list", nil); r.Error == nil || r.Error.Code != codeNotInitialized {
		t.Fatalf("before initialize: %+v", r.Error)
	}
	if r := cl.request("ping", nil); r.Error != nil || string(r.Result) != "{}" {
		t.Fatalf("ping %s %+v", r.Result, r.Error)
	}
	init := cl.request("initialize", map[string]any{"protocolVersion": "2026-07-28"})
	var ir struct {
		Version string `json:"protocolVersion"`
	}
	if json.Unmarshal(init.Result, &ir) != nil || ir.Version != "2026-07-28" {
		t.Fatalf("initialize %s", init.Result)
	}
	if r := cl.request("initialize", map[string]any{"protocolVersion": "1999-01-01"}); !strings.Contains(string(r.Result), Versions[0]) {
		t.Fatalf("unknown version must get the newest: %s", r.Result)
	}
	cl.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	cl.send(`not json`)
	if r := cl.read(); r.Error == nil || r.Error.Code != codeParse || string(r.ID) != "null" {
		t.Fatalf("parse error %+v id %s", r.Error, r.ID)
	}
	cl.send(`[{"jsonrpc":"2.0","id":9,"method":"ping"}]`)
	if r := cl.read(); r.Error == nil || r.Error.Code != codeInvalidRequest {
		t.Fatalf("batch %+v", r.Error)
	}
	cl.send(`{"jsonrpc":"1.0","id":10,"method":"ping"}`)
	if r := cl.read(); r.Error == nil || r.Error.Code != codeInvalidRequest || string(r.ID) != "10" {
		t.Fatalf("bad version %+v", r.Error)
	}
	if r := cl.request("prompts/list", nil); r.Error == nil || r.Error.Code != codeMethod {
		t.Fatalf("unknown method %+v", r.Error)
	}
	if r := cl.request("tools/call", map[string]any{"name": "nexus_execute", "arguments": map[string]any{}}); r.Error == nil || r.Error.Code != codeParams {
		t.Fatalf("unknown tool %+v", r.Error)
	}
	// hidden alias: callable, never listed
	if o := cl.tool("hub_peers", `{}`); o.IsError || !strings.Contains(o.Text, "peer-fixture") {
		t.Fatalf("hub_peers alias %+v", o)
	}
	if r := cl.request("tools/list", nil); strings.Contains(string(r.Result), "hub_") {
		t.Fatal("alias listed")
	}
	// bad arguments are a tool error, not a protocol error
	if o := cl.tool("nexus_peers", `{"x":1}`); !o.IsError || o.Code != "invalid" {
		t.Fatalf("unknown argument %+v", o)
	}
	// credential-looking arguments are refused before Nexus
	if o := cl.tool("send_message", `{"to":"peer-fixture","text":"x","client_event_id":"Bearer `+nexusopstest.Key+`"}`); !o.IsError {
		t.Fatalf("credential-bearing input accepted: %+v", o)
	}
}

// A message from the person's login that stopped being live fails the start
// with the fixed sentence (checked in cmd/newtype); here: tool calls after the
// login is revoked fail as not_live, never with server text.
func TestNotLiveToolError(t *testing.T) {
	f := nexusopstest.New(t)
	c := attach(t, f, "claude-newtype", seatRoot)
	cl := startServer(t, c)
	cl.initialize()
	f.LoginRevoked.Store(true)
	if o := cl.tool("nexus_peers", `{}`); !o.IsError || o.Code != "not_live" {
		t.Fatalf("%+v", o)
	}
}
