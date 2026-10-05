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

// Stage-0 conformance: the engine path (core.Tool.Run) and the MCP path
// (tools/call over stdio) give the same outcome for the same call, and Nexus,
// not the client, enforces the delegation.
type path struct {
	name string
	call func(t *testing.T, tool, args string) outcome
}

func paths(t *testing.T, f *nexusopstest.Fake) ([]path, []*nexusops.Contract) {
	t.Helper()
	eng := attach(t, f, "engine-seat", seatRoot)
	mcp := attach(t, f, "mcp-seat", seatRoot)
	cl := startServer(t, mcp)
	cl.initialize()
	// the remote transport (Streamable HTTP) runs the same Server
	remote := attach(t, f, "http-seat", seatRoot)
	srv, _ := startHTTP(t, map[string]Caller{"tok": remote})
	hc := &httpClient{t: t, url: srv.URL, token: "tok"}
	hc.initialize(map[string]any{})
	n := 1000
	return []path{
		{"engine", func(t *testing.T, tool, args string) outcome { return engine(t, eng, tool, args) }},
		{"mcp", func(t *testing.T, tool, args string) outcome { return cl.tool(tool, args) }},
		{"http", func(t *testing.T, tool, args string) outcome {
			n++
			res := hc.call(n, tool, args)
			var r struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				IsError bool `json:"isError"`
			}
			if json.Unmarshal(res["result"], &r) != nil || len(r.Content) != 1 {
				t.Fatalf("http %s: %v", tool, res)
			}
			return mkOutcome(r.Content[0].Text, r.IsError)
		}},
	}, []*nexusops.Contract{eng, mcp, remote}
}

func live(t *testing.T, f *nexusopstest.Fake, title string) ids.Session {
	t.Helper()
	root, p := f.Root(t, title)
	if err := f.Service.Touch(context.Background(), p); err != nil { // presence: a runner is there
		t.Fatal(err)
	}
	return root.Session.ID
}

func TestConformanceOutOfDelegationRefused(t *testing.T) {
	f := nexusopstest.New(t)
	worker := live(t, f, "worker-fixture")
	if _, err := nexusops.Attach(context.Background(), f.Identity(), "operator", nexusops.Options{Transport: f.Transport()}); err != nil {
		t.Fatal(err) // the person's approver seat exists
	}
	ps, _ := paths(t, f)
	for _, p := range ps {
		// the server says no for an action no rule allows
		o := p.call(t, "delegation_info", `{"action":"tool:shell"}`)
		var info struct {
			Scope  []string `json:"scope"`
			Action struct {
				Effect string `json:"effect"`
			} `json:"action_check"`
		}
		if o.IsError || json.Unmarshal([]byte(o.Text), &info) != nil || info.Action.Effect != "deny" || strings.Join(info.Scope, ",") != "session:delegate" {
			t.Fatalf("%s: delegation_info %+v", p.name, o)
		}
		// a delegated scope this seat does not hold is refused by Nexus
		o = p.call(t, "delegate_task", `{"to_session_id":"`+string(worker)+`","title":"x","brief":"y","scope":["newtype:run"],"limits":{},"ttl_seconds":60}`)
		if !o.IsError || o.Code != "refused" {
			t.Fatalf("%s: out-of-delegation delegate %+v", p.name, o)
		}
		// asking leads to an approval request to the person's seat, not authority
		o = p.call(t, "request_approval", `{"action":"tool:shell","reason":"need a shell"}`)
		if o.IsError || !contains(o, `"status":"requested"`) || !contains(o, `"decision":"deny"`) {
			t.Fatalf("%s: request_approval %+v", p.name, o)
		}
		// an action already inside the delegation needs no approval
		o = p.call(t, "request_approval", `{"action":"send_message","reason":"talk"}`)
		if o.IsError || !contains(o, `"status":"allowed"`) {
			t.Fatalf("%s: allowed %+v", p.name, o)
		}
	}
}

func TestConformanceChildCannotWiden(t *testing.T) {
	f := nexusopstest.New(t)
	worker := live(t, f, "worker-fixture")
	ps, _ := paths(t, f)
	for _, p := range ps {
		for name, args := range map[string]string{
			"model tokens":   `{"to_session_id":"` + string(worker) + `","title":"x","brief":"y","scope":[],"limits":{"model_tokens":1},"ttl_seconds":60}`,
			"sub sessions":   `{"to_session_id":"` + string(worker) + `","title":"x","brief":"y","scope":[],"limits":{"sub_sessions":1},"ttl_seconds":60}`,
			"foreign scope":  `{"to_session_id":"` + string(worker) + `","title":"x","brief":"y","scope":["model:example-model"],"limits":{},"ttl_seconds":60}`,
			"delegate again": `{"to_session_id":"` + string(worker) + `","title":"x","brief":"y","scope":["session:delegate"],"limits":{"max_depth":1},"ttl_seconds":60}`,
		} {
			o := p.call(t, "delegate_task", args)
			if name == "delegate again" {
				// allowed (⊆ own scope) but the child's depth is capped by Nexus at 0
				if o.IsError {
					t.Fatalf("%s %s: %+v", p.name, name, o)
				}
				var got struct {
					Delegation ids.Delegation `json:"delegation_id"`
				}
				_ = json.Unmarshal([]byte(o.Text), &got)
				d, err := f.Service.DelegationInfo(context.Background(), f.Person, got.Delegation)
				if err != nil || d.Delegation.Limits.MaxDepth != 0 {
					t.Fatalf("%s: child depth %+v %v", p.name, d.Delegation.Limits, err)
				}
				continue
			}
			if !o.IsError || o.Code != "refused" {
				t.Fatalf("%s %s: widened %+v", p.name, name, o)
			}
		}
		// the same request within its own (zero) limits is accepted
		o := p.call(t, "delegate_task", `{"to_session_id":"`+string(worker)+`","title":"review","brief":"please review","scope":[],"limits":{},"ttl_seconds":60}`)
		if o.IsError || !contains(o, `"task_id":"req_`) {
			t.Fatalf("%s: within limits %+v", p.name, o)
		}
		var got struct {
			Task ids.Task `json:"task_id"`
		}
		_ = json.Unmarshal([]byte(o.Text), &got)
		if st := p.call(t, "task_status", `{"task_id":"`+string(got.Task)+`"}`); st.IsError || !contains(st, string(got.Task)) {
			t.Fatalf("%s: task_status %+v", p.name, st)
		}
	}
}

func TestConformanceReadOnlyWhenReturned(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	_, sender := f.Root(t, "sender-fixture")
	ps, seats := paths(t, f)
	for i, p := range ps {
		seat := seats[i].Seat
		m, err := f.Service.Send(ctx, sender, nexus.Message{To: seat.ID, Text: "for " + p.name})
		if err != nil {
			t.Fatal(err)
		}
		// peers, tree, log and delegation_info never touch receipts
		for _, tool := range []string{"nexus_peers", "nexus_tree", "nexus_log", "delegation_info"} {
			if o := p.call(t, tool, `{}`); o.IsError {
				t.Fatalf("%s %s: %+v", p.name, tool, o)
			}
		}
		if _, read := readAt(t, f, seat.ID, m.Event); read {
			t.Fatalf("%s: read without nexus_inbox", p.name)
		}
		o := p.call(t, "nexus_inbox", `{}`)
		if o.IsError || !contains(o, "for "+p.name) {
			t.Fatalf("%s: inbox %+v", p.name, o)
		}
		// MCP records read right after writing the response (asynchronously).
		deadline := time.Now().Add(5 * time.Second)
		for {
			delivered, read := readAt(t, f, seat.ID, m.Event)
			if delivered && read {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: returned message not read (delivered=%v read=%v)", p.name, delivered, read)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if o := p.call(t, "nexus_inbox", `{}`); o.IsError || contains(o, "for "+p.name) {
			t.Fatalf("%s: returned again %+v", p.name, o)
		}
	}
}
