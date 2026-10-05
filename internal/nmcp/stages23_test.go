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

// initializeWith declares a protocol version and client capabilities.
func (c *client) initializeWith(version string, capabilities map[string]any) map[string]any {
	c.t.Helper()
	r := c.request("initialize", map[string]any{"protocolVersion": version, "capabilities": capabilities, "clientInfo": map[string]string{"name": "fixture", "version": "1"}})
	if r.Error != nil {
		c.t.Fatalf("initialize: %+v", r.Error)
	}
	c.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	var out map[string]any
	_ = json.Unmarshal(r.Result, &out)
	return out
}

// line reads the next raw JSON-RPC message (a response or a server request).
func (c *client) line() map[string]json.RawMessage {
	c.t.Helper()
	raw, err := c.out.ReadBytes('\n')
	if err != nil {
		c.t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		c.t.Fatalf("not JSON: %q", raw)
	}
	return m
}

func toolText(t *testing.T, result json.RawMessage) string {
	t.Helper()
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(result, &res) != nil || len(res.Content) != 1 {
		t.Fatalf("result %s", result)
	}
	return res.Content[0].Text
}

// (a) With the elicitation capability the person decides through the host:
// exactly that path (no operator-seat message), "session" is remembered for the
// MCP session, a decline is a denial, and every decision lands in the ledger.
func TestRequestApprovalThroughElicitation(t *testing.T) {
	f := nexusopstest.New(t)
	c := attach(t, f, "claude-newtype", seatRoot)
	cl := startServer(t, c)
	cl.initializeWith("2025-11-25", map[string]any{"elicitation": map[string]any{}})

	id := cl.sendRequest("tools/call", map[string]any{"name": "request_approval", "arguments": map[string]string{"action": "tool:shell", "reason": "run the build"}})
	ask := cl.line()
	var method string
	_ = json.Unmarshal(ask["method"], &method)
	if method != "elicitation/create" {
		t.Fatalf("expected elicitation/create, got %v", ask)
	}
	var params struct {
		Message string         `json:"message"`
		Schema  map[string]any `json:"requestedSchema"`
	}
	_ = json.Unmarshal(ask["params"], &params)
	if !strings.Contains(params.Message, "tool:shell") || !strings.Contains(params.Message, "run the build") || params.Schema == nil {
		t.Fatalf("elicitation params %s", ask["params"])
	}
	cl.send(`{"jsonrpc":"2.0","id":` + string(ask["id"]) + `,"result":{"action":"accept","content":{"decision":"session"}}}`)
	res := cl.read()
	if string(res.ID) != jsonID(id) {
		t.Fatalf("response id %s", res.ID)
	}
	text := toolText(t, res.Result)
	if !strings.Contains(text, `"status":"approved"`) || !strings.Contains(text, `"decision":"session"`) {
		t.Fatal(text)
	}
	// remembered for this MCP session: no second question
	again := cl.tool("request_approval", `{"action":"tool:shell","reason":"again"}`)
	if !contains(again, `"decision":"session"`) {
		t.Fatal(again.Text)
	}
	// a decline is a denial
	cl.sendRequest("tools/call", map[string]any{"name": "request_approval", "arguments": map[string]string{"action": "tool:remove_file", "reason": "cleanup"}})
	ask = cl.line()
	cl.send(`{"jsonrpc":"2.0","id":` + string(ask["id"]) + `,"result":{"action":"decline"}}`)
	if text := toolText(t, cl.read().Result); !strings.Contains(text, `"status":"denied"`) {
		t.Fatal(text)
	}
	// an answer that is not an allowed choice is a denial too
	cl.sendRequest("tools/call", map[string]any{"name": "request_approval", "arguments": map[string]string{"action": "tool:edit_file", "reason": "x"}})
	ask = cl.line()
	cl.send(`{"jsonrpc":"2.0","id":` + string(ask["id"]) + `,"result":{"action":"accept","content":{"decision":"forever"}}}`)
	if text := toolText(t, cl.read().Result); !strings.Contains(text, `"status":"denied"`) {
		t.Fatal(text)
	}
	// the ledger holds every decision with the decider and time
	log := cl.tool("nexus_log", `{}`)
	if strings.Count(log.Text, `"kind":"tool.approval"`) != 3 || !strings.Contains(log.Text, `person:mcp-elicitation`) {
		t.Fatal("ledger:", log.Text)
	}
}

// (a) Without the capability the operator-seat message decides (no
// elicitation request is ever sent), and the seat can never be its own approver.
func TestRequestApprovalWithoutElicitationUsesTheOperatorSeat(t *testing.T) {
	f := nexusopstest.New(t)
	if _, err := nexusops.Attach(context.Background(), f.Identity(), "operator", nexusops.Options{Transport: f.Transport()}); err != nil {
		t.Fatal(err)
	}
	c := attach(t, f, "claude-newtype", seatRoot)
	cl := startServer(t, c)
	cl.initializeWith("2025-11-25", map[string]any{})
	got := cl.tool("request_approval", `{"action":"tool:shell","reason":"run the build"}`)
	if !contains(got, `"status":"requested"`) {
		t.Fatal(got.Text)
	}
	self := attach(t, f, "self-approver", seatRoot)
	self.Approver = "self-approver"
	if o := engine(t, self, "request_approval", `{"action":"tool:shell","reason":"x"}`); o.Code != "no_approver" {
		t.Fatal(o.Text)
	}
}

// (b) Tasks: a waiting nexus_inbox becomes a task handle; tasks/get, tasks/list,
// tasks/result work; the read receipt is written only after tasks/result handed
// the message over; cancel works; non-task tools and old clients are refused.
func TestLongWaitsAsTasks(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	_, tuiP := f.Root(t, "tui-fixture")
	c := attach(t, f, "claude-newtype", seatRoot)
	cl := startServer(t, c)
	init := cl.initializeWith("2025-11-25", map[string]any{"tasks": map[string]any{}})
	caps, _ := init["capabilities"].(map[string]any)
	if _, ok := caps["tasks"]; !ok {
		t.Fatalf("no tasks capability: %v", init)
	}
	list := cl.request("tools/list", map[string]any{})
	if !strings.Contains(string(list.Result), `"taskSupport":"optional"`) {
		t.Fatal("tools/list lacks execution.taskSupport")
	}
	r := cl.request("tools/call", map[string]any{"name": "nexus_inbox", "arguments": map[string]int{"wait_seconds": 30}, "task": map[string]int{"ttl": 60000}})
	var created struct {
		Task struct {
			TaskID string `json:"taskId"`
			Status string `json:"status"`
		} `json:"task"`
	}
	if r.Error != nil || json.Unmarshal(r.Result, &created) != nil || created.Task.Status != "working" || created.Task.TaskID == "" {
		t.Fatalf("create %s %+v", r.Result, r.Error)
	}
	if got := cl.request("tasks/get", map[string]string{"taskId": created.Task.TaskID}); !strings.Contains(string(got.Result), `"status":"working"`) {
		t.Fatal(string(got.Result))
	}
	sent, err := f.Service.Send(ctx, tuiP, nexus.Message{To: c.Seat.ID, Text: "reply from the TUI"})
	if err != nil {
		t.Fatal(err)
	}
	res := cl.request("tasks/result", map[string]string{"taskId": created.Task.TaskID})
	if res.Error != nil || !strings.Contains(toolText(t, res.Result), "reply from the TUI") || !strings.Contains(string(res.Result), "related-task") {
		t.Fatalf("result %s %+v", res.Result, res.Error)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, read := readAt(t, f, c.Seat.ID, sent.Event); read {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read receipt missing after tasks/result")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := cl.request("tasks/list", map[string]any{}); !strings.Contains(string(got.Result), created.Task.TaskID) {
		t.Fatal(string(got.Result))
	}
	// cancel: a second wait with no new mail stays working until cancelled, and
	// its result is then refused (nothing is marked read)
	r = cl.request("tools/call", map[string]any{"name": "nexus_inbox", "arguments": map[string]int{"wait_seconds": 30}, "task": map[string]any{}})
	if r.Error != nil || json.Unmarshal(r.Result, &created) != nil || created.Task.Status != "working" {
		t.Fatalf("second task %s %+v", r.Result, r.Error)
	}
	if got := cl.request("tasks/cancel", map[string]string{"taskId": created.Task.TaskID}); !strings.Contains(string(got.Result), `"status":"cancelled"`) {
		t.Fatal(string(got.Result))
	}
	if got := cl.request("tasks/result", map[string]string{"taskId": created.Task.TaskID}); got.Error == nil || !strings.Contains(got.Error.Message, "cancelled") {
		t.Fatalf("result of a cancelled task: %+v %s", got.Error, got.Result)
	}
	// a tool that does not support tasks
	if r := cl.request("tools/call", map[string]any{"name": "send_message", "arguments": map[string]string{"to": "tui-fixture", "text": "x"}, "task": map[string]any{}}); r.Error == nil || r.Error.Code != codeParams {
		t.Fatalf("send_message as a task: %+v", r)
	}

	// an older client: no tasks capability, no tasks methods, blocking calls only
	old := startServer(t, attach(t, f, "old-client", seatRoot))
	init = old.initializeWith("2025-06-18", map[string]any{})
	if caps, _ := init["capabilities"].(map[string]any); caps["tasks"] != nil {
		t.Fatal("tasks offered to an old client")
	}
	if r := old.request("tasks/list", map[string]any{}); r.Error == nil || r.Error.Code != codeMethod {
		t.Fatalf("%+v", r)
	}
	if r := old.request("tools/call", map[string]any{"name": "nexus_inbox", "arguments": map[string]int{}, "task": map[string]any{}}); r.Error == nil {
		t.Fatal("task accepted from an old client")
	}
}

// (c) delegation_info shows the execution grants a person issued for this
// seat, filtered by sender; MCP can read them but never issue one.
func TestDelegationInfoShowsExecutionGrants(t *testing.T) {
	ctx := context.Background()
	f := nexusopstest.New(t)
	tui, _ := f.Root(t, "tui-fixture")
	other, _ := f.Root(t, "someone-else")
	c := attach(t, f, "claude-newtype", seatRoot)
	cl := startServer(t, c)
	cl.initialize()
	none := cl.tool("delegation_info", `{}`)
	if none.IsError || !contains(none, `"execution_grants":[]`) {
		t.Fatal(none.Text)
	}
	_, err := f.Service.IssueExecutionGrant(ctx, f.Person, nexus.ExecutionGrant{Receiver: c.Seat.ID, Delegation: c.Seat.Delegation,
		Senders: []ids.Session{tui.Session.ID}, Tools: []string{"tool:edit_file"}, Paths: []string{"/repo/x/**"}, MaxTurns: 5}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	from := cl.tool("delegation_info", `{"from":"tui-fixture"}`)
	if !contains(from, `"senders":["`+string(tui.Session.ID)+`"]`) || !contains(from, `"turns_left":5`) {
		t.Fatal(from.Text)
	}
	if o := cl.tool("delegation_info", `{"from":"`+string(other.Session.ID)+`"}`); !contains(o, `"execution_grants":[]`) {
		t.Fatal(o.Text)
	}
	// no contract tool issues grants
	for _, d := range nexusops.Defs {
		if strings.Contains(d.Name, "grant") {
			t.Fatal("a grant-issuing tool exists:", d.Name)
		}
	}
}

func jsonID(id int64) string { raw, _ := json.Marshal(id); return string(raw) }
