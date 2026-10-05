package nmcp

import (
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/internal/nexusops/nexusopstest"
)

// Tool errors say what failed and what to do next, in English first; never a
// bare code or a generic HTTP status.
func TestToolErrorsAreActionable(t *testing.T) {
	f := nexusopstest.New(t)
	cl := startServer(t, attach(t, f, "claude-newtype", seatRoot))
	cl.initialize()
	for _, c := range []struct {
		tool, args, code string
		want             []string
	}{
		{"send_message", `{"to":"nobody-here","text":"hi"}`, "not_found", []string{"nexus_peers"}},
		{"send_message", `{"to":"x","text":"hi","reply_to":"nope"}`, "invalid", []string{"reply_to", "evt_"}},
		{"send_message", `{"to":"x","text":"   "}`, "invalid", []string{"text is required"}},
		{"send_message", `{"to":"x","text":"hi","bogus":1}`, "invalid", []string{"inputSchema", "bogus"}},
		{"task_status", `{"task_id":"bad"}`, "invalid", []string{"task_id", "req_", "nexus_tree"}},
		{"nexus_inbox", `{"wait_seconds":9999}`, "invalid", []string{"wait_seconds", "0 and 600"}},
		{"request_approval", `{"action":"tool:shell","reason":""}`, "invalid", []string{"reason is required"}},
		{"delegate_task", `{"to_session_id":"x","title":"t","brief":"b","scope":[],"limits":{},"ttl_seconds":60}`, "invalid", []string{"to_session_id", "slv_"}},
		{"nexus_log", `{"session":"nobody-here"}`, "not_found", []string{"nexus_peers"}},
	} {
		o := cl.tool(c.tool, c.args)
		if !o.IsError || o.Code != c.code {
			t.Fatalf("%s %s: %+v", c.tool, c.args, o)
		}
		for _, w := range c.want {
			if !strings.Contains(o.Text, w) {
				t.Fatalf("%s %s: %q misses %q", c.tool, c.args, o.Text, w)
			}
		}
		if strings.Contains(o.Text, "HTTP 4") || strings.Contains(o.Text, "HTTP 5") {
			t.Fatalf("%s: generic HTTP error %s", c.tool, o.Text)
		}
	}
	// protocol errors name the fix too
	if r := cl.request("tools/call", map[string]any{"name": "no_such_tool", "arguments": map[string]any{}}); r.Error == nil || !strings.Contains(r.Error.Message, "tools/list") {
		t.Fatalf("unknown tool %+v", r.Error)
	}
}
