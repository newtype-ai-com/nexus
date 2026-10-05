package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestExternalToolRequiresPolicy(t *testing.T) {
	for _, withGate := range []bool{false, true} {
		calls := 0
		runs := 0
		gates := 0
		e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
			calls++
			if calls == 1 {
				return ModelResponse{ToolCalls: []ToolCall{call("mcp_test_echo", `{}`)}}, nil
			}
			return ModelResponse{Content: "denied"}, nil
		}), nil)
		external := tool("mcp_test_echo", false, func(context.Context, ToolContext, json.RawMessage) (string, error) { runs++; return "bad", nil })
		external.RequiresGate = true
		e.opts.Binder = BinderFunc(func(context.Context, BindRequest) (*Binding, error) {
			b := &Binding{Tools: []Tool{external}}
			if withGate {
				b.Gate = func(context.Context, string, json.RawMessage) (bool, string) { gates++; return false, "policy denied" }
			}
			return b, nil
		})
		events := send(t, e, ChatRequest{Message: "try"})
		if runs != 0 || (withGate && gates != 1) || !strings.Contains(eventText(events), "failed") {
			t.Fatal("external policy bypass", runs, gates)
		}
	}
}
