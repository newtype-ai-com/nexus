package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type resultContextTools struct {
	testTools
	hints     int
	panicHint bool
}

func (s *resultContextTools) ToolResultContext(context.Context, ToolContext, ToolCall) string {
	s.hints++
	if s.panicHint {
		panic("optional context failed")
	}
	return "\n" + WrapDataSection("rules", "hint-marker")
}
func TestToolResultContextOnlyAfterSuccessfulAuthorizedTool(t *testing.T) {
	for _, mode := range []string{"success", "failure", "gate-denied", "panic-hint"} {
		t.Run(mode, func(t *testing.T) {
			runs := 0
			ts := &resultContextTools{panicHint: mode == "panic-hint", testTools: testTools{tool("create_file", false, func(context.Context, ToolContext, json.RawMessage) (string, error) {
				runs++
				if mode == "failure" {
					return "", errors.New("write failed")
				}
				return "created-marker", nil
			})}}
			sets, err := CombineToolsets(ts)
			if err != nil {
				t.Fatal(err)
			}
			round := 0
			model := modelFunc(func(_ context.Context, req ModelRequest, _ func(string)) (ModelResponse, error) {
				round++
				if round == 1 {
					return ModelResponse{ToolCalls: []ToolCall{call("create_file", `{"path":"src/a.go"}`)}}, nil
				}
				if round == 2 {
					last := req.Messages[len(req.Messages)-1]
					if last.Role != "tool" || strings.Contains(last.Content, "hint-marker") != (mode == "success") {
						t.Errorf("unexpected tool context: %s", last.Content)
					}
					if mode == "panic-hint" && (!strings.Contains(last.Content, "Status: Success") || !strings.Contains(last.Content, "created-marker")) {
						t.Errorf("context panic changed execution status: %s", last.Content)
					}
				}
				return ModelResponse{Content: "done"}, nil
			})
			e, err := New(Options{Model: model, Tools: sets, WorkDir: t.TempDir(), RetryDelay: -1, Binder: BinderFunc(func(context.Context, BindRequest) (*Binding, error) {
				return &Binding{Gate: func(context.Context, string, json.RawMessage) (bool, string) { return mode != "gate-denied", "denied" }}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			events := send(t, e, ChatRequest{Message: "test", PromptType: ModeAuto})
			assertTerminated(t, events)
			wantHints := 0
			if mode == "success" || mode == "panic-hint" {
				wantHints = 1
			}
			if ts.hints != wantHints {
				t.Fatal("hint call count", ts.hints)
			}
			if mode == "gate-denied" {
				if runs != 0 {
					t.Fatal("denied tool ran")
				}
			}
		})
	}
}
