package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
)

func TestWorkPlanIntegrationClaimsAndChurnCannotStop(t *testing.T) {
	for _, name := range []string{"empty", "waiting_status", "approval_titles", "rename"} {
		t.Run(name, func(t *testing.T) {
			var rounds, updates atomic.Int32
			e := newTestEngine(t, modelFunc(func(_ context.Context, req ModelRequest, _ func(string)) (ModelResponse, error) {
				n := rounds.Add(1)
				if n%2 == 1 {
					title, status := "implement", "waiting_person"
					if name == "approval_titles" {
						title = "approval required"
						status = "done"
					}
					if name == "rename" {
						title = fmt.Sprintf("renamed %d", n)
						status = "done"
					}
					tasks := []WorkPlanTask{{Title: title, Status: status}}
					if name == "empty" {
						tasks = []WorkPlanTask{}
					}
					raw, _ := json.Marshal(map[string]any{"tasks": tasks})
					return ModelResponse{ToolCalls: []ToolCall{call("work_plan", string(raw))}}, nil
				}
				return ModelResponse{ToolCalls: []ToolCall{call("end_turn", `{"reason":"needs_person","message":"claimed stop"}`)}}, nil
			}), testTools{tool("work_plan", true, func(ctx context.Context, tc ToolContext, raw json.RawMessage) (string, error) {
				if tc.UpdateWorkPlan == nil {
					t.Error("missing callback")
					return "", fmt.Errorf("missing callback")
				}
				var args struct {
					Tasks []WorkPlanTask `json:"tasks"`
				}
				if err := json.Unmarshal(raw, &args); err != nil {
					return "", err
				}
				updates.Add(1)
				return "claimed plan", tc.UpdateWorkPlan(ctx, args.Tasks)
			})})
			r, err := e.EnableWorkPlanVerification("")
			if err != nil {
				t.Fatal(err)
			}
			events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
			integrationTerminal(t, events, "blocked_no_progress")
			if rounds.Load() != 6 || updates.Load() != 3 || eventCount(events, "plan_verification") != 3 {
				t.Fatal(eventText(events))
			}
			stored, err := e.LoadSession(r.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if name == "rename" {
				want = 3
			}
			if name == "empty" {
				want = 0
			}
			if len(stored.WorkPlan.Items) != want {
				t.Fatal("stale ledger", stored.WorkPlan)
			}
			if _, err = e.EnableWorkPlanVerification(r.ID); err != nil {
				t.Fatal(err)
			}
			again := send(t, e, ChatRequest{SessionID: r.ID, Message: "continue"})
			integrationTerminal(t, again, "blocked_no_progress")
			if eventCount(again, "plan_verification") != 1 {
				t.Fatal("re-enable reset memory counter")
			}
		})
	}
}

func TestWorkPlanIntegrationCallbackIsolation(t *testing.T) {
	for _, mode := range []string{"ordinary", "pinned", "other_tool"} {
		t.Run(mode, func(t *testing.T) {
			name := "work_plan"
			if mode == "other_tool" {
				name = "report"
			}
			var calls, executions atomic.Int32
			e := newTestEngine(t, modelFunc(func(_ context.Context, _ ModelRequest, _ func(string)) (ModelResponse, error) {
				if calls.Add(1) == 1 {
					return ModelResponse{ToolCalls: []ToolCall{call(name, `{}`)}}, nil
				}
				return ModelResponse{Content: "done"}, nil
			}), testTools{tool(name, true, func(_ context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
				executions.Add(1)
				if tc.UpdateWorkPlan != nil {
					t.Error("callback escaped to " + mode)
				}
				return "advisory", nil
			})})
			request := ChatRequest{Message: "work"}
			if mode == "other_tool" {
				r, err := e.EnableWorkPlanVerification("")
				if err != nil {
					t.Fatal(err)
				}
				request.SessionID = r.ID
			}
			if mode == "pinned" {
				request.SessionID = integrationPin(t, e, "- [ ] approval required\n").ID
			}
			events := send(t, e, request)
			assertTerminated(t, events)
			if executions.Load() != 1 {
				t.Fatal(eventText(events))
			}
			if mode == "ordinary" && eventCount(events, "plan_verification") != 0 {
				t.Fatal("ordinary mode gated")
			}
		})
	}
}
