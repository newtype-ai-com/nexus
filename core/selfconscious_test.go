package core

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Fake-model tests for self-conscious continuation (docs/tui-modes.md).

func lastContent(r ModelRequest) string { return r.Messages[len(r.Messages)-1].Content }

func doneStatus(t *testing.T, events []Event) string {
	t.Helper()
	assertTerminated(t, events)
	s, _ := events[len(events)-1].Data["status"].(string)
	return s
}

func selfEvents(events []Event, action string) int {
	n := 0
	for _, e := range events {
		if e.Type == "self_conscious" && e.Data["action"] == action {
			n++
		}
	}
	return n
}

func hasEndTurn(r ModelRequest) bool {
	for _, s := range r.Tools {
		if s.Name == "end_turn" {
			return true
		}
	}
	return false
}

func planTool(ran *atomic.Int32) Tool {
	return tool("work_plan", true, func(context.Context, ToolContext, json.RawMessage) (string, error) {
		if ran != nil {
			ran.Add(1)
		}
		return "plan recorded", nil
	})
}

// drainAnswering reads a turn to the end, answering approvals and optionally
// reacting to events (e.g. cancelling) from the host side.
func drainAnswering(t *testing.T, e *Engine, r ChatRequest, approve bool, on func(Event)) []Event {
	t.Helper()
	ch, err := e.SendMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	var out []Event
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
			if ev.Type == "approval_needed" {
				id, _ := ev.Data["tool_call_id"].(string)
				_ = e.SendApproval(id, approve)
			}
			if on != nil {
				on(ev)
			}
		case <-timeout:
			t.Fatal("turn timed out")
		}
	}
}

func TestSelfConsciousContinuesWhileStepsRemainThenDone(t *testing.T) {
	var round atomic.Int32
	m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		if !hasEndTurn(r) {
			t.Error("self-conscious turn did not advertise end_turn")
		}
		switch round.Add(1) {
		case 1:
			return ModelResponse{ToolCalls: []ToolCall{call("work_plan", `{"tasks":[{"title":"step one","status":"in_progress"},{"title":"step two","status":"pending"}]}`)}}, nil
		case 2:
			// A plain reply with steps left must not end the turn.
			return ModelResponse{Content: "step one is done"}, nil
		case 3:
			if !strings.Contains(lastContent(r), "step one") || !strings.Contains(lastContent(r), "2 of 2") {
				t.Errorf("continuation prompt lacks plan state: %s", lastContent(r))
			}
			return ModelResponse{ToolCalls: []ToolCall{call("work_plan", `{"tasks":[{"title":"step one","status":"done"},{"title":"step two","status":"done"}]}`)}}, nil
		default:
			return ModelResponse{ToolCalls: []ToolCall{call("end_turn", `{"reason":"done","message":"all steps finished and verified"}`)}}, nil
		}
	})
	var plans atomic.Int32
	e := newTestEngine(t, m, testTools{planTool(&plans)})
	events := send(t, e, ChatRequest{Message: "do the work", PromptType: ModeSelfConscious})
	if s := doneStatus(t, events); s != "" {
		t.Fatalf("status %q: %s", s, eventText(events))
	}
	if round.Load() != 4 || plans.Load() != 2 || selfEvents(events, "continue") != 1 || selfEvents(events, "stop") != 1 {
		t.Fatalf("rounds=%d plans=%d %s", round.Load(), plans.Load(), eventText(events))
	}
	if got := events[len(events)-2].Data["content"]; got != "all steps finished and verified" {
		t.Fatalf("final answer %q", got)
	}
	r, _ := e.LoadSession(events[0].SessionID)
	if r.Turns[0].Mode != ModeSelfConscious {
		t.Fatal("mode not recorded")
	}
}

func TestSelfConsciousStopsOnNeedsPersonAndBlocked(t *testing.T) {
	for _, reason := range []string{"needs_person", "blocked"} {
		t.Run(reason, func(t *testing.T) {
			var round atomic.Int32
			m := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
				if round.Add(1) == 1 {
					return ModelResponse{ToolCalls: []ToolCall{call("work_plan", `{"tasks":[{"title":"deploy","status":"pending"}]}`)}}, nil
				}
				return ModelResponse{ToolCalls: []ToolCall{call("end_turn", `{"reason":"`+reason+`","message":"need the owner's approval for deploy"}`)}}, nil
			})
			e := newTestEngine(t, m, testTools{planTool(nil)})
			events := send(t, e, ChatRequest{Message: "ship it", PromptType: ModeSelfConscious})
			if s := doneStatus(t, events); s != reason {
				t.Fatalf("status %q", s)
			}
			// Even with plan steps left, a person-needed stop is immediate.
			if round.Load() != 2 || selfEvents(events, "continue") != 0 {
				t.Fatalf("continued past %s: %s", reason, eventText(events))
			}
			if events[len(events)-2].Data["content"] != "need the owner's approval for deploy" {
				t.Fatal("message not used as the answer")
			}
		})
	}
}

func TestSelfConsciousContinuationLimit(t *testing.T) {
	var round atomic.Int32
	m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		n := round.Add(1)
		if n == 1 {
			return ModelResponse{ToolCalls: []ToolCall{call("work_plan", `{"tasks":[{"title":"endless","status":"pending"}]}`)}}, nil
		}
		if r.Messages[len(r.Messages)-1].Role == "tool" {
			return ModelResponse{Content: "made some progress"}, nil
		}
		return ModelResponse{ToolCalls: []ToolCall{call("probe", `{"n":`+strings.Repeat("1", int(n%5)+1)+`}`)}}, nil
	})
	e := newTestEngine(t, m, testTools{planTool(nil), tool("probe", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { return "ok", nil })})
	events := send(t, e, ChatRequest{Message: "loop", PromptType: ModeSelfConscious})
	if s := doneStatus(t, events); s != StatusSelfConsciousLimit {
		t.Fatalf("status %q: %s", s, eventText(events))
	}
	if c := selfEvents(events, "continue"); c != MaxSelfConsciousContinuations {
		t.Fatalf("continuations %d", c)
	}
}

func TestSelfConsciousStallsWithoutToolProgress(t *testing.T) {
	var round atomic.Int32
	m := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		if round.Add(1) == 1 {
			return ModelResponse{ToolCalls: []ToolCall{call("work_plan", `{"tasks":[{"title":"left","status":"pending"}]}`)}}, nil
		}
		return ModelResponse{Content: "I will do it later"}, nil
	})
	e := newTestEngine(t, m, testTools{planTool(nil)})
	events := send(t, e, ChatRequest{Message: "go", PromptType: ModeSelfConscious})
	if s := doneStatus(t, events); s != StatusSelfConsciousStalled {
		t.Fatalf("status %q", s)
	}
	if selfEvents(events, "continue") != 2 || round.Load() != 4 {
		t.Fatalf("nudge cap not applied: rounds=%d %s", round.Load(), eventText(events))
	}
}

func TestSelfConsciousGoalCheckThenAnswerEnds(t *testing.T) {
	var round atomic.Int32
	m := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		round.Add(1)
		return ModelResponse{Content: "the answer is 42"}, nil
	})
	e := newTestEngine(t, m, nil)
	events := send(t, e, ChatRequest{Message: "what is it?", PromptType: ModeSelfConscious})
	if s := doneStatus(t, events); s != "" || round.Load() != 2 || selfEvents(events, "continue") != 1 {
		t.Fatalf("status %q rounds %d %s", s, round.Load(), eventText(events))
	}
}

func TestSelfConsciousEscCancelsContinuation(t *testing.T) {
	var round atomic.Int32
	m := modelFunc(func(ctx context.Context, _ ModelRequest, _ func(string)) (ModelResponse, error) {
		switch round.Add(1) {
		case 1:
			return ModelResponse{ToolCalls: []ToolCall{call("work_plan", `{"tasks":[{"title":"a","status":"pending"}]}`)}}, nil
		case 2:
			return ModelResponse{Content: "partial"}, nil
		default:
			<-ctx.Done() // the person pressed Esc during the continuation
			return ModelResponse{}, ctx.Err()
		}
	})
	e := newTestEngine(t, m, testTools{planTool(nil)})
	events := drainAnswering(t, e, ChatRequest{Message: "go", PromptType: ModeSelfConscious}, false, func(ev Event) {
		if ev.Type == "self_conscious" && ev.Data["action"] == "continue" {
			go e.Cancel()
		}
	})
	if s := doneStatus(t, events); s != "cancelled" || round.Load() != 3 {
		t.Fatalf("status %q rounds %d", s, round.Load())
	}
}

func TestSelfConsciousStopsAfterHumanDeniedApproval(t *testing.T) {
	var round atomic.Int32
	var executed atomic.Int32
	m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		switch round.Add(1) {
		case 1:
			return ModelResponse{ToolCalls: []ToolCall{call("work_plan", `{"tasks":[{"title":"remove","status":"pending"},{"title":"other","status":"pending"}]}`)}}, nil
		case 2:
			return ModelResponse{ToolCalls: []ToolCall{call("danger", `{}`)}}, nil
		default:
			return ModelResponse{Content: "the removal was refused"}, nil
		}
	})
	danger := tool("danger", false, func(ctx context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
		if !tc.Approve(ctx, Approval{ToolName: "danger", Description: "remote send", Class: ApprovalRemote}) {
			return "", context.Canceled
		}
		executed.Add(1)
		return "sent", nil
	})
	e := newTestEngine(t, m, testTools{planTool(nil), danger})
	events := drainAnswering(t, e, ChatRequest{Message: "go", PromptType: ModeSelfConscious}, false, nil)
	if s := doneStatus(t, events); s != StatusNeedsPerson {
		t.Fatalf("status %q: %s", s, eventText(events))
	}
	if executed.Load() != 0 || round.Load() != 3 || selfEvents(events, "continue") != 0 {
		t.Fatalf("continued after a refused approval: rounds=%d", round.Load())
	}
	// The class reaches the host unchanged so it can keep remote requests human.
	if !strings.Contains(eventText(events), `"class":"remote"`) {
		t.Fatal("approval class not forwarded")
	}
}

func TestSelfConsciousEmptyEndTurnAsksOnceForFinalMessage(t *testing.T) {
	for _, second := range []string{"here is the final summary", ""} {
		t.Run("second="+second, func(t *testing.T) {
			var round atomic.Int32
			m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
				switch round.Add(1) {
				case 1:
					return ModelResponse{Content: "interim note", ToolCalls: []ToolCall{call("probe", `{}`)}}, nil
				case 2:
					return ModelResponse{ToolCalls: []ToolCall{call("end_turn", `{"reason":"done","message":""}`)}}, nil
				default:
					if !strings.Contains(lastContent(r), "final message") {
						t.Errorf("did not ask for final text: %s", lastContent(r))
					}
					return ModelResponse{Content: second}, nil
				}
			})
			e := newTestEngine(t, m, testTools{tool("probe", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { return "ok", nil })})
			events := send(t, e, ChatRequest{Message: "go", PromptType: ModeSelfConscious})
			if s := doneStatus(t, events); s != "" || round.Load() != 3 || selfEvents(events, "continue") != 0 {
				t.Fatalf("status %q rounds %d %s", s, round.Load(), eventText(events))
			}
			want := second
			if want == "" {
				want = "interim note" // N1 fallback: this turn's last utterance
			}
			if got := events[len(events)-2].Data["content"]; got != want {
				t.Fatalf("answer %q want %q", got, want)
			}
		})
	}
}

func TestAutoAndLegacyModesNeverContinue(t *testing.T) {
	for _, mode := range []string{ModeAuto, "", "agent", "ask", "plan", "SELF-CONSCIOUS", "self"} {
		t.Run(mode, func(t *testing.T) {
			var round atomic.Int32
			m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
				if hasEndTurn(r) || strings.Contains(r.Messages[0].Content, "SELF-CONSCIOUS MODE") {
					t.Error("auto turn received self-conscious contract")
				}
				round.Add(1)
				return ModelResponse{Content: "ok"}, nil
			})
			e := newTestEngine(t, m, nil)
			events := send(t, e, ChatRequest{Message: "hi", PromptType: mode})
			if s := doneStatus(t, events); s != "" || round.Load() != 1 || eventCount(events, "self_conscious") != 0 {
				t.Fatalf("status %q rounds %d", s, round.Load())
			}
			r, _ := e.LoadSession(events[0].SessionID)
			if r.Turns[0].Mode != ModeAuto {
				t.Fatalf("mode %q", r.Turns[0].Mode)
			}
		})
	}
}
