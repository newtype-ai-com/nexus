package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

// docs/tui-modes-manager-review.md corrections (MODE-R2, MODE-R3, MODE-O1).

func finalContent(events []Event) any { return events[len(events)-2].Data["content"] }

func deniedRemoteTool(name string, asked, ran *atomic.Int32) Tool {
	return tool(name, false, func(ctx context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
		asked.Add(1)
		if !tc.Approve(ctx, Approval{ToolName: name, Description: "remote", Class: ApprovalRemote}) {
			return "", errors.New("denied")
		}
		ran.Add(1)
		return "sent", nil
	})
}

// MODE-R2: a model that asks for the refused action again gets no second
// approval prompt and no further tool round; the turn ends needs_person.
func TestSelfConsciousRefusalStopsFurtherToolRounds(t *testing.T) {
	for _, closing := range []string{"", "The send was refused; tell me whether to try another way."} {
		t.Run("closing="+closing, func(t *testing.T) {
			var rounds, asked, ran, approvals atomic.Int32
			m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
				if rounds.Add(1) == 2 && !strings.Contains(lastContent(r), "refused an approval") {
					t.Errorf("closing prompt missing: %s", lastContent(r))
				}
				// Always tries the same remote call again (with any closing text).
				return ModelResponse{Content: map[bool]string{true: closing}[rounds.Load() > 1], ToolCalls: []ToolCall{call("danger", `{}`)}}, nil
			})
			e := newTestEngine(t, m, testTools{deniedRemoteTool("danger", &asked, &ran)})
			events := drainAnswering(t, e, ChatRequest{Message: "work", PromptType: ModeSelfConscious}, false, func(ev Event) {
				if ev.Type == "approval_needed" {
					approvals.Add(1)
				}
			})
			if s := doneStatus(t, events); s != StatusNeedsPerson {
				t.Fatalf("status %q: %s", s, eventText(events))
			}
			if approvals.Load() != 1 || asked.Load() != 1 || ran.Load() != 0 || rounds.Load() != 2 || selfEvents(events, "continue") != 0 {
				t.Fatalf("approvals=%d asked=%d ran=%d rounds=%d", approvals.Load(), asked.Load(), ran.Load(), rounds.Load())
			}
			want := closing
			if want == "" {
				want = RefusedApprovalMessage
			}
			if got := finalContent(events); got != want {
				t.Fatalf("answer %q want %q", got, want)
			}
		})
	}
}

// MODE-R2 within one batch: after the refusal, later calls in the same batch
// neither run nor ask.
func TestSelfConsciousRefusalStopsRestOfBatch(t *testing.T) {
	var rounds, asked, ran, otherAsked, otherRan, local atomic.Int32
	m := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		if rounds.Add(1) == 1 {
			return ModelResponse{ToolCalls: []ToolCall{call("danger", `{}`), call("other", `{}`), call("probe", `{}`)}}, nil
		}
		return ModelResponse{Content: "refused"}, nil
	})
	probe := tool("probe", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { local.Add(1); return "ok", nil })
	e := newTestEngine(t, m, testTools{deniedRemoteTool("danger", &asked, &ran), deniedRemoteTool("other", &otherAsked, &otherRan), probe})
	events := drainAnswering(t, e, ChatRequest{Message: "work", PromptType: ModeSelfConscious}, false, nil)
	if s := doneStatus(t, events); s != StatusNeedsPerson || asked.Load() != 1 || otherAsked.Load() != 0 || local.Load() != 0 || rounds.Load() != 2 {
		t.Fatalf("status=%q asked=%d other=%d local=%d rounds=%d", s, asked.Load(), otherAsked.Load(), local.Load(), rounds.Load())
	}
}

// MODE-R3: an empty end_turn(done) is judged before the final-message
// fallback. Pending steps continue; all waiting_person ends needs_person; an
// all-done plan is accepted and only then asked once for its text.
func TestSelfConsciousEmptyDoneRespectsPlan(t *testing.T) {
	for _, c := range []struct {
		name, plan, status string
		continues          bool
	}{
		{"pending", `{"tasks":[{"title":"a","status":"pending"}]}`, "", true},
		{"in_progress", `{"tasks":[{"title":"a","status":"done"},{"title":"b","status":"in_progress"}]}`, "", true},
		{"waiting_person", `{"tasks":[{"title":"a","status":"done"},{"title":"b","status":"waiting_person"}]}`, StatusNeedsPerson, false},
		{"all_done", `{"tasks":[{"title":"a","status":"done"}]}`, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var rounds atomic.Int32
			var prompts []string
			m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
				n := rounds.Add(1)
				if n > 1 {
					prompts = append(prompts, lastContent(r))
				}
				switch n {
				case 1:
					return ModelResponse{ToolCalls: []ToolCall{call("work_plan", c.plan)}}, nil
				case 2:
					return ModelResponse{ToolCalls: []ToolCall{call("end_turn", `{"reason":"done","message":""}`)}}, nil
				case 3:
					if c.continues {
						// Finish the plan, then a proper done.
						return ModelResponse{ToolCalls: []ToolCall{call("work_plan", `{"tasks":[{"title":"a","status":"done"},{"title":"b","status":"done"}]}`)}}, nil
					}
					// In final-message-only state a tool call is not executed.
					return ModelResponse{Content: "final text", ToolCalls: []ToolCall{call("work_plan", `{"tasks":[]}`)}}, nil
				default:
					return ModelResponse{ToolCalls: []ToolCall{call("end_turn", `{"reason":"done","message":"all finished"}`)}}, nil
				}
			})
			var planRuns atomic.Int32
			e := newTestEngine(t, m, testTools{planTool(&planRuns)})
			events := send(t, e, ChatRequest{Message: "finish", PromptType: ModeSelfConscious})
			if s := doneStatus(t, events); s != c.status {
				t.Fatalf("status %q want %q: %s", s, c.status, eventText(events))
			}
			if c.continues {
				if selfEvents(events, "continue") != 1 || !strings.Contains(prompts[1], "unfinished") || rounds.Load() != 4 || finalContent(events) != "all finished" {
					t.Fatalf("open plan not continued: rounds=%d prompts=%q", rounds.Load(), prompts)
				}
				return
			}
			if selfEvents(events, "continue") != 0 || !strings.Contains(prompts[1], "final message") || rounds.Load() != 3 || planRuns.Load() != 1 || finalContent(events) != "final text" {
				t.Fatalf("accepted stop: rounds=%d planRuns=%d prompts=%q answer=%v", rounds.Load(), planRuns.Load(), prompts, finalContent(events))
			}
		})
	}
}

// MODE-O1 (documented, unchanged): an explicit, non-empty done with no open
// plan is accepted as the model's own goal assessment without a separate goal
// check; a reply without end_turn gets exactly one goal check.
func TestSelfConsciousGoalCheckScopeMatchesDocs(t *testing.T) {
	s := &selfConscious{}
	if d := s.decide(&StopAttempt{Reason: "done", Message: "finished"}, false); !d.stop || d.summary != "done" || s.goalChecked {
		t.Fatalf("explicit done: %+v", d)
	}
	s = &selfConscious{}
	if d := s.decide(nil, false); d.stop || d.summary != "goal_check" {
		t.Fatalf("plain reply: %+v", d)
	}
	if d := s.decide(nil, false); !d.stop || d.summary != "answered" {
		t.Fatalf("after goal check: %+v", d)
	}
}
