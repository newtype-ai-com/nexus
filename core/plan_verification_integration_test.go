package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type integrationPlanVerifier func(context.Context, VerificationInput) ([]ItemVerdict, error)

func (f integrationPlanVerifier) Verify(c context.Context, i VerificationInput) ([]ItemVerdict, error) {
	return f(c, i)
}
func TestPlanGateIntegrationCancellationDuringVerifier(t *testing.T) {
	entered := make(chan struct{})
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		return ModelResponse{Content: "tentative"}, nil
	}), nil)
	e.opts.PlanVerifier = integrationPlanVerifier(func(ctx context.Context, _ VerificationInput) ([]ItemVerdict, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	ch, err := e.SendMessage(ChatRequest{SessionID: r.ID, Message: "work"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("verifier not entered")
	}
	e.Cancel()
	events := collect(t, ch)
	integrationTerminal(t, events, "cancelled")
	if strings.Contains(events[len(events)-2].Data["content"].(string), "tentative") {
		t.Fatal("cancelled tentative completion persisted")
	}
}

func TestPlanGateIntegrationStreamFailureDoesNotPersistTentative(t *testing.T) {
	e := newTestEngine(t, modelFunc(func(_ context.Context, _ ModelRequest, on func(string)) (ModelResponse, error) {
		on("tentative unverified answer")
		return ModelResponse{}, errors.New("stream interrupted")
	}), nil)
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
	assertTerminated(t, events)
	if eventCount(events, "content_done") != 1 || eventCount(events, "content_delta") != 0 || strings.Contains(events[len(events)-2].Data["content"].(string), "tentative unverified answer") {
		t.Fatal("stream failure leaked tentative", eventText(events))
	}
	record, err := e.LoadSession(r.ID)
	if err != nil || strings.Contains(record.Turns[0].Assistant, "tentative unverified answer") {
		t.Fatal("tentative stored")
	}
}

func TestPlanGateIntegrationNoProgressSurvivesNextTurn(t *testing.T) {
	var calls atomic.Int32
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls.Add(1)
		return ModelResponse{Content: "done"}, nil
	}), nil)
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	first := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
	integrationTerminal(t, first, "blocked_no_progress")
	second := send(t, e, ChatRequest{SessionID: r.ID, Message: "continue"})
	integrationTerminal(t, second, "blocked_no_progress")
	if calls.Load() != 4 || eventCount(second, "plan_verification") != 1 {
		t.Fatal("turn reset no-progress counter")
	}
}

func TestPlanGateIntegrationPinDoesNotOverrideToolGate(t *testing.T) {
	var rounds, executions, gates atomic.Int32
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		if rounds.Add(1) == 1 {
			return ModelResponse{ToolCalls: []ToolCall{call("mutate", `{}`)}}, nil
		}
		return ModelResponse{Content: "nothing changed"}, nil
	}), testTools{tool("mutate", false, func(context.Context, ToolContext, json.RawMessage) (string, error) {
		executions.Add(1)
		return "changed", nil
	})})
	e.opts.Binder = BinderFunc(func(context.Context, BindRequest) (*Binding, error) {
		return &Binding{Gate: func(context.Context, string, json.RawMessage) (bool, string) {
			gates.Add(1)
			return false, "denied by existing mandate"
		}}, nil
	})
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
	integrationTerminal(t, events, "blocked_no_progress")
	if executions.Load() != 0 || gates.Load() != 1 {
		t.Fatal("pin expanded authority")
	}
}

func integrationPin(t *testing.T, e *Engine, body string) SessionRecord {
	t.Helper()
	p := filepath.Join(e.opts.WorkDir, "acceptance plan.md")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := e.PinPlan("", p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func integrationResult(t *testing.T, ev Event) VerificationResult {
	t.Helper()
	b, err := json.Marshal(ev.Data["result"])
	if err != nil {
		t.Fatal(err)
	}
	var r VerificationResult
	if err = json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func integrationTerminal(t *testing.T, events []Event, status string) {
	t.Helper()
	assertTerminated(t, events)
	if eventCount(events, "content_done") != 1 || eventCount(events, "done") != 1 {
		t.Fatal("multiple final answers")
	}
	if events[len(events)-1].Data["status"] != status {
		t.Fatalf("status want %s: %s", status, eventText(events))
	}
}
func TestPlanGateIntegrationThreeNoProgressFinalOnce(t *testing.T) {
	var calls atomic.Int32
	e := newTestEngine(t, modelFunc(func(_ context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
		n := calls.Add(1)
		if n > 1 && !strings.Contains(r.Messages[len(r.Messages)-1].Content, PlanContinuation) {
			t.Error("missing continuation")
		}
		on("tentative completion")
		return ModelResponse{Content: "tentative completion"}, nil
	}), nil)
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work", PromptType: ModeAuto})
	integrationTerminal(t, events, "blocked_no_progress")
	if calls.Load() != 3 || eventCount(events, "plan_verification") != 3 || eventCount(events, "content_delta") != 0 {
		t.Fatal("continue count or tentative leak", eventText(events))
	}
	checks := 0
	for _, ev := range events {
		if ev.Type == "plan_verification" {
			checks++
			result := integrationResult(t, ev)
			if result.NoProgress != checks || result.Remaining != 1 {
				t.Fatal(result)
			}
		}
	}
	record, err := e.LoadSession(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Turns) != 1 || strings.Contains(record.Turns[0].Assistant, "tentative completion") || !strings.Contains(record.Turns[0].Assistant, "blocked_no_progress") {
		t.Fatal("tentative persisted", record.Turns)
	}
}
func TestPlanGateIntegrationAllWaitingNoVerifier(t *testing.T) {
	var calls atomic.Int32
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls.Add(1)
		return ModelResponse{Content: "all done"}, nil
	}), nil)
	e.opts.PlanVerifier = integrationPlanVerifier(func(context.Context, VerificationInput) ([]ItemVerdict, error) {
		t.Error("approval wait spent verifier call")
		return nil, nil
	})
	r := integrationPin(t, e, "- [ ] separate approval required for deployment\n- [ ] owner input for physical copy\n")
	events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
	integrationTerminal(t, events, "waiting_person")
	if calls.Load() != 1 || eventCount(events, "plan_verification") != 1 {
		t.Fatal(eventText(events))
	}
	for _, ev := range events {
		if ev.Type == "plan_verification" {
			result := integrationResult(t, ev)
			if result.Remaining != 2 {
				t.Fatal(result)
			}
			for _, v := range result.Items {
				if v.State != "waiting_person" {
					t.Fatal(v)
				}
			}
		}
	}
}
func TestPlanGateIntegrationMixedWaitingContinues(t *testing.T) {
	var calls atomic.Int32
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls.Add(1)
		return ModelResponse{Content: "need person"}, nil
	}), nil)
	r := integrationPin(t, e, "- [ ] separate approval required for deployment\n- [ ] implement independent local work\n")
	events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
	integrationTerminal(t, events, "blocked_no_progress")
	if calls.Load() != 3 {
		t.Fatal("wait blocked independent work")
	}
}
func TestPlanGateIntegrationVerifierCannotOverrideInvalidEvidence(t *testing.T) {
	var calls atomic.Int32
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		return ModelResponse{Content: "worker-private-answer"}, nil
	}), nil)
	e.opts.PlanVerifier = integrationPlanVerifier(func(_ context.Context, i VerificationInput) ([]ItemVerdict, error) {
		calls.Add(1)
		b, _ := json.Marshal(i)
		if strings.Contains(string(b), "worker-private-answer") {
			t.Error("worker conversation leaked")
		}
		out := make([]ItemVerdict, 0, len(i.Plan.Items))
		for _, item := range i.Plan.Items {
			out = append(out, ItemVerdict{ID: item.ID, State: "verified_done", Reason: "model claims PASS"})
		}
		i.Plan.Items[0].RequiresApproval = true
		return out, nil
	})
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
	integrationTerminal(t, events, "blocked_no_progress")
	if calls.Load() != 3 {
		t.Fatal("verifier invocation count")
	}
	for _, ev := range events {
		if ev.Type == "plan_verification" {
			result := integrationResult(t, ev)
			if result.Items[0].State != "unresolved" {
				t.Fatal("invalid evidence overridden", result)
			}
		}
	}
	p, err := e.GetPinnedPlan(r.ID)
	if err != nil || p.Items[0].RequiresApproval {
		t.Fatal("verifier mutated fixed plan")
	}
}
func TestPlanGateIntegrationCancellationOverrides(t *testing.T) {
	entered := make(chan struct{})
	e := newTestEngine(t, modelFunc(func(ctx context.Context, _ ModelRequest, _ func(string)) (ModelResponse, error) {
		close(entered)
		<-ctx.Done()
		return ModelResponse{}, ctx.Err()
	}), nil)
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	ch, err := e.SendMessage(ChatRequest{SessionID: r.ID, Message: "work"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("model not entered")
	}
	e.Cancel()
	events := collect(t, ch)
	integrationTerminal(t, events, "cancelled")
	if eventCount(events, "plan_verification") != 0 {
		t.Fatal("cancelled work verified")
	}
}
func TestPlanGateIntegrationRoundLimitOverrides(t *testing.T) {
	var calls atomic.Int32
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls.Add(1)
		return ModelResponse{Content: "tentative"}, nil
	}), nil)
	e.opts.MaxRounds = 2
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
	integrationTerminal(t, events, "round_limit")
	if calls.Load() != 2 || eventCount(events, "plan_verification") != 2 {
		t.Fatal(eventText(events))
	}
	if strings.Contains(events[len(events)-2].Data["content"].(string), "tentative") {
		t.Fatal("tentative answer survived safety limit")
	}
}
func TestPlanGateIntegrationNoOptIn(t *testing.T) {
	// Read-only ask/plan modes were removed (docs/tui-modes.md); only the
	// person's opt-in controls the gate.
	for _, mode := range []string{"unpin", "deactivate"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			e := newTestEngine(t, modelFunc(func(_ context.Context, req ModelRequest, _ func(string)) (ModelResponse, error) {
				for _, spec := range req.Tools {
					if spec.Name == "end_turn" {
						t.Error("ungated turn advertised end_turn")
					}
				}
				calls.Add(1)
				return ModelResponse{Content: "normal answer"}, nil
			}), nil)
			r := integrationPin(t, e, "- [ ] implement local feature\n")
			prompt := ModeAuto
			switch mode {
			case "unpin":
				if _, err := e.UnpinPlan(r.ID); err != nil {
					t.Fatal(err)
				}
			case "deactivate":
				if err := e.DeactivatePlan(r.ID); err != nil {
					t.Fatal(err)
				}
			}
			events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work", PromptType: prompt})
			assertTerminated(t, events)
			if calls.Load() != 1 || eventCount(events, "plan_verification") != 0 || eventCount(events, "content_done") != 1 {
				t.Fatal("mode autoenabled", eventText(events))
			}
		})
	}
}
func TestPlanGateIntegrationBackgroundDoesNotOptIn(t *testing.T) {
	var calls atomic.Int32
	e := backgroundEngine(t, modelFunc(func(_ context.Context, req ModelRequest, _ func(string)) (ModelResponse, error) {
		for _, spec := range req.Tools {
			if spec.Name == "end_turn" {
				t.Error("background advertised end_turn")
			}
		}
		calls.Add(1)
		return ModelResponse{Content: "completion observed"}, nil
	}), nil)
	r := integrationPin(t, e, "- [ ] implement local feature\n")
	callback := registerFixture(t, e, r.ID)
	callback(BackgroundCompletion{JobID: "fixture-job", Status: "succeeded", Output: "PASS is not evidence"})
	events := nextBackground(t, e, r.ID)
	assertTerminated(t, events)
	if calls.Load() != 1 || eventCount(events, "plan_verification") != 0 || eventCount(events, "content_done") != 1 {
		t.Fatal("background autoenabled plan gate", eventText(events))
	}
}
