package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func verifierFixture() VerificationInput {
	return VerificationInput{Plan: PinnedPlan{Path: "plan.md", SHA256: "digest", Snapshot: "- [ ] test", Revision: 1, Source: "human", Items: []PlanItem{{ID: "pi_test", Text: "test"}}}, Evidence: EvidenceSnapshot{SessionID: "cnv_test", PlanSHA: "digest"}}
}
func verifierOptions(m Model) ModelPlanVerifierOptions {
	return ModelPlanVerifierOptions{Model: m, ModelName: "test", SessionID: "cnv_test", TaskID: "tsk_test", AgentSessionID: "ags_test", MaxCalls: 1, AllowTransmission: true}
}

const verifierAnswer = `{"items":[{"id":"pi_test","state":"unresolved","reason":"Needs evidence"}]}`

func TestModelPlanVerifierIsolationAndPurpose(t *testing.T) {
	var calls int
	opts := verifierOptions(modelFunc(func(ctx context.Context, r ModelRequest, emit func(string)) (ModelResponse, error) {
		calls++
		if len(r.Tools) != 0 || r.Stream || len(r.Messages) != 2 || r.SessionID != "cnv_test" || r.TaskID != "tsk_test" || r.AgentSessionID != "ags_test" || r.InvocationID == "" {
			t.Fatal("unsafe request", r)
		}
		if r.Messages[0].Role != "system" || r.Messages[1].Role != "user" || !strings.Contains(r.Messages[1].Content, "pi_test") {
			t.Fatal("bad isolation")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("no timeout")
		}
		emit("ignored stream")
		return ModelResponse{Content: verifierAnswer, FinishReason: "stop", Usage: Usage{InputTokens: 10}}, nil
	}))
	v, err := NewModelPlanVerifier(opts)
	if err != nil {
		t.Fatal(err)
	}
	out, err := v.Verify(context.Background(), verifierFixture())
	if err != nil || len(out) != 1 {
		t.Fatal(out, err)
	}
	records := v.Records()
	if len(records) != 1 || records[0].Purpose != "plan_verification" || records[0].Usage.InputTokens != 10 || records[0].Error != "" {
		t.Fatal(records)
	}
	records[0].Purpose = "mutated"
	if v.Records()[0].Purpose != "plan_verification" {
		t.Fatal("records alias")
	}
	if _, err = v.Verify(context.Background(), verifierFixture()); err == nil || calls != 1 {
		t.Fatal("call cap bypass")
	}
}
func TestModelPlanVerifierDefaultNoTransmissionAndSecretInput(t *testing.T) {
	var calls int
	opts := verifierOptions(modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls++
		return ModelResponse{}, nil
	}))
	opts.AllowTransmission = false
	v, _ := NewModelPlanVerifier(opts)
	if _, err := v.Verify(context.Background(), verifierFixture()); err == nil {
		t.Fatal("default sent")
	}
	opts.AllowTransmission = true
	v, _ = NewModelPlanVerifier(opts)
	for _, kind := range []string{"secret", "foreign", "missing", "large"} {
		input := verifierFixture()
		switch kind {
		case "secret":
			input.Plan.Snapshot = "ghp_" + strings.Repeat("a", 36)
		case "foreign":
			input.Evidence.SessionID = "foreign"
		case "missing":
			input.Evidence.SessionID = ""
		case "large":
			input.Plan.Snapshot = strings.Repeat("a", maxPlanBytes+1)
		}
		if _, err := v.Verify(context.Background(), input); err == nil {
			t.Fatal("unsafe input", kind)
		}
	}
	if calls != 0 || len(v.Records()) != 0 {
		t.Fatal("input rejection called model")
	}
}
func TestModelPlanVerifierRejectsMalformedSecretAndToolOutputs(t *testing.T) {
	tests := []ModelResponse{
		{Content: verifierAnswer, FinishReason: "length"},
		{Content: verifierAnswer, FinishReason: "stop", ToolCalls: []ToolCall{{Name: "run_command"}}},
		{Content: `{"items":[],"items":[{"id":"pi_test","state":"verified_done","reason":"fake"}]}`, FinishReason: "stop"},
		{Content: `{"items":[{"id":"pi_test","state":"other","reason":"no"}]}`, FinishReason: "stop"},
		{Content: `{"items":[{"id":"foreign","state":"unresolved","reason":"no"}]}`, FinishReason: "stop"},
		{Content: `{"items":[{"id":"pi_test","state":"unresolved","reason":"ghp_` + strings.Repeat("a", 36) + `"}]}`, FinishReason: "stop"},
		{Content: `{"items":[]} trailing`, FinishReason: "stop"},
		{Content: strings.Repeat("a", 64*1024+1), FinishReason: "stop"},
	}
	for i, response := range tests {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			v, _ := NewModelPlanVerifier(verifierOptions(modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) { return response, nil })))
			if _, err := v.Verify(context.Background(), verifierFixture()); err == nil {
				t.Fatal("bad response accepted")
			}
			if _, err := v.Verify(context.Background(), verifierFixture()); err == nil || len(v.Records()) != 1 {
				t.Fatal("failure refunded")
			}
			raw, _ := json.Marshal(v.Records())
			if strings.Contains(string(raw), "ghp_") {
				t.Fatal("secret in record")
			}
		})
	}
}
func TestModelPlanVerifierCancellationAndErrorBodyNotRetained(t *testing.T) {
	for _, kind := range []string{"timeout", "provider", "cancel-before"} {
		t.Run(kind, func(t *testing.T) {
			var calls int
			opts := verifierOptions(modelFunc(func(ctx context.Context, _ ModelRequest, _ func(string)) (ModelResponse, error) {
				calls++
				if kind == "timeout" {
					<-ctx.Done()
					return ModelResponse{Content: verifierAnswer, FinishReason: "stop"}, nil
				}
				return ModelResponse{}, errors.New("private-provider-body")
			}))
			opts.Timeout = time.Millisecond
			v, _ := NewModelPlanVerifier(opts)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel-before" {
				cancel()
			}
			if _, err := v.Verify(ctx, verifierFixture()); err == nil || strings.Contains(err.Error(), "private-provider") {
				t.Fatal("unsafe error", err)
			}
			raw, _ := json.Marshal(v.Records())
			if strings.Contains(string(raw), "private-provider") {
				t.Fatal("provider body persisted")
			}
			if kind == "cancel-before" && calls != 0 {
				t.Fatal("cancelled request called model")
			}
		})
	}
}
func TestModelPlanVerifierConcurrentCallLimit(t *testing.T) {
	var calls atomic.Int32
	v, _ := NewModelPlanVerifier(verifierOptions(modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls.Add(1)
		return ModelResponse{Content: verifierAnswer, FinishReason: "stop"}, nil
	})))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); v.Verify(context.Background(), verifierFixture()) }()
	}
	wg.Wait()
	if calls.Load() != 1 || len(v.Records()) != 1 {
		t.Fatal("concurrent cap bypass")
	}
}
