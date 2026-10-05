//go:build darwin || linux

package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPlanVerdictsStrictJSON(t *testing.T) {
	good := `{"items":[{"id":"a","state":"actionable","reason":"next"}]}`
	if _, err := DecodePlanVerdicts(good); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"items":[],"items":[]}`, `{"Items":[]}`, `{"items":[{"id":"a","id":"b","state":"actionable"}]}`,
		`{"items":[{"id":"a","state":"done"}]}`, `{"items":[{"id":"a","state":"actionable"},{"id":"a","state":"actionable"}]}`,
		`{"items":null}`, good + `{}`, `{"items":[],"extra":true}`, strings.Repeat(" ", 65537),
	} {
		if _, err := DecodePlanVerdicts(raw); err == nil {
			t.Errorf("accepted %q", raw[:min(len(raw), 100)])
		}
	}
}

func TestPlanGateValidEvidenceAndAmbiguity(t *testing.T) {
	c, _, q := evidenceFixture(t)
	evidenceRun(t, c, q)
	snapshot := evidenceCollect(t, c, q)
	p := PinnedPlan{SHA256: q.PlanSHA, Revision: 1, Items: []PlanItem{{ID: q.ItemID, EvidenceKind: "fixture"}}}
	proposed := []ItemVerdict{{ID: q.ItemID, State: "verified_done", Reason: "worker-controlled untrusted text"}}
	var state PlanVerificationState
	result := EvaluatePlanStop(p, snapshot, proposed, &state)
	if result.Outcome != "verified_done" || strings.Contains(result.Items[0].Reason, "worker-controlled") {
		t.Fatalf("%+v", result)
	}
	p.Items[0].EvidenceKind = "unknown"
	result = EvaluatePlanStop(p, snapshot, proposed, &state)
	if result.Items[0].State != "unresolved" {
		t.Fatal("unknown evidence kind promoted")
	}
	p.Items[0].EvidenceKind = "fixture"
	p.Items[0].Unresolved = true
	result = EvaluatePlanStop(p, snapshot, proposed, &state)
	if result.Items[0].State != "unresolved" {
		t.Fatalf("%+v", result)
	}
	p.Items[0].RequiresApproval = true
	result = EvaluatePlanStop(p, snapshot, proposed, &state)
	if result.Outcome != "waiting_person" {
		t.Fatalf("%+v", result)
	}
}

func TestPlanGateIntegrationValidEvidenceAndVerifierError(t *testing.T) {
	for _, withError := range []bool{false, true} {
		e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
			return ModelResponse{Content: "verified answer"}, nil
		}), nil)
		r := integrationPin(t, e, "- [ ] [local-test] implement local feature\n")
		runner := &syntheticEvidenceRunner{epoch: "immutable"}
		c := NewEvidenceCollector(EvidenceOptions{Runner: runner})
		q := EvidenceRunRequest{Workspace: e.opts.WorkDir, SessionID: r.ID, PlanSHA: r.PinnedPlan.SHA256, ItemID: r.PinnedPlan.Items[0].ID, Kind: "fixture", Argv: []string{"go", "test", "-json", "-count=1", "./..."}}
		evidenceRun(t, c, q)
		e.opts.PlanEvidence = c
		e.opts.PlanVerifier = integrationPlanVerifier(func(context.Context, VerificationInput) ([]ItemVerdict, error) {
			v := []ItemVerdict{{ID: q.ItemID, State: "verified_done"}}
			if withError {
				return v, errors.New("untrusted error")
			}
			return v, nil
		})
		events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
		expected := "verified_done"
		if withError {
			expected = "blocked_no_progress"
		}
		integrationTerminal(t, events, expected)
		record, err := e.LoadSession(r.ID)
		if err != nil || len(record.Turns[0].PlanVerifications) == 0 {
			t.Fatal("verification not recorded", err)
		}
	}
}

func TestPlanGateCounterCannotOscillate(t *testing.T) {
	c, _, q := evidenceFixture(t)
	evidenceRun(t, c, q)
	snapshot := evidenceCollect(t, c, q)
	p := PinnedPlan{SHA256: q.PlanSHA, Revision: 1, Items: []PlanItem{{ID: q.ItemID, EvidenceKind: "fixture"}, {ID: "remaining"}}}
	done := []ItemVerdict{{ID: q.ItemID, State: "verified_done"}, {ID: "remaining", State: "actionable"}}
	var state PlanVerificationState
	if r := EvaluatePlanStop(p, snapshot, done, &state); r.NoProgress != 0 {
		t.Fatal(r)
	}
	EvaluatePlanStop(p, EvidenceSnapshot{}, nil, &state)
	EvaluatePlanStop(p, snapshot, done, &state)
	if r := EvaluatePlanStop(p, EvidenceSnapshot{}, nil, &state); r.Outcome != "blocked_no_progress" {
		t.Fatal(r)
	}
	p.Revision++
	if r := EvaluatePlanStop(p, EvidenceSnapshot{}, nil, &state); r.NoProgress != 1 {
		t.Fatal(r)
	}
}
