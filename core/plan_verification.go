package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const PlanContinuation = "What you said just now is not kept as this turn's answer: the answer is what you say when the turn ends. Until then work without summing up again; then give one answer that stands on its own."

type ItemVerdict struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}
type VerificationResult struct {
	Items      []ItemVerdict `json:"items"`
	Outcome    string        `json:"outcome"`
	Remaining  int           `json:"remaining"`
	NoProgress int           `json:"no_progress"`
}

// VerificationInput intentionally excludes the worker's conversation, answer,
// tool arguments, credentials and authority. Evidence is data, not instructions.
type VerificationInput struct {
	Plan     PinnedPlan       `json:"plan"`
	Evidence EvidenceSnapshot `json:"evidence"`
}
type PlanVerifier interface {
	Verify(context.Context, VerificationInput) ([]ItemVerdict, error)
}
type StopAttempt struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func planStopSpec() ToolSpec {
	return ToolSpec{Name: "end_turn", Description: "Request to end this plan-gated turn. This is not completion evidence: the engine checks remaining work and approvals before allowing an end.", Parameters: json.RawMessage(`{"type":"object","properties":{"reason":{"type":"string","enum":["done","needs_person","blocked"]},"message":{"type":"string"}},"required":["reason","message"],"additionalProperties":false}`)}
}

func decodePlanStop(raw json.RawMessage) (StopAttempt, error) {
	var out StopAttempt
	if len(raw) > 64*1024 {
		return out, errors.New("invalid_stop_attempt")
	}
	if err := checkVerdictJSON(json.NewDecoder(strings.NewReader(string(raw))), 0); err != nil {
		return out, errors.New("invalid_stop_attempt")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return out, errors.New("invalid_stop_attempt")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return out, errors.New("invalid_stop_attempt")
	}
	if strings.TrimSpace(out.Message) == "" {
		return out, errors.New("invalid_stop_attempt")
	}
	switch out.Reason {
	case "done", "needs_person", "blocked":
	default:
		return out, errors.New("invalid_stop_attempt")
	}
	return out, nil
}

type PlanVerificationState struct {
	Revision  int
	Source    string
	SHA       string
	Remaining int
	Checks    int
}

// EvaluatePlanStop cannot promote model claims over missing/invalid evidence or
// release approval waits. It also cannot execute anything or grant authority.
func EvaluatePlanStop(plan PinnedPlan, evidence EvidenceSnapshot, proposed []ItemVerdict, state *PlanVerificationState) VerificationResult {
	result := VerificationResult{}
	byID := map[string]ItemVerdict{}
	valid := len(proposed) == len(plan.Items)
	known := map[string]bool{}
	for _, item := range plan.Items {
		known[item.ID] = true
	}
	for _, v := range proposed {
		if !known[v.ID] || byID[v.ID].ID != "" || len(v.Reason) > 1024 {
			valid = false
		}
		switch v.State {
		case "actionable", "waiting_person", "verified_done", "unresolved":
		default:
			valid = false
		}
		byID[v.ID] = v
	}
	waits := 0
	for _, item := range plan.Items {
		v := ItemVerdict{ID: item.ID, State: "actionable", Reason: "No verified completion; continue within existing permissions."}
		if item.Unresolved {
			v.State = "unresolved"
			v.Reason = "Plan item needs clarification or evidence."
		}
		if valid {
			candidate := byID[item.ID]
			switch candidate.State {
			case "verified_done":
				if item.EvidenceKind == "fixture" && !item.Unresolved && evidence.PlanSHA == plan.SHA256 && evidence.ValidFor(item.ID) {
					v.State = "verified_done"
					v.Reason = "Independent verdict supported by valid execution evidence."
				} else {
					v.State = "unresolved"
					v.Reason = "Completion rejected: missing, stale or invalid execution evidence or ambiguous requirement."
				}
			case "unresolved":
				v.State = "unresolved"
				v.Reason = "Independent verifier could not establish completion."
			}
		}
		if item.RequiresApproval {
			v.State = "waiting_person"
			v.Reason = "Separate human approval required; pinning is not approval."
		}
		if v.State != "verified_done" {
			result.Remaining++
		}
		if v.State == "waiting_person" {
			waits++
		}
		result.Items = append(result.Items, v)
	}
	if state.Source != plan.Source || (plan.Source != "model_work_plan" && (state.Revision != plan.Revision || state.SHA != plan.SHA256)) || state.SHA == "" {
		*state = PlanVerificationState{Revision: plan.Revision, Source: plan.Source, SHA: plan.SHA256, Remaining: len(plan.Items)}
	}
	// Track the best verified remainder, not oscillation between stale/new evidence.
	if result.Remaining < state.Remaining {
		state.Checks = 0
		state.Remaining = result.Remaining
	} else if state.Checks < 3 {
		state.Checks++
	}
	result.NoProgress = state.Checks
	switch {
	case len(plan.Items) == 0:
		result.Outcome = "blocked_unresolved_plan"
	case result.Remaining == 0:
		result.Outcome = "verified_done"
	case waits == result.Remaining:
		result.Outcome = "waiting_person"
	case state.Checks >= 3:
		result.Outcome = "blocked_no_progress"
	default:
		result.Outcome = "continue"
	}
	return result
}

func (t *turn) startPlanVerification() (*PinnedPlan, error) {
	e := t.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.planVerificationEnabled[t.request.SessionID] || t.backgroundTurn || t.inboxTurn {
		return nil, nil
	}
	r, err := e.loadRecord(t.request.SessionID)
	if err != nil {
		return nil, err
	}
	if r.PinnedPlan != nil {
		return r.PinnedPlan, nil
	}
	if r.WorkPlan != nil {
		return r.WorkPlan.VerificationPlan(), nil
	}
	return nil, nil
}

func (t *turn) verifyPlanStop(plan *PinnedPlan, state *PlanVerificationState) VerificationResult {
	e := t.engine
	if plan.Source == "model_work_plan" {
		current, err := t.startPlanVerification()
		if err != nil || current == nil || current.Source != "model_work_plan" {
			return VerificationResult{Outcome: "blocked_unresolved_plan", Remaining: len(plan.Items)}
		}
		*plan = *current
	}
	evidence := EvidenceSnapshot{}
	if e.opts.PlanEvidence != nil && e.checkExecution(t.ctx) == nil {
		snapshot, err := e.opts.PlanEvidence.Collect(t.ctx, t.request.WorkDir, t.request.SessionID, plan.SHA256)
		if err == nil {
			evidence = snapshot
		}
	}
	var proposed []ItemVerdict
	// Do not spend a verifier call for an entirely approval-blocked document.
	needsVerifier := false
	for _, item := range plan.Items {
		if !item.RequiresApproval {
			needsVerifier = true
		}
	}
	if needsVerifier && e.opts.PlanVerifier != nil && e.checkExecution(t.ctx) == nil {
		ctx, cancel := context.WithTimeout(t.ctx, 15*time.Second)
		// Clone: verifier implementations cannot mutate the engine's pinned plan.
		raw, _ := json.Marshal(VerificationInput{Plan: *plan, Evidence: evidence})
		var input VerificationInput
		if json.Unmarshal(raw, &input) == nil {
			verdicts, err := e.opts.PlanVerifier.Verify(ctx, input)
			if err == nil && e.checkExecution(ctx) == nil {
				proposed = verdicts
			}
		}
		cancel()
	}
	result := EvaluatePlanStop(*plan, evidence, proposed, state)
	e.mu.Lock()
	if e.planVerificationStates == nil {
		e.planVerificationStates = map[string]PlanVerificationState{}
	}
	e.planVerificationStates[t.request.SessionID] = *state
	e.mu.Unlock()
	t.record.PlanVerifications = append(t.record.PlanVerifications, result)
	t.emit("plan_verification", map[string]any{"revision": plan.Revision, "result": result})
	return result
}

func planStopMessage(plan *PinnedPlan, result VerificationResult) string {
	var b strings.Builder
	if result.Outcome == "continue" {
		b.WriteString("Continue the remaining plan items within existing permissions. Do not ask for confirmation of a recommended safe next step.\n")
	} else {
		fmt.Fprintf(&b, "Plan verification: %s.\n", result.Outcome)
	}
	for _, v := range result.Items {
		if v.State == "verified_done" {
			continue
		}
		for _, item := range plan.Items {
			if item.ID == v.ID {
				fmt.Fprintf(&b, "- %s [%s] %s: %s\n", v.ID, v.State, clean(item.Text), v.Reason)
				break
			}
		}
	}
	if result.Outcome == "continue" {
		b.WriteString(PlanContinuation)
	}
	return b.String()
}

// DecodePlanVerdicts is shared by tool-free verifier adapters. Unknown fields,
// trailing JSON, excessive output and malformed enums fail closed at the gate.
func DecodePlanVerdicts(raw string) ([]ItemVerdict, error) {
	if len(raw) > 64*1024 {
		return nil, errors.New("plan_verifier_output_too_large")
	}
	if err := checkVerdictJSON(json.NewDecoder(strings.NewReader(raw)), 0); err != nil {
		return nil, errors.New("invalid_plan_verdict")
	}
	var out struct {
		Items []ItemVerdict `json:"items"`
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return nil, errors.New("invalid_plan_verdict")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("invalid_plan_verdict")
	}
	if out.Items == nil {
		return nil, errors.New("missing_plan_verdicts")
	}
	seen := map[string]bool{}
	for _, v := range out.Items {
		if v.ID == "" || len(v.ID) > 128 || seen[v.ID] || len(v.Reason) > 1024 {
			return nil, errors.New("invalid_plan_verdict")
		}
		seen[v.ID] = true
		switch v.State {
		case "actionable", "waiting_person", "verified_done", "unresolved":
		default:
			return nil, errors.New("invalid_plan_verdict")
		}
	}
	return out.Items, nil
}

// Reject duplicate/case-aliased fields before encoding/json can accept last-wins.
func checkVerdictJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("json_depth")
	}
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || s != strings.ToLower(s) || seen[s] {
				return errors.New("json_key")
			}
			seen[s] = true
			if err := checkVerdictJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("json_object")
		}
	case '[':
		for d.More() {
			if err := checkVerdictJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("json_array")
		}
	default:
		return errors.New("json_delimiter")
	}
	return nil
}
