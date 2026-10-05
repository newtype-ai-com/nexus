package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Self-conscious mode (docs/tui-modes.md, docs/m14-self-conscious-policy.md):
// a turn a person started after a person-typed activation keeps working until
// the goal is met. Continuation is bounded; it never widens tools, policy,
// approvals or authority. Automatic (inbox/background) turns are always auto.

// MaxSelfConsciousContinuations caps the engine-issued "keep going" prompts in
// one human turn. Model rounds remain bounded by Options.MaxRounds as well.
const MaxSelfConsciousContinuations = 12

// maxSelfConsciousIdle stops a model that keeps replying without running any
// tool: at most two consecutive continuation prompts without a tool execution
// (the "nudge" cap).
const maxSelfConsciousIdle = 2

// Turn statuses produced only by the self-conscious controller. A normal,
// goal-met finish keeps the ordinary empty status.
const (
	StatusNeedsPerson          = "needs_person"
	StatusBlocked              = "blocked"
	StatusSelfConsciousLimit   = "self_conscious_limit"
	StatusSelfConsciousStalled = "self_conscious_stalled"
)

const selfConsciousContract = "SELF-CONSCIOUS MODE (the person enabled it for this turn): keep working until the person's goal is met. Keep a work_plan of the remaining steps and start the next step yourself; verify after changes. Do not hand the turn back just because a tool call or a reply ended, and do not ask the person whether to continue. When the goal is met and verified, call end_turn with reason done and a final message. If only the person can provide a decision, approval or input, call end_turn with reason needs_person and say exactly what is needed; if you tried and cannot proceed, use reason blocked and say why. Never request secrets in conversation. This mode grants no extra permission: tool policy and approvals are unchanged, and a refused approval must not be requested again."

func selfStopSpec() ToolSpec {
	return ToolSpec{Name: "end_turn", Description: "Self-conscious mode: end this turn. reason done = goal met and verified; needs_person = only the person can decide/approve/provide input; blocked = tried and cannot proceed. message is the final reply to the person. The engine may continue the turn if planned steps remain.", Parameters: json.RawMessage(`{"type":"object","properties":{"reason":{"type":"string","enum":["done","needs_person","blocked"]},"message":{"type":"string"}},"required":["reason","message"],"additionalProperties":false}`)}
}

// decodeSelfStop accepts the legacy "note" field for message and an
// empty message; an empty final reply is handled by asking once for text.
func decodeSelfStop(raw json.RawMessage) (StopAttempt, error) {
	var in struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
		Note    string `json:"note"`
	}
	if len(raw) > 64*1024 {
		return StopAttempt{}, errors.New("invalid_stop_attempt")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil {
		return StopAttempt{}, errors.New("invalid_stop_attempt")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return StopAttempt{}, errors.New("invalid_stop_attempt")
	}
	switch in.Reason {
	case "done", "needs_person", "blocked":
	default:
		return StopAttempt{}, errors.New("invalid_stop_attempt")
	}
	message := in.Message
	if strings.TrimSpace(message) == "" {
		message = in.Note
	}
	return StopAttempt{Reason: in.Reason, Message: strings.TrimSpace(message)}, nil
}

// selfConscious is turn-local controller state; it is never persisted and never
// restored, so a reload or restart cannot resume autonomy.
type selfConscious struct {
	continuations int
	idle          int  // consecutive continuation prompts with no tool executed since
	toolRan       bool // a tool executed since the last continuation prompt
	goalChecked   bool // a goal check was issued and no tool has run since
	finalAsked    bool // N1: asked once for a final text; the next reply ends the turn
	finalStatus   string
	// refused: a person refused an approval in this turn. No further tool runs;
	// the next reply is the final message and the turn ends needs_person.
	refused bool
	plan    []WorkPlanTask
	hasPlan bool
}

type selfDecision struct {
	stop    bool
	status  string
	prompt  string // continuation prompt for the model
	summary string // short, content-free reason for the host
}

// observeTool records tool executions and the latest successful local plan.
func (s *selfConscious) observeTool(name string, builtin, ok, executed bool, args json.RawMessage) {
	if executed {
		s.toolRan = true
		s.goalChecked = false
	}
	if name != "work_plan" || !builtin || !ok {
		return
	}
	var in struct {
		Tasks []WorkPlanTask `json:"tasks"`
	}
	if json.Unmarshal(args, &in) != nil {
		return
	}
	for i := range in.Tasks {
		switch in.Tasks[i].Status {
		case "todo":
			in.Tasks[i].Status = "pending"
		case "active":
			in.Tasks[i].Status = "in_progress"
		case "completed":
			in.Tasks[i].Status = "done"
		}
	}
	s.plan, s.hasPlan = in.Tasks, true
}

func (s *selfConscious) remaining() (open []WorkPlanTask, waiting int) {
	for _, task := range s.plan {
		switch task.Status {
		case "done":
		case "waiting_person":
			waiting++
		default:
			open = append(open, task)
		}
	}
	return open, waiting
}

// decide runs when the model produced a final reply (with or without an
// end_turn request). stop==nil means a plain reply without end_turn.
func (s *selfConscious) decide(stop *StopAttempt, approvalDenied bool) selfDecision {
	if stop != nil && (stop.Reason == "needs_person" || stop.Reason == "blocked") {
		status := StatusNeedsPerson
		if stop.Reason == "blocked" {
			status = StatusBlocked
		}
		return selfDecision{stop: true, status: status, summary: stop.Reason}
	}
	if approvalDenied {
		// A person refused an approval: never re-request it autonomously.
		return selfDecision{stop: true, status: StatusNeedsPerson, summary: "approval_denied"}
	}
	if s.finalAsked {
		return selfDecision{stop: true, status: s.finalStatus, summary: "final_message"}
	}
	open, waiting := s.remaining()
	var prompt, summary string
	switch {
	case len(open) > 0:
		next := open[0].Title
		prompt = fmt.Sprintf("[Self-conscious mode] Your work_plan still has %d of %d steps unfinished. Next: %q. Continue now without asking the person. Verify after changes. If a step needs only the person, mark it waiting_person and continue the other steps; if everything left needs the person, call end_turn with reason needs_person.", len(open), len(s.plan), next)
		summary = "plan_remaining"
	case s.hasPlan && waiting > 0:
		return selfDecision{stop: true, status: StatusNeedsPerson, summary: "waiting_person"}
	case stop != nil && stop.Reason == "done":
		return selfDecision{stop: true, summary: "done"}
	case s.goalChecked:
		// Already asked to check the goal and nothing ran since: accept the answer.
		return selfDecision{stop: true, summary: "answered"}
	default:
		prompt = "[Self-conscious mode] Before ending, compare the result with the person's whole goal for this session. If anything is unfinished, unverified or only prepared but not applied, record it with work_plan and start it now without asking. If the goal is met and verified (or this was a question with nothing left to do), call end_turn with reason done and your final message."
		summary = "goal_check"
		s.goalChecked = true
	}
	if s.continuations >= MaxSelfConsciousContinuations {
		return selfDecision{stop: true, status: StatusSelfConsciousLimit, summary: "continuation_limit"}
	}
	if s.toolRan {
		s.idle = 0
	}
	if s.idle >= maxSelfConsciousIdle {
		return selfDecision{stop: true, status: StatusSelfConsciousStalled, summary: "no_progress"}
	}
	s.idle++
	s.continuations++
	s.toolRan = false
	return selfDecision{prompt: prompt, summary: summary}
}

// askFinal implements N1: an end_turn without any text asks once for the final
// message and the next reply ends the turn without re-entering continuation.
// Only a stop decide already accepted (with its status) may enter this state
// (MODE-R3); a done with planned steps left is continued instead.
func (s *selfConscious) askFinal(status string) string {
	s.finalAsked = true
	s.finalStatus = status
	return "[Self-conscious mode] You ended without a message. Write your final message to the person now as plain text. Do not continue working; no tool will run."
}

// refusedPrompt asks for the closing reply after a person refused an approval
// (MODE-R2). Tool calls in that reply are not executed.
func (s *selfConscious) refusedPrompt() string {
	s.refused = true
	return "[Self-conscious mode] A person refused an approval in this turn. No more tools will run in this turn and the refused request must not be repeated. Write your final message to the person now as plain text: what was refused and what they need to decide."
}

// finalOnly reports whether the turn may only produce its closing text now.
func (s *selfConscious) finalOnly() bool { return s.refused || s.finalAsked }

// RefusedApprovalMessage is the closing reply when a person refused an
// approval and the model wrote nothing afterwards.
const RefusedApprovalMessage = "Stopped: a person refused an approval in this turn, so nothing further was run. Tell me how you want to proceed."

// emitSelfConscious tells the host about a continuation or stop. It carries
// only counters and a fixed reason, never model content.
func (t *turn) emitSelfConscious(action string, s *selfConscious, reason string) {
	t.emit("self_conscious", map[string]any{"action": action, "reason": reason, "count": s.continuations, "limit": MaxSelfConsciousContinuations})
}
