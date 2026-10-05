package core

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPlanEndTurnIntegrationClaimsDoNotPromote(t *testing.T) {
	for _, reason := range []string{"done", "needs_person", "blocked"} {
		for _, waiting := range []bool{false, true} {
			name := reason
			if waiting {
				name += "/waiting"
			}
			t.Run(name, func(t *testing.T) {
				var calls atomic.Int32
				e := newTestEngine(t, modelFunc(func(_ context.Context, req ModelRequest, _ func(string)) (ModelResponse, error) {
					calls.Add(1)
					found := 0
					for _, spec := range req.Tools {
						if spec.Name == "end_turn" {
							found++
						}
					}
					if found != 1 {
						t.Error("missing or duplicate end_turn schema")
					}
					return ModelResponse{ToolCalls: []ToolCall{call("end_turn", `{"reason":"`+reason+`","message":"unverified private completion"}`)}}, nil
				}), nil)
				body, want, rounds := "- [ ] implement independent local feature\n", "blocked_no_progress", int32(3)
				if waiting {
					body, want, rounds = "- [ ] separate approval required for deployment\n", "waiting_person", 1
				}
				r := integrationPin(t, e, body)
				events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
				integrationTerminal(t, events, want)
				if calls.Load() != rounds || eventCount(events, "tool_start") != 0 {
					t.Fatal(eventText(events))
				}
				stored, err := e.LoadSession(r.ID)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(stored.Turns[0].Assistant, "unverified private completion") {
					t.Fatal("claim persisted as final answer")
				}
			})
		}
	}
}

func TestPlanEndTurnIntegrationRejectsBatchAndInvalid(t *testing.T) {
	cases := map[string][]ToolCall{
		"mixed":           {call("mutate", `{}`), call("end_turn", `{"reason":"done","message":"done"}`)},
		"duplicate":       {call("end_turn", `{"reason":"done","message":"done"}`), call("end_turn", `{"reason":"done","message":"done"}`)},
		"unknown_field":   {call("end_turn", `{"reason":"done","message":"done","approved":true}`)},
		"duplicate_field": {call("end_turn", `{"reason":"done","reason":"blocked","message":"done"}`)},
		"missing_message": {call("end_turn", `{"reason":"done"}`)},
		"invalid_reason":  {call("end_turn", `{"reason":"approved","message":"done"}`)},
	}
	for name, batch := range cases {
		t.Run(name, func(t *testing.T) {
			var rounds, executions atomic.Int32
			e := newTestEngine(t, modelFunc(func(_ context.Context, req ModelRequest, _ func(string)) (ModelResponse, error) {
				if rounds.Add(1) == 1 {
					return ModelResponse{ToolCalls: batch}, nil
				}
				last := req.Messages[len(req.Messages)-1].Content
				if !strings.Contains(last, "end_turn") {
					t.Error("missing corrective prompt")
				}
				return ModelResponse{ToolCalls: []ToolCall{call("end_turn", `{"reason":"done","message":"done"}`)}}, nil
			}), testTools{tool("mutate", false, func(context.Context, ToolContext, json.RawMessage) (string, error) {
				executions.Add(1)
				return "changed", nil
			})})
			r := integrationPin(t, e, "- [ ] separate approval required for deployment\n")
			events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
			integrationTerminal(t, events, "waiting_person")
			if rounds.Load() != 2 || executions.Load() != 0 || eventCount(events, "plan_verification") != 1 {
				t.Fatal(eventText(events))
			}
		})
	}
}

func TestPlanEndTurnIntegrationCollision(t *testing.T) {
	var calls, executions atomic.Int32
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls.Add(1)
		return ModelResponse{Content: "done"}, nil
	}), testTools{tool("end_turn", false, func(context.Context, ToolContext, json.RawMessage) (string, error) {
		executions.Add(1)
		return "done", nil
	})})
	r := integrationPin(t, e, "- [ ] implement feature\n")
	events := send(t, e, ChatRequest{SessionID: r.ID, Message: "work"})
	integrationTerminal(t, events, "plan_error")
	if calls.Load() != 0 || executions.Load() != 0 {
		t.Fatal("collision reached model/tool")
	}
}
