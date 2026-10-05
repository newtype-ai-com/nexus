package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type contextLimitError struct{}

func (contextLimitError) Error() string         { return "model context limit" }
func (contextLimitError) ContextOverflow() bool { return true }

func TestReduceRejectedContextPreservesProtectedAndPairs(t *testing.T) {
	request := ModelRequest{MaxTokens: 8000, Messages: []Message{
		{Role: "system", Content: "한국어로 답하세요"},
		{Role: "user", Content: strings.Repeat("old", 1000)},
		{Role: "assistant", ToolCalls: []ToolCall{call("read_file", `{}`)}},
		{Role: "tool", ToolCallID: "call-1", Content: strings.Repeat("old output", 1000)},
		{Role: "user", Content: "current", Images: []Image{{URL: "https://example.com/image.png"}}},
		{Role: "assistant", ToolCalls: []ToolCall{call("read_file", `{}`)}},
		{Role: "tool", ToolCallID: "call-1", Content: "recent output"},
	}}
	original := cloneMessages(request.Messages)
	got, current, changed := reduceRejectedContext(context.Background(), request, 4)
	if !changed || got.MaxTokens >= request.MaxTokens || RequestTokens(got) >= RequestTokens(request) {
		t.Fatal("request was not reduced")
	}
	if !reflect.DeepEqual(got.Messages[0], original[0]) || !reflect.DeepEqual(got.Messages[current:], original[4:]) {
		t.Fatal("protected request or current tool pairs changed")
	}
	if !reflect.DeepEqual(request.Messages, original) {
		t.Fatal("caller messages mutated")
	}
	if len(got.Messages) != 4 || current != 1 {
		t.Fatalf("historical tool exchange not removed as a unit: %+v", got.Messages)
	}
}

func TestContextRecoveryLifecycle(t *testing.T) {
	for _, scenario := range []string{"success", "rejected-again", "streamed", "canceled", "retry-fails", "later-round"} {
		t.Run(scenario, func(t *testing.T) {
			var requests []ModelRequest
			calls := 0
			m := modelFunc(func(_ context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
				calls++
				requests = append(requests, r)
				if calls == 1 {
					if scenario == "streamed" {
						on("already visible\n")
					}
					if scenario == "canceled" {
						return ModelResponse{}, errors.Join(context.Canceled, contextLimitError{})
					}
					return ModelResponse{Usage: Usage{InputTokens: 7}}, fmt.Errorf("wrapped: %w", contextLimitError{})
				}
				if scenario == "rejected-again" || calls == 3 {
					return ModelResponse{}, contextLimitError{}
				}
				if scenario == "retry-fails" {
					return ModelResponse{}, errors.New("transient failure")
				}
				if scenario == "later-round" {
					return ModelResponse{ToolCalls: []ToolCall{call("read_file", `{}`)}}, nil
				}
				return ModelResponse{Content: "완료", Usage: Usage{OutputTokens: 2}}, nil
			})
			e := newTestEngine(t, m, testTools{tool("read_file", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { return "ok", nil })})
			events := send(t, e, ChatRequest{Message: "현재 요청 원문"})
			assertTerminated(t, events)
			wantCalls := 2
			if scenario == "streamed" || scenario == "canceled" {
				wantCalls = 1
			}
			if scenario == "later-round" {
				wantCalls = 3
			}
			if calls != wantCalls {
				t.Fatalf("calls=%d want=%d", calls, wantCalls)
			}
			if calls >= 2 {
				if requests[1].MaxTokens >= requests[0].MaxTokens || !reflect.DeepEqual(requests[0].Messages, requests[1].Messages) {
					t.Fatal("output budget not reduced or protected messages modified")
				}
			}
			wantNotices := 1
			if wantCalls == 1 {
				wantNotices = 0
			}
			if eventCount(events, "notice") != wantNotices {
				t.Fatal(eventText(events))
			}
			if scenario == "success" && eventCount(events, "error") != 0 {
				t.Fatal(eventText(events))
			}
			if scenario == "rejected-again" || scenario == "later-round" {
				if events[len(events)-1].Data["status"] != "context_overflow" {
					t.Fatal(eventText(events))
				}
			}
			record, err := e.LoadSession(events[0].SessionID)
			if err != nil {
				t.Fatal(err)
			}
			inv := record.Turns[0].Invocations
			if len(inv) != calls {
				t.Fatal("missing invocation accounting")
			}
			seen := map[string]bool{}
			for _, item := range inv {
				if item.ID == "" || seen[item.ID] {
					t.Fatal("reused invocation ID")
				}
				seen[item.ID] = true
			}
			if scenario == "success" && (inv[0].Usage.InputTokens != 7 || inv[1].Usage.OutputTokens != 2) {
				t.Fatal("lost usage")
			}
		})
	}
}
