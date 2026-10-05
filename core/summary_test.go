package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

func TestRoundLimitIsNotSuccessfulCompletion(t *testing.T) {
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		return ModelResponse{ToolCalls: []ToolCall{call("read_file", `{}`)}}, nil
	}), testTools{tool("read_file", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { return "ok", nil })})
	e.opts.MaxRounds = 2
	events := send(t, e, ChatRequest{Message: "keep working"})
	assertTerminated(t, events)
	if events[len(events)-1].Data["status"] != "round_limit" || eventCount(events, "error") != 1 {
		t.Fatalf("missing limit status: %s", eventText(events))
	}
	record, err := e.LoadSession(events[0].SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Turns[0].Status != "round_limit" || len(record.Turns[0].Invocations) != 2 {
		t.Fatalf("bad record: %+v", record)
	}
}

func TestEngineSixtyTurns32K(t *testing.T) {
	var system, current string
	summaries, chats := 0, 0
	model := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		if RequestTokens(r)+r.MaxTokens+4096 > 32000 {
			t.Error("request exceeds 32K window")
		}
		if !r.Stream {
			summaries++
			return ModelResponse{Content: "이전 작업 요약"}, nil
		}
		chats++
		if system == "" {
			system = r.Messages[0].Content
		}
		if r.Messages[0].Content != system || !strings.Contains(system, "한국어") {
			t.Error("system or language changed across turns")
		}
		if r.Messages[len(r.Messages)-1].Content != current {
			t.Error("current request changed")
		}
		return ModelResponse{Content: "한국어 응답"}, nil
	})
	e := newTestEngine(t, model, nil)
	e.opts.ContextTokens = 32000
	for i := 0; i < 60; i++ {
		current = fmt.Sprintf("요청 %d: %s", i, strings.Repeat("가", 3000))
		events := send(t, e, ChatRequest{SessionID: "sixty-turns", Message: current})
		assertTerminated(t, events)
		if eventCount(events, "error") != 0 {
			t.Fatalf("turn %d: %s", i, eventText(events))
		}
	}
	if summaries == 0 || chats != 60 {
		t.Fatalf("summaries=%d chats=%d", summaries, chats)
	}
	record, err := e.LoadSession("sixty-turns")
	if err != nil || len(record.Turns) != 60 {
		t.Fatalf("turn records=%d err=%v", len(record.Turns), err)
	}
	for i, turn := range record.Turns {
		if turn.Assistant != "한국어 응답" {
			t.Fatalf("turn %d: unexpected answer %q", i, turn.Assistant)
		}
	}
}

func TestProtectedContextOverflowDoesNotCallModel(t *testing.T) {
	calls := 0
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls++
		return ModelResponse{Content: "unexpected"}, nil
	}), nil)
	e.opts.ContextTokens = 32000
	events := send(t, e, ChatRequest{Message: strings.Repeat("가", 32000)})
	assertTerminated(t, events)
	if calls != 0 || eventCount(events, "error") != 1 || events[len(events)-1].Data["status"] != "context_overflow" {
		t.Fatalf("calls=%d events=%s", calls, eventText(events))
	}
}

func TestSummaryInvocationAccountingAndFallback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "fallback"
		}
		t.Run(name, func(t *testing.T) {
			summaries, chats := 0, 0
			seen := map[string]bool{}
			m := modelFunc(func(ctx context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
				if ids.Check(ids.KindInvocation, r.InvocationID) != nil || seen[r.InvocationID] {
					t.Error("invalid or reused invocation ID")
				}
				seen[r.InvocationID] = true
				if RequestTokens(r)+r.MaxTokens+4096 > 32000 {
					t.Error("request exceeds model window")
				}
				if !r.Stream {
					summaries++
					response := ModelResponse{Content: "한국어 작업 요약", Usage: Usage{InputTokens: 123, OutputTokens: 17}}
					if fail {
						return response, errors.New("summary unavailable")
					}
					return response, nil
				}
				chats++
				if r.Messages[len(r.Messages)-1].Content != "현재 요청 원문" {
					t.Error("current request changed")
				}
				if !strings.Contains(r.Messages[0].Content, "한국어") {
					t.Error("system language changed")
				}
				return ModelResponse{Content: "완료", Usage: Usage{InputTokens: 50, OutputTokens: 2}}, nil
			})
			e := newTestEngine(t, m, nil)
			e.opts.ContextTokens = 32000
			record := SessionRecord{Version: 1, ID: "summary-test", WorkDir: e.opts.WorkDir, CreatedAt: time.Now()}
			for i := 0; i < 10; i++ {
				record.Turns = append(record.Turns, TurnRecord{User: strings.Repeat("이전 요청", 2000), Assistant: "이전 응답"})
			}
			e.records[record.ID] = record
			events := send(t, e, ChatRequest{SessionID: record.ID, Message: "현재 요청 원문"})
			assertTerminated(t, events)
			if eventCount(events, "error") != 0 || summaries != 1 || chats != 1 {
				t.Fatalf("summaries=%d chats=%d events=%s", summaries, chats, eventText(events))
			}
			saved, err := e.LoadSession(record.ID)
			if err != nil {
				t.Fatal(err)
			}
			inv := saved.Turns[len(saved.Turns)-1].Invocations
			if len(inv) != 2 || inv[0].Purpose != "summary" || inv[0].Usage.InputTokens != 123 || inv[0].Usage.OutputTokens != 17 || inv[1].Purpose != "" {
				t.Fatalf("bad accounting: %+v", inv)
			}
			if (inv[0].Error != "") != fail {
				t.Fatalf("bad summary error: %+v", inv[0])
			}
		})
	}
}
