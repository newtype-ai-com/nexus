package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type modelFunc func(context.Context, ModelRequest, func(string)) (ModelResponse, error)

func (f modelFunc) Chat(c context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
	return f(c, r, on)
}

type testTools []Tool

func (ts testTools) Tools() []Tool { return ts }
func (ts testTools) Close() error  { return nil }
func tool(name string, ro bool, run func(context.Context, ToolContext, json.RawMessage) (string, error)) Tool {
	return Tool{Spec: ToolSpec{Name: name, Parameters: json.RawMessage(`{"type":"object"}`)}, ReadOnly: ro, Run: run}
}
func call(name, args string) ToolCall {
	return ToolCall{ID: "call-1", Name: name, Arguments: json.RawMessage(args)}
}
func newTestEngine(t *testing.T, m Model, ts testTools) *Engine {
	t.Helper()
	e, err := New(Options{Model: m, Tools: ts, WorkDir: t.TempDir(), RetryDelay: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}
func collect(t *testing.T, ch <-chan Event) []Event {
	t.Helper()
	var events []Event
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return events
			}
			events = append(events, event)
		case <-timer.C:
			t.Fatal("turn did not finish")
			return nil
		}
	}
}
func send(t *testing.T, e *Engine, r ChatRequest) []Event {
	t.Helper()
	ch, err := e.SendMessage(r)
	if err != nil {
		t.Fatal(err)
	}
	return collect(t, ch)
}
func eventCount(events []Event, kind string) int {
	n := 0
	for _, e := range events {
		if e.Type == kind {
			n++
		}
	}
	return n
}
func eventText(events []Event) string { raw, _ := json.Marshal(events); return string(raw) }
func assertTerminated(t *testing.T, events []Event) {
	t.Helper()
	if len(events) < 3 || events[0].Type != "stream_start" || events[len(events)-2].Type != "content_done" || events[len(events)-1].Type != "done" {
		t.Fatalf("invalid lifecycle: %v", events)
	}
	seen := map[string]bool{}
	for _, e := range events {
		if seen[e.EventID] {
			t.Fatal("duplicate event ID")
		}
		seen[e.EventID] = true
	}
}

func TestAnswerLifecycleAndSession(t *testing.T) {
	m := modelFunc(func(ctx context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
		return ModelResponse{Content: "<think>private reasoning</think>안녕하세요"}, nil
	})
	e := newTestEngine(t, m, nil)
	events := send(t, e, ChatRequest{Message: "hi"})
	assertTerminated(t, events)
	if strings.Contains(eventText(events), "private reasoning") {
		t.Fatal("reasoning leaked")
	}
	id := events[0].SessionID
	r, err := e.LoadSession(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Turns) != 1 || r.Turns[0].Assistant != "안녕하세요" || len(r.Turns[0].Invocations) != 1 {
		t.Fatalf("bad record: %+v", r)
	}
	r.Turns[0].Assistant = "mutated"
	r2, _ := e.LoadSession(id)
	if r2.Turns[0].Assistant == "mutated" {
		t.Fatal("record not copied")
	}
}
func TestNativeToolPairingAndModeGate(t *testing.T) {
	// Only auto and self-conscious exist; legacy agent/ask/plan prompt types
	// are auto and get the same Gate-governed tool surface.
	for _, mode := range []string{ModeAuto, "agent", "ask", "plan", ""} {
		t.Run(mode, func(t *testing.T) {
			rounds, runs, gates := 0, 0, 0
			m := modelFunc(func(ctx context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
				rounds++
				if rounds == 1 {
					return ModelResponse{ToolCalls: []ToolCall{call("mutate", `{"path":"a"}`)}}, nil
				}
				a, b := r.Messages[len(r.Messages)-2], r.Messages[len(r.Messages)-1]
				if a.Role != "assistant" || len(a.ToolCalls) != 1 || b.Role != "tool" || b.ToolCallID != a.ToolCalls[0].ID {
					t.Error("call/result pair not preserved")
				}
				return ModelResponse{Content: "done"}, nil
			})
			e := newTestEngine(t, m, testTools{tool("mutate", false, func(context.Context, ToolContext, json.RawMessage) (string, error) { runs++; return "ok", nil })})
			e.opts.Binder = BinderFunc(func(context.Context, BindRequest) (*Binding, error) {
				return &Binding{Gate: func(context.Context, string, json.RawMessage) (bool, string) {
					gates++
					return false, "denied by mandate"
				}}, nil
			})
			events := send(t, e, ChatRequest{Message: "test", PromptType: mode})
			assertTerminated(t, events)
			if runs != 0 {
				t.Fatal("denied tool ran")
			}
			if gates != 1 {
				t.Fatal("missing gate")
			}
		})
	}
}
func TestBindingFailureFailsClosed(t *testing.T) {
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		t.Error("unbound model call")
		return ModelResponse{}, nil
	}), nil)
	e.opts.Binder = BinderFunc(func(context.Context, BindRequest) (*Binding, error) { return nil, errors.New("network") })
	events := send(t, e, ChatRequest{Message: "x"})
	assertTerminated(t, events)
	if !strings.Contains(eventText(events), "binding_error") {
		t.Fatal("binding error not surfaced")
	}
}
func TestRetryAndPermanentErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		stream bool
		want   int
	}{{"transient", errors.New("HTTP 503"), false, 3}, {"permanent", errors.New("HTTP 401 unauthorized"), false, 1}, {"partial", errors.New("connection reset"), true, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			e := newTestEngine(t, modelFunc(func(ctx context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
				n++
				if tc.stream {
					on("partial")
				}
				return ModelResponse{}, tc.err
			}), nil)
			events := send(t, e, ChatRequest{Message: "x"})
			assertTerminated(t, events)
			if n != tc.want {
				t.Fatalf("got %d attempts", n)
			}
			if eventCount(events, "error") != 1 {
				t.Fatal("no error")
			}
		})
	}
}
func TestEmptyAndLengthNudges(t *testing.T) {
	for _, tc := range []struct {
		name, reason, content string
		want                  int
	}{{"empty", "stop", "", 3}, {"length", "length", "partial", 4}} {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
				n++
				return ModelResponse{Content: tc.content, FinishReason: tc.reason}, nil
			}), nil)
			events := send(t, e, ChatRequest{Message: "x"})
			assertTerminated(t, events)
			if n != tc.want {
				t.Fatalf("got %d calls", n)
			}
		})
	}
}
func TestApprovalAndCancel(t *testing.T) {
	started := make(chan struct{})
	m := modelFunc(func(ctx context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
		return ModelResponse{ToolCalls: []ToolCall{call("remove_file", `{}`)}}, nil
	})
	ts := testTools{tool("remove_file", false, func(ctx context.Context, tc ToolContext, args json.RawMessage) (string, error) {
		close(started)
		if !tc.Approve(ctx, Approval{ToolName: "remove_file", Risk: "medium"}) {
			return "", errors.New("rejected")
		}
		return "removed", nil
	})}
	e := newTestEngine(t, m, ts)
	ch, err := e.SendMessage(ChatRequest{Message: "remove"})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err = e.SendMessage(ChatRequest{Message: "race"}); !errors.Is(err, ErrTurnInProgress) {
		t.Fatal("concurrent turn accepted")
	}
	var all []Event
	var approvalID string
	for event := range ch {
		all = append(all, event)
		if event.Type == "approval_needed" {
			approvalID = event.Data["tool_call_id"].(string)
			e.Cancel()
		}
	}
	assertTerminated(t, all)
	if err = e.SendApproval(approvalID, true); err == nil {
		t.Fatal("expired approval accepted")
	}
	if !strings.Contains(eventText(all), "cancelled") {
		t.Fatal("cancel status missing")
	}
}
func TestToolFailureCircuitAndFinishGates(t *testing.T) {
	t.Run("fifth blocked", func(t *testing.T) {
		runs, n := 0, 0
		e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
			n++
			if n <= 6 {
				return ModelResponse{ToolCalls: []ToolCall{call("update_file", `{"path":"a"}`)}}, nil
			}
			return ModelResponse{Content: "done"}, nil
		}), testTools{tool("update_file", false, func(context.Context, ToolContext, json.RawMessage) (string, error) {
			runs++
			return "", errors.New("not read")
		})})
		events := send(t, e, ChatRequest{Message: "edit"})
		if runs != 4 {
			t.Fatalf("executed %d times", runs)
		}
		if !strings.Contains(eventText(events), "repeated_tool_failure") {
			t.Fatal("no escalation")
		}
	})
	t.Run("verify exactly once", func(t *testing.T) {
		n, nudges := 0, 0
		e := newTestEngine(t, modelFunc(func(ctx context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
			n++
			if n == 1 {
				return ModelResponse{ToolCalls: []ToolCall{call("create_file", `{}`)}}, nil
			}
			if strings.Contains(r.Messages[len(r.Messages)-1].Content, "without running a verification") {
				nudges++
			}
			return ModelResponse{Content: "done"}, nil
		}), testTools{tool("create_file", false, func(context.Context, ToolContext, json.RawMessage) (string, error) { return "created", nil })})
		_ = send(t, e, ChatRequest{Message: "edit"})
		if n != 3 || nudges != 1 {
			t.Fatalf("rounds=%d nudges=%d", n, nudges)
		}
	})
	t.Run("honesty", func(t *testing.T) {
		n := 0
		e := newTestEngine(t, modelFunc(func(ctx context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
			n++
			if n == 1 {
				return ModelResponse{ToolCalls: []ToolCall{call("update_file", `{}`)}}, nil
			}
			if n == 3 && !strings.Contains(r.Messages[len(r.Messages)-1].Content, "All file write attempts failed") {
				t.Error("missing honesty nudge")
			}
			return ModelResponse{Content: "done"}, nil
		}), testTools{tool("update_file", false, func(context.Context, ToolContext, json.RawMessage) (string, error) { return "", errors.New("failed") })})
		_ = send(t, e, ChatRequest{Message: "edit"})
		if n != 3 {
			t.Fatal(n)
		}
	})
}
func TestDenseAbortAndToolPanic(t *testing.T) {
	n := 0
	var e *Engine
	m := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		n++
		return ModelResponse{ToolCalls: []ToolCall{call("first", `{}`), call("second", `{}`), call("second", `{}`)}}, nil
	})
	ts := testTools{tool("first", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { e.Cancel(); return "first", nil }), tool("second", true, func(context.Context, ToolContext, json.RawMessage) (string, error) {
		t.Error("executed after cancel")
		return "", nil
	})}
	e = newTestEngine(t, m, ts)
	events := send(t, e, ChatRequest{Message: "x"})
	assertTerminated(t, events)
	r, _ := e.LoadSession(events[0].SessionID)
	if len(r.Turns[0].Actions) != 3 {
		t.Fatal("abort left action holes")
	}
	if !strings.Contains(r.Turns[0].Actions[1].Error, "NOT_EXECUTED") {
		t.Fatal("missing cancellation result")
	}
}
func TestCloseWithAbandonedConsumer(t *testing.T) {
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		return ModelResponse{ToolCalls: []ToolCall{call("read", `{}`)}}, nil
	}), testTools{tool("read", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { return "ok", nil })})
	e.opts.MaxRounds = 1000
	_, err := e.SendMessage(ChatRequest{Message: "x"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	done := make(chan struct{})
	go func() { _ = e.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked")
	}
	if _, err = e.SendMessage(ChatRequest{}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
func TestSessionDiskPersistenceAndRedaction(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 36)
	m := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		return ModelResponse{Content: secret}, nil
	})
	opts := Options{Model: m, WorkDir: t.TempDir(), SessionDir: t.TempDir()}
	e, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	events := send(t, e, ChatRequest{Message: secret})
	_ = e.Close()
	id := events[0].SessionID
	raw, err := os.ReadFile(filepath.Join(opts.SessionDir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(eventText(events), secret) {
		t.Fatal("secret leaked")
	}
	// POSIX permission bits only; Windows reports 0666 for any writable file.
	if runtime.GOOS != "windows" {
		stat, _ := os.Stat(filepath.Join(opts.SessionDir, id+".json"))
		if stat.Mode().Perm() != 0600 {
			t.Fatalf("mode=%v", stat.Mode())
		}
	}
	e2, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	record, err := e2.LoadSession(id)
	if err != nil || len(record.Turns) != 1 {
		t.Fatal(err)
	}
	if _, err = e2.LoadSession("../escape"); err == nil {
		t.Fatal("invalid ID accepted")
	}
	if err = e2.DeleteSession(id); err != nil {
		t.Fatal(err)
	}
}
func TestEnginePanicAndConcurrentClose(t *testing.T) {
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) { panic("internal secret") }), nil)
	events := send(t, e, ChatRequest{Message: "x"})
	assertTerminated(t, events)
	if !strings.Contains(eventText(events), "engine_error") || strings.Contains(eventText(events), "internal secret") {
		t.Fatal("bad panic handling")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = e.Close() }()
	}
	wg.Wait()
}
func TestTextProtocol(t *testing.T) {
	text, calls := parseTextToolCalls("hello <tool_call>```json\n{\"name\":\"read_file\",\"arguments\":{\"path\":\"a\"}}\n```</tool_call> tail")
	if text != "hello  tail" || len(calls) != 1 || calls[0].Name != "read_file" {
		t.Fatalf("%q %+v", text, calls)
	}
	_, calls = parseTextToolCalls("<tool_call>{bad</tool_call><tool_call>unfinished")
	if len(calls) != 2 || calls[0].Name != "invalid_tool_call" || calls[1].Name != "invalid_tool_call" {
		t.Fatal(calls)
	}
}
