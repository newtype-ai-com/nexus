package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func backgroundEngine(t *testing.T, model Model, tools testTools) *Engine {
	t.Helper()
	e, err := New(Options{Model: model, Tools: tools, WorkDir: t.TempDir(), RetryDelay: -1, EnableBackgroundTurns: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func nextBackground(t *testing.T, e *Engine, session string) []Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := e.NextBackgroundTurn(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	return collect(t, ch)
}

func TestBackgroundQueueIdleDedupAndFreshBinding(t *testing.T) {
	callbacks := make(chan func(BackgroundCompletion), 1)
	blocked := make(chan struct{})
	release := make(chan struct{})
	var rounds int
	m := modelFunc(func(ctx context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		rounds++
		switch rounds {
		case 1:
			return ModelResponse{ToolCalls: []ToolCall{call("start", `{}`)}}, nil
		case 2:
			close(blocked)
			select {
			case <-release:
			case <-ctx.Done():
				return ModelResponse{}, ctx.Err()
			}
			return ModelResponse{Content: "started"}, nil
		default:
			if !strings.Contains(r.Messages[len(r.Messages)-1].Content, "background-result") {
				t.Error("missing completion prompt")
			}
			return ModelResponse{ToolCalls: []ToolCall{call("approve", `{}`)}}, nil
		}
	})
	var executions int
	e := backgroundEngine(t, m, testTools{
		tool("start", false, func(ctx context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
			f, err := tc.RegisterBackground()
			callbacks <- f
			return "started", err
		}),
		tool("approve", false, func(ctx context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
			executions++
			if tc.RegisterBackground != nil {
				t.Error("recursive auto-turn capability")
			}
			if !tc.Approve(ctx, Approval{ToolName: "approve"}) {
				return "", errors.New("denied")
			}
			return "ok", nil
		}),
	})
	var binds []BindRequest
	e.opts.Binder = BinderFunc(func(ctx context.Context, r BindRequest) (*Binding, error) {
		binds = append(binds, r)
		if len(binds) > 1 {
			return nil, errors.New("expired")
		}
		return &Binding{}, nil
	})
	ch, err := e.SendMessage(ChatRequest{SessionID: "one", Message: "start"})
	if err != nil {
		t.Fatal(err)
	}
	<-blocked
	f := <-callbacks
	f(BackgroundCompletion{JobID: "job", Status: "succeeded", Output: "result"})
	f(BackgroundCompletion{JobID: "job", Status: "succeeded", Output: "duplicate"})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := e.NextBackgroundTurn(ctx, "one"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("active turn interrupted", err)
	}
	close(release)
	original := collect(t, ch)
	events := nextBackground(t, e, "one")
	assertTerminated(t, events)
	if eventCount(events, "background_completed") != 1 || !strings.Contains(eventText(events), "binding_error") {
		t.Fatal(events)
	}
	if executions != 0 || len(binds) != 2 || binds[0].Task == binds[1].Task {
		t.Fatal("binding reused")
	}
	if events[0].Data["parent_task_id"] != original[0].TaskID {
		t.Fatal("parent task lost")
	}
	e.background.mu.Lock()
	defer e.background.mu.Unlock()
	if len(e.background.tickets) != 0 {
		t.Fatal("duplicate pending work")
	}
}

func registerFixture(t *testing.T, e *Engine, session string) func(BackgroundCompletion) {
	t.Helper()
	turn := &turn{engine: e, ctx: context.Background(), request: ChatRequest{SessionID: session}}
	f, err := turn.registerBackground()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBackgroundRevocationAndBoundedQueue(t *testing.T) {
	for _, action := range []string{"cancel", "delete", "close"} {
		t.Run(action, func(t *testing.T) {
			e := backgroundEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
				return ModelResponse{Content: "ok"}, nil
			}), nil)
			f := registerFixture(t, e, "one")
			g := registerFixture(t, e, "two")
			f(BackgroundCompletion{JobID: "one", Status: "succeeded"})
			switch action {
			case "cancel":
				e.Cancel()
			case "delete":
				if err := e.DeleteSession("one"); err != nil {
					t.Fatal(err)
				}
			case "close":
				e.Close()
			}
			f(BackgroundCompletion{JobID: "one", Status: "succeeded"})
			g(BackgroundCompletion{JobID: "two", Status: "succeeded"})
			e.background.mu.Lock()
			defer e.background.mu.Unlock()
			want := 0
			if action == "delete" {
				want = 1
			}
			if len(e.background.tickets) != want {
				t.Fatal("revoked callback resurrected", len(e.background.tickets))
			}
		})
	}
	e := backgroundEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) { return ModelResponse{}, nil }), nil)
	var callbacks []func(BackgroundCompletion)
	for i := 0; i < 128; i++ {
		callbacks = append(callbacks, registerFixture(t, e, "one"))
	}
	turn := &turn{engine: e, ctx: context.Background()}
	if _, err := turn.registerBackground(); err == nil {
		t.Fatal("unbounded queue")
	}
	callbacks[0](BackgroundCompletion{})
	if _, err := turn.registerBackground(); err != nil {
		t.Fatal("reservation not released", err)
	}
}

func TestBackgroundConcurrentCompletionsAndWaiters(t *testing.T) {
	e := backgroundEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		return ModelResponse{Content: "done"}, nil
	}), nil)
	// Real task IDs are obtained from a regular request, as registration normally is.
	events := send(t, e, ChatRequest{SessionID: "one", Message: "start"})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		turn := &turn{engine: e, ctx: context.Background(), request: ChatRequest{SessionID: "one", TaskID: events[0].TaskID}}
		f, err := turn.registerBackground()
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() { defer wg.Done(); f(BackgroundCompletion{JobID: "job", Status: "succeeded"}) }()
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err := e.NextBackgroundTurn(ctx, "other"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cross-session delivery", err)
	}
	cancel()
	for i := 0; i < 20; i++ {
		if eventCount(nextBackground(t, e, "one"), "background_completed") != 1 {
			t.Fatal("lost completion")
		}
	}
	wait := make(chan error, 1)
	go func() { _, err := e.NextBackgroundTurn(context.Background(), "one"); wait <- err }()
	e.Close()
	select {
	case err := <-wait:
		if !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake waiter")
	}
}

func TestBackgroundDefaultDisabled(t *testing.T) {
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) { return ModelResponse{}, nil }), nil)
	if _, err := e.NextBackgroundTurn(context.Background(), "one"); !errors.Is(err, ErrBackgroundDisabled) {
		t.Fatal(err)
	}
}
