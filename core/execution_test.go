package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type suspendTestTools struct {
	testTools
	suspended            atomic.Int32
	suspendErr, closeErr error
}

func (s *suspendTestTools) SuspendExecution() error { s.suspended.Add(1); return s.suspendErr }
func (s *suspendTestTools) Close() error            { return s.closeErr }

func TestExecutionClosePreservesCleanupErrors(t *testing.T) {
	pending, closed := errors.New("cleanup pending"), errors.New("close failed")
	tools := &suspendTestTools{suspendErr: pending, closeErr: closed}
	combined, err := CombineToolsets(tools)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{WorkDir: t.TempDir(), Tools: combined, Model: modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) { return ModelResponse{}, nil })})
	if err != nil {
		t.Fatal(err)
	}
	e.executionCancel() // race the automatic watcher with explicit cleanup
	if err = e.Close(); !errors.Is(err, pending) || !errors.Is(err, closed) {
		t.Fatalf("cleanup errors lost: %v", err)
	}
	if tools.suspended.Load() != 1 {
		t.Fatal("suspend was not once-only")
	}
	if !errors.Is(e.SuspendExecution(), pending) {
		t.Fatal("cached error lost")
	}
}

func TestExecutionCancellationRejectsLateModelSuccess(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	e, err := New(Options{WorkDir: t.TempDir(), ExecutionContext: parent, RetryDelay: -1, Model: modelFunc(func(ctx context.Context, _ ModelRequest, emit func(string)) (ModelResponse, error) {
		close(started)
		<-ctx.Done()
		emit("LATE_SUCCESS")
		return ModelResponse{Content: "LATE_SUCCESS", ToolCalls: []ToolCall{call("mutate", `{}`)}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ch, err := e.SendMessage(ChatRequest{Message: "test"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("model not entered")
	}
	cancel()
	events := collect(t, ch)
	assertTerminated(t, events)
	if strings.Contains(eventText(events), "LATE_SUCCESS") {
		t.Fatal("late response accepted")
	}
	if _, err = e.SendMessage(ChatRequest{Message: "again"}); !errors.Is(err, ErrExecutionSuspended) {
		t.Fatalf("new work allowed: %v", err)
	}
	if err = e.HealthCheck(); err != nil {
		t.Fatal("suspension closed readable engine", err)
	}
}

func TestExecutionRechecksAfterGateAndStaysSuspended(t *testing.T) {
	var denied atomic.Bool
	var runs atomic.Int32
	e, err := New(Options{WorkDir: t.TempDir(), RetryDelay: -1, CheckExecution: func() error {
		if denied.Load() {
			return errors.New("private remote reason")
		}
		return nil
	},
		Model: modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
			return ModelResponse{ToolCalls: []ToolCall{call("read", `{}`)}}, nil
		}),
		Tools: testTools{tool("read", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { runs.Add(1); return "bad", nil })},
		Binder: BinderFunc(func(context.Context, BindRequest) (*Binding, error) {
			return &Binding{Gate: func(context.Context, string, json.RawMessage) (bool, string) { denied.Store(true); return true, "" }}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	events := send(t, e, ChatRequest{Message: "test", PromptType: ModeAuto})
	if runs.Load() != 0 {
		t.Fatal("read-only tool ran after authority loss during gate")
	}
	if strings.Contains(eventText(events), "private remote reason") {
		t.Fatal("reason leaked")
	}
	denied.Store(false)
	if _, err = e.SendMessage(ChatRequest{Message: "again"}); !errors.Is(err, ErrExecutionSuspended) {
		t.Fatalf("authority revived: %v", err)
	}
}
