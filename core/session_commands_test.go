package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSessionCommandsPersistence(t *testing.T) {
	e := newTestEngine(t, modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		return ModelResponse{Content: "요약된 목표", Usage: Usage{InputTokens: 12, OutputTokens: 4}}, nil
	}), nil)
	e.opts.SessionDir = t.TempDir()
	for i := 0; i < 5; i++ {
		send(t, e, ChatRequest{SessionID: "commands", Message: "request"})
	}
	if err := e.Compact(context.Background(), "commands"); err != nil {
		t.Fatal(err)
	}
	r, err := e.LoadSession("commands")
	if err != nil {
		t.Fatal(err)
	}
	if r.SummaryTurns != 5 || len(r.Compactions) != 1 || r.Compactions[0].Usage.InputTokens != 12 {
		t.Fatalf("bad compaction %+v", r)
	}
	h, _ := e.history("commands")
	if len(h) != 1 || !strings.Contains(h[0].Content, "요약된 목표") {
		t.Fatal(h)
	}
	r, err = e.RewindSession("commands", 3)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := e.MessageCount("commands"); n != 6 {
		t.Fatal(n)
	}
	if len(r.Rewinds) != 1 || len(r.Rewinds[0].Turns) != 5 || r.Summary != "" {
		t.Fatal("backup or summary invalidation missing")
	}
	md, err := e.ExportSession("commands")
	if err != nil || !strings.Contains(md, "Turn 3") || strings.Contains(md, "Turn 4") {
		t.Fatal(md, err)
	}
	raw, err := e.ExportSessionJSON("commands")
	if err != nil || !strings.Contains(string(raw), "rewinds") {
		t.Fatal(err)
	}
	delete(e.records, "commands")
	reloaded, err := e.LoadSession("commands")
	if err != nil || len(reloaded.Turns) != 3 || len(reloaded.Rewinds[0].Turns) != 5 {
		t.Fatal("reload", err)
	}
}
func TestCompactBlocksTurnAndCancels(t *testing.T) {
	entered := make(chan struct{})
	e := newTestEngine(t, modelFunc(func(ctx context.Context, _ ModelRequest, _ func(string)) (ModelResponse, error) {
		close(entered)
		<-ctx.Done()
		return ModelResponse{}, ctx.Err()
	}), nil)
	e.records["c"] = SessionRecord{Version: 1, ID: "c", WorkDir: e.opts.WorkDir, Turns: []TurnRecord{{User: "hi", Assistant: "hello"}}}
	result := make(chan error, 1)
	go func() { result <- e.Compact(context.Background(), "c") }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	if _, err := e.SendMessage(ChatRequest{Message: "race"}); !errors.Is(err, ErrTurnInProgress) {
		t.Fatal(err)
	}
	if _, err := e.RewindSession("c", 0); !errors.Is(err, ErrTurnInProgress) {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r, _ := e.LoadSession("c")
	if r.Summary != "" || len(r.Compactions) != 1 || r.Compactions[0].Error == "" {
		t.Fatal("failed summary not recorded")
	}
}
