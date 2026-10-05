package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWaitIdleWaitsForTheActiveTurn(t *testing.T) {
	e := &Engine{}
	if err := e.WaitIdle(context.Background()); err != nil {
		t.Fatal("idle engine:", err)
	}
	tr := &turn{finished: make(chan struct{})}
	e.active = tr
	done := make(chan error, 1)
	go func() { done <- e.WaitIdle(context.Background()) }()
	select {
	case err := <-done:
		t.Fatal("returned while a turn was active:", err)
	case <-time.After(50 * time.Millisecond):
	}
	e.mu.Lock()
	e.active = nil
	e.mu.Unlock()
	close(tr.finished)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// cancellation while a turn stays active
	e.active = &turn{finished: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := e.WaitIdle(ctx); err == nil {
		t.Fatal("no error after cancellation")
	}
}

func TestLastSaveReportsTheOutcome(t *testing.T) {
	e := &Engine{}
	if saved, err := e.LastSave("cnv_a"); saved || err != nil {
		t.Fatal("nothing saved yet", saved, err)
	}
	e.mu.Lock()
	e.noteSave("cnv_a", nil)
	e.noteSave("cnv_b", errFixtureSave)
	e.mu.Unlock()
	if saved, err := e.LastSave("cnv_a"); !saved || err != nil {
		t.Fatal("confirmed save", saved, err)
	}
	if saved, err := e.LastSave("cnv_b"); saved || err != errFixtureSave {
		t.Fatal("failed save", saved, err)
	}
}

var errFixtureSave = errors.New("public fixture save failure")

// TSC-R2: an early save failure (an unreadable record) is recorded too.
func TestLastSaveRecordsEarlyFailures(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{opts: Options{SessionDir: dir, WorkDir: dir}, records: map[string]SessionRecord{}}
	if err := os.WriteFile(filepath.Join(dir, "cnv_corrupt.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.saveTurn(ChatRequest{SessionID: "cnv_corrupt", WorkDir: dir}, TurnRecord{At: time.Now().UTC()}); err == nil {
		t.Fatal("corrupt record saved")
	}
	if saved, err := e.LastSave("cnv_corrupt"); saved || err == nil {
		t.Fatalf("early failure not recorded: %v %v", saved, err)
	}
}
