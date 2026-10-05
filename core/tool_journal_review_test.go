package core

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestM19JournalSyncCancellationDoesNotRun(t *testing.T) {
	f := newJournalFixture(t, "secret", `{}`)
	f.engine.journal.hook = func(stage string) error {
		if stage == "sync" {
			f.engine.Cancel()
		}
		return nil
	}
	collect(t, mustJournalSend(t, f.engine))
	if f.runs.Load() != 0 || f.secrets.Load() != 0 {
		t.Fatalf("ran after sync cancellation: run=%d secret=%d", f.runs.Load(), f.secrets.Load())
	}
	r := f.otherReader("review-sync")
	if len(r.Entries) != 1 || r.Entries[0].Outcome != ToolOutcomeNotExecuted {
		t.Fatalf("journal: %+v", r)
	}
}

func mustJournalSend(t *testing.T, e *Engine) <-chan Event {
	t.Helper()
	ch, err := e.SendMessage(ChatRequest{SessionID: "review-sync", Message: "go"})
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestM19JournalPreservesCrashTailAndRetriesDirectorySync(t *testing.T) {
	j, _ := newTestJournal(t)
	if err := os.WriteFile(j.path("tail"), []byte(`{"v":1`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.started("tail", "", "", "a", "tool", time.Now()); err == nil {
		t.Fatal("appended to crash tail")
	}
	raw, _ := os.ReadFile(j.path("tail"))
	if string(raw) != `{"v":1` {
		t.Fatal("tail changed")
	}
	calls := 0
	j.hook = func(stage string) error {
		if stage == "dirsync" {
			calls++
			return errors.New("fixture sync failure")
		}
		return nil
	}
	for i := 0; i < 2; i++ {
		if err := j.started("sync", "", "", "a", "tool", time.Now()); err == nil {
			t.Fatal("directory sync bypassed")
		}
	}
	if calls != 2 {
		t.Fatalf("directory sync attempts=%d", calls)
	}
}

func TestM19JournalRejectsAmbiguousSchema(t *testing.T) {
	for _, raw := range []string{
		`{"v":1,"v":1,"at":"2026-10-03T00:00:00Z"}`,
		`{"V":1,"at":"2026-10-03T00:00:00Z"}`,
		`{"v":1,"secret":"public fixture","at":"2026-10-03T00:00:00Z"}`,
		`{"v":1}`,
	} {
		var rec toolJournalRecord
		if decodeJournalRecord([]byte(raw), &rec) == nil {
			t.Fatalf("ambiguous schema accepted: %s", raw)
		}
	}
}

func TestM19JournalRejectsAliasAndBoundsCorruptBytes(t *testing.T) {
	j, _ := newTestJournal(t)
	outside := t.TempDir() + "/untouched"
	if err := os.WriteFile(outside, []byte("public fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, j.path("alias")); err == nil {
		if err := j.started("alias", "", "", "a", "tool", time.Now()); err == nil {
			t.Fatal("alias written")
		}
		if _, err := j.read("alias"); err == nil {
			t.Fatal("alias read")
		}
		raw, _ := os.ReadFile(outside)
		if string(raw) != "public fixture\n" {
			t.Fatal("outside changed")
		}
	}
	if err := os.WriteFile(j.path("big"), []byte(strings.Repeat("x", toolJournalMaxBytes+1024)), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := j.read("big")
	if err != nil || !strings.Contains(strings.Join(r.Problems, ","), "byte_limit") || !r.TruncatedTail {
		t.Fatalf("unbounded/corrupt report: %+v %v", r, err)
	}
}
