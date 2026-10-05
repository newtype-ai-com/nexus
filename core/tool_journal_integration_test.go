package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Engine-level M19-B tests: the journal is written before Run, bound to the
// action ID, and read back by a different engine as evidence, never as a
// command.

type journalFixture struct {
	t       *testing.T
	dir     string
	work    string
	engine  *Engine
	runs    atomic.Int32
	secrets atomic.Int32
	entered chan string // session id, sent when the blocking tool enters Run
	release chan struct{}
}

// newJournalFixture builds an engine with a session directory, a model that
// calls `tool` once then answers, and tools: "block" (waits for release),
// "ok", "fail", "panic", "secret" (asks the binding for a secret), "bg"
// (registers background work).
func newJournalFixture(t *testing.T, toolName string, args string) *journalFixture {
	t.Helper()
	f := &journalFixture{t: t, dir: t.TempDir(), work: t.TempDir(), entered: make(chan string, 1), release: make(chan struct{})}
	rounds := 0
	m := modelFunc(func(ctx context.Context, r ModelRequest, on func(string)) (ModelResponse, error) {
		rounds++
		if rounds == 1 {
			return ModelResponse{ToolCalls: []ToolCall{call(toolName, args)}}, nil
		}
		return ModelResponse{Content: "done"}, nil
	})
	tools := testTools{
		tool("block", true, func(ctx context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
			f.runs.Add(1)
			f.entered <- tc.SessionID
			select {
			case <-f.release:
				return "released", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}),
		tool("ok", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { f.runs.Add(1); return "ok", nil }),
		tool("fail", true, func(context.Context, ToolContext, json.RawMessage) (string, error) {
			f.runs.Add(1)
			return "", errors.New("public tool failure")
		}),
		tool("panic", true, func(context.Context, ToolContext, json.RawMessage) (string, error) {
			f.runs.Add(1)
			panic("public tool panic")
		}),
		tool("secret", true, func(ctx context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
			f.runs.Add(1)
			if tc.Secret == nil {
				return "", errors.New("no secret callback")
			}
			_, err := tc.Secret(ctx, "TEST")
			return "used", err
		}),
		tool("bg", true, func(ctx context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
			f.runs.Add(1)
			if tc.RegisterBackground == nil {
				return "", errors.New("no background")
			}
			done, err := tc.RegisterBackground()
			if err != nil {
				return "", err
			}
			go func() { time.Sleep(50 * time.Millisecond); done(BackgroundCompletion{}) }()
			return "ticket", nil
		}),
	}
	e, err := New(Options{Model: m, Tools: tools, WorkDir: f.work, SessionDir: f.dir, RetryDelay: -1, EnableBackgroundTurns: true})
	if err != nil {
		t.Fatal(err)
	}
	e.opts.Binder = BinderFunc(func(context.Context, BindRequest) (*Binding, error) {
		return &Binding{Secret: func(context.Context, string) (string, error) {
			f.secrets.Add(1)
			return "public-fixture-value", nil
		}}, nil
	})
	t.Cleanup(func() { _ = e.Close() })
	f.engine = e
	return f
}

// otherReader is "another process": a fresh journal over the same directory.
func (f *journalFixture) otherReader(session string) ToolJournalReport {
	f.t.Helper()
	r, err := newToolJournal(f.dir, f.work).read(session)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func toolDone(events []Event) (map[string]any, bool) {
	for _, e := range events {
		if e.Type == "tool_call_done" {
			return e.Data, true
		}
	}
	return nil, false
}

func TestM19ToolStartedDurableBeforeRun(t *testing.T) {
	f := newJournalFixture(t, "block", `{}`)
	ch, err := f.engine.SendMessage(ChatRequest{SessionID: "s-durable", Message: "go"})
	if err != nil {
		t.Fatal(err)
	}
	var session string
	select {
	case session = <-f.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("tool never entered Run")
	}
	// Run is blocked at the barrier. A separate reader already sees the start.
	report := f.otherReader(session)
	if len(report.Entries) != 1 || report.Entries[0].Tool != "block" || report.Entries[0].Outcome != "unknown" || report.Entries[0].StartedAt.IsZero() {
		t.Fatalf("start not durable before Run: %+v", report)
	}
	if report.Entries[0].Turn == "" {
		t.Fatalf("start record lacks the turn id: %+v", report.Entries[0])
	}
	// This engine knows it is still running.
	mine, _ := f.engine.ToolJournal(session)
	if len(mine.Entries) != 1 || mine.Entries[0].Outcome != "running" {
		t.Fatalf("live action misreported by the owning engine: %+v", mine)
	}
	// The session record itself is NOT yet on disk: the journal is the only
	// durable evidence while the tool runs.
	if _, err := os.Stat(filepath.Join(f.dir, session+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("session record saved before the turn ended")
	}
	close(f.release)
	events := collect(t, ch)
	assertTerminated(t, events)
	done, _ := toolDone(events)
	if done["outcome"] != ToolOutcomeReturned || done["action_id"] != report.Entries[0].Action {
		t.Fatalf("done event: %+v", done)
	}
	report = f.otherReader(session)
	if len(report.Entries) != 1 || report.Entries[0].Outcome != ToolOutcomeReturned || report.Entries[0].FinishedAt.IsZero() {
		t.Fatalf("finish not recorded: %+v", report)
	}
	rec, err := f.engine.LoadSession(session)
	if err != nil || len(rec.Turns) != 1 || len(rec.Turns[0].Actions) != 1 || rec.Turns[0].Actions[0].ID != report.Entries[0].Action || rec.Turns[0].Actions[0].Journal != "" {
		t.Fatalf("session action does not match the journal: %+v %v", rec, err)
	}
	if f.engine.ToolJournalPath(session) != filepath.Join(f.dir, session+".tools.jsonl") {
		t.Fatal("journal path")
	}
}

func TestM19ToolStartWriteFailureDoesNotRun(t *testing.T) {
	for _, stage := range []string{"open", "write", "sync", "dirsync"} {
		t.Run(stage, func(t *testing.T) {
			f := newJournalFixture(t, "secret", `{}`)
			fail := errors.New("public journal failure")
			f.engine.journal.hook = func(s string) error {
				if s == stage {
					return fail
				}
				return nil
			}
			events := send(t, f.engine, ChatRequest{SessionID: "s-" + stage, Message: "go"})
			assertTerminated(t, events)
			if f.runs.Load() != 0 || f.secrets.Load() != 0 {
				t.Fatalf("%s: tool ran %d times, secret read %d times without a durable start", stage, f.runs.Load(), f.secrets.Load())
			}
			done, ok := toolDone(events)
			if !ok || done["status"] != "failed" || !strings.Contains(done["result"].(string), "NOT_EXECUTED") || !strings.Contains(done["result"].(string), "tool journal start failed") || done["outcome"] != ToolOutcomeNotExecuted {
				t.Fatalf("%s: tool result does not say it was not executed: %+v", stage, done)
			}
			// The refusal is not reported as success anywhere.
			rec, _ := f.engine.LoadSession("s-" + stage)
			if len(rec.Turns) != 1 || len(rec.Turns[0].Actions) != 1 || rec.Turns[0].Actions[0].OK {
				t.Fatalf("%s: action recorded as ok: %+v", stage, rec.Turns)
			}
		})
	}
}

func TestM19ToolFinishUsesSameActionID(t *testing.T) {
	cases := map[string]struct {
		tool, outcome string
		started       bool
	}{
		"ok":    {"ok", ToolOutcomeReturned, true},
		"fail":  {"fail", ToolOutcomeFailed, true},
		"panic": {"panic", ToolOutcomePanicked, true},
		"bg":    {"bg", ToolOutcomeReturned, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newJournalFixture(t, tc.tool, `{}`)
			events := send(t, f.engine, ChatRequest{SessionID: "s-" + name, Message: "go"})
			assertTerminated(t, events)
			done, _ := toolDone(events)
			report := f.otherReader("s-" + name)
			if len(report.Entries) != 1 || report.Entries[0].Action != done["action_id"] || report.Entries[0].Outcome != tc.outcome || len(report.Problems) != 0 {
				t.Fatalf("%s: %+v / %+v", name, report, done)
			}
			if (tc.tool == "bg") != report.Entries[0].Background {
				t.Fatalf("%s: background flag %v", name, report.Entries[0].Background)
			}
			if tc.tool == "bg" && report.Entries[0].Outcome != ToolOutcomeReturned {
				t.Fatal("background return must be recorded as the call returning, nothing more")
			}
			rec, _ := f.engine.LoadSession("s-" + name)
			if rec.Turns[0].Actions[0].ID != report.Entries[0].Action {
				t.Fatal("action id differs between session and journal")
			}
		})
	}
	// Policy denial: never started, recorded as a refusal bound to the same id.
	t.Run("policy_denied", func(t *testing.T) {
		f := newJournalFixture(t, "ok", `{}`)
		f.engine.opts.Binder = BinderFunc(func(context.Context, BindRequest) (*Binding, error) {
			return &Binding{Gate: func(context.Context, string, json.RawMessage) (bool, string) { return false, "denied by mandate" }}, nil
		})
		events := send(t, f.engine, ChatRequest{SessionID: "s-denied", Message: "go"})
		assertTerminated(t, events)
		done, _ := toolDone(events)
		if f.runs.Load() != 0 || done["outcome"] != ToolOutcomePolicyDenied {
			t.Fatalf("denied tool: runs %d, %+v", f.runs.Load(), done)
		}
		report := f.otherReader("s-denied")
		if len(report.Entries) != 1 || report.Entries[0].Outcome != ToolOutcomePolicyDenied || report.Entries[0].Action != done["action_id"] || len(report.Unfinished()) != 0 {
			t.Fatalf("denial not journaled as a refusal: %+v", report)
		}
	})
	// Cancellation: the execution context is suspended while the tool runs.
	t.Run("cancelled", func(t *testing.T) {
		f := newJournalFixture(t, "block", `{}`)
		ch, err := f.engine.SendMessage(ChatRequest{SessionID: "s-cancel", Message: "go"})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-f.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("tool never entered Run")
		}
		if err := f.engine.SuspendExecution(); err != nil {
			t.Fatal(err)
		}
		collect(t, ch)
		// After suspension the turn's events are dropped (existing M18 behaviour),
		// so the durable journal is the evidence: the start has a cancelled finish.
		report := f.otherReader("s-cancel")
		if len(report.Entries) != 1 || report.Entries[0].Outcome != ToolOutcomeCancelled || len(report.Unfinished()) != 0 {
			t.Fatalf("cancellation not bound to the action: %+v", report)
		}
	})
}

func TestM19ToolRestartUnfinishedIsUnknown(t *testing.T) {
	f := newJournalFixture(t, "block", `{}`)
	ch, err := f.engine.SendMessage(ChatRequest{SessionID: "s-restart", Message: "go"})
	if err != nil {
		t.Fatal(err)
	}
	session := <-f.entered
	// "Restart": a second engine over the same directories, as after a crash.
	runs2 := 0
	e2, err := New(Options{WorkDir: f.work, SessionDir: f.dir, RetryDelay: -1,
		Model: modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
			return ModelResponse{Content: "x"}, nil
		}),
		Tools: testTools{tool("block", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { runs2++; return "", nil })}})
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	report, err := e2.ToolJournal(session)
	if err != nil || len(report.Entries) != 1 || report.Entries[0].Outcome != "unknown" || len(report.Unfinished()) != 1 {
		t.Fatalf("unfinished start not unknown in a new engine: %+v %v", report, err)
	}
	// Loading the session (there is none yet) and reading the journal execute
	// nothing and restore no permission: the new engine ran no tool.
	if _, err := e2.LoadSession(session); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session record unexpectedly present: %v", err)
	}
	if runs2 != 0 {
		t.Fatal("restart re-executed a tool")
	}
	// A different workspace cannot read this session's journal as its own.
	foreign := newToolJournal(f.dir, "/elsewhere")
	fr, _ := foreign.read(session)
	if len(fr.Entries) != 0 || len(fr.Problems) == 0 {
		t.Fatalf("foreign workspace read the journal: %+v", fr)
	}
	close(f.release)
	collect(t, ch)
	report, _ = e2.ToolJournal(session)
	if report.Entries[0].Outcome != ToolOutcomeReturned {
		t.Fatalf("finish not visible to the other engine: %+v", report)
	}
}

func TestM19ToolFinishWriteFailureCannotReportSuccess(t *testing.T) {
	f := newJournalFixture(t, "block", `{}`)
	ch, err := f.engine.SendMessage(ChatRequest{SessionID: "s-finishfail", Message: "go"})
	if err != nil {
		t.Fatal(err)
	}
	session := <-f.entered
	// The start is on disk; from now on every write fails.
	var writes atomic.Int32
	f.engine.journal.hook = func(s string) error {
		if s == "write" {
			writes.Add(1)
			return errors.New("public disk full")
		}
		return nil
	}
	close(f.release)
	events := collect(t, ch)
	assertTerminated(t, events)
	done, _ := toolDone(events)
	if done["journal"] != "finish_write_failed" || !strings.Contains(done["result"].(string), "finish record not saved") {
		t.Fatalf("finish failure hidden: %+v", done)
	}
	if writes.Load() != 1 {
		t.Fatalf("finish write retried: %d attempts", writes.Load())
	}
	rec, _ := f.engine.LoadSession(session)
	if rec.Turns[0].Actions[0].Journal != "finish_write_failed" {
		t.Fatalf("session action does not carry the journal failure: %+v", rec.Turns[0].Actions[0])
	}
	// On disk the action is still only started: unknown to any reader.
	f.engine.journal.hook = nil
	report := f.otherReader(session)
	if len(report.Entries) != 1 || report.Entries[0].Outcome != "unknown" {
		t.Fatalf("disk claims an outcome that was never saved: %+v", report)
	}
}

func TestM19ToolJournalPreservesSessionOperations(t *testing.T) {
	// v1 session records without journal fields load unchanged.
	f := newJournalFixture(t, "ok", `{}`)
	work, _ := json.Marshal(f.work) // a Windows path carries backslashes
	v1 := `{"v":1,"id":"legacy","work_dir":` + string(work) + `,"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z","turns":[{"at":"2026-10-01T00:00:00Z","task_id":"t","user":"u","assistant":"a","mode":"agent","ms":1,"actions":[{"id":"act_legacy","at":"2026-10-01T00:00:00Z","tool":"ok","ok":true,"ms":1,"invocation_id":"i"}]}]}`
	if err := os.WriteFile(filepath.Join(f.dir, "legacy.json"), []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := f.engine.LoadSession("legacy")
	if err != nil || len(rec.Turns) != 1 || rec.Turns[0].Actions[0].Journal != "" {
		t.Fatalf("v1 record: %+v %v", rec, err)
	}
	if report, err := f.engine.ToolJournal("legacy"); err != nil || len(report.Entries) != 0 {
		t.Fatalf("legacy session has no journal: %+v %v", report, err)
	}

	// A turn with a tool, then rewind: the journal is append-only evidence and
	// keeps the action with its real outcome; the session record is rewound.
	events := send(t, f.engine, ChatRequest{SessionID: "s-ops", Message: "go"})
	assertTerminated(t, events)
	before := f.otherReader("s-ops")
	if len(before.Entries) != 1 || before.Entries[0].Outcome != ToolOutcomeReturned {
		t.Fatalf("baseline journal: %+v", before)
	}
	if _, err := f.engine.RewindSession("s-ops", 0); err != nil {
		t.Fatal(err)
	}
	after := f.otherReader("s-ops")
	if len(after.Entries) != 1 || after.Entries[0] != before.Entries[0] {
		t.Fatalf("rewind altered the journal: %+v", after)
	}
	// Export is the v1 record and carries no journal lines.
	raw, err := f.engine.ExportSessionJSON("s-ops")
	if err != nil || strings.Contains(string(raw), `"kind":"started"`) {
		t.Fatalf("export changed: %v", err)
	}
	// Delete removes the journal with the record.
	if err := f.engine.DeleteSession("s-ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.engine.ToolJournalPath("s-ops")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal survived DeleteSession")
	}

	// Memory-only engine: tools run, nothing is claimed durable.
	rounds := 0
	mem, err := New(Options{WorkDir: t.TempDir(), RetryDelay: -1,
		Model: modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
			rounds++
			if rounds == 1 {
				return ModelResponse{ToolCalls: []ToolCall{call("ok", `{}`)}}, nil
			}
			return ModelResponse{Content: "done"}, nil
		}),
		Tools: testTools{tool("ok", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { return "ok", nil })}})
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	events = send(t, mem, ChatRequest{SessionID: "s-mem", Message: "go"})
	assertTerminated(t, events)
	done, _ := toolDone(events)
	if done["status"] != "done" {
		t.Fatalf("memory-only tool call: %+v", done)
	}
	if report, err := mem.ToolJournal("s-mem"); err != nil || len(report.Entries) != 0 || mem.ToolJournalPath("s-mem") != "" {
		t.Fatalf("memory-only engine claimed a journal: %+v %v", report, err)
	}
}
