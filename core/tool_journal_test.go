package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Unit tests of the journal file itself: schema, corruption handling and the
// absence of arguments/secrets. Engine behaviour is in the integration file.

func newTestJournal(t *testing.T) (*toolJournal, string) {
	t.Helper()
	dir := t.TempDir()
	return newToolJournal(dir, "/work/space"), dir
}

func TestM19ToolJournalRejectsCorruptionAndLeaksNoArguments(t *testing.T) {
	j, dir := newTestJournal(t)
	at := time.Date(2026, 10, 3, 5, 0, 0, 0, time.UTC)
	const sentinel = "PUBLIC-SENTINEL-must-not-be-written"
	// A tool name that is not a tool name is recorded as unknown, never verbatim.
	if err := j.started("s1", "turn-1", "inv-1", "act_1", "read_file; rm -rf "+sentinel, at); err != nil {
		t.Fatal(err)
	}
	if err := j.finished("s1", "act_1", ToolOutcomeReturned, false, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(j.path("s1"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, sentinel) || strings.Contains(text, "rm -rf") || strings.Contains(text, "/work/space") {
		t.Fatalf("journal leaked an argument, a command or the workspace path: %s", text)
	}
	if !strings.Contains(text, `"tool":"unknown"`) {
		t.Fatalf("invalid tool name not normalised: %s", text)
	}
	for _, key := range []string{"args", "arguments", "command", "path", "output", "result", "error", "secret"} {
		if strings.Contains(text, `"`+key+`"`) {
			t.Fatalf("journal schema carries %q", key)
		}
	}
	report, err := j.read("s1")
	if err != nil || len(report.Entries) != 1 || report.Entries[0].Outcome != ToolOutcomeReturned || report.Entries[0].Tool != "unknown" || len(report.Problems) != 0 {
		t.Fatalf("clean journal misread: %+v %v", report, err)
	}

	// Corruption: duplicate start, finish without start, foreign session, foreign
	// workspace, invalid JSON, unsupported version, oversized line, cut tail.
	lines := []string{
		`{"v":1,"kind":"started","session":"s1","workspace":"` + j.workspace + `","action":"act_dup","tool":"read_file","at":"2026-10-03T05:00:00Z"}`,
		`{"v":1,"kind":"started","session":"s1","workspace":"` + j.workspace + `","action":"act_dup","tool":"read_file","at":"2026-10-03T05:00:01Z"}`,
		`{"v":1,"kind":"finished","session":"s1","workspace":"` + j.workspace + `","action":"act_orphan","outcome":"returned","at":"2026-10-03T05:00:02Z"}`,
		`{"v":1,"kind":"started","session":"OTHER","workspace":"` + j.workspace + `","action":"act_foreign","tool":"read_file","at":"2026-10-03T05:00:03Z"}`,
		`{"v":1,"kind":"started","session":"s1","workspace":"deadbeefdeadbeef","action":"act_ws","tool":"read_file","at":"2026-10-03T05:00:04Z"}`,
		`{not json`,
		`{"v":2,"kind":"started","session":"s1","workspace":"` + j.workspace + `","action":"act_v2","tool":"read_file","at":"2026-10-03T05:00:05Z"}`,
		`{"v":1,"kind":"started","session":"s1","workspace":"` + j.workspace + `","action":"act_big","tool":"` + strings.Repeat("x", toolJournalMaxLine) + `","at":"2026-10-03T05:00:06Z"}`,
		`{"v":1,"kind":"finished","session":"s1","workspace":"` + j.workspace + `","action":"act_dup","outcome":"returned","at":"2026-10-03T05:00:07Z"}`,
		`{"v":1,"kind":"finished","session":"s1","workspace":"` + j.workspace + `","action":"act_dup","outcome":"failed","at":"2026-10-03T05:00:08Z"}`,
		`{"v":1,"kind":"started","session":"s1","workspace":"` + j.workspace + `","action":"act_cut","tool":"read_file","at":"2026-10-03T05:00:09Z"`, // no newline, no closing brace: a cut write
	}
	if err := os.WriteFile(j.path("s1"), []byte(text+strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = j.read("s1")
	if err != nil {
		t.Fatal(err)
	}
	if !report.TruncatedTail {
		t.Fatal("cut tail not flagged")
	}
	want := []string{"duplicate_start", "finish_without_start", "foreign_record", "foreign_record", "invalid_json", "unsupported_version", "oversized_line", "duplicate_finish"}
	if strings.Join(report.Problems, ",") != strings.Join(want, ",") {
		t.Fatalf("problems %v, want %v", report.Problems, want)
	}
	// The valid entries survive: act_1 returned, act_dup returned (first finish
	// wins; the second is a problem, not a change). The cut entry is not there.
	if len(report.Entries) != 2 || report.Entries[1].Action != "act_dup" || report.Entries[1].Outcome != ToolOutcomeReturned {
		t.Fatalf("entries after corruption: %+v", report.Entries)
	}
	for _, e := range report.Entries {
		if e.Action == "act_cut" || e.Action == "act_big" || e.Action == "act_foreign" {
			t.Fatalf("corrupt entry accepted: %+v", e)
		}
	}
	// A problem report never carries file contents.
	for _, p := range report.Problems {
		if strings.Contains(p, "{") || strings.Contains(p, "act_") {
			t.Fatalf("problem label leaks content: %q", p)
		}
	}
	// Invalid session IDs are refused on both sides; another session's file is
	// not read through this one.
	if _, err := j.read("../etc"); err == nil {
		t.Fatal("path-like session accepted")
	}
	if err := j.started("../etc", "", "", "act_x", "t", at); err == nil {
		t.Fatal("path-like session written")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("unexpected files in journal dir: %d", len(entries))
	}
	// Memory-only journal: inert, never durable, never an error.
	none := newToolJournal("", "/w")
	if err := none.started("s", "", "", "a", "t", at); err != nil || none.enabled() {
		t.Fatal("memory-only journal must be inert")
	}
	if r, err := none.read("s"); err != nil || len(r.Entries) != 0 {
		t.Fatal("memory-only journal reported entries")
	}
}

func TestM19ToolJournalRestartUnfinishedIsUnknownUnit(t *testing.T) {
	j, _ := newTestJournal(t)
	at := time.Now()
	if err := j.started("s1", "t", "i", "act_live", "read_file", at); err != nil {
		t.Fatal(err)
	}
	// In the writing process the action is live, not unknown.
	r, _ := j.read("s1")
	if len(r.Entries) != 1 || r.Entries[0].Outcome != "running" || len(r.Unfinished()) != 0 {
		t.Fatalf("live action misreported: %+v", r)
	}
	// Another process (a fresh journal over the same directory) sees unknown.
	other := newToolJournal(j.dir, "/work/space")
	r, _ = other.read("s1")
	if len(r.Entries) != 1 || r.Entries[0].Outcome != "unknown" || len(r.Unfinished()) != 1 {
		t.Fatalf("unfinished action not unknown after restart: %+v", r)
	}
	// Finishing from the other process binds to the same action id.
	if err := other.finished("s1", "act_live", ToolOutcomeCancelled, false, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	r, _ = other.read("s1")
	if r.Entries[0].Outcome != ToolOutcomeCancelled || len(r.Unfinished()) != 0 {
		t.Fatalf("finish not bound: %+v", r)
	}
}

func TestM19ToolJournalWriteFailureStages(t *testing.T) {
	j, _ := newTestJournal(t)
	fail := errors.New("public disk failure")
	// What a reader may see after each failure stage. open/write: nothing.
	// sync/dirsync: the line is in the file but its durability was not
	// confirmed, so the caller is told "not started" and the reader sees an
	// unfinished start — the safe direction (an action that may never have run
	// shows as unknown, never the reverse).
	expectRecords := map[string]int{"open": 0, "write": 0, "sync": 1, "dirsync": 1}
	for _, stage := range []string{"open", "write", "sync", "dirsync"} {
		j.hook = func(s string) error {
			if s == stage {
				return fail
			}
			return nil
		}
		err := j.started("s"+stage, "", "", "act_"+stage, "read_file", time.Now())
		if !errors.Is(err, fail) {
			t.Fatalf("%s failure not reported: %v", stage, err)
		}
		if j.live["act_"+stage] {
			t.Fatalf("%s failure left the action live", stage)
		}
		other := newToolJournal(j.dir, "/work/space")
		r, _ := other.read("s" + stage)
		if n := len(r.Unfinished()); n != expectRecords[stage] {
			t.Fatalf("%s failure: %d unfinished records, want %d", stage, n, expectRecords[stage])
		}
	}
	j.hook = nil
	if _, err := os.Stat(filepath.Join(j.dir, "sopen.tools.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("open failure created a file")
	}
	// After the hook is cleared the same journal writes normally.
	if err := j.started("sok", "", "", "act_ok", "read_file", time.Now()); err != nil {
		t.Fatal(err)
	}
}
