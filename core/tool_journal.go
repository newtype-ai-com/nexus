package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"sync"
	"time"
)

// M19-B — a durable record that a tool STARTED, written before it runs.
//
// The session record (SessionRecord v1) is saved when a turn ends. A tool that
// never returns therefore leaves no trace on disk: after a crash or a hang the
// operator cannot tell that anything was running, let alone what. The tool
// journal is a small append-only file next to the session record that gets a
// "started" line, fsynced, before Tool.Run is called, and a "finished" line
// bound to the same action ID afterwards. A started line without a finished
// line is exactly the evidence a restart needs: this action's outcome is
// unknown.
//
// What it is not: it never stores arguments, commands, paths, output, error
// text or secrets — only IDs, a validated tool name, a time and an outcome. It
// grants nothing: a started line is not permission, and nothing in it is read
// back as an instruction. It is not durable against power loss beyond what
// fsync of the file (and of the directory on creation) provides, and it does
// not coordinate two processes writing the same session directory.

const toolJournalVersion = 1

// toolJournalMaxLine bounds one record on disk; longer lines are corruption.
const toolJournalMaxLine = 4096

// toolJournalMaxRecords bounds how many records one read will parse.
const toolJournalMaxRecords = 200000

// Corrupt oversized lines count against a total byte budget too.
const toolJournalMaxBytes = 16 * 1024 * 1024

// Outcomes a finished record may carry. "returned" means Tool.Run returned
// without error — a background tool's ticket counts as returned, not as its
// descendants having succeeded.
const (
	ToolOutcomeReturned     = "returned"
	ToolOutcomeFailed       = "failed"
	ToolOutcomeCancelled    = "cancelled"
	ToolOutcomePanicked     = "panicked"
	ToolOutcomeNotExecuted  = "not_executed"
	ToolOutcomePolicyDenied = "policy_denied"
)

// toolJournalName accepts the shape of tool names this engine registers.
// Anything else — including external tool names, which are untrusted input —
// is recorded as "unknown" rather than written verbatim.
var toolJournalName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

// toolJournalRecord is one line of the journal.
type toolJournalRecord struct {
	V          int       `json:"v"`
	Kind       string    `json:"kind"` // started | finished
	Session    string    `json:"session"`
	Workspace  string    `json:"workspace"` // sha256 prefix of the engine work dir
	Turn       string    `json:"turn,omitempty"`
	Invocation string    `json:"invocation,omitempty"`
	Action     string    `json:"action"`
	Tool       string    `json:"tool,omitempty"`
	At         time.Time `json:"at"`
	Outcome    string    `json:"outcome,omitempty"`
	Background bool      `json:"background,omitempty"`
}

// ToolJournalEntry is the read-side view of one action.
type ToolJournalEntry struct {
	Action     string    `json:"action"`
	Tool       string    `json:"tool"`
	Turn       string    `json:"turn,omitempty"`
	Invocation string    `json:"invocation,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// Outcome is the finished outcome, or "unknown" when only a start was
	// recorded by a process that is no longer this one, or "running" when this
	// engine is executing the action right now.
	Outcome    string `json:"outcome"`
	Background bool   `json:"background,omitempty"`
}

// ToolJournalReport is what a reader gets: the entries plus every integrity
// problem found. Problems never make the file unreadable as a whole; they are
// evidence too.
type ToolJournalReport struct {
	Entries       []ToolJournalEntry `json:"entries"`
	TruncatedTail bool               `json:"truncated_tail,omitempty"` // last line had no newline: a write was cut
	Problems      []string           `json:"problems,omitempty"`       // fixed labels, no file contents
}

// Unfinished lists actions with a start and no finish that this process is
// not running.
func (r ToolJournalReport) Unfinished() []ToolJournalEntry {
	var out []ToolJournalEntry
	for _, e := range r.Entries {
		if e.Outcome == "unknown" {
			out = append(out, e)
		}
	}
	return out
}

// toolJournal writes and reads the per-session journal files of one engine.
type toolJournal struct {
	dir       string
	workspace string
	mu        sync.Mutex

	// live actions of this process: a start without a finish that is not a
	// crash, just now.
	live map[string]bool
	// hook lets tests inject failures at a named stage; nil in production.
	hook func(stage string) error
}

func newToolJournal(dir, workDir string) *toolJournal {
	return &toolJournal{dir: dir, workspace: workspaceTag(workDir), live: map[string]bool{}}
}

func workspaceTag(workDir string) string {
	sum := sha256.Sum256([]byte(workDir))
	return hex.EncodeToString(sum[:8])
}

func (j *toolJournal) enabled() bool { return j != nil && j.dir != "" }

func (j *toolJournal) path(session string) string {
	return filepath.Join(j.dir, session+".tools.jsonl")
}

func (j *toolJournal) stage(name string) error {
	if j.hook != nil {
		return j.hook(name)
	}
	return nil
}

// cleanToolName returns a name safe to store, or "unknown".
func cleanToolName(name string) string {
	if toolJournalName.MatchString(name) {
		return name
	}
	return "unknown"
}

// started appends and fsyncs a started record. It returns an error when the
// record is not known to be on disk; the caller must then not run the tool.
func (j *toolJournal) started(session, turn, invocation, action, tool string, at time.Time) error {
	if !j.enabled() {
		return nil
	}
	if !validConversation(session) {
		return errors.New("tool journal: invalid session")
	}
	rec := toolJournalRecord{V: toolJournalVersion, Kind: "started", Session: session, Workspace: j.workspace, Turn: turn, Invocation: invocation, Action: action, Tool: cleanToolName(tool), At: at.UTC()}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.append(session, rec); err != nil {
		return err
	}
	j.live[action] = true
	return nil
}

// finished appends and fsyncs a finished record for the same action. A failure
// here is reported to the caller, who must surface it and must not retry: the
// tool has already run (or not), and a second finish line would be a lie.
func (j *toolJournal) finished(session, action, outcome string, background bool, at time.Time) error {
	if !j.enabled() {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.live, action)
	rec := toolJournalRecord{V: toolJournalVersion, Kind: "finished", Session: session, Workspace: j.workspace, Action: action, Outcome: outcome, Background: background, At: at.UTC()}
	return j.append(session, rec)
}

// append writes one line with O_APPEND and fsyncs it. The first write to a new
// file also fsyncs the directory so the file's existence is durable. This is
// a single-process writer: the mutex serialises this engine, and nothing
// detects another process appending to the same file (documented limit).
func (j *toolJournal) append(session string, rec toolJournalRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(line)+1 > toolJournalMaxLine {
		return errors.New("tool journal: record too large")
	}
	if err := j.stage("open"); err != nil {
		return err
	}
	f, err := j.open(session, os.O_RDWR|os.O_APPEND|os.O_CREATE)
	if err != nil {
		return err
	}
	defer f.Close()
	// Never concatenate a new start with a crash tail. Preserve the original
	// bytes and require explicit recovery rather than silently losing evidence.
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], st.Size()-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			return errors.New("tool journal: truncated tail requires recovery")
		}
	}
	if err := j.stage("write"); err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := j.stage("sync"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	// Also sync existing files: an earlier failed creation sync or recreation
	// must not bypass the directory durability barrier on a later start.
	{
		if err := j.stage("dirsync"); err != nil {
			return err
		}
		if err := syncDir(j.dir); err != nil {
			return err
		}

	}
	return nil
}

// The private session directory is host-owned, not a multi-writer sandbox.
// Root confinement and nofollow/nonblock protect against leaf aliases/FIFOs;
// descriptor checks reject insecure pre-existing files before reading/writing.
func (j *toolJournal) open(session string, flags int) (*os.File, error) {
	if !validConversation(session) {
		return nil, errors.New("tool journal: invalid session")
	}
	root, err := os.OpenRoot(j.dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := session + ".tools.jsonl"
	before, err := root.Lstat(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && (!before.Mode().IsRegular() || !journalModePrivate(before)) {
		return nil, errors.New("tool journal: unsafe file")
	}
	f, err := openJournalFile(root, name, flags)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !journalModePrivate(after) || (before != nil && !os.SameFile(before, after)) {
		f.Close()
		return nil, errors.New("tool journal: unsafe file")
	}
	return f, nil
}

// read parses one session's journal with bounds, reporting problems instead
// of hiding them. Lines of another session or workspace are rejected as
// problems. A trailing line without a newline is a cut write and is dropped
// from entries but flagged.
func (j *toolJournal) read(session string) (ToolJournalReport, error) {
	report := ToolJournalReport{}
	if !j.enabled() {
		return report, nil
	}
	if !validConversation(session) {
		return report, errors.New("tool journal: invalid session")
	}
	f, err := j.open(session, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err != nil {
		return report, err
	}
	defer f.Close()
	j.mu.Lock()
	live := make(map[string]bool, len(j.live))
	for k := range j.live {
		live[k] = true
	}
	j.mu.Unlock()
	entries := map[string]*ToolJournalEntry{}
	var order []string
	problem := func(label string) { report.Problems = append(report.Problems, label) }
	limited := &io.LimitedReader{R: f, N: toolJournalMaxBytes}
	reader := bufio.NewReaderSize(limited, toolJournalMaxLine+1)
	records := 0
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) > 0 {
			records++
			if records > toolJournalMaxRecords {
				problem("too_many_records")
				break
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			problem("oversized_line")
			// Skip the rest of this line.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = reader.ReadSlice('\n')
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					return report, err
				}
				report.TruncatedTail = true
				break
			}
			continue
		}
		if err != nil {
			if len(line) > 0 {
				report.TruncatedTail = true
			}
			if !errors.Is(err, io.EOF) {
				return report, err
			}
			break
		}
		if len(line) > toolJournalMaxLine {
			problem("oversized_line")
			continue
		}
		var rec toolJournalRecord
		if decodeJournalRecord(line, &rec) != nil {
			problem("invalid_json")
			continue
		}
		if rec.V != toolJournalVersion {
			problem("unsupported_version")
			continue
		}
		if rec.Session != session || rec.Workspace != j.workspace {
			problem("foreign_record")
			continue
		}
		if rec.Action == "" || len(rec.Action) > 128 {
			problem("invalid_action_id")
			continue
		}
		switch rec.Kind {
		case "started":
			if _, dup := entries[rec.Action]; dup {
				problem("duplicate_start")
				continue
			}
			entries[rec.Action] = &ToolJournalEntry{Action: rec.Action, Tool: cleanToolName(rec.Tool), Turn: rec.Turn, Invocation: rec.Invocation, StartedAt: rec.At, Outcome: "unknown"}
			order = append(order, rec.Action)
		case "finished":
			if cleanOutcome(rec.Outcome) == "unknown" {
				problem("invalid_outcome")
				continue
			}
			e, ok := entries[rec.Action]
			if !ok {
				// A finish without a start is legitimate only for a refusal that
				// never started: not_executed or policy_denied.
				if rec.Outcome != ToolOutcomeNotExecuted && rec.Outcome != ToolOutcomePolicyDenied {
					problem("finish_without_start")
					continue
				}
				e = &ToolJournalEntry{Action: rec.Action, Tool: "unknown", StartedAt: rec.At}
				entries[rec.Action] = e
				order = append(order, rec.Action)
			}
			if e.Outcome != "unknown" && e.Outcome != "" {
				problem("duplicate_finish")
				continue
			}
			e.FinishedAt = rec.At
			e.Outcome = cleanOutcome(rec.Outcome)
			e.Background = rec.Background
		default:
			problem("unknown_kind")
		}
	}
	if limited.N == 0 {
		problem("byte_limit")
	}
	for _, id := range order {
		e := entries[id]
		if e.Outcome == "unknown" && live[id] {
			e.Outcome = "running"
		}
		report.Entries = append(report.Entries, *e)
	}
	sort.SliceStable(report.Entries, func(a, b int) bool { return report.Entries[a].StartedAt.Before(report.Entries[b].StartedAt) })
	return report, nil
}

// Journal v1 is a flat exact-key object. Reject duplicate/unknown/case-alias
// fields rather than accepting encoding/json's last-wins interpretation.
func decodeJournalRecord(line []byte, rec *toolJournalRecord) error {
	d := json.NewDecoder(bytes.NewReader(line))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("invalid journal object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return errors.New("duplicate journal field")
		}
		switch key {
		case "v", "kind", "session", "workspace", "turn", "invocation", "action", "tool", "at", "outcome", "background":
		default:
			return errors.New("unknown journal field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing journal data")
	}
	if err := json.Unmarshal(line, rec); err != nil {
		return err
	}
	if rec.At.IsZero() {
		return errors.New("missing journal timestamp")
	}
	return nil
}

func cleanOutcome(s string) string {
	switch s {
	case ToolOutcomeReturned, ToolOutcomeFailed, ToolOutcomeCancelled, ToolOutcomePanicked, ToolOutcomeNotExecuted, ToolOutcomePolicyDenied:
		return s
	}
	return "unknown"
}

// remove deletes a session's journal with its session record.
func (j *toolJournal) remove(session string) error {
	if !j.enabled() {
		return nil
	}
	if err := os.Remove(j.path(session)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ToolJournal returns the durable start/finish record of a session's tool
// calls. With SessionDir empty there is no journal and the report is empty:
// the memory-only engine does not claim durability. Nothing here is executed
// or re-executed; the report is evidence for a person or a supervisor.
func (e *Engine) ToolJournal(id string) (ToolJournalReport, error) {
	if !validConversation(id) {
		return ToolJournalReport{}, errors.New("invalid conversation ID")
	}
	if e.journal == nil {
		return ToolJournalReport{}, nil
	}
	return e.journal.read(id)
}

// ToolJournalPath tells an operator where the journal of a session lives, or
// "" for a memory-only engine.
func (e *Engine) ToolJournalPath(id string) string {
	if e.journal == nil || !e.journal.enabled() || !validConversation(id) {
		return ""
	}
	return e.journal.path(id)
}

func toolJournalError(stage string, err error) error {
	return fmt.Errorf("tool journal %s failed: %w", stage, err)
}
