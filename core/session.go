package core

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type InvocationRecord struct {
	ID      string    `json:"id"`
	Purpose string    `json:"purpose,omitempty"` // "summary" for compaction; empty for ordinary chat.
	At      time.Time `json:"at"`
	Round   int       `json:"round"`
	MS      int64     `json:"ms"`
	Error   string    `json:"error,omitempty"`
	Usage   Usage     `json:"usage"`
}
type ActionRecord struct {
	ID           string    `json:"id"`
	At           time.Time `json:"at"`
	Tool         string    `json:"tool"`
	Target       string    `json:"target,omitempty"`
	OK           bool      `json:"ok"`
	MS           int64     `json:"ms"`
	InvocationID string    `json:"invocation_id"`
	Error        string    `json:"error,omitempty"`
	// Journal (M19-B) is set only when the durable tool journal could not be
	// written for this action after it ran ("finish_write_failed"): the tool's
	// outcome is then unknown on disk even though OK/Error describe what this
	// process observed. v1 records without the field read unchanged.
	Journal string `json:"journal,omitempty"`
}
type TurnRecord struct {
	At                time.Time            `json:"at"`
	TaskID            string               `json:"task_id"`
	User              string               `json:"user"`
	Assistant         string               `json:"assistant"`
	Mode              string               `json:"mode"`
	Status            string               `json:"status,omitempty"`
	MS                int64                `json:"ms"`
	Invocations       []InvocationRecord   `json:"invocations,omitempty"`
	Actions           []ActionRecord       `json:"actions,omitempty"`
	PlanVerifications []VerificationResult `json:"plan_verifications,omitempty"`
}
type SessionRecord struct {
	Version      int                `json:"v"`
	ID           string             `json:"id"`
	WorkDir      string             `json:"work_dir"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
	Turns        []TurnRecord       `json:"turns"`
	Summary      string             `json:"summary,omitempty"`
	SummaryTurns int                `json:"summary_turns,omitempty"`
	Compactions  []InvocationRecord `json:"compactions,omitempty"`
	PinnedPlan   *PinnedPlan        `json:"pinned_plan,omitempty"`
	WorkPlan     *WorkPlanLedger    `json:"work_plan,omitempty"` // model ledger; never restores opt-in
	PlanRevision int                `json:"plan_revision,omitempty"`
	PlanHistory  []PinnedPlan       `json:"plan_history,omitempty"`
	Rewinds      []SessionSnapshot  `json:"rewinds,omitempty"`
}

func cloneRecord(r SessionRecord) SessionRecord {
	raw, _ := json.Marshal(r)
	var out SessionRecord
	_ = json.Unmarshal(raw, &out)
	return out
}
func (e *Engine) loadRecord(id string) (SessionRecord, error) {
	if !validConversation(id) {
		return SessionRecord{}, errors.New("invalid conversation ID")
	}
	if r, ok := e.records[id]; ok {
		return cloneRecord(r), nil
	}
	if e.opts.SessionDir == "" {
		return SessionRecord{}, os.ErrNotExist
	}
	raw, err := os.ReadFile(filepath.Join(e.opts.SessionDir, id+".json"))
	if err != nil {
		return SessionRecord{}, err
	}
	var r SessionRecord
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if r.Version != 1 || r.ID != id {
		return SessionRecord{}, errors.New("unsupported session record version or ID")
	}
	if r.WorkDir != e.opts.WorkDir {
		return SessionRecord{}, errors.New("session belongs to another workspace")
	}
	e.records[id] = r
	return cloneRecord(r), nil
}
func (e *Engine) LoadSession(id string) (SessionRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadRecord(id)
}
func (e *Engine) ListSessions() ([]SessionRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.opts.SessionDir != "" {
		entries, err := os.ReadDir(e.opts.SessionDir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
				id := entry.Name()[:len(entry.Name())-5]
				if _, err = e.loadRecord(id); err != nil {
					return nil, err
				}
			}
		}
	}
	records := make([]SessionRecord, 0, len(e.records))
	for _, r := range e.records {
		records = append(records, cloneRecord(r))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].UpdatedAt.After(records[j].UpdatedAt) })
	return records, nil
}
func (e *Engine) DeleteSession(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !validConversation(id) {
		return errors.New("invalid conversation ID")
	}
	if e.maintenanceDone != nil {
		return ErrTurnInProgress
	}
	if e.active != nil && e.active.request.SessionID == id {
		return ErrTurnInProgress
	}
	if e.opts.SessionDir != "" {
		if err := os.Remove(filepath.Join(e.opts.SessionDir, id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// The tool journal goes with the session record it belongs to.
		if err := e.journal.remove(id); err != nil {
			return err
		}
	}
	// Revoke tickets before joining tools; completion callbacks never need e.mu.
	e.background.clear(id, false)
	if closer, ok := e.opts.Tools.(interface{ CloseSession(string) error }); ok {
		if err := closer.CloseSession(id); err != nil {
			return err
		}
	}
	delete(e.records, id)
	return nil
}
func (e *Engine) saveTurn(req ChatRequest, t TurnRecord) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() { e.noteSave(req.SessionID, err) }() // every exit, early failures included
	r, err := e.loadRecord(req.SessionID)
	if errors.Is(err, os.ErrNotExist) {
		r = SessionRecord{Version: 1, ID: req.SessionID, WorkDir: req.WorkDir, CreatedAt: t.At}
	} else if err != nil {
		return err
	}
	r.Turns = append(r.Turns, t)
	r.UpdatedAt = time.Now().UTC()
	return e.storeRecord(r)
}

// storeRecord requires e.mu and only publishes memory after durable replacement.
func (e *Engine) storeRecord(r SessionRecord) error {
	if e.opts.SessionDir != "" {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		f, err := os.CreateTemp(e.opts.SessionDir, ".session-*")
		if err != nil {
			return err
		}
		name := f.Name()
		defer os.Remove(name)
		if _, err = f.Write(data); err != nil {
			f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		if err = os.Rename(name, filepath.Join(e.opts.SessionDir, r.ID+".json")); err != nil {
			return err
		}
	}
	e.records[r.ID] = r
	return nil
}
func (e *Engine) history(id string) ([]Message, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.loadRecord(id)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	turns := r.Turns
	if r.SummaryTurns > 0 && r.SummaryTurns <= len(turns) {
		turns = turns[r.SummaryTurns:]
	}
	if len(turns) > 10 {
		turns = turns[len(turns)-10:]
	}
	var messages []Message
	if r.Summary != "" {
		messages = append(messages, Message{Role: "user", Content: WrapDataSection("summary", r.Summary)})
	}
	for _, t := range turns {
		messages = append(messages, Message{Role: "user", Content: t.User}, Message{Role: "assistant", Content: clipText(t.Assistant, 4000)})
	}
	return messages, nil
}
func clipText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "\n[truncated]"
}
