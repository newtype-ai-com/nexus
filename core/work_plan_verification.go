package core

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/redact"
)

const WorkPlanSource = "model_work_plan"
const maxWorkPlanItems = 500

// WorkPlanTask is a model claim, not a requirement supplied by the person, an
// approval, or a completion receipt. There is deliberately no ID or evidence kind.
type WorkPlanTask struct {
	Title      string `json:"title"`
	Status     string `json:"status"`
	ActiveForm string `json:"active_form,omitempty"`
}

type WorkPlanEntry struct {
	ID               string `json:"id"`
	Title            string `json:"title"`
	Occurrence       int    `json:"occurrence"`
	ClaimedStatus    string `json:"claimed_status"`
	RequiresApproval bool   `json:"requires_approval,omitempty"`
}

// WorkPlanLedger retains every obligation ever reported during this session.
// Deletion/renaming only adds obligations. Persisted data never enables the gate.
type WorkPlanLedger struct {
	Source   string          `json:"source"`
	Revision int             `json:"revision"`
	Items    []WorkPlanEntry `json:"items"`
}

// VerificationPlan returns detached, explicitly model-origin evidence data.
// Claims cannot select fixture semantics, and cannot establish verified_done.
func (w *WorkPlanLedger) VerificationPlan() *PinnedPlan {
	if w == nil {
		return nil
	}
	p := &PinnedPlan{Source: WorkPlanSource, Revision: w.Revision}
	for i, item := range w.Items {
		p.Items = append(p.Items, PlanItem{ID: item.ID, Line: i + 1, Text: item.Title,
			RequiresApproval: item.RequiresApproval || planNeedsApproval(item.Title),
			EvidenceKind:     "unknown", Unresolved: true})
	}
	// Model reports cannot establish that the person's whole goal is covered.
	// Keep this host-owned obligation even for empty/all-approval work tables.
	p.Items = append(p.Items, PlanItem{ID: "work_goal_coverage", Text: "Goal coverage has not been established by a person-pinned contract.", EvidenceKind: "unknown", Unresolved: true})
	raw, _ := json.Marshal(p.Items)
	p.Snapshot = string(raw)
	sum := sha256.Sum256(append([]byte(WorkPlanSource+"\x00"), raw...))
	p.SHA256 = fmt.Sprintf("%x", sum)
	return p
}

// merge is transactional and bounded. Exact title plus occurrence identifies an
// existing obligation; supplied IDs, status, order and active_form cannot erase it.
func (w *WorkPlanLedger) merge(tasks []WorkPlanTask) error {
	if len(tasks) > 50 {
		return errors.New("work plan exceeds 50 reported steps")
	}
	active := 0
	for _, task := range tasks {
		if !validWorkPlanText(task.Title, 200, false) || !validWorkPlanText(task.ActiveForm, 200, true) {
			return errors.New("invalid work plan text")
		}
		switch task.Status {
		case "pending", "done", "waiting_person":
		case "in_progress":
			active++
		default:
			return errors.New("invalid work plan status")
		}
	}
	if active > 1 {
		return errors.New("only one work plan step may be in progress")
	}
	next := *w
	next.Source = WorkPlanSource
	next.Items = append([]WorkPlanEntry(nil), w.Items...)
	occurrences := map[string]int{}
	changed := false
	for _, task := range tasks {
		title := strings.TrimSpace(task.Title)
		occurrences[title]++
		occurrence := occurrences[title]
		found := -1
		for i, item := range next.Items {
			if item.Title == title && item.Occurrence == occurrence {
				found = i
				break
			}
		}
		if found < 0 {
			if len(next.Items) >= maxWorkPlanItems {
				return errors.New("work plan ledger is full; existing obligations retained")
			}
			next.Items = append(next.Items, WorkPlanEntry{ID: fmt.Sprintf("wi_%d", len(next.Items)+1), Title: title, Occurrence: occurrence})
			found = len(next.Items) - 1
			changed = true
		}
		item := &next.Items[found]
		wait := planNeedsApproval(title)
		if wait && !item.RequiresApproval {
			changed = true
		}
		item.RequiresApproval = item.RequiresApproval || wait
		item.ClaimedStatus = task.Status
	}
	if changed {
		next.Revision++
	}
	if next.Revision == 0 {
		next.Revision = 1
	}
	raw, _ := json.Marshal(next)
	if len(raw) > maxPlanBytes {
		return errors.New("work plan ledger is full; existing obligations retained")
	}
	*w = next
	return nil
}

func validWorkPlanText(s string, limit int, empty bool) bool {
	if !utf8.ValidString(s) || len(s) > limit*4 || len([]rune(s)) > limit || (!empty && strings.TrimSpace(s) == "") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	_, secrets := redact.Text(s)
	return secrets == 0
}

// EnableWorkPlanVerification is person-facing only, never a model tool. Loading
// a ledger or enabling it again neither resets counters nor discards obligations.
func (e *Engine) EnableWorkPlanVerification(sessionID string) (SessionRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return SessionRecord{}, ErrClosed
	}
	if e.active != nil || e.maintenanceDone != nil {
		return SessionRecord{}, ErrTurnInProgress
	}
	var r SessionRecord
	var err error
	if sessionID == "" {
		r = SessionRecord{Version: 1, ID: ids.New(ids.KindConv), WorkDir: e.opts.WorkDir, CreatedAt: time.Now().UTC()}
	} else {
		r, err = e.loadRecord(sessionID)
		if err != nil {
			return SessionRecord{}, err
		}
	}
	if r.PinnedPlan != nil {
		r.PlanHistory = append(r.PlanHistory, *r.PinnedPlan)
		r.PinnedPlan = nil
	}
	if r.WorkPlan == nil {
		r.WorkPlan = &WorkPlanLedger{Source: WorkPlanSource, Revision: 1}
	}
	r.UpdatedAt = time.Now().UTC()
	if err = e.storeRecord(r); err != nil {
		return SessionRecord{}, err
	}
	if e.planVerificationEnabled == nil {
		e.planVerificationEnabled = map[string]bool{}
	}
	e.planVerificationEnabled[r.ID] = true
	return cloneRecord(r), nil
}

// updateWorkPlan is a turn-scoped capability injected only for the local built-in
// work_plan tool. Remote reports and deserialized tool arguments cannot obtain it.
func (t *turn) updateWorkPlan(ctx context.Context, tasks []WorkPlanTask) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e := t.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.closed || e.active != t || t.ctx.Err() != nil || t.backgroundTurn || t.inboxTurn || !e.planVerificationEnabled[t.request.SessionID] {
		return errors.New("work plan verification is not active for this turn")
	}
	r, err := e.loadRecord(t.request.SessionID)
	if err != nil {
		return err
	}
	if r.PinnedPlan != nil || r.WorkPlan == nil {
		return errors.New("work plan verification is not active for this turn")
	}
	if err = r.WorkPlan.merge(tasks); err != nil {
		return err
	}
	r.UpdatedAt = time.Now().UTC()
	return e.storeRecord(r)
}
