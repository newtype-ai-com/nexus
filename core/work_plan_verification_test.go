package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestWorkPlanLedgerAppendOnly(t *testing.T) {
	w := &WorkPlanLedger{}
	tasks := []WorkPlanTask{{Title: "implement", Status: "pending"}, {Title: "implement", Status: "pending"}, {Title: "approval", Status: "waiting_person"}}
	if err := w.merge(tasks); err != nil {
		t.Fatal(err)
	}
	original := w.VerificationPlan()
	if err := w.merge(nil); err != nil {
		t.Fatal(err)
	}
	if len(w.Items) != 3 || w.VerificationPlan().SHA256 != original.SHA256 {
		t.Fatal("deletion changed obligations")
	}
	if err := w.merge([]WorkPlanTask{{Title: "implement", Status: "done"}, {Title: "approval", Status: "done"}}); err != nil {
		t.Fatal(err)
	}
	if w.VerificationPlan().SHA256 != original.SHA256 || !w.Items[2].RequiresApproval {
		t.Fatal("claims changed obligations or released wait")
	}
	if err := w.merge([]WorkPlanTask{{Title: "renamed", Status: "done"}}); err != nil {
		t.Fatal(err)
	}
	p := w.VerificationPlan()
	if len(p.Items) != 5 || p.SHA256 == original.SHA256 || p.Source != WorkPlanSource || p.Path != "" {
		t.Fatal(p)
	}
	for i, item := range p.Items {
		if item.EvidenceKind != "unknown" || !item.Unresolved {
			t.Fatal(item)
		}
		for j := 0; j < i; j++ {
			if p.Items[j].ID == item.ID {
				t.Fatal("duplicate identity")
			}
		}
	}
	p.Items[0].Text = "mutated"
	if w.Items[0].Title != "implement" {
		t.Fatal("snapshot aliases ledger")
	}
}

func TestWorkPlanLedgerRejectsInvalidAtomically(t *testing.T) {
	cases := [][]WorkPlanTask{
		{{Title: "ok", Status: "approved"}}, {{Title: "", Status: "pending"}},
		{{Title: strings.Repeat("a", 201), Status: "done"}}, {{Title: "bad\nline", Status: "done"}},
		{{Title: "ghp_" + strings.Repeat("a", 36), Status: "pending"}},
		{{Title: "ok", Status: "pending", ActiveForm: strings.Repeat("b", 201)}},
		{{Title: "one", Status: "in_progress"}, {Title: "two", Status: "in_progress"}},
		make([]WorkPlanTask, 51),
	}
	for i, tasks := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w := &WorkPlanLedger{}
			if err := w.merge([]WorkPlanTask{{Title: "existing", Status: "pending"}}); err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(w)
			if err := w.merge(tasks); err == nil {
				t.Fatal("invalid merge accepted")
			}
			after, _ := json.Marshal(w)
			if string(before) != string(after) {
				t.Fatal("partial merge")
			}
		})
	}
}

func TestWorkPlanLedgerBoundAndClaimedKind(t *testing.T) {
	w := &WorkPlanLedger{}
	for i := 0; i < maxWorkPlanItems; i++ {
		if err := w.merge([]WorkPlanTask{{Title: fmt.Sprintf("item %d", i), Status: "done"}}); err != nil {
			t.Fatal(err)
		}
	}
	before := w.VerificationPlan()
	if err := w.merge([]WorkPlanTask{{Title: "extra", Status: "done"}}); err == nil {
		t.Fatal("unbounded ledger")
	}
	if w.VerificationPlan().SHA256 != before.SHA256 {
		t.Fatal("overflow mutated ledger")
	}
	if err := w.merge([]WorkPlanTask{{Title: "item 0", Status: "pending"}}); err != nil {
		t.Fatal("existing updates should fit", err)
	}
	var claimed WorkPlanTask
	if err := json.Unmarshal([]byte(`{"title":"[local-test] fixture","status":"done","id":"human","evidence_kind":"fixture"}`), &claimed); err != nil {
		t.Fatal(err)
	}
	fresh := &WorkPlanLedger{}
	if err := fresh.merge([]WorkPlanTask{claimed}); err != nil {
		t.Fatal(err)
	}
	p := fresh.VerificationPlan()
	if p.Items[0].ID == "human" || p.Items[0].EvidenceKind != "unknown" {
		t.Fatal("model promoted requirement kind")
	}
	result := EvaluatePlanStop(*p, EvidenceSnapshot{}, []ItemVerdict{{ID: p.Items[0].ID, State: "verified_done"}}, &PlanVerificationState{})
	if result.Remaining != 2 || result.Items[0].State != "unresolved" {
		t.Fatal(result)
	}
}

func TestWorkPlanEnableIsolationAndReload(t *testing.T) {
	e := planTestEngine(t)
	r, err := e.EnableWorkPlanVerification("")
	if err != nil || r.WorkPlan == nil || !e.planVerificationEnabled[r.ID] {
		t.Fatal(r, err)
	}
	if p, err := e.GetPinnedPlan(r.ID); err != nil || p != nil {
		t.Fatal("work ledger impersonated pin")
	}
	e.planVerificationStates = map[string]PlanVerificationState{r.ID: {Checks: 2}}
	r.WorkPlan.Source = "human"
	again, err := e.EnableWorkPlanVerification(r.ID)
	if err != nil || again.WorkPlan.Source != WorkPlanSource || e.planVerificationStates[r.ID].Checks != 2 {
		t.Fatal("re-enable reset/aliased", err)
	}
	off, err := e.UnpinPlan(r.ID)
	if err != nil || e.planVerificationEnabled[r.ID] || off.WorkPlan == nil {
		t.Fatal("off erased ledger", err)
	}
	_, err = e.EnableWorkPlanVerification(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := e.PinPlan(r.ID, writePlan(t, e, "p.md", "- [ ] local task"))
	if err != nil || pinned.PinnedPlan == nil || pinned.WorkPlan == nil {
		t.Fatal(err)
	}
	again, err = e.EnableWorkPlanVerification(r.ID)
	if err != nil || again.PinnedPlan != nil || len(again.PlanHistory) != 1 {
		t.Fatal("pin/work exclusion", err)
	}
	e2, err := New(e.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	loaded, err := e2.LoadSession(r.ID)
	if err != nil || loaded.WorkPlan == nil || e2.planVerificationEnabled[r.ID] {
		t.Fatal("reload restored authority", err)
	}
	if err = e.DeactivatePlan(r.ID); err != nil || e.planVerificationEnabled[r.ID] {
		t.Fatal(err)
	}
}

func workPlanTestTurn(t *testing.T) (*Engine, *turn, string) {
	t.Helper()
	e := planTestEngine(t)
	r, err := e.EnableWorkPlanVerification("")
	if err != nil {
		t.Fatal(err)
	}
	tr := &turn{engine: e, request: ChatRequest{SessionID: r.ID}, ctx: context.Background(), record: TurnRecord{Mode: ModeAuto}}
	e.active = tr
	t.Cleanup(func() { e.mu.Lock(); e.active = nil; e.mu.Unlock() })
	return e, tr, r.ID
}

func TestWorkPlanCallbackDurableConcurrentAndDetached(t *testing.T) {
	e, tr, id := workPlanTestTurn(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := tr.updateWorkPlan(context.Background(), []WorkPlanTask{{Title: fmt.Sprintf("task %d", i), Status: "done"}}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	r, err := e.LoadSession(id)
	if err != nil || len(r.WorkPlan.Items) != 16 {
		t.Fatal("lost append", err)
	}
	e2, err := New(e.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	disk, err := e2.LoadSession(id)
	if err != nil || len(disk.WorkPlan.Items) != 16 {
		t.Fatal("not durable", err)
	}
}

func TestWorkPlanCallbackRejectsWrongContext(t *testing.T) {
	for _, name := range []string{"cancelled", "stale", "background", "inbox", "off", "pinned", "turn_cancelled"} {
		t.Run(name, func(t *testing.T) {
			e, tr, id := workPlanTestTurn(t)
			ctx := context.Background()
			switch name {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "stale":
				e.active = nil
			case "background":
				tr.backgroundTurn = true
			case "inbox":
				tr.inboxTurn = true
			case "off":
				delete(e.planVerificationEnabled, id)
			case "pinned":
				r := e.records[id]
				r.PinnedPlan = &PinnedPlan{}
				e.records[id] = r
			case "turn_cancelled":
				var cancel context.CancelFunc
				tr.ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := tr.updateWorkPlan(ctx, []WorkPlanTask{{Title: "forbidden", Status: "done"}}); err == nil {
				t.Fatal("callback accepted")
			}
			r, err := e.LoadSession(id)
			if err != nil || len(r.WorkPlan.Items) != 0 {
				t.Fatal("failed callback changed ledger")
			}
		})
	}
}

func TestWorkPlanCoverageCannotBeClaimedAway(t *testing.T) {
	for _, tasks := range [][]WorkPlanTask{nil, {{Title: "implement", Status: "waiting_person"}}, {{Title: "approval required", Status: "done"}}, {{Title: "approval required", Status: "waiting_person"}}} {
		w := &WorkPlanLedger{}
		if err := w.merge(tasks); err != nil {
			t.Fatal(err)
		}
		p := w.VerificationPlan()
		sentinel := p.Items[len(p.Items)-1]
		if sentinel.ID != "work_goal_coverage" || sentinel.RequiresApproval || !sentinel.Unresolved || sentinel.EvidenceKind != "unknown" {
			t.Fatal(sentinel)
		}
		var state PlanVerificationState
		for _, claim := range []string{"waiting_person", "verified_done", "unresolved"} {
			proposed := make([]ItemVerdict, len(p.Items))
			for i, item := range p.Items {
				proposed[i] = ItemVerdict{ID: item.ID, State: claim}
			}
			result := EvaluatePlanStop(*p, EvidenceSnapshot{}, proposed, &state)
			if result.Outcome == "waiting_person" || result.Outcome == "verified_done" || result.Items[len(result.Items)-1].State != "unresolved" {
				t.Fatal(result)
			}
		}
		if len(tasks) > 0 && tasks[0].Title == "implement" && (w.Items[0].RequiresApproval || w.Items[0].ClaimedStatus != "waiting_person" || p.Items[0].RequiresApproval) {
			t.Fatal("model status promoted host approval")
		}
	}
}

func TestWorkPlanChurnCannotResetNoProgress(t *testing.T) {
	w := &WorkPlanLedger{}
	var state PlanVerificationState
	for i := 0; i < 4; i++ {
		if err := w.merge([]WorkPlanTask{{Title: fmt.Sprintf("renamed %d", i), Status: "done"}}); err != nil {
			t.Fatal(err)
		}
		result := EvaluatePlanStop(*w.VerificationPlan(), EvidenceSnapshot{}, nil, &state)
		if result.NoProgress != min(i+1, 3) {
			t.Fatalf("churn reset counter: %+v", result)
		}
		if i >= 2 && result.Outcome != "blocked_no_progress" {
			t.Fatal(result)
		}
	}
}
