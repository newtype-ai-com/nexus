package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func planTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Options{WorkDir: t.TempDir(), SessionDir: t.TempDir(), Model: modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		t.Error("pin must not call model")
		return ModelResponse{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
func writePlan(t *testing.T, e *Engine, name, text string) string {
	t.Helper()
	path := filepath.Join(e.opts.WorkDir, name)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestPlanPinSnapshotSurvivesFileEdit(t *testing.T) {
	e := planTestEngine(t)
	path := writePlan(t, e, "my plan.md", "# Plan\n- [ ] implement\n- [x] test\n")
	r, err := e.PinPlan("", path)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "" || !e.planVerificationEnabled[r.ID] || r.PlanRevision != 1 {
		t.Fatalf("bad pin: %+v", r)
	}
	original := r.PinnedPlan.Snapshot
	firstID := r.PinnedPlan.Items[0].ID
	writePlan(t, e, "my plan.md", "# Changed\n\n- [x] implement\n- [ ] added\n")
	r.PinnedPlan.Items[0].Text = "mutated"
	p, err := e.GetPinnedPlan(r.ID)
	if err != nil || p.Snapshot != original || p.Items[0].Text != "implement" {
		t.Fatal(p, err)
	}
	p.Items[0].Text = "mutated again"
	next, err := e.PinPlan(r.ID, path)
	if err != nil {
		t.Fatal(err)
	}
	if next.PlanRevision != 2 || next.PinnedPlan.Items[0].ID != firstID || len(next.PlanHistory) != 1 || next.PlanHistory[0].Snapshot != original {
		t.Fatal("revision/history/stable ID mismatch")
	}
	off, err := e.UnpinPlan(r.ID)
	if err != nil || off.PinnedPlan != nil || len(off.PlanHistory) != 2 || e.planVerificationEnabled[r.ID] {
		t.Fatal("unpin", off, err)
	}
	next, err = e.PinPlan(r.ID, path)
	if err != nil || next.PlanRevision != 3 {
		t.Fatal("revision reset", err)
	}
}
func TestPlanPinRejectsWorkspaceEscapeAndSecrets(t *testing.T) {
	e := planTestEngine(t)
	outside := filepath.Join(t.TempDir(), "outside.md")
	os.WriteFile(outside, []byte("- [ ] private"), 0600)
	os.Symlink(outside, filepath.Join(e.opts.WorkDir, "alias.md"))
	os.Mkdir(filepath.Join(e.opts.WorkDir, "docs"), 0700)
	os.Symlink(filepath.Join(e.opts.WorkDir, "docs"), filepath.Join(e.opts.WorkDir, "link"))
	os.WriteFile(filepath.Join(e.opts.WorkDir, "docs", "ok.md"), []byte("- [ ] ok"), 0600)
	writePlan(t, e, "secret.md", "- [ ] not read")
	writePlan(t, e, "token.md", "ghp_"+strings.Repeat("a", 36))
	writePlan(t, e, "large.md", strings.Repeat("a", maxPlanBytes+1))
	writePlan(t, e, "binary.md", string([]byte{0xff, 0}))
	writePlan(t, e, "control.md", "hello\x1b[0m")
	for _, path := range []string{"../outside.md", outside, "alias.md", "link/ok.md", "secret.md", "token.md", "large.md", "binary.md", "control.md", ".env", "docs"} {
		t.Run(path, func(t *testing.T) {
			if _, err := e.PinPlan("", path); err == nil {
				t.Fatal("unsafe pin accepted")
			}
		})
	}
	if len(e.records) != 0 {
		t.Fatal("failed pins created sessions")
	}
}
func TestPlanParserRetainsAmbiguousAndSelfCheckedItems(t *testing.T) {
	items := parsePlanItems("# Plan\n- [x] own done\n- [ ] 별도 승인 후 배포\n  - [ ] nested\n| task | status |\nprose\n```\n- [ ] example\n```\n- [?] unknown\n")
	if len(items) != 9 {
		t.Fatalf("dropped requirements: %+v", items)
	}
	if items[0].Text != "own done" || items[0].Unresolved || !items[1].RequiresApproval {
		t.Fatal(items)
	}
	// Indented checkboxes are conservative unresolved, not independent tasks.
	for _, item := range items[2:] {
		if !item.Unresolved {
			t.Fatalf("ambiguous accepted %+v", item)
		}
	}
	dup := parsePlanItems("- [ ] same\n- [ ] same")
	if dup[0].ID == dup[1].ID {
		t.Fatal("duplicate IDs")
	}
	if len(parsePlanItems("# Title")) != 1 {
		t.Fatal("empty plan vacuous completion")
	}
	approval := parsePlanItems("## 별도 승인 후\n- [ ] deploy\n## Next\n- [ ] restart")
	for _, item := range approval {
		if !item.RequiresApproval {
			t.Fatal("approval scope lost", item)
		}
	}
}
func TestPlanReloadDoesNotRestoreApproval(t *testing.T) {
	e := planTestEngine(t)
	r, err := e.PinPlan("", writePlan(t, e, "plan.md", "- [ ] approval required"))
	if err != nil {
		t.Fatal(err)
	}
	e2, err := New(e.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	loaded, err := e2.LoadSession(r.ID)
	if err != nil || loaded.PinnedPlan == nil || e2.planVerificationEnabled[r.ID] {
		t.Fatal("authority restored", err)
	}
	if _, err = e2.RewindSession(r.ID, 0); err != nil {
		t.Fatal(err)
	}
	if e2.planVerificationEnabled[r.ID] {
		t.Fatal("rewind restored opt-in")
	}
}
func TestPlanPinSaveFailureNotAcknowledged(t *testing.T) {
	e := planTestEngine(t)
	path := writePlan(t, e, "plan.md", "- [ ] work")
	os.Remove(e.opts.SessionDir)
	if _, err := e.PinPlan("", path); err == nil {
		t.Fatal("save failure ignored")
	}
	if len(e.records) != 0 || len(e.planVerificationEnabled) != 0 {
		t.Fatal("published failed write")
	}
}
func TestPlanUnpinSaveFailurePreservesSnapshotAndOptIn(t *testing.T) {
	e := planTestEngine(t)
	r, err := e.PinPlan("", writePlan(t, e, "plan.md", "- [ ] work"))
	if err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(t.TempDir(), "not-directory")
	if err = os.WriteFile(blocker, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	e.opts.SessionDir = blocker
	if _, err = e.UnpinPlan(r.ID); err == nil {
		t.Fatal("unpin save failure ignored")
	}
	if e.records[r.ID].PinnedPlan == nil || !e.planVerificationEnabled[r.ID] {
		t.Fatal("failed unpin changed published state")
	}
}

func TestPlanDeactivatePreservesSnapshotAndReadAPIsPreserveOptIn(t *testing.T) {
	e := planTestEngine(t)
	r, err := e.PinPlan("", writePlan(t, e, "plan.md", "- [ ] work"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.LoadSession(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ExportSession(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = e.ExportSessionJSON(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = e.MessageCount(r.ID); err != nil {
		t.Fatal(err)
	}
	if !e.planVerificationEnabled[r.ID] {
		t.Fatal("read API revoked opt-in")
	}
	if err = e.DeactivatePlan(r.ID); err != nil {
		t.Fatal(err)
	}
	p, err := e.GetPinnedPlan(r.ID)
	if err != nil || p == nil || e.planVerificationEnabled[r.ID] {
		t.Fatal("deactivation changed snapshot", err)
	}
	if _, err = e.LoadSession(r.ID); err != nil || e.planVerificationEnabled[r.ID] {
		t.Fatal("load restored opt-in", err)
	}
}

func TestPlanOperationalRequirementsCannotUseFixtureCompletion(t *testing.T) {
	for _, text := range []string{"서버 배포 완료", "DB 초기화", "키 교체", "운영 주입", "deploy service", "rotate signing key", "database migration", "restart server", "로컬 fixture로 production 배포 검증"} {
		t.Run(text, func(t *testing.T) {
			items := parsePlanItems("- [x] " + text)
			if len(items) != 1 || !items[0].RequiresApproval || !items[0].Unresolved {
				t.Fatal("operational item not fenced", items)
			}
			p := PinnedPlan{SHA256: "plan", Revision: 1, Items: items}
			result := EvaluatePlanStop(p, EvidenceSnapshot{PlanSHA: "plan"}, []ItemVerdict{{ID: items[0].ID, State: "verified_done"}}, &PlanVerificationState{})
			if result.Outcome != "waiting_person" || result.Items[0].State == "verified_done" {
				t.Fatal("fixture elevated operational requirement", result)
			}
		})
	}
	items := parsePlanItems("# Production rollout\n- [ ] apply change\n# Next\n- [ ] validate")
	for _, item := range items {
		if !item.RequiresApproval {
			t.Fatal("operational heading scope lost", item)
		}
	}
	safe := parsePlanItems("- [ ] implement parser\n- [ ] run unit tests")
	for _, item := range safe {
		if item.RequiresApproval || item.Unresolved {
			t.Fatal("ordinary local work blocked", item)
		}
	}
}

func TestPlanParserEvidenceKindRequiresExplicitLocalContract(t *testing.T) {
	cases := []struct {
		name, body string
		fixture    bool
	}{
		{"unchecked", "- [ ] [local-test] parser acceptance passes", true},
		{"self_checked", "- [x] [local-test] parser acceptance passes", true},
		{"ordinary", "- [ ] parser acceptance passes", false},
		{"unknown_operational_language", "- [ ] 고객 환경에 변경 적용", false},
		{"middle_marker", "- [ ] explain [local-test] parser acceptance", false},
		{"quoted_marker", "- [ ] `[local-test]` parser acceptance", false},
		{"case_alias", "- [ ] [LOCAL-TEST] parser acceptance", false},
		{"empty_contract", "- [ ] [local-test]", false},
		{"prefix_alias", "- [ ] [local-test]parser acceptance", false},
		{"prose", "[local-test] parser acceptance", false},
		{"nested", "  - [ ] [local-test] parser acceptance", false},
		{"fenced", "```\n- [ ] [local-test] parser acceptance\n```", false},
		{"approval", "- [ ] [local-test] approval required", false},
		{"operational", "- [ ] [local-test] deploy service", false},
		{"approval_heading", "# Approval required\n- [ ] [local-test] parser acceptance", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items := parsePlanItems(tc.body)
			for _, item := range items {
				if got := item.EvidenceKind == "fixture"; got != tc.fixture {
					t.Fatalf("fixture=%v want %v: %+v", got, tc.fixture, item)
				}
			}
		})
	}
	plain := parsePlanItems("- [ ] parser acceptance passes")[0]
	typed := parsePlanItems("- [ ] [local-test] parser acceptance passes")[0]
	checked := parsePlanItems("- [x] [local-test] parser acceptance passes")[0]
	if plain.ID == typed.ID || typed.ID != checked.ID {
		t.Fatal("acceptance marker must change identity; checkbox must not")
	}
	result := EvaluatePlanStop(PinnedPlan{Revision: 1, Items: []PlanItem{typed}}, EvidenceSnapshot{}, []ItemVerdict{{ID: typed.ID, State: "verified_done"}}, &PlanVerificationState{})
	if result.Items[0].State == "verified_done" {
		t.Fatal("local-test marker or self-check manufactured evidence")
	}
}

func TestPlanPinActiveAndInvalidSessionRejected(t *testing.T) {
	e := planTestEngine(t)
	path := writePlan(t, e, "plan.md", "- [ ] work")
	if _, err := e.PinPlan("missing", path); err == nil {
		t.Fatal("created caller-selected session")
	}
	if _, err := e.PinPlan("../bad", path); err == nil {
		t.Fatal("invalid ID")
	}
	e.active = &turn{}
	if _, err := e.PinPlan("", path); err != ErrTurnInProgress {
		t.Fatal(err)
	}
	if _, err := e.UnpinPlan(""); err != ErrTurnInProgress {
		t.Fatal(err)
	}
	e.active = nil
}
