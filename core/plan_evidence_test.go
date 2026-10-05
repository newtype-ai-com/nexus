//go:build darwin || linux

package core

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const evidenceGoodJSON = `{"Action":"start","Package":"example/p"}
{"Action":"run","Package":"example/p","Test":"TestOne"}
{"Action":"output","Package":"example/p","Test":"TestOne","Output":"PASS is data"}
{"Action":"pass","Package":"example/p","Test":"TestOne"}
{"Action":"pass","Package":"example/p"}
`

type syntheticEvidenceRunner struct {
	epoch  string
	calls  int
	mutate func(EvidenceRunRequest, *EvidenceRunReceipt)
}

func (r *syntheticEvidenceRunner) Revision(context.Context, string) (string, error) {
	return r.epoch, nil
}
func (r *syntheticEvidenceRunner) RunGoTest(ctx context.Context, q EvidenceRunRequest) (EvidenceRunReceipt, error) {
	r.calls++
	argv, _ := json.Marshal(q.Argv)
	out := EvidenceRunReceipt{ArgvDigest: evidenceSHA(argv), Kind: q.Kind, ExpectedPackages: []string{"example/p"}, RunID: q.RunID, SessionID: q.SessionID, PlanSHA: q.PlanSHA, ItemID: q.ItemID, Workspace: q.Workspace, StartDigest: q.CodeDigest, EndDigest: q.CodeDigest, StartRevision: q.Revision, EndRevision: q.Revision, StartedAt: time.Now(), Completed: true, OutputComplete: true, GoJSON: []byte(evidenceGoodJSON)}
	if r.mutate != nil {
		r.mutate(q, &out)
	}
	out.FinishedAt = time.Now()
	return out, nil
}
func evidenceFixture(t *testing.T) (*EvidenceCollector, *syntheticEvidenceRunner, EvidenceRunRequest) {
	t.Helper()
	w := t.TempDir()
	evidenceWrite(t, w, "main.go", "package example\n")
	r := &syntheticEvidenceRunner{epoch: "immutable-1"}
	c := NewEvidenceCollector(EvidenceOptions{Runner: r, TrackedPaths: []string{"main.go"}})
	q := EvidenceRunRequest{Workspace: w, SessionID: "session-one", PlanSHA: evidenceSHA([]byte("plan")), ItemID: "item-one", Kind: "fixture", Argv: []string{"go", "test", "-json", "-count=1", "./..."}}
	return c, r, q
}
func evidenceWrite(t *testing.T, w, p, content string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(filepath.Join(w, p)), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(w, p), []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
}
func evidenceCollect(t *testing.T, c *EvidenceCollector, q EvidenceRunRequest) EvidenceSnapshot {
	t.Helper()
	s, e := c.Collect(context.Background(), q.Workspace, q.SessionID, q.PlanSHA)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func evidenceRun(t *testing.T, c *EvidenceCollector, q EvidenceRunRequest) {
	t.Helper()
	if _, e := c.RunGoTest(context.Background(), q); e != nil {
		t.Fatal(e)
	}
}

func TestPlanEvidenceTrustedReceiptAndIsolation(t *testing.T) {
	c, _, q := evidenceFixture(t)
	evidenceRun(t, c, q)
	s := evidenceCollect(t, c, q)
	if !s.ValidFor(q.ItemID) || s.ValidFor("other") || s.ValidForKind(q.ItemID, "operational") {
		t.Fatal("item/kind binding")
	}
	q.SessionID = "another"
	if evidenceCollect(t, c, q).ValidFor(q.ItemID) {
		t.Fatal("foreign session")
	}
	q.SessionID = "session-one"
	q.PlanSHA = evidenceSHA([]byte("another"))
	if evidenceCollect(t, c, q).ValidFor(q.ItemID) {
		t.Fatal("foreign revision")
	}
}
func TestPlanEvidenceRejectsSelfReportedDone(t *testing.T) {
	c, _, q := evidenceFixture(t)
	s := evidenceCollect(t, c, q)
	s.Tests = []TestEvidence{{ItemID: q.ItemID, Valid: true, Passed: 999}}
	if s.ValidFor(q.ItemID) {
		t.Fatal("claimed PASS")
	}
	evidenceRun(t, c, q)
	s = evidenceCollect(t, c, q)
	b, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	var restored EvidenceSnapshot
	if e = json.Unmarshal(b, &restored); e != nil {
		t.Fatal(e)
	}
	if restored.ValidFor(q.ItemID) {
		t.Fatal("restored seal")
	}
	s.SessionID = "another"
	if s.ValidFor(q.ItemID) {
		t.Fatal("tampered binding")
	}
}
func TestPlanEvidenceRejectsEchoPass(t *testing.T) {
	for _, output := range []string{"PASS\n", `{"Action":"pass","Package":"p"}`, "", strings.ReplaceAll(evidenceGoodJSON, `"Action":"pass"`, `"Action":"output"`)} {
		t.Run(evidenceSHA([]byte(output))[:8], func(t *testing.T) {
			c, r, q := evidenceFixture(t)
			r.mutate = func(_ EvidenceRunRequest, o *EvidenceRunReceipt) { o.GoJSON = []byte(output) }
			if _, e := c.RunGoTest(context.Background(), q); e == nil {
				t.Fatal("invalid output accepted")
			}
		})
	}
	c, r, q := evidenceFixture(t)
	q.Argv = []string{"sh", "-c", "echo PASS"}
	if _, e := c.RunGoTest(context.Background(), q); e == nil || r.calls != 0 {
		t.Fatal("shell called")
	}
}
func TestPlanEvidenceSkipIsNotPass(t *testing.T) {
	c, r, q := evidenceFixture(t)
	r.mutate = func(_ EvidenceRunRequest, o *EvidenceRunReceipt) {
		o.GoJSON = []byte(strings.Replace(evidenceGoodJSON, `"Action":"pass","Package":"example/p","Test"`, `"Action":"skip","Package":"example/p","Test"`, 1))
	}
	got, e := c.RunGoTest(context.Background(), q)
	if e == nil || got.Skipped != 1 || evidenceCollect(t, c, q).ValidFor(q.ItemID) {
		t.Fatal("skip treated as PASS")
	}
}
func TestPlanEvidenceRejectsEditsDuringRun(t *testing.T) {
	for _, revert := range []bool{false, true} {
		t.Run(map[bool]string{false: "edit", true: "edit_revert"}[revert], func(t *testing.T) {
			c, r, q := evidenceFixture(t)
			r.mutate = func(_ EvidenceRunRequest, _ *EvidenceRunReceipt) {
				evidenceWrite(t, q.Workspace, "main.go", "package edited\n")
				if revert {
					evidenceWrite(t, q.Workspace, "main.go", "package example\n")
					r.epoch = "immutable-2"
				}
			}
			if _, e := c.RunGoTest(context.Background(), q); e == nil {
				t.Fatal("edit passed")
			}
		})
	}
}
func TestPlanEvidenceInvalidatedByEdit(t *testing.T) {
	c, r, q := evidenceFixture(t)
	evidenceRun(t, c, q)
	s := evidenceCollect(t, c, q)
	evidenceWrite(t, q.Workspace, "main.go", "package edited\n")
	if s.ValidFor(q.ItemID) {
		t.Fatal("old PASS")
	}
	evidenceWrite(t, q.Workspace, "main.go", "package example\n")
	r.epoch = "immutable-2"
	if s.ValidFor(q.ItemID) {
		t.Fatal("edit/revert PASS")
	}
}
func TestPlanEvidenceIncludesUntrackedFiles(t *testing.T) {
	c, _, q := evidenceFixture(t)
	s := evidenceCollect(t, c, q)
	if len(s.Files) != 1 || s.Files[0].Tracking != "tracked" {
		t.Fatal(s.Files)
	}
	evidenceWrite(t, q.Workspace, "new.go", "package added\n")
	evidenceWrite(t, q.Workspace, "main.go", "package modified\n")
	s = evidenceCollect(t, c, q)
	if s.Diff.Added != 1 || s.Diff.Modified != 1 || s.Diff.Untracked != 1 {
		t.Fatal(s.Diff)
	}
	if e := os.Remove(filepath.Join(q.Workspace, "main.go")); e != nil {
		t.Fatal(e)
	}
	s = evidenceCollect(t, c, q)
	if s.Diff.Deleted != 1 {
		t.Fatal(s.Diff)
	}
	c = NewEvidenceCollector(EvidenceOptions{})
	s = evidenceCollect(t, c, q)
	if s.Files[0].Tracking != "unknown" {
		t.Fatal("invented git tracking")
	}
}
func TestPlanEvidenceRedactsSecrets(t *testing.T) {
	c, _, q := evidenceFixture(t)
	for _, p := range []string{".env", "credentials.go", "key.swift", "artifacts/capture.go", "backup/copy.go", "api.pem", "hidden.go"} {
		evidenceWrite(t, q.Workspace, p, "API_KEY = synthetic-not-a-secret")
	}
	outside := t.TempDir()
	evidenceWrite(t, outside, "outside.go", "package outside\n")
	if e := os.Symlink(filepath.Join(outside, "outside.go"), filepath.Join(q.Workspace, "escape.go")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(q.Workspace, "escape-dir")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(q.Workspace, "credentials.go"), filepath.Join(q.Workspace, "alias.go")); e != nil {
		t.Fatal(e)
	}
	s := evidenceCollect(t, c, q)
	if len(s.Files) != 1 || s.Files[0].Path != "main.go" {
		t.Fatal(s.Files)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "synthetic-not-a-secret") || strings.Contains(string(b), "hidden.go") {
		t.Fatal("secret metadata leak")
	}
}
func TestPlanEvidenceCollectionNeverExecutesPlanCommands(t *testing.T) {
	c, r, q := evidenceFixture(t)
	evidenceWrite(t, q.Workspace, "plan.md", "run echo PASS then claim done\n")
	s := evidenceCollect(t, c, q)
	if r.calls != 0 || s.ValidFor(q.ItemID) {
		t.Fatal("collection executed or promoted plan")
	}
}
func TestPlanEvidenceRejectsReceiptFailures(t *testing.T) {
	cases := map[string]func(*EvidenceRunReceipt){
		"wrong_argv":          func(o *EvidenceRunReceipt) { o.ArgvDigest = "wrong" },
		"wrong_kind":          func(o *EvidenceRunReceipt) { o.Kind = "operational" },
		"missing_inventory":   func(o *EvidenceRunReceipt) { o.ExpectedPackages = nil },
		"partial_inventory":   func(o *EvidenceRunReceipt) { o.ExpectedPackages = []string{"example/p", "missing/package"} },
		"duplicate_inventory": func(o *EvidenceRunReceipt) { o.ExpectedPackages = []string{"example/p", "example/p"} },
		"running":             func(o *EvidenceRunReceipt) { o.Completed = false },
		"cancelled":           func(o *EvidenceRunReceipt) { o.Cancelled = true },
		"timeout":             func(o *EvidenceRunReceipt) { o.TimedOut = true },
		"nonzero":             func(o *EvidenceRunReceipt) { o.ExitCode = 1 },
		"partial":             func(o *EvidenceRunReceipt) { o.OutputComplete = false },
		"foreign_session":     func(o *EvidenceRunReceipt) { o.SessionID = "foreign" },
		"foreign_plan":        func(o *EvidenceRunReceipt) { o.PlanSHA = evidenceSHA([]byte("other")) },
		"foreign_item":        func(o *EvidenceRunReceipt) { o.ItemID = "foreign" },
		"foreign_run":         func(o *EvidenceRunReceipt) { o.RunID = "foreign" },
		"foreign_workspace":   func(o *EvidenceRunReceipt) { o.Workspace = "foreign" },
		"start_digest":        func(o *EvidenceRunReceipt) { o.StartDigest = "foreign" },
		"end_digest":          func(o *EvidenceRunReceipt) { o.EndDigest = "foreign" },
		"start_epoch":         func(o *EvidenceRunReceipt) { o.StartRevision = "foreign" },
		"end_epoch":           func(o *EvidenceRunReceipt) { o.EndRevision = "foreign" },
		"old_time":            func(o *EvidenceRunReceipt) { o.StartedAt = time.Time{} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, r, q := evidenceFixture(t)
			evidenceRun(t, c, q)
			s := evidenceCollect(t, c, q)
			r.mutate = func(_ EvidenceRunRequest, o *EvidenceRunReceipt) { change(o) }
			if _, e := c.RunGoTest(context.Background(), q); e == nil {
				t.Fatal("bad receipt")
			}
			if s.ValidFor(q.ItemID) {
				t.Fatal("old success survived failed run")
			}
		})
	}
}
func TestPlanEvidenceGoJSONMalformedLifecycle(t *testing.T) {
	for name, data := range map[string]string{
		"partial_suite":      strings.TrimSuffix(evidenceGoodJSON, "{\"Action\":\"pass\",\"Package\":\"example/p\"}\n"),
		"partial_test":       strings.Replace(evidenceGoodJSON, "{\"Action\":\"pass\",\"Package\":\"example/p\",\"Test\":\"TestOne\"}\n", "", 1),
		"duplicate":          evidenceGoodJSON + "{\"Action\":\"pass\",\"Package\":\"example/p\"}\n",
		"bad_json":           evidenceGoodJSON + "oops\n",
		"empty_tests":        "{\"Action\":\"start\",\"Package\":\"p\"}\n{\"Action\":\"pass\",\"Package\":\"p\"}\n",
		"test_without_start": "{\"Action\":\"run\",\"Package\":\"p\",\"Test\":\"T\"}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, e := parseEvidenceGoJSON([]byte(data), 4096); e == nil {
				t.Fatal("malformed accepted")
			}
		})
	}
}
func TestPlanEvidenceBoundsAndNoRunner(t *testing.T) {
	c, _, q := evidenceFixture(t)
	c = NewEvidenceCollector(EvidenceOptions{})
	if _, e := c.RunGoTest(context.Background(), q); e == nil {
		t.Fatal("no runner")
	}
	for name, opts := range map[string]EvidenceOptions{"file": {MaxFileBytes: 2}, "total": {MaxTotalBytes: 2}, "count": {MaxFiles: 1}} {
		t.Run(name, func(t *testing.T) {
			evidenceWrite(t, q.Workspace, "second.go", "package p\n")
			c := NewEvidenceCollector(opts)
			if _, e := c.Collect(context.Background(), q.Workspace, q.SessionID, q.PlanSHA); e == nil {
				t.Fatal("limit ignored")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.Collect(ctx, q.Workspace, q.SessionID, q.PlanSHA); e == nil {
		t.Fatal("cancel ignored")
	}
	if _, _, _, e := parseEvidenceGoJSON([]byte(evidenceGoodJSON), 2); e == nil {
		t.Fatal("output bound")
	}
	q.PlanSHA = "not-a-sha"
	if _, e := c.Collect(context.Background(), q.Workspace, q.SessionID, q.PlanSHA); e == nil {
		t.Fatal("invalid plan")
	}
}
func TestPlanEvidenceArgvSubsetAndShellRejected(t *testing.T) {
	for _, a := range [][]string{{"go", "test", "-json", "-run=TestOne", "."}, {"go", "test", "-json", "-exec=echo", "."}, {"go", "test", "-json", "../outside"}, {"go", "test", "-json", "./a;echo PASS"}, {"go", "test", "-json", "-toolexec=echo", "."}} {
		if evidenceGoArgv(a) {
			t.Fatal(a)
		}
	}
}
func TestPlanEvidenceRejectsHardlinkAlias(t *testing.T) {
	c, _, q := evidenceFixture(t)
	evidenceWrite(t, q.Workspace, ".env", "synthetic fixture only")
	if err := os.Link(filepath.Join(q.Workspace, ".env"), filepath.Join(q.Workspace, "alias.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Collect(context.Background(), q.Workspace, q.SessionID, q.PlanSHA); err == nil {
		t.Fatal("hardlink content read")
	}
}

func TestPlanEvidenceNativeGoJSONAdapter(t *testing.T) {
	// Disposable module only. Parser conformance, NOT a production runner.
	w := t.TempDir()
	evidenceWrite(t, w, "go.mod", "module evidencefixture\n\ngo 1.24\n")
	evidenceWrite(t, w, "main_test.go", `package evidencefixture
import "testing"
func TestOne(t *testing.T) { t.Run("nested",func(t *testing.T){t.Parallel()}) }
`)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-json", "-count=1", ".")
	cmd.Dir = w
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=")
	data, err := cmd.Output()
	if err != nil {
		t.Fatal("disposable go test failed", err)
	}
	p, f, s, err := parseEvidenceGoJSON(data, 1<<20, "evidencefixture")
	if err != nil || p != 2 || f != 0 || s != 0 {
		t.Fatalf("adapter p=%d f=%d s=%d err=%v", p, f, s, err)
	}
}

func TestPlanEvidenceRejectsPublicSnapshotTampering(t *testing.T) {
	c, _, q := evidenceFixture(t)
	evidenceRun(t, c, q)
	s := evidenceCollect(t, c, q)
	s.Files[0].Digest = "forged"
	if s.ValidFor(q.ItemID) {
		t.Fatal("modified file evidence")
	}
	s = evidenceCollect(t, c, q)
	s.Tests[0].Passed = 999
	if s.ValidFor(q.ItemID) {
		t.Fatal("modified test evidence")
	}
}

func TestPlanEvidenceRejectsCachedRun(t *testing.T) {
	c, r, q := evidenceFixture(t)
	q.Argv = []string{"go", "test", "-json", "./..."}
	if _, err := c.RunGoTest(context.Background(), q); err == nil || r.calls != 0 {
		t.Fatal("cached test allowed")
	}
}

func TestPlanEvidenceRejectsEmptyEpoch(t *testing.T) {
	c, r, q := evidenceFixture(t)
	r.epoch = ""
	if _, err := c.RunGoTest(context.Background(), q); err == nil || r.calls != 0 {
		t.Fatal("untracked runner called")
	}
}

func TestPlanEvidenceCallerBindingsCannotReplaceCollectorBindings(t *testing.T) {
	c, r, q := evidenceFixture(t)
	q.RunID = "caller-forged-run"
	q.CodeDigest = evidenceSHA([]byte("caller-forged-code"))
	q.Revision = "caller-forged-revision"
	expectedDigest := evidenceCollect(t, c, q).CodeDigest
	r.mutate = func(actual EvidenceRunRequest, _ *EvidenceRunReceipt) {
		if actual.RunID != "evidence-1" || actual.CodeDigest != expectedDigest || actual.Revision != r.epoch {
			t.Fatal("caller controlled host bindings")
		}
	}
	evidenceRun(t, c, q)
	if r.calls != 1 || !evidenceCollect(t, c, q).ValidFor(q.ItemID) {
		t.Fatal("collector-owned fixture bindings rejected")
	}
}

func TestPlanEvidenceRunnerRemovalInvalidatesExistingSeal(t *testing.T) {
	c, _, q := evidenceFixture(t)
	evidenceRun(t, c, q)
	s := evidenceCollect(t, c, q)
	if !s.ValidFor(q.ItemID) {
		t.Fatal("fixture evidence missing")
	}
	// Synthetic host configuration change, not an approval/revocation adapter.
	c.mu.Lock()
	c.opts.Runner = nil
	c.mu.Unlock()
	if s.ValidFor(q.ItemID) {
		t.Fatal("removed runner left an authoritative-looking seal")
	}
	if _, err := c.RunGoTest(context.Background(), q); err == nil {
		t.Fatal("missing host runner accepted a new run")
	}
	if evidenceCollect(t, c, q).ValidFor(q.ItemID) {
		t.Fatal("collection manufactured evidence without a runner")
	}
}

func TestPlanEvidenceConcurrentCollection(t *testing.T) {
	c, _, q := evidenceFixture(t)
	evidenceRun(t, c, q)
	s := evidenceCollect(t, c, q)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !s.ValidFor(q.ItemID) {
				t.Error("concurrent validity")
			}
			if _, e := c.Collect(context.Background(), q.Workspace, q.SessionID, q.PlanSHA); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
}
