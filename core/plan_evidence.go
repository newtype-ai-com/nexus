package core

// V2 evidence is local observation, never authority or semantic completion.
// This file deliberately contains no process execution or model/tool-output adapter.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrEvidenceUnresolved = errors.New("plan evidence unresolved")

// EvidenceRunner is a HOST trust boundary, injected only by the application.
// Never implement it using model arguments, arbitrary shell stdout, or restored
// session JSON. Revision must cover ALL workspace changes (including edit then
// revert) with a monotonic epoch, or identify an immutable execution snapshot.
// A digest alone is NOT a revision. No production runner is provided here.
type EvidenceRunner interface {
	Revision(context.Context, string) (string, error)
	RunGoTest(context.Context, EvidenceRunRequest) (EvidenceRunReceipt, error)
}

type EvidenceOptions struct {
	Runner EvidenceRunner
	// TrackedPaths is a trusted index manifest, not a git command. nil means unknown.
	TrackedPaths   []string
	MaxFiles       int
	MaxFileBytes   int64
	MaxTotalBytes  int64
	MaxOutputBytes int
}

type EvidenceRunRequest struct {
	Workspace, SessionID, PlanSHA, ItemID string
	Argv                                  []string // exact direct argv; only go test -json, no shell
	Kind                                  string   // fixture or operational; never interchangeable
	// Filled by collector, not caller.
	RunID, CodeDigest, Revision string
}

type EvidenceRunReceipt struct {
	// Host-attested actual invocation and complete package inventory, not log claims.
	ArgvDigest, Kind                                   string
	ExpectedPackages                                   []string
	RunID, SessionID, PlanSHA, ItemID, Workspace       string
	StartDigest, EndDigest, StartRevision, EndRevision string
	StartedAt, FinishedAt                              time.Time
	ExitCode                                           int
	Completed, Cancelled, TimedOut, OutputComplete     bool
	GoJSON                                             []byte // transient bounded input, NEVER copied to snapshot
}

type FileEvidence struct {
	Path, Kind, Digest, Tracking, Change string
	Bytes                                int64
}
type EvidenceDiff struct{ Added, Modified, Deleted, Unchanged, Untracked int }
type TestEvidence struct {
	ItemID, RunID, Kind, ArgvDigest, CodeDigest, Revision string
	Passed, Failed, Skipped                               int
	Valid                                                 bool
	Reason                                                string
}
type EvidenceSnapshot struct {
	Workspace, SessionID, PlanSHA, CodeDigest string
	CollectedAt                               time.Time
	Files                                     []FileEvidence
	Diff                                      EvidenceDiff
	Tests                                     []TestEvidence
	// Private live seal: serialization/restoration cannot manufacture valid evidence.
	seal *evidenceSeal
}
type evidenceSeal struct {
	collector                                  *EvidenceCollector
	workspace, session, plan, digest, revision string
	tests                                      map[string]TestEvidence
	publicHash                                 string
}

type EvidenceCollector struct {
	mu       sync.Mutex
	opts     EvidenceOptions
	tracked  map[string]bool
	baseline map[string]map[string]FileEvidence
	tests    map[string]TestEvidence
	sequence uint64
}

func NewEvidenceCollector(o EvidenceOptions) *EvidenceCollector {
	if o.MaxFiles <= 0 {
		o.MaxFiles = 4096
	}
	if o.MaxFiles > 16384 {
		o.MaxFiles = 16384
	}
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = 1 << 20
	}
	if o.MaxFileBytes > 8<<20 {
		o.MaxFileBytes = 8 << 20
	}
	if o.MaxTotalBytes <= 0 {
		o.MaxTotalBytes = 16 << 20
	}
	if o.MaxTotalBytes > 64<<20 {
		o.MaxTotalBytes = 64 << 20
	}
	if o.MaxOutputBytes <= 0 {
		o.MaxOutputBytes = 4 << 20
	}
	if o.MaxOutputBytes > 8<<20 {
		o.MaxOutputBytes = 8 << 20
	}
	c := &EvidenceCollector{opts: o, baseline: make(map[string]map[string]FileEvidence), tests: make(map[string]TestEvidence)}
	if o.TrackedPaths != nil {
		c.tracked = make(map[string]bool)
		for _, p := range o.TrackedPaths {
			if evidencePathSafe(p) {
				c.tracked[filepath.ToSlash(p)] = true
			}
		}
	}
	return c
}

func evidenceSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func evidenceSHAValid(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func evidenceKey(w, s, p string) string { return w + "\x00" + s + "\x00" + p }
func evidenceBinding(w, s, p string) (string, error) {
	if s == "" || len(s) > 256 || strings.ContainsAny(s, "\x00\r\n") || !evidenceSHAValid(p) {
		return "", ErrEvidenceUnresolved
	}
	w, e := filepath.Abs(w)
	if e != nil {
		return "", ErrEvidenceUnresolved
	}
	w, e = filepath.EvalSymlinks(w)
	if e != nil {
		return "", ErrEvidenceUnresolved
	}
	return w, nil
}
func evidencePathSafe(p string) bool {
	if p == "" || filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\\\r\n") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		s := strings.ToLower(part)
		if s == ".." || s == "." || strings.HasPrefix(s, ".") || strings.Contains(s, "credential") || strings.Contains(s, "secret") || strings.Contains(s, "password") || strings.Contains(s, "key") || strings.Contains(s, "token") || s == "node_modules" || s == "vendor" || s == "artifacts" || s == "artifact" || s == "dist" || s == "build" || s == "backup" || s == "backups" {
			return false
		}
	}
	return true
}
func evidenceSource(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".go", ".py", ".swift", ".rs", ".c", ".h", ".cpp", ".ts", ".tsx", ".js", ".sh", ".md", ".mod", ".sum":
		return true
	}
	return false
}
func evidenceSensitive(b []byte) bool {
	upper := bytes.ToUpper(b)
	for _, x := range []string{"PRIVATE KEY", "SECRET://", "API_KEY", "APIKEY", "PASSWORD", "BEARER ", "CREDENTIAL", "ACCESS_TOKEN", "AWS_SECRET", "CONNECTION_STRING"} {
		if bytes.Contains(upper, []byte(x)) {
			return true
		}
	}
	return bytes.IndexByte(b, 0) >= 0
}

// scan hashes only bounded, regular, source-like files. It never emits contents,
// ignored paths, secret digests, raw errors, subprocess output or external diffs.
// os.Root enforces containment even when a symlink is raced between checks.
func (c *EvidenceCollector) scan(ctx context.Context, w string) ([]FileEvidence, string, error) {
	root, e := os.OpenRoot(w)
	if e != nil {
		return nil, "", ErrEvidenceUnresolved
	}
	defer root.Close()
	var files []FileEvidence
	count := 0
	var total int64
	var walk func(string) error
	walk = func(dir string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f, e := openEvidenceFile(root, dir)
		if e != nil {
			return ErrEvidenceUnresolved
		}
		entries, e := f.ReadDir(c.opts.MaxFiles + 1)
		f.Close()
		if e != nil && e != io.EOF {
			return ErrEvidenceUnresolved
		}
		count += len(entries)
		if count > c.opts.MaxFiles {
			return ErrEvidenceUnresolved
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, ent := range entries {
			p := ent.Name()
			if dir != "." {
				p = dir + "/" + p
			}
			if !evidencePathSafe(p) {
				continue
			}
			info, e := root.Lstat(p)
			if e != nil {
				return ErrEvidenceUnresolved
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if info.IsDir() {
				if e = walk(p); e != nil {
					return e
				}
				continue
			}
			if !info.Mode().IsRegular() || !evidenceSource(p) {
				continue
			}
			if info.Size() > c.opts.MaxFileBytes {
				return ErrEvidenceUnresolved
			}
			in, e := openEvidenceFile(root, p)
			if e != nil {
				return ErrEvidenceUnresolved
			}
			opened, e := in.Stat()
			if e != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
				in.Close()
				return ErrEvidenceUnresolved
			}
			b, e := io.ReadAll(io.LimitReader(in, c.opts.MaxFileBytes+1))
			after, se := in.Stat()
			in.Close()
			total += int64(len(b))
			if e != nil || se != nil || int64(len(b)) > c.opts.MaxFileBytes || total > c.opts.MaxTotalBytes || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
				return ErrEvidenceUnresolved
			}
			if evidenceSensitive(b) {
				continue
			}
			tracking := "unknown"
			if c.tracked != nil {
				tracking = "untracked"
				if c.tracked[p] {
					tracking = "tracked"
				}
			}
			files = append(files, FileEvidence{Path: p, Kind: "regular", Digest: evidenceSHA(b), Tracking: tracking, Bytes: int64(len(b))})
		}
		return nil
	}
	if e = walk("."); e != nil {
		return nil, "", e
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	b, _ := json.Marshal(files)
	return files, evidenceSHA(b), nil
}

func (c *EvidenceCollector) Collect(ctx context.Context, workspace, sessionID, planSHA string) (EvidenceSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, e := evidenceBinding(workspace, sessionID, planSHA)
	if e != nil {
		return EvidenceSnapshot{}, e
	}
	rev := ""
	if c.opts.Runner != nil {
		rev, e = c.opts.Runner.Revision(ctx, w)
		if e != nil {
			return EvidenceSnapshot{}, ErrEvidenceUnresolved
		}
	}
	files, digest, e := c.scan(ctx, w)
	if e != nil {
		return EvidenceSnapshot{}, e
	}
	if c.opts.Runner != nil {
		after, err := c.opts.Runner.Revision(ctx, w)
		if err != nil || rev != after {
			return EvidenceSnapshot{}, ErrEvidenceUnresolved
		}
	}
	key := evidenceKey(w, sessionID, planSHA)
	base, exists := c.baseline[key]
	if !exists {
		if len(c.baseline) >= 64 {
			return EvidenceSnapshot{}, ErrEvidenceUnresolved
		}
		base = make(map[string]FileEvidence)
		for _, f := range files {
			base[f.Path] = f
		}
		c.baseline[key] = base
	}
	snap := EvidenceSnapshot{Workspace: w, SessionID: sessionID, PlanSHA: planSHA, CodeDigest: digest, CollectedAt: time.Now().UTC()}
	seen := make(map[string]bool)
	for _, f := range files {
		seen[f.Path] = true
		old, ok := base[f.Path]
		snap.Diff.Untracked += boolInt(f.Tracking == "untracked")
		switch {
		case !ok:
			f.Change = "added"
			snap.Diff.Added++
		case old.Digest != f.Digest:
			f.Change = "modified"
			snap.Diff.Modified++
		default:
			f.Change = "unchanged"
			snap.Diff.Unchanged++
		}
		snap.Files = append(snap.Files, f)
	}
	for p, f := range base {
		if !seen[p] {
			// Filtered/secret/symlink files are not proof of deletion.
			if _, statErr := os.Lstat(filepath.Join(w, p)); !os.IsNotExist(statErr) {
				continue
			}
			f.Change = "deleted"
			f.Kind = "absent"
			f.Digest = ""
			f.Bytes = 0
			snap.Files = append(snap.Files, f)
			snap.Diff.Deleted++
		}
	}
	sort.Slice(snap.Files, func(i, j int) bool { return snap.Files[i].Path < snap.Files[j].Path })
	seal := &evidenceSeal{collector: c, workspace: w, session: sessionID, plan: planSHA, digest: digest, revision: rev, tests: make(map[string]TestEvidence)}
	for k, t := range c.tests {
		if strings.HasPrefix(k, key+"\x00") {
			if t.CodeDigest != digest || t.Revision != rev {
				t.Valid = false
				t.Reason = "stale_code"
			}
			snap.Tests = append(snap.Tests, t)
			seal.tests[t.ItemID] = t
		}
	}
	sort.Slice(snap.Tests, func(i, j int) bool { return snap.Tests[i].ItemID < snap.Tests[j].ItemID })
	snap.seal = seal
	encoded, _ := json.Marshal(snap)
	seal.publicHash = evidenceSHA(encoded)
	return snap, nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ValidFor means current, authenticated fixture test evidence, NOT semantic done.
// A model/verifier cannot override false. Operational evidence must be requested
// explicitly through ValidForKind; fixture PASS cannot establish deployment.
func (s EvidenceSnapshot) ValidFor(itemID string) bool { return s.ValidForKind(itemID, "fixture") }
func (s EvidenceSnapshot) ValidForKind(itemID, kind string) bool {
	z := s.seal
	if z == nil || s.Workspace != z.workspace || s.SessionID != z.session || s.PlanSHA != z.plan || s.CodeDigest != z.digest {
		return false
	}
	encoded, err := json.Marshal(s)
	if err != nil || evidenceSHA(encoded) != z.publicHash {
		return false
	}
	c := z.collector
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := z.tests[itemID]
	if !ok || !t.Valid || t.Kind != kind || c.opts.Runner == nil {
		return false
	}
	latest, ok := c.tests[evidenceKey(z.workspace, z.session, z.plan)+"\x00"+itemID]
	if !ok || latest.RunID != t.RunID || !latest.Valid {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rev, e := c.opts.Runner.Revision(ctx, z.workspace)
	if e != nil || rev == "" || rev != z.revision {
		return false
	}
	_, digest, e := c.scan(ctx, z.workspace)
	if e != nil || digest != z.digest {
		return false
	}
	rev2, e := c.opts.Runner.Revision(ctx, z.workspace)
	return e == nil && rev2 == rev
}

func evidenceGoArgv(a []string) bool {
	if len(a) < 4 || a[0] != "go" || a[1] != "test" || a[2] != "-json" {
		return false
	}
	packages := 0
	uncached := false
	for _, s := range a[3:] {
		if s == "-count=1" {
			uncached = true
			continue
		}
		if s == "-race" {
			continue
		}
		// No -run subset, -exec, -toolexec, shell, environment or output paths.
		if s != "." && s != "./..." && (!strings.HasPrefix(s, "./") || strings.Contains(s, "..") || strings.ContainsAny(s, " ;|&$`\\\r\n\t")) {
			return false
		}
		packages++
	}
	return packages > 0 && uncached
}

// RunGoTest only calls the configured host runner; absence fails closed. It
// computes its own code bindings, ignores caller supplied RunID/digest/revision,
// and replaces earlier successful evidence even if this attempt fails.
func (c *EvidenceCollector) RunGoTest(ctx context.Context, req EvidenceRunRequest) (TestEvidence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, e := evidenceBinding(req.Workspace, req.SessionID, req.PlanSHA)
	if e != nil {
		return TestEvidence{}, e
	}
	if req.ItemID == "" || len(req.ItemID) > 256 || strings.ContainsAny(req.ItemID, "\x00\r\n") {
		return TestEvidence{}, ErrEvidenceUnresolved
	}
	key := evidenceKey(w, req.SessionID, req.PlanSHA) + "\x00" + req.ItemID
	delete(c.tests, key)
	if len(c.tests) >= 4096 {
		return TestEvidence{}, ErrEvidenceUnresolved
	}
	if c.opts.Runner == nil || !evidenceGoArgv(req.Argv) || (req.Kind != "fixture" && req.Kind != "operational") {
		return TestEvidence{}, ErrEvidenceUnresolved
	}
	req.Argv = append([]string(nil), req.Argv...)
	req.Workspace = w
	rev, e := c.opts.Runner.Revision(ctx, w)
	if e != nil || rev == "" {
		return TestEvidence{}, ErrEvidenceUnresolved
	}
	_, digest, e := c.scan(ctx, w)
	if e != nil {
		return TestEvidence{}, e
	}
	readyRevision, readyErr := c.opts.Runner.Revision(ctx, w)
	if readyErr != nil || readyRevision != rev || ctx.Err() != nil {
		return TestEvidence{}, ErrEvidenceUnresolved
	}
	c.sequence++
	req.RunID = fmt.Sprintf("evidence-%d", c.sequence)
	req.CodeDigest = digest
	req.Revision = rev
	argv, _ := json.Marshal(req.Argv)
	t := TestEvidence{ItemID: req.ItemID, RunID: req.RunID, Kind: req.Kind, ArgvDigest: evidenceSHA(argv), CodeDigest: digest, Revision: rev, Reason: "runner_unresolved"}
	start := time.Now()
	r, runErr := c.opts.Runner.RunGoTest(ctx, req)
	end := time.Now()
	after, revErr := c.opts.Runner.Revision(ctx, w)
	_, endDigest, scanErr := c.scan(ctx, w)
	valid := runErr == nil && ctx.Err() == nil && revErr == nil && scanErr == nil &&
		after == rev && endDigest == digest && r.ArgvDigest == t.ArgvDigest && r.Kind == req.Kind &&
		r.RunID == req.RunID && r.SessionID == req.SessionID && r.PlanSHA == req.PlanSHA &&
		r.ItemID == req.ItemID && r.Workspace == w && r.StartDigest == digest && r.EndDigest == digest &&
		r.StartRevision == rev && r.EndRevision == rev && !r.StartedAt.Before(start) &&
		!r.FinishedAt.Before(r.StartedAt) && !r.FinishedAt.After(end) &&
		r.Completed && !r.Cancelled && !r.TimedOut && r.ExitCode == 0 && r.OutputComplete
	if valid {
		t.Passed, t.Failed, t.Skipped, e = parseEvidenceGoJSON(r.GoJSON, c.opts.MaxOutputBytes, r.ExpectedPackages...)
		if len(r.ExpectedPackages) == 0 {
			e = ErrEvidenceUnresolved
		}
		valid = e == nil && t.Passed > 0 && t.Failed == 0 && t.Skipped == 0
		t.Reason = "invalid_go_test_results"
	}
	t.Valid = valid
	if valid {
		t.Reason = "trusted_go_test_pass"
	}
	c.tests[key] = t
	if !valid {
		return t, ErrEvidenceUnresolved
	}
	return t, nil
}

// Go output text is discarded. Only lifecycle events from a trusted direct
// runner count. Every started suite/test must terminate; SKIP is never PASS.
func parseEvidenceGoJSON(data []byte, limit int, expected ...string) (passed, failed, skipped int, err error) {
	if len(data) == 0 || len(data) > limit {
		return 0, 0, 0, ErrEvidenceUnresolved
	}
	type state struct{ started, terminal bool }
	suites := map[string]state{}
	tests := map[string]state{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), min(limit, 256<<10))
	for scanner.Scan() {
		var ev struct{ Action, Package, Test string }
		if json.Unmarshal(scanner.Bytes(), &ev) != nil || ev.Package == "" {
			return passed, failed, skipped, ErrEvidenceUnresolved
		}
		if len(ev.Package) > 1024 || len(ev.Test) > 2048 {
			return passed, failed, skipped, ErrEvidenceUnresolved
		}
		suite := suites[ev.Package]
		key := ev.Package + "\x00" + ev.Test
		test := tests[key]
		switch ev.Action {
		case "start":
			if ev.Test != "" || suite.started {
				return passed, failed, skipped, ErrEvidenceUnresolved
			}
			suite.started = true
			suites[ev.Package] = suite
		case "run":
			if !suite.started || suite.terminal || ev.Test == "" || test.started {
				return passed, failed, skipped, ErrEvidenceUnresolved
			}
			test.started = true
			tests[key] = test
		case "pass", "fail", "skip":
			if !suite.started || suite.terminal {
				return passed, failed, skipped, ErrEvidenceUnresolved
			}
			if ev.Test == "" {
				suite.terminal = true
				suites[ev.Package] = suite
			} else {
				if !test.started || test.terminal {
					return passed, failed, skipped, ErrEvidenceUnresolved
				}
				test.terminal = true
				tests[key] = test
			}
			if ev.Action == "fail" {
				failed++
			}
			if ev.Action == "skip" {
				skipped++
			}
			if ev.Action == "pass" && ev.Test != "" {
				passed++
			}
		case "output", "pause", "cont":
			if !suite.started || suite.terminal || (ev.Test != "" && !test.started) {
				return passed, failed, skipped, ErrEvidenceUnresolved
			}
		default:
			return passed, failed, skipped, ErrEvidenceUnresolved
		}
	}
	if scanner.Err() != nil || len(suites) == 0 || len(tests) == 0 {
		return passed, failed, skipped, ErrEvidenceUnresolved
	}
	if len(expected) > 0 {
		if len(expected) != len(suites) {
			return passed, failed, skipped, ErrEvidenceUnresolved
		}
		seen := make(map[string]bool)
		for _, p := range expected {
			if _, ok := suites[p]; !ok || seen[p] {
				return passed, failed, skipped, ErrEvidenceUnresolved
			}
			seen[p] = true
		}
	}
	for _, s := range suites {
		if !s.terminal {
			return passed, failed, skipped, ErrEvidenceUnresolved
		}
	}
	for _, s := range tests {
		if !s.terminal {
			return passed, failed, skipped, ErrEvidenceUnresolved
		}
	}
	return passed, failed, skipped, nil
}
