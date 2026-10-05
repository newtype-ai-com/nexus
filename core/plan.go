package core

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/redact"
)

const maxPlanBytes = 128 * 1024

// PinnedPlan is a human-selected immutable requirement snapshot, not an
// approval, a tool capability, or evidence that any requirement was completed.
// Source records provenance only; deserializing it never enables verification.
type PinnedPlan struct {
	Path     string     `json:"path"`
	SHA256   string     `json:"sha256"`
	Snapshot string     `json:"snapshot"`
	Revision int        `json:"revision"`
	Source   string     `json:"source"`
	Items    []PlanItem `json:"items"`
}

type PlanItem struct {
	ID   string `json:"id"`
	Line int    `json:"line"`
	Text string `json:"text"`
	// EvidenceKind is human-selected acceptance scope, not execution authority.
	// Unknown requirements cannot be completed by local fixture evidence.
	EvidenceKind     string `json:"evidence_kind,omitempty"`
	RequiresApproval bool   `json:"requires_approval,omitempty"`
	Unresolved       bool   `json:"unresolved,omitempty"`
}

// PinPlan is a local person-facing API. It is deliberately absent from the
// model tool registry. The caller must authenticate the user, not document text.
// An empty session ID creates only a local conversation, never a remote root.
func (e *Engine) PinPlan(sessionID, path string) (SessionRecord, error) {
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
	p, err := readPinnedPlan(e.opts.WorkDir, path)
	if err != nil {
		return SessionRecord{}, err
	}
	if r.PinnedPlan != nil {
		r.PlanHistory = append(r.PlanHistory, *r.PinnedPlan)
	}
	r.PlanRevision++
	p.Revision = r.PlanRevision
	r.PinnedPlan = p
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

// UnpinPlan retains the old snapshot for audit, but removes the current opt-in.
func (e *Engine) UnpinPlan(sessionID string) (SessionRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return SessionRecord{}, ErrClosed
	}
	if e.active != nil || e.maintenanceDone != nil {
		return SessionRecord{}, ErrTurnInProgress
	}
	if sessionID == "" {
		return SessionRecord{}, nil
	}
	r, err := e.loadRecord(sessionID)
	if err != nil {
		return SessionRecord{}, err
	}
	if r.PinnedPlan != nil {
		r.PlanHistory = append(r.PlanHistory, *r.PinnedPlan)
		r.PinnedPlan = nil
		r.UpdatedAt = time.Now().UTC()
		if err = e.storeRecord(r); err != nil {
			return SessionRecord{}, err
		}
	}
	delete(e.planVerificationEnabled, sessionID)
	return cloneRecord(r), nil
}

// GetPinnedPlan returns a detached snapshot, without reading the source file or
// activating verification. Changes to the original file require an explicit pin.
func (e *Engine) GetPinnedPlan(sessionID string) (*PinnedPlan, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrClosed
	}
	if sessionID == "" {
		return nil, nil
	}
	r, err := e.loadRecord(sessionID)
	if err != nil {
		return nil, err
	}
	return r.PinnedPlan, nil
}

// DeactivatePlan drops only the in-memory opt-in when the person switches
// conversations. It does not read/write storage or change the pinned snapshot.
func (e *Engine) DeactivatePlan(sessionID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	if e.active != nil || e.maintenanceDone != nil {
		return ErrTurnInProgress
	}
	delete(e.planVerificationEnabled, sessionID)
	return nil
}

func planSecretPath(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		part = strings.ToLower(part)
		if strings.HasPrefix(part, ".") || strings.Contains(part, "credential") || strings.Contains(part, "secret") || strings.HasPrefix(part, "id_rsa") || strings.HasPrefix(part, "id_ed25519") || strings.HasSuffix(part, ".pem") || strings.HasSuffix(part, ".key") || strings.HasSuffix(part, ".p12") || strings.HasSuffix(part, ".pfx") {
			return true
		}
	}
	return false
}

func readPinnedPlan(workDir, path string) (*PinnedPlan, error) {
	names, err := NormalizeActiveFiles(workDir, []string{path})
	if err != nil {
		return nil, errors.New("invalid plan path")
	}
	path = names[0]
	for _, r := range path {
		if unicode.IsControl(r) {
			return nil, errors.New("invalid plan path")
		}
	}
	if _, count := redact.Text(path); count != 0 {
		return nil, errors.New("invalid plan path")
	}
	if planSecretPath(path) {
		return nil, errors.New("plan path may contain credentials")
	}
	if strings.ToLower(filepath.Ext(path)) != ".md" {
		return nil, errors.New("plan must be a Markdown (.md) document")
	}
	// Pin directory descriptors and reject symlinks at every component. Root
	// confinement alone would still permit an in-workspace alias to a secret.
	root, err := os.OpenRoot(workDir)
	if err != nil {
		return nil, errors.New("cannot open plan workspace")
	}
	defer func() { root.Close() }()
	parts := strings.Split(filepath.FromSlash(path), string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		before, statErr := root.Lstat(part)
		if statErr != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("plan directory must not be a symlink")
		}
		next, openErr := root.OpenRoot(part)
		if openErr != nil {
			return nil, errors.New("cannot open plan directory")
		}
		after, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(before, after) {
			next.Close()
			return nil, errors.New("plan directory changed while opening")
		}
		root.Close()
		root = next
	}
	name := parts[len(parts)-1]
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxPlanBytes {
		return nil, errors.New("plan must be a bounded regular file, not a symlink")
	}
	f, err := openPlanFile(root, name)
	if err != nil {
		return nil, errors.New("cannot open plan file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, errors.New("plan file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxPlanBytes+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || len(raw) > maxPlanBytes || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, errors.New("plan file is oversized or changed while reading")
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("plan must be UTF-8")
	}
	text := string(raw)
	for _, r := range text {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return nil, errors.New("plan contains control characters")
		}
	}
	if _, count := redact.Text(text); count != 0 {
		return nil, errors.New("plan contains recognizable secrets; remove them before pinning")
	}
	sum := sha256.Sum256(raw)
	return &PinnedPlan{Path: path, SHA256: fmt.Sprintf("%x", sum), Snapshot: text, Source: "human", Items: parsePlanItems(text)}, nil
}

var planCheckbox = regexp.MustCompile(`^[-*+] \[[ xX]\] (.+)$`)
var planApproval = regexp.MustCompile(`(?i)(승인|암호|비밀번호|사람.*입력|approval|approve|password|credential|human input|owner input)`)

// Conservative operational boundary, not a semantic classifier or permission
// grant. Even a local fixture mentioning these targets cannot certify live work.
var planOperational = regexp.MustCompile(`(?i)(운영|배포|서버|데이터베이스|키|자격|인증서|방화벽|포트|터널|실모델|실행환경|재기동|재시작|주입|복구|production|operational|deploy|server|database|\bdb\b|postgres|mysql|sqlite|\bsql\b|migration|key|credential|certificate|firewall|\bport\b|tunnel|\bssh\b|\bkubectl\b|\bterraform\b|restart|reboot|restore|custody|live model)`)

func planNeedsApproval(text string) bool {
	return planApproval.MatchString(text) || planOperational.MatchString(text)
}

// Only simple top-level checkboxes are actionable. Prose, tables, nested lists,
// code and malformed checkboxes are retained as unresolved instead of omitted.
// A checked box is a self-report, never a verified_done state.
func parsePlanItems(text string) []PlanItem {
	var items []PlanItem
	occurrences := map[string]int{}
	fenced := false
	fence := ""
	approvalScope := false
	add := func(line int, text string, unresolved bool) {
		occurrences[text]++
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", text, occurrences[text])))
		item := PlanItem{ID: fmt.Sprintf("pi_%x", sum[:16]), Line: line, Text: text, RequiresApproval: approvalScope || planNeedsApproval(text), Unresolved: unresolved || planOperational.MatchString(text), EvidenceKind: "unknown"}
		// A literal prefix on an unambiguous human checkbox narrows acceptance
		// to a local test. It never certifies the broader semantic requirement.
		const marker = "[local-test] "
		if !item.Unresolved && !item.RequiresApproval && strings.HasPrefix(text, marker) && strings.TrimSpace(strings.TrimPrefix(text, marker)) != "" {
			item.EvidenceKind = "fixture"
		}
		items = append(items, item)
	}
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			marker := trimmed[:3]
			if !fenced {
				fenced = true
				fence = marker
			} else if marker == fence {
				fenced = false
			}
			add(i+1, trimmed, true)
			continue
		}
		if !fenced && strings.HasPrefix(trimmed, "#") {
			// Headings are context, except approval boundaries which cannot be lost.
			// Conservatively retain an approval boundary for all subsequent items.
			// Parsing a later heading cannot certify that an earlier dependency ended.
			approvalScope = approvalScope || planNeedsApproval(trimmed)
			if planNeedsApproval(trimmed) {
				add(i+1, trimmed, true)
			}
			continue
		}
		if match := planCheckbox.FindStringSubmatch(raw); !fenced && match != nil {
			itemText := strings.TrimSpace(match[1])
			add(i+1, itemText, itemText == "")
		} else {
			add(i+1, trimmed, true)
		}
	}
	if len(items) == 0 {
		add(1, "No unambiguous plan requirements", true)
	}
	return items
}
