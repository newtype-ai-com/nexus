package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// ModelCallBudgetHeader is operator-provisioned, not an approval. One ledger
// must be shared by all handlers in a rollout and retained across restarts.
// Filesystem administrators can roll back this file: this is not a tamper-proof
// billing ledger and cannot enforce a USD limit.
type ModelCallBudgetHeader struct {
	Version   int       `json:"version"`
	Rollout   string    `json:"rollout"`
	MaxCalls  int64     `json:"max_calls"`
	ExpiresAt time.Time `json:"expires_at"`
}

var errModelCallBudget = errors.New("gate: model call budget unavailable or exhausted")

func validModelCallBudgetHeader(h ModelCallBudgetHeader) bool {
	return h.Version == 1 && regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$`).MatchString(h.Rollout) && h.MaxCalls > 0 && h.MaxCalls <= 100000 && !h.ExpiresAt.IsZero()
}

// InitializeModelCallBudget creates a new private ledger exclusively. Never use
// it to replace/reset a live ledger. Provisioning it is a separate operator act.
func InitializeModelCallBudget(path string, h ModelCallBudgetHeader) error {
	if !validModelCallBudgetHeader(h) || !time.Now().Before(h.ExpiresAt) {
		return errModelCallBudget
	}
	f, err := createModelCallBudgetFile(path)
	if err != nil {
		return errModelCallBudget
	}
	defer f.Close()
	raw, _ := json.Marshal(h)
	raw = append(raw, '\n')
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		return errModelCallBudget
	}
	if f.Sync() != nil {
		return errModelCallBudget
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errModelCallBudget
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errModelCallBudget
	}
	return nil
}

// ModelCallBudgetStatus is a locked local snapshot, not proof that a running
// server uses this file, nor authorization to dispatch a model request.
type ModelCallBudgetStatus struct {
	Header    ModelCallBudgetHeader `json:"header"`
	Used      int64                 `json:"used"`
	Remaining int64                 `json:"remaining"`
	Expired   bool                  `json:"expired"`
}

// InspectModelCallBudget opens an existing ledger read-only and never consumes,
// repairs or creates it. A valid expired/exhausted ledger remains inspectable.
func InspectModelCallBudget(path string) (ModelCallBudgetStatus, error) {
	f, unlock, err := openReadOnlyModelCallBudget(path)
	if err != nil {
		return ModelCallBudgetStatus{}, errModelCallBudget
	}
	defer f.Close()
	defer unlock()
	return readModelCallBudget(f, time.Now())
}

func readModelCallBudget(f io.Reader, now time.Time) (ModelCallBudgetStatus, error) {
	invalid := ModelCallBudgetStatus{}
	// Bounded parser, including malformed operator-provided files.
	raw, err := io.ReadAll(io.LimitReader(f, 2<<20))
	if err != nil || len(raw) == 0 || len(raw) >= 2<<20 || raw[len(raw)-1] != '\n' {
		return invalid, errModelCallBudget
	}
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	var h ModelCallBudgetHeader
	dec := json.NewDecoder(bytes.NewReader(lines[0]))
	dec.DisallowUnknownFields()
	if dec.Decode(&h) != nil || dec.Decode(new(any)) != io.EOF || !validModelCallBudgetHeader(h) {
		return invalid, errModelCallBudget
	}
	// Require canonical header: rejects duplicates/alternate ambiguous encodings.
	canonical, _ := json.Marshal(h)
	if !bytes.Equal(canonical, lines[0]) {
		return invalid, errModelCallBudget
	}
	used := int64(len(lines) - 1)
	if used > h.MaxCalls {
		return invalid, errModelCallBudget
	}
	for i, line := range lines[1:] {
		if string(line) != strconv.Itoa(i+1) {
			return invalid, errModelCallBudget
		}
	}
	return ModelCallBudgetStatus{Header: h, Used: used, Remaining: h.MaxCalls - used, Expired: !now.Before(h.ExpiresAt)}, nil
}

func checkModelCallBudget(path string, consume bool) error {
	f, unlock, err := openLockedModelCallBudget(path)
	if err != nil {
		return errModelCallBudget
	}
	defer f.Close()
	defer unlock()
	return consumeModelCallBudget(f, consume, time.Now())
}

// Keep I/O failures testable without replacing process-global filesystem hooks.
// The caller holds the exclusive ledger lock throughout validation and syncing.
type modelCallBudgetIO interface {
	io.Reader
	io.Seeker
	io.Writer
	Sync() error
}

func consumeModelCallBudget(f modelCallBudgetIO, consume bool, now time.Time) error {
	status, err := readModelCallBudget(f, now)
	if err != nil || status.Expired {
		return errModelCallBudget
	}
	if !consume {
		return nil
	}
	if status.Remaining == 0 {
		return errModelCallBudget
	}
	// A failed write/fsync is never refunded. Partial records fail closed next time.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return errModelCallBudget
	}
	record := []byte(fmt.Sprintf("%d\n", status.Used+1))
	if n, err := f.Write(record); err != nil || n != len(record) {
		return errModelCallBudget
	}
	if f.Sync() != nil {
		return errModelCallBudget
	}
	return nil
}
