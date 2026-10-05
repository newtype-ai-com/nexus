package gate

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrChangeInvalid  = errors.New("gate: invalid change request")
	ErrChangeNotFound = errors.New("gate: change not found")
	ErrChangeConflict = errors.New("gate: change conflict")
	ErrChangeStorage  = errors.New("gate: change storage unavailable")
	ErrChangeLimit    = errors.New("gate: change mail limit reached")
)

type ChangeInput struct {
	Requester  string `json:"requester"`
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	Manifest   string `json:"manifest"`
	BaseState  string `json:"base_state"`
	Impact     string `json:"impact"`
	Cost       string `json:"cost"`
	Recovery   string `json:"recovery"`
	ClientID   string `json:"client_id"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}
type ChangeApproval struct {
	ChangeInput
	ID         string    `json:"id"`
	Digest     string    `json:"digest"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Status     string    `json:"status"`
	DecidedAt  time.Time `json:"decided_at,omitempty"`
	DecidedIP  string    `json:"decided_ip,omitempty"`
	DecidedUA  string    `json:"decided_ua,omitempty"`
	ConsumedAt time.Time `json:"consumed_at,omitempty"`
	Result     string    `json:"result,omitempty"`
}

// Link verifier and delivery bookkeeping are never part of a public response.
type changeRecord struct {
	Change       ChangeApproval `json:"change"`
	ApprovalHash string         `json:"approval_hash"`
	Delivered    bool           `json:"delivered"`
}
type ChangeStore interface {
	Begin(ChangeInput, time.Time) (ChangeApproval, string, error)
	Delivery(string, bool) error
	Get(string, time.Time) (ChangeApproval, error)
	ByLink(string, string, time.Time) (ChangeApproval, error)
	Decide(string, string, string, bool, string, string, time.Time) (ChangeApproval, error)
	Consume(string, string, time.Time) (ChangeApproval, error)
	Result(string, string, time.Time) (ChangeApproval, error)
}

// FileChangeStore is an append-only, fsynced journal owned by one process. A
// failed write poisons the instance; do not retry until an operator recovers it.
// This is not a defense against the filesystem owner or an execution gate.
type FileChangeStore struct {
	mu       sync.Mutex
	file     *os.File
	records  map[string]changeRecord
	clients  map[string]string
	max      int
	poisoned bool
}

func OpenFileChangeStore(path string, maxRequests int) (*FileChangeStore, error) {
	if !filepath.IsAbs(path) || maxRequests < 1 || maxRequests > 10000 {
		return nil, ErrChangeInvalid
	}
	// Require a private pre-created directory and reject symlink ancestors.
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrChangeStorage
		}
		if p == filepath.Dir(path) && info.Mode().Perm() != 0700 {
			return nil, ErrChangeStorage
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	f, err := openChangeJournal(path)
	if err != nil {
		return nil, ErrChangeStorage
	}
	fail := func() (*FileChangeStore, error) { f.Close(); return nil, ErrChangeStorage }
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 64<<20 {
		return fail()
	}
	if err = lockChangeJournal(f); err != nil {
		return fail()
	}
	s := &FileChangeStore{file: f, records: map[string]changeRecord{}, clients: map[string]string{}, max: maxRequests}
	r := bufio.NewReader(f)
	for {
		line, e := r.ReadBytes('\n')
		if e == io.EOF && len(line) == 0 {
			break
		}
		if e != nil || len(line) > 128<<10 {
			return fail()
		} // torn tail is never silently truncated
		var rec changeRecord
		if json.Unmarshal(line, &rec) != nil || !validChangeRecord(rec) {
			return fail()
		}
		key := rec.Change.Requester + "\x00" + rec.Change.ClientID
		if prev, ok := s.records[rec.Change.ID]; ok {
			if prev.Change.ChangeInput != rec.Change.ChangeInput || prev.ApprovalHash != rec.ApprovalHash || prev.Change.Digest != rec.Change.Digest || !prev.Change.CreatedAt.Equal(rec.Change.CreatedAt) || !prev.Change.ExpiresAt.Equal(rec.Change.ExpiresAt) {
				return fail()
			}
		}
		if id, ok := s.clients[key]; ok && id != rec.Change.ID {
			return fail()
		}
		s.records[rec.Change.ID] = rec
		s.clients[key] = rec.Change.ID
	}
	// Ensure creation metadata is durable too, not just file contents.
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return fail()
	}
	e = dir.Sync()
	dir.Close()
	if e != nil {
		return fail()
	}
	// An interrupted delivery has unknown mail outcome: never resend/approve it.
	for _, rec := range s.records {
		if rec.Change.Status == "pending" && !rec.Delivered {
			rec.Change.Status = "failed"
			if s.append(rec) != nil {
				return fail()
			}
		}
	}
	return s, nil
}
func validChangeRecord(r changeRecord) bool {
	a := r.Change
	if validateChangeInput(a.ChangeInput) != nil || len(a.ID) != 68 || !strings.HasPrefix(a.ID, "car_") || a.Digest != changeDigest(a.Manifest) || len(r.ApprovalHash) != 64 || a.CreatedAt.IsZero() || !a.ExpiresAt.After(a.CreatedAt) {
		return false
	}
	switch a.Status {
	case "pending", "approved", "denied", "failed", "consumed":
		return true
	}
	return false
}
func validateChangeInput(in ChangeInput) error {
	switch in.Kind {
	case "db_login", "deploy", "dns", "key", "mcp_connect", "mcp_approval":
	default:
		return ErrChangeInvalid
	}
	if in.TTLSeconds < 0 || in.TTLSeconds > 86400 {
		return ErrChangeInvalid
	}
	for _, v := range []string{in.Requester, in.Target, in.Manifest, in.BaseState, in.Impact, in.Cost, in.Recovery, in.ClientID} {
		if strings.TrimSpace(v) == "" || len(v) > 16384 || strings.ContainsRune(v, 0) {
			return ErrChangeInvalid
		}
	}
	if len(in.ClientID) > 128 || len(in.Requester) > 254 {
		return ErrChangeInvalid
	}
	return nil
}
func changeDigest(v string) string { s := sha256.Sum256([]byte(v)); return hex.EncodeToString(s[:]) }
func (s *FileChangeStore) append(rec changeRecord) error {
	if s.poisoned || s.file == nil {
		return ErrChangeStorage
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return ErrChangeStorage
	}
	raw = append(raw, '\n')
	n, err := s.file.Write(raw)
	if err != nil || n != len(raw) {
		s.poisoned = true
		return ErrChangeStorage
	}
	if s.file.Sync() != nil {
		s.poisoned = true
		return ErrChangeStorage
	}
	s.records[rec.Change.ID] = rec
	s.clients[rec.Change.Requester+"\x00"+rec.Change.ClientID] = rec.Change.ID
	return nil
}
func (s *FileChangeStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	if err != nil {
		return ErrChangeStorage
	}
	return nil
}
func (s *FileChangeStore) Begin(in ChangeInput, now time.Time) (ChangeApproval, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if validateChangeInput(in) != nil || now.IsZero() {
		return ChangeApproval{}, "", ErrChangeInvalid
	}
	if in.TTLSeconds == 0 {
		in.TTLSeconds = 1800
	}
	if s.poisoned || s.file == nil {
		return ChangeApproval{}, "", ErrChangeStorage
	}
	if id, ok := s.clients[in.Requester+"\x00"+in.ClientID]; ok {
		r := s.records[id]
		if r.Change.ChangeInput != in {
			return ChangeApproval{}, "", ErrChangeConflict
		}
		return visibleChange(r, now), "", nil
	}
	// Lifetime cap survives restart. Failed deliveries consume a slot as well.
	if len(s.records) >= s.max {
		return ChangeApproval{}, "", ErrChangeLimit
	}
	id, e1 := randomToken("car_")
	token, e2 := randomToken("cap_")
	if e1 != nil || e2 != nil {
		return ChangeApproval{}, "", ErrChangeStorage
	}
	rec := changeRecord{Change: ChangeApproval{ChangeInput: in, ID: id, Digest: changeDigest(in.Manifest), CreatedAt: now.UTC(), ExpiresAt: now.Add(time.Duration(in.TTLSeconds) * time.Second).UTC(), Status: "pending"}, ApprovalHash: Verifier(token)}
	if s.append(rec) != nil {
		return ChangeApproval{}, "", ErrChangeStorage
	}
	return rec.Change, token, nil
}
func visibleChange(r changeRecord, now time.Time) ChangeApproval {
	a := r.Change
	if (a.Status == "pending" || a.Status == "approved") && !now.Before(a.ExpiresAt) {
		a.Status = "expired"
	}
	return a
}
func (s *FileChangeStore) get(id string) (changeRecord, error) {
	if s.file == nil || s.poisoned {
		return changeRecord{}, ErrChangeStorage
	}
	r, ok := s.records[id]
	if !ok {
		return r, ErrChangeNotFound
	}
	return r, nil
}
func (s *FileChangeStore) Delivery(id string, success bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.get(id)
	if e != nil {
		return e
	}
	if r.Change.Status != "pending" || r.Delivered {
		return ErrChangeConflict
	}
	r.Delivered = success
	if !success {
		r.Change.Status = "failed"
	}
	return s.append(r)
}
func (s *FileChangeStore) Get(id string, now time.Time) (ChangeApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.get(id)
	return visibleChange(r, now), e
}
func (s *FileChangeStore) link(id, token string) (changeRecord, error) {
	r, e := s.get(id)
	if e != nil {
		return r, e
	}
	if len(token) != 68 || !r.Delivered || subtle.ConstantTimeCompare([]byte(r.ApprovalHash), []byte(Verifier(token))) != 1 {
		return changeRecord{}, ErrChangeNotFound
	}
	return r, nil
}
func (s *FileChangeStore) ByLink(id, token string, now time.Time) (ChangeApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.link(id, token)
	return visibleChange(r, now), e
}
func (s *FileChangeStore) Decide(id, token, digest string, approve bool, ip, ua string, now time.Time) (ChangeApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.link(id, token)
	if e != nil {
		return ChangeApproval{}, e
	}
	if r.Change.Status != "pending" || !now.Before(r.Change.ExpiresAt) || digest != r.Change.Digest {
		return ChangeApproval{}, ErrChangeConflict
	}
	r.Change.Status = "denied"
	if approve {
		r.Change.Status = "approved"
	}
	r.Change.DecidedAt = now.UTC()
	r.Change.DecidedIP = safeChangeIP(ip)
	r.Change.DecidedUA = "sha256:" + changeDigest(ua)
	if s.append(r) != nil {
		return ChangeApproval{}, ErrChangeStorage
	}
	return r.Change, nil
}
func (s *FileChangeStore) Consume(id, manifest string, now time.Time) (ChangeApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.get(id)
	if e != nil {
		return ChangeApproval{}, e
	}
	if r.Change.Status != "approved" || !now.Before(r.Change.ExpiresAt) || changeDigest(manifest) != r.Change.Digest {
		return ChangeApproval{}, ErrChangeConflict
	}
	r.Change.Status = "consumed"
	r.Change.ConsumedAt = now.UTC()
	if s.append(r) != nil {
		return ChangeApproval{}, ErrChangeStorage
	}
	return r.Change, nil
}
func (s *FileChangeStore) Result(id, result string, now time.Time) (ChangeApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.get(id)
	if e != nil {
		return ChangeApproval{}, e
	}
	if r.Change.Status != "consumed" || r.Change.Result != "" || (result != "succeeded" && result != "failed" && result != "unknown") {
		return ChangeApproval{}, ErrChangeConflict
	}
	r.Change.Result = result
	if s.append(r) != nil {
		return ChangeApproval{}, ErrChangeStorage
	}
	return r.Change, nil
}
