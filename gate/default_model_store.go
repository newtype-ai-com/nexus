package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/seal"
)

// The operator-set default model credential is persisted only as a sealed
// envelope produced by the deployment's existing sealing facility
// (SEAL_MASTER-derived AES-256-GCM over an Ed25519-signed JWS). These labels
// bind the envelope to this one purpose; they are not secrets.
const (
	defaultModelSealAccount    = "nexus-default-model"
	defaultModelSealDelegation = "default-model"
	defaultModelSealSession    = "v1"
	defaultModelRecordVersion  = 1
)

var ErrDefaultModelStorage = errors.New("gate: default model storage unavailable")

// defaultModelRecord is the sealed payload. It exists in plaintext only in
// memory, transiently, while sealing or opening.
type defaultModelRecord struct {
	V         int       `json:"v"`
	Kind      string    `json:"kind"`
	Upstream  string    `json:"upstream"`
	Key       string    `json:"key"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
	ChangeID  string    `json:"change_id,omitempty"`
}

type sealedDefaultModel struct {
	V      int    `json:"v"`
	Sealed string `json:"sealed"`
}

func sealDefaultModel(ctx context.Context, s *seal.Sealer, rec defaultModelRecord) ([]byte, error) {
	if s == nil || s.Signer == nil || s.Deriver == nil {
		return nil, seal.ErrConfig
	}
	rec.V, rec.Kind = defaultModelRecordVersion, "nexus-default-model"
	payload, err := json.Marshal(rec)
	if err != nil {
		return nil, seal.ErrConfig
	}
	defer wipe(payload)
	out, err := s.Seal(ctx, defaultModelSealAccount, defaultModelSealDelegation, defaultModelSealSession, payload)
	if err != nil {
		return nil, err
	}
	wipe(out.Key)
	return json.Marshal(sealedDefaultModel{V: defaultModelRecordVersion, Sealed: out.Sealed})
}

func openDefaultModel(ctx context.Context, s *seal.Sealer, raw []byte) (defaultModelRecord, error) {
	var env sealedDefaultModel
	if s == nil || s.Signer == nil || s.Deriver == nil {
		return defaultModelRecord{}, seal.ErrConfig
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&env) != nil || env.V != defaultModelRecordVersion || env.Sealed == "" {
		return defaultModelRecord{}, seal.ErrOpen
	}
	key, kid, err := s.Deriver.Derive(ctx, defaultModelSealAccount, seal.Info(defaultModelSealDelegation, defaultModelSealSession))
	if err != nil {
		return defaultModelRecord{}, err
	}
	defer wipe(key)
	jws, header, err := seal.Open(env.Sealed, key)
	if err != nil || header != kid+":"+defaultModelSealDelegation+":"+defaultModelSealSession {
		return defaultModelRecord{}, seal.ErrOpen
	}
	payload, err := seal.Verify(jws, s.Signer.Keys())
	if err != nil {
		return defaultModelRecord{}, seal.ErrOpen
	}
	defer wipe(payload)
	var rec defaultModelRecord
	pd := json.NewDecoder(bytes.NewReader(payload))
	pd.DisallowUnknownFields()
	if pd.Decode(&rec) != nil || rec.V != defaultModelRecordVersion || rec.Kind != "nexus-default-model" || validModelUpstream(rec.Upstream) != nil || !validModelKey(rec.Key) || rec.UpdatedAt.IsZero() || rec.UpdatedBy == "" {
		return defaultModelRecord{}, seal.ErrOpen
	}
	return rec, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// DefaultModelStore persists only the sealed envelope. A confirmed absence is
// os.ErrNotExist; anything else unreadable is an error, never "absent".
type DefaultModelStore interface {
	Load(context.Context) ([]byte, error)
	Save(context.Context, []byte) error
}

// FileDefaultModelStore keeps one sealed file in a pre-created private (0700)
// directory, replaced atomically (temp + fsync + rename + directory fsync).
type FileDefaultModelStore struct{ path string }

func NewFileDefaultModelStore(path string) (*FileDefaultModelStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
		return nil, ErrDefaultModelStorage
	}
	return &FileDefaultModelStore{path: path}, nil
}

func (s *FileDefaultModelStore) dir() error {
	info, err := os.Lstat(filepath.Dir(s.path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ErrDefaultModelStorage
	}
	return nil
}

func (s *FileDefaultModelStore) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.dir() != nil {
		return nil, ErrDefaultModelStorage
	}
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 64<<10 {
		return nil, ErrDefaultModelStorage
	}
	raw, err := os.ReadFile(s.path)
	if err != nil || len(raw) > 64<<10 {
		return nil, ErrDefaultModelStorage
	}
	return raw, nil
}

func (s *FileDefaultModelStore) Save(ctx context.Context, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.dir() != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return ErrDefaultModelStorage
	}
	if info, err := os.Lstat(s.path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o600) {
		return ErrDefaultModelStorage // never overwrite an unsafe existing file
	}
	tmp := s.path + ".pending"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrDefaultModelStorage
	}
	n, werr := f.Write(raw)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || n != len(raw) || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return ErrDefaultModelStorage
	}
	if os.Rename(tmp, s.path) != nil {
		_ = os.Remove(tmp)
		return ErrDefaultModelStorage
	}
	d, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return ErrDefaultModelStorage
	}
	err = d.Sync()
	_ = d.Close()
	if err != nil {
		return ErrDefaultModelStorage
	}
	return nil
}
