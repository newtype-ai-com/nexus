package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/seal"
)

// DefaultModelConfig wires the operator surface for the server default model.
//
// Only the account owner, authenticated as a person with licence + login (no
// session, delegation, agent or executor credential), may read the status or
// request a change. A change is never applied on the owner's request alone:
// it goes through the owner email change-approval facility (Approvals) and is
// applied only after that exact, digest-bound change was approved by mail.
type DefaultModelConfig struct {
	Model      *ModelHandler
	Service    *nexus.Service
	Store      CredentialStore // the same (owner-filtered) store the server authenticates with
	OwnerEmail string
	// Optional: without all three, status is readable but changes are refused.
	Sealer    *seal.Sealer
	Storage   DefaultModelStore
	Approvals ChangeApprovals
	Audit     *Audit
	Clock     func() time.Time
}

type pendingDefaultModel struct {
	approvalID string
	manifest   string
	sealed     []byte // sealed candidate; plaintext key is never kept
	host       string
	protocol   string
	expires    time.Time
}

type DefaultModelOperator struct {
	cfg     DefaultModelConfig
	mux     *http.ServeMux
	mu      sync.Mutex // serializes begin/apply and guards pending
	pending map[string]pendingDefaultModel
}

const maxPendingDefaultModel = 8

// NewDefaultModelOperator also applies a stored operator value, which takes
// precedence over the environment bootstrap value. A stored value that cannot
// be opened is an error: falling back silently could resurrect a retired key.
func NewDefaultModelOperator(ctx context.Context, cfg DefaultModelConfig) (*DefaultModelOperator, error) {
	cfg.OwnerEmail = strings.ToLower(strings.TrimSpace(cfg.OwnerEmail))
	if cfg.Model == nil || cfg.Service == nil || cfg.Store == nil || !validEmail(cfg.OwnerEmail) || strings.Contains(cfg.OwnerEmail, "*") {
		return nil, errors.New("gate: invalid default model operator configuration")
	}
	if cfg.Storage != nil && cfg.Sealer == nil {
		return nil, errors.New("gate: default model storage requires sealing")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	o := &DefaultModelOperator{cfg: cfg, mux: http.NewServeMux(), pending: map[string]pendingDefaultModel{}}
	if cfg.Storage != nil {
		raw, err := cfg.Storage.Load(ctx)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, ErrDefaultModelStorage
		default:
			rec, err := openDefaultModel(ctx, cfg.Sealer, raw)
			if err != nil {
				return nil, errors.New("gate: stored default model cannot be opened")
			}
			if cfg.Model.SwapUpstream(rec.Upstream, rec.Key, "operator", rec.UpdatedAt, rec.UpdatedBy) != nil {
				return nil, errors.New("gate: stored default model is invalid")
			}
		}
	}
	o.mux.HandleFunc("GET /v1/operator/default-model", o.status)
	o.mux.HandleFunc("PUT /v1/operator/default-model", o.begin)
	o.mux.HandleFunc("POST /v1/operator/default-model", o.begin)
	o.mux.HandleFunc("POST /v1/operator/default-model/changes/{id}/apply", o.apply)
	return o, nil
}

func (o *DefaultModelOperator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	o.mux.ServeHTTP(w, r.WithContext(ctx))
}

// owner admits exactly the configured owner as a person. The principal comes
// from the live Nexus authenticator; the licence is then looked up again so a
// login alone (or a session/agent/executor token) can never stand in for it.
func (o *DefaultModelOperator) owner(w http.ResponseWriter, r *http.Request) (nexus.Principal, bool) {
	if r.Header.Get("X-Newtype-Session") != "" || len(r.Header.Values("X-Newtype-Session")) != 0 {
		o.refused(r, nexus.Principal{}, "session_refused")
		gateError(w, 403, "owner_person_required")
		return nexus.Principal{}, false
	}
	token := bearer(r)
	if token == "" || strings.HasPrefix(token, "nta_") || strings.HasPrefix(token, nexus.ExecutorTokenPrefix) {
		gateError(w, 401, "unauthenticated")
		return nexus.Principal{}, false
	}
	p, err := NexusAuth{Store: o.cfg.Store, Service: o.cfg.Service, Clock: o.cfg.Clock}.Authenticate(r)
	if err != nil {
		gateError(w, 401, "unauthenticated")
		return nexus.Principal{}, false
	}
	lic, err := o.cfg.Store.LookupCredential(r.Context(), Verifier(token))
	if p.Kind != nexus.PrincipalUser || p.CredentialID != "" || p.SessionID != "" || !SameEmail(p.Email, o.cfg.OwnerEmail) ||
		err != nil || lic.Kind != "licence" || lic.Revoked || !o.cfg.Clock().Before(lic.Expires) || !SameEmail(lic.Email, o.cfg.OwnerEmail) || lic.Account != p.AccountID {
		o.refused(r, p, "not_owner")
		gateError(w, 403, "forbidden")
		return nexus.Principal{}, false
	}
	return p, true
}

func (o *DefaultModelOperator) audit(kind, request string, p nexus.Principal, outcome string) {
	if o.cfg.Audit != nil {
		o.cfg.Audit.Write(AuditEvent{Type: kind, RequestID: request, Established: AuditEstablished{AccountID: string(p.AccountID), Email: p.Email, SessionID: string(p.SessionID), Outcome: outcome}})
	}
}
func (o *DefaultModelOperator) refused(r *http.Request, p nexus.Principal, outcome string) {
	o.audit("default_model.refused", "", p, outcome)
}

// DefaultModelStatus is the only view of the configuration. It never carries
// the key or any derivative of it (no prefix, suffix, length or hash).
type DefaultModelStatus struct {
	EndpointHost    string    `json:"endpoint_host"`
	Protocol        string    `json:"protocol"`
	Models          []string  `json:"models"`
	Source          string    `json:"source"`
	Key             string    `json:"key"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
	UpdatedBy       string    `json:"updated_by,omitempty"`
	ChangeAvailable bool      `json:"change_available"`
	ApprovalBy      string    `json:"approval,omitempty"`
}

func (o *DefaultModelOperator) Status() DefaultModelStatus { return o.statusLocked() }

// statusLocked reads only the atomic snapshot; it needs no lock.
func (o *DefaultModelOperator) statusLocked() DefaultModelStatus {
	up := o.cfg.Model.up.Load()
	host := ""
	if u, err := url.Parse(up.upstream); err == nil {
		host = u.Hostname()
	}
	st := DefaultModelStatus{EndpointHost: host, Protocol: up.protocol(), Models: append([]string(nil), o.cfg.Model.cfg.Models...), Source: up.source, Key: "set", UpdatedBy: up.updatedBy, ChangeAvailable: o.changeAvailable()}
	if !up.updatedAt.IsZero() {
		st.UpdatedAt = up.updatedAt
	}
	if st.ChangeAvailable {
		st.ApprovalBy = "owner_email"
	}
	return st
}
func (o *DefaultModelOperator) changeAvailable() bool {
	return o.cfg.Sealer != nil && o.cfg.Storage != nil && o.cfg.Approvals != nil
}

func (o *DefaultModelOperator) status(w http.ResponseWriter, r *http.Request) {
	if _, ok := o.owner(w, r); !ok {
		return
	}
	gateJSON(w, 200, o.Status())
}

type defaultModelChangeRequest struct {
	Endpoint string `json:"endpoint"`
	Protocol string `json:"protocol,omitempty"`
	Key      string `json:"key"`
}

// DefaultModelChange is the response to a change request or apply.
type DefaultModelChange struct {
	ChangeID     string              `json:"change_id"`
	Status       string              `json:"status"` // pending_approval, applied
	EndpointHost string              `json:"endpoint_host"`
	Protocol     string              `json:"protocol"`
	ExpiresAt    time.Time           `json:"expires_at,omitempty"`
	Current      *DefaultModelStatus `json:"current,omitempty"`
}

func (o *DefaultModelOperator) begin(w http.ResponseWriter, r *http.Request) {
	p, ok := o.owner(w, r)
	if !ok {
		return
	}
	if !o.changeAvailable() {
		gateError(w, 503, "operator_change_unavailable")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	defer wipe(raw)
	var in defaultModelChangeRequest
	if err == nil {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			err = nexus.ErrInvalid
		}
	}
	if err != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	protocol := in.Protocol
	if protocol == "" {
		protocol = o.cfg.Model.Protocol()
	}
	upstream, err := FoundryModelEndpoint(in.Endpoint, protocol)
	if err != nil || validModelUpstream(upstream) != nil {
		gateError(w, 400, "invalid_endpoint")
		return
	}
	if !validModelKey(in.Key) {
		gateError(w, 400, "invalid_key")
		return
	}
	u, _ := url.Parse(upstream)
	host := u.Hostname()
	id, err := randomToken("dmc_")
	if err != nil {
		gateError(w, 503, "unavailable")
		return
	}
	id = id[:4+32] // short enough for a path; 128 bits of randomness
	sealed, err := sealDefaultModel(r.Context(), o.cfg.Sealer, defaultModelRecord{Upstream: upstream, Key: in.Key, UpdatedAt: o.cfg.Clock().UTC(), UpdatedBy: o.cfg.OwnerEmail, ChangeID: id})
	if err != nil {
		gateError(w, 503, "sealing_unavailable")
		return
	}
	digest := sha256.Sum256(sealed)
	cur := o.Status()
	manifest := fmt.Sprintf("change: nexus default model upstream\nchange_id: %s\nendpoint_host: %s\nprotocol: %s\nmodels: %s\nkey: replaced (not shown)\nsealed_candidate_sha256: %s\nrequested_by: %s", id, host, protocol, strings.Join(cur.Models, ","), hex.EncodeToString(digest[:]), o.cfg.OwnerEmail)
	in2 := ChangeInput{
		Requester: o.cfg.OwnerEmail, Kind: "key", Target: "nexus default model (" + host + ")", Manifest: manifest,
		BaseState: fmt.Sprintf("source=%s endpoint_host=%s protocol=%s", cur.Source, cur.EndpointHost, cur.Protocol),
		Impact:    "모든 사용자의 기본 모델 호출이 새 엔드포인트/키로 전환됩니다. 진행 중 호출은 이전 값으로 끝납니다. 예산·모델·한도는 바뀌지 않습니다.",
		Cost:      "새 키의 Azure 요금이 적용됩니다.",
		Recovery:  "이전 엔드포인트와 키로 다시 변경 요청하거나, 저장 파일을 지우고 재시작하면 환경 변수 값으로 돌아갑니다.",
		ClientID:  id, TTLSeconds: 1800,
	}
	// Defense in depth: the approval manifest must never carry the key.
	if blob, _ := json.Marshal(in2); strings.Contains(string(blob), in.Key) {
		gateError(w, 400, "invalid_key")
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.cfg.Clock()
	for k, v := range o.pending {
		if !now.Before(v.expires) {
			delete(o.pending, k)
		}
	}
	if len(o.pending) >= maxPendingDefaultModel {
		gateError(w, 429, "rate_limited")
		return
	}
	a, err := o.cfg.Approvals.Begin(r.Context(), in2)
	if err != nil {
		o.audit("default_model.change_request_failed", id, p, "approval_unavailable")
		if errors.Is(err, ErrChangeLimit) {
			gateError(w, 429, "mail_limit")
			return
		}
		gateError(w, 502, "approval_unavailable")
		return
	}
	o.pending[id] = pendingDefaultModel{approvalID: a.ID, manifest: manifest, sealed: sealed, host: host, protocol: protocol, expires: a.ExpiresAt}
	o.audit("default_model.change_requested", id, p, "pending_approval")
	gateJSON(w, 202, DefaultModelChange{ChangeID: id, Status: "pending_approval", EndpointHost: host, Protocol: protocol, ExpiresAt: a.ExpiresAt})
}

func (o *DefaultModelOperator) apply(w http.ResponseWriter, r *http.Request) {
	p, ok := o.owner(w, r)
	if !ok {
		return
	}
	out, code, label := o.resolve(r.Context(), r.PathValue("id"), p)
	if label != "" {
		gateError(w, code, label)
		return
	}
	gateJSON(w, code, out)
}

// Run applies approved changes without waiting for the owner to call apply,
// so an approval takes effect shortly after the mail link decision. Denied
// or expired requests are dropped and leave the current upstream in place.
func (o *DefaultModelOperator) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 10 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.ResolvePending(ctx)
		}
	}
}

// ResolvePending checks every pending change once.
func (o *DefaultModelOperator) ResolvePending(ctx context.Context) {
	o.mu.Lock()
	ids := make([]string, 0, len(o.pending))
	for id := range o.pending {
		ids = append(ids, id)
	}
	o.mu.Unlock()
	for _, id := range ids {
		step, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, _, _ = o.resolve(step, id, nexus.Principal{Kind: nexus.PrincipalSystem, Email: o.cfg.OwnerEmail})
		cancel()
	}
}

// resolve moves one pending change forward: still pending, closed (denied,
// expired, failed) or, only when the exact digest-bound change was approved
// by mail, consumed, persisted sealed and swapped in.
func (o *DefaultModelOperator) resolve(ctx context.Context, id string, p nexus.Principal) (DefaultModelChange, int, string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	pc, found := o.pending[id]
	if !found || !o.changeAvailable() {
		return DefaultModelChange{}, 404, "not_found"
	}
	if !o.cfg.Clock().Before(pc.expires) {
		delete(o.pending, id)
		o.audit("default_model.change_closed", id, p, "expired")
		return DefaultModelChange{}, 409, "approval_expired"
	}
	a, err := o.cfg.Approvals.Get(ctx, pc.approvalID)
	if err != nil {
		return DefaultModelChange{}, 502, "approval_unavailable"
	}
	switch a.Status {
	case "pending":
		return DefaultModelChange{ChangeID: id, Status: "pending_approval", EndpointHost: pc.host, Protocol: pc.protocol, ExpiresAt: pc.expires}, 202, ""
	case "approved":
	default: // denied, expired, failed, consumed
		delete(o.pending, id)
		o.audit("default_model.change_closed", id, p, a.Status)
		return DefaultModelChange{}, 409, "approval_" + a.Status
	}
	if a.Digest != changeDigest(pc.manifest) {
		delete(o.pending, id)
		o.audit("default_model.change_closed", id, p, "digest_mismatch")
		return DefaultModelChange{}, 409, "approval_conflict"
	}
	if _, err = o.cfg.Approvals.Consume(ctx, pc.approvalID, pc.manifest); err != nil {
		return DefaultModelChange{}, 409, "approval_conflict"
	}
	delete(o.pending, id)
	result := "failed"
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = o.cfg.Approvals.Result(rctx, pc.approvalID, result)
	}()
	rec, err := openDefaultModel(ctx, o.cfg.Sealer, pc.sealed)
	if err != nil || rec.ChangeID != id {
		o.audit("default_model.apply_failed", id, p, "sealing")
		return DefaultModelChange{}, 503, "sealing_unavailable"
	}
	rec.UpdatedAt = o.cfg.Clock().UTC()
	final, err := sealDefaultModel(ctx, o.cfg.Sealer, rec)
	if err != nil {
		o.audit("default_model.apply_failed", id, p, "sealing")
		return DefaultModelChange{}, 503, "sealing_unavailable"
	}
	// Persist first: a value that is live but not durable would silently
	// revert to an older key on the next restart.
	if err = o.cfg.Storage.Save(ctx, final); err != nil {
		o.audit("default_model.apply_failed", id, p, "storage")
		return DefaultModelChange{}, 503, "storage_unavailable"
	}
	if err = o.cfg.Model.SwapUpstream(rec.Upstream, rec.Key, "operator", rec.UpdatedAt, rec.UpdatedBy); err != nil {
		o.audit("default_model.apply_failed", id, p, "swap")
		return DefaultModelChange{}, 503, "unavailable"
	}
	result = "succeeded"
	o.audit("default_model.applied", id, p, "applied")
	st := o.statusLocked()
	return DefaultModelChange{ChangeID: id, Status: "applied", EndpointHost: st.EndpointHost, Protocol: st.Protocol, Current: &st}, 200, ""
}
