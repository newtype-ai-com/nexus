// Package httpapi provides a local integration adapter, not a production Gate.
// Authentication and execution are trusted injected dependencies. Durable mode
// persists approvals/results in the Nexus ledger; legacy mode keeps them local.
// Neither mode returns credentials, arguments or runner output in results/events.
// This is intentionally a status-only runner API.
package httpapi

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
	"strconv"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/redact"
)

// Authenticator must validate credential integrity, expiry and revocation and
// return a trusted identity. Never derive it from account/session HTTP fields.
// Returning PrincipalSystem is always rejected by this adapter.
type Authenticator func(*http.Request) (nexus.Principal, error)
type Runner func(context.Context, string, json.RawMessage) error

type Config struct {
	Service      *nexus.Service
	Authenticate Authenticator
	// Reauthenticate must be side-effect-free: an existing request is not
	// fresh presence. If nil, Authenticate must itself be side-effect-free.
	Reauthenticate Authenticator
	Run            Runner
	// Durable persists approvals and results in the Nexus ledger. Required for
	// RunMetered; the legacy local adapter remains available for compatibility.
	Durable         bool
	RunMetered      MeteredRunner
	RecheckInterval time.Duration
	// Actions sets fixed costs for Run, or admission ceilings for RunMetered.
	// Neither value comes from client-reported usage.
	Actions     map[string]int64
	Clock       func() time.Time
	ApprovalTTL time.Duration
	MaxRecords  int
	// StreamLife is how long one event stream stays open before the server
	// ends it for the reader to open again (default DefaultStreamLife).
	// Heartbeat is the SSE keep-alive interval (default 15s). Both exist for
	// tests; production leaves them zero.
	StreamLife time.Duration
	Heartbeat  time.Duration
	// OwnerPerson is the trusted Gate check that this request carries the
	// configured owner's own person credentials (licence + login, both the
	// owner's email). nil means no owner: an unlimited root is always refused.
	OwnerPerson func(*http.Request, nexus.Principal) bool
	// ModelScope (optional) decides whether a new root may carry the scope
	// model:<name> for this principal (the relayed default model is limited to
	// the owner and designated users); a refusal is 403 model_relay_not_allowed.
	ModelScope func(*http.Request, nexus.Principal, string) bool
}

// DefaultStreamLife is how long one stream stays open before Nexus ends it
// for the reader to open again. Well under nexus.PresenceGrace, so a session
// that only listens still sends an authenticated request often enough to
// count as there.
//
// Why a stream ends by itself at all: opening it is the request that says the
// session is there. The stream staying open says nothing — behind a proxy or
// tunnel this handler does not learn that its reader died, and writes to a
// dead reader succeed until the proxy's own limit. A reader that is alive
// reopens from its own cursor; a dead one does not, and is seen to be gone.
const DefaultStreamLife = 3 * time.Minute

// MaxStreamLife bounds an injected StreamLife; a stream must end well before
// the presence grace would let a dead reader keep a session alive.
const MaxStreamLife = 4 * time.Minute

type request struct {
	Delegation ids.Delegation  `json:"delegation_id"`
	Action     string          `json:"action"`
	Args       json.RawMessage `json:"args"`
}
type Result struct {
	ID              ids.Invocation `json:"id"`
	Status          string         `json:"status"`
	InputHash       string         `json:"input_hash"`
	ApprovalExpires time.Time      `json:"approval_expires_at,omitempty"`
}
type record struct {
	Result
	actor      nexus.Principal
	delegation ids.Delegation
	action     string
	tokens     int64
	cancel     context.CancelFunc
}
type API struct {
	cfg     Config
	mu      sync.Mutex
	records map[ids.Invocation]*record
	mux     *http.ServeMux
}

func New(cfg Config) (*API, error) {
	if cfg.Service == nil || cfg.Authenticate == nil || (cfg.Run == nil && cfg.RunMetered == nil) || (cfg.RunMetered != nil && !cfg.Durable) {
		return nil, nexus.ErrInvalid
	}
	if cfg.Reauthenticate == nil {
		cfg.Reauthenticate = cfg.Authenticate
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.ApprovalTTL == 0 {
		cfg.ApprovalTTL = 5 * time.Minute
	}
	if cfg.RecheckInterval == 0 {
		cfg.RecheckInterval = time.Second
	}
	if cfg.RecheckInterval < 0 || cfg.RecheckInterval > 30*time.Second {
		return nil, nexus.ErrInvalid
	}
	if cfg.ApprovalTTL < 0 || cfg.ApprovalTTL > 24*time.Hour {
		return nil, nexus.ErrInvalid
	}
	if cfg.MaxRecords == 0 {
		cfg.MaxRecords = 4096
	}
	if cfg.MaxRecords < 1 {
		return nil, nexus.ErrInvalid
	}
	if cfg.StreamLife == 0 {
		cfg.StreamLife = DefaultStreamLife
	}
	if cfg.StreamLife < 0 || cfg.StreamLife > MaxStreamLife {
		return nil, nexus.ErrInvalid
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = 15 * time.Second
	}
	if cfg.Heartbeat < 0 || cfg.Heartbeat > cfg.StreamLife {
		return nil, nexus.ErrInvalid
	}
	actions := make(map[string]int64, len(cfg.Actions))
	for action, cost := range cfg.Actions {
		if cost < 0 {
			return nil, nexus.ErrInvalid
		}
		actions[action] = cost
	}
	cfg.Actions = actions
	a := &API{cfg: cfg, records: make(map[ids.Invocation]*record), mux: http.NewServeMux()}
	a.registerSessions()
	a.registerTasks()
	a.registerGrants()
	a.registerCredentials()
	a.registerCustody()
	a.registerExecutionGrants()
	a.registerSecrets()
	a.registerAccountSelf()
	a.registerSecretPlans()
	a.registerTeams()
	a.mux.HandleFunc("POST /v1/delegations", a.delegate)
	if cfg.Durable {
		a.mux.HandleFunc("POST /v1/executions/{id}", a.durableExecute)
		a.mux.HandleFunc("GET /v1/executions/{id}", a.durableGet)
		a.mux.HandleFunc("POST /v1/executions/{id}/approval", a.durableApprove)
		a.mux.HandleFunc("POST /v1/executions/{id}/cancel", a.durableCancel)
	} else {
		a.mux.HandleFunc("POST /v1/executions/{id}", a.execute)
		a.mux.HandleFunc("GET /v1/executions/{id}", a.get)
		a.mux.HandleFunc("POST /v1/executions/{id}/approval", a.approve)
		a.mux.HandleFunc("POST /v1/executions/{id}/cancel", a.cancel)
	}
	a.mux.HandleFunc("POST /v1/messages", a.message)
	a.mux.HandleFunc("POST /v1/messages/delivered", a.messageDelivered)
	a.mux.HandleFunc("POST /v1/messages/read", a.messageRead)
	a.mux.HandleFunc("GET /v1/messages/{id}", a.messageDelivery)
	a.mux.HandleFunc("POST /v1/sessions/{session}/messages", a.message)
	a.mux.HandleFunc("GET /v1/inbox", a.inbox)
	a.mux.HandleFunc("GET /v1/sessions/{session}/events", a.events)
	a.mux.HandleFunc("POST /v1/sessions/{session}/events", a.recordToolCalls)
	a.mux.HandleFunc("GET /v1/sessions/{session}/stream", a.stream)
	return a, nil
}

type principalKey struct{}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, err := a.cfg.Authenticate(r)
	if err != nil || (p.Kind != nexus.PrincipalSession && p.Kind != nexus.PrincipalUser) {
		write(w, 401, map[string]string{"error": "unauthenticated"})
		return
	}
	if _, err = ids.ParseAccount(string(p.AccountID)); err != nil {
		write(w, 401, map[string]string{"error": "unauthenticated"})
		return
	}
	if p.Kind == nexus.PrincipalSession {
		if _, err = ids.ParseSession(string(p.SessionID)); err != nil {
			write(w, 401, map[string]string{"error": "unauthenticated"})
			return
		}
	} else if p.SessionID != "" {
		write(w, 401, map[string]string{"error": "unauthenticated"})
		return
	}
	if p.CredentialID != "" && !executorAudience(r.Method, r.URL.Path) {
		write(w, 401, map[string]string{"error": "unauthenticated"}) // nte_ is audience-limited
		return
	}
	// An executor credential never refreshes or restores ordinary session
	// presence; its liveness is checked by each executor operation.
	if p.CredentialID == "" {
		if err := a.cfg.Service.Touch(r.Context(), p); err != nil {
			fail(w, err)
			return
		}
		if a.cfg.Service.WakeHint(r.Context(), p) {
			w.Header().Set(nexus.WakeHeader, "1")
		}
	}
	a.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
}
func principal(r *http.Request) nexus.Principal {
	return r.Context().Value(principalKey{}).(nexus.Principal)
}
func write(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, err error) {
	code, label := 500, "internal"
	switch {
	case errors.Is(err, nexus.ErrRunnerUnavailable):
		code, label = 409, "runner_unavailable_specify_live_session"
	case errors.Is(err, nexus.ErrInvalid):
		code, label = 400, "invalid"
	case errors.Is(err, nexus.ErrForbidden):
		code, label = 403, "forbidden"
	case errors.Is(err, nexus.ErrNotFound):
		code, label = 404, "not_found"
	case errors.Is(err, nexus.ErrConflict):
		code, label = 409, "conflict"
	case errors.Is(err, nexus.ErrExpired), errors.Is(err, nexus.ErrRevoked):
		code, label = 403, "inactive"
	case errors.Is(err, nexus.ErrLimit):
		code, label = 429, "limit"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		code, label = 408, "cancelled"
	}
	write(w, code, map[string]string{"error": label})
}
func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		return nexus.ErrInvalid
	}
	// Reject duplicate keys and known credential-bearing input. Arbitrary args
	// may still be sensitive: they are never logged or included in responses.
	_, count, err := redact.JSON(raw)
	if err != nil || count != 0 {
		return nexus.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return nexus.ErrInvalid
	}
	return nil
}
func (a *API) lookup(r *http.Request) (*record, error) {
	id, err := ids.ParseInvocation(r.PathValue("id"))
	if err != nil {
		return nil, nexus.ErrInvalid
	}
	x := a.records[id]
	p := principal(r)
	if x == nil || x.actor.AccountID != p.AccountID || (p.Kind == nexus.PrincipalSession && p.SessionID != x.actor.SessionID) {
		return nil, nexus.ErrNotFound
	}
	return x, nil
}
func (a *API) execute(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind != nexus.PrincipalSession {
		fail(w, nexus.ErrForbidden)
		return
	}
	id, err := ids.ParseInvocation(r.PathValue("id"))
	if err != nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	var req request
	if err = decode(w, r, &req); err != nil {
		fail(w, err)
		return
	}
	cost, supported := a.cfg.Actions[req.Action]
	if !supported {
		fail(w, nexus.ErrForbidden)
		return
	}
	if _, err = ids.ParseDelegation(string(req.Delegation)); err != nil || len(req.Args) == 0 || !json.Valid(req.Args) {
		fail(w, nexus.ErrInvalid)
		return
	}
	// Canonicalize whitespace only. Key order and number spelling deliberately
	// remain significant; approval binds to these exact JSON argument bytes.
	var compact bytes.Buffer
	_ = json.Compact(&compact, req.Args)
	req.Args = compact.Bytes()
	sum := sha256.Sum256(req.Args)
	hash := hex.EncodeToString(sum[:])
	a.mu.Lock()
	x := a.records[id]
	if x != nil {
		if x.actor.AccountID != p.AccountID || x.actor.SessionID != p.SessionID {
			a.mu.Unlock()
			fail(w, nexus.ErrNotFound)
			return
		}
		if x.delegation != req.Delegation || x.action != req.Action || x.InputHash != hash {
			a.mu.Unlock()
			fail(w, nexus.ErrConflict)
			return
		}
		if x.Status != "approved" && x.Status != "pending" {
			out := x.Result
			a.mu.Unlock()
			write(w, 200, out)
			return
		}
		if !a.cfg.Clock().Before(x.ApprovalExpires) {
			x.Status = "expired"
			out := x.Result
			a.mu.Unlock()
			write(w, 403, out)
			return
		}
	}
	decision, err := a.cfg.Service.Authorize(r.Context(), p, req.Delegation, req.Action)
	if err != nil || decision.Effect == "deny" {
		a.mu.Unlock()
		if err == nil {
			err = nexus.ErrForbidden
		}
		fail(w, err)
		return
	}
	if x == nil {
		if len(a.records) >= a.cfg.MaxRecords {
			a.mu.Unlock()
			fail(w, nexus.ErrLimit)
			return
		}
		x = &record{Result: Result{ID: id, InputHash: hash, Status: "ready"}, actor: p, delegation: req.Delegation, action: req.Action, tokens: cost}
		a.records[id] = x
	}
	if decision.Effect == "ask" && x.Status != "approved" {
		// This local adapter supports human approvals only. A delegator-specific
		// approver must not silently become any same-account session.
		if decision.Approver != "user" && decision.Approver != "" {
			a.mu.Unlock()
			fail(w, nexus.ErrForbidden)
			return
		}
		if x.Status != "pending" {
			x.Status = "pending"
			x.ApprovalExpires = a.cfg.Clock().Add(a.cfg.ApprovalTTL)
		}
		out := x.Result
		a.mu.Unlock()
		write(w, 202, out)
		return
	}
	fresh, err := a.cfg.Service.BeginExecution(r.Context(), p, req.Delegation, id, req.Action, hash, cost, x.Status == "approved")
	if err != nil {
		a.mu.Unlock()
		fail(w, err)
		return
	}
	if !fresh {
		x.Status = "indeterminate"
		out := x.Result
		a.mu.Unlock()
		write(w, 409, out)
		return
	}
	ctx, cancel := context.WithCancel(context.WithValue(r.Context(), executionKey{}, executionIdentity{
		actor: p, delegation: req.Delegation, invocation: id, approved: x.Status == "approved",
		approvalExpires: x.ApprovalExpires, clock: a.cfg.Clock,
	}))
	x.cancel = cancel
	x.Status = "running"
	a.mu.Unlock()
	err = a.run(ctx, req.Action, req.Args)
	cancel()
	a.mu.Lock()
	switch {
	case ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || r.Context().Err() != nil || x.Status == "cancelling"):
		x.Status = "cancelled"
	case err != nil:
		x.Status = "failed"
	default:
		x.Status = "completed"
	}
	x.cancel = nil
	out := x.Result
	// Persist only a fixed vocabulary status; no args, errors or executor output.
	payload, _ := json.Marshal(map[string]string{"status": out.Status})
	persistCtx, done := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	_, persistErr := a.cfg.Service.AppendEvents(persistCtx, nexus.SystemPrincipal(p.AccountID), p.SessionID, []nexus.EventInput{{Source: "hub", Kind: "execution.finished", InvocationID: id, ClientEventID: "execution-finished:" + string(id), Payload: payload}})
	done()
	a.mu.Unlock()
	if persistErr != nil {
		fail(w, persistErr)
		return
	}
	write(w, 200, out)
}
func (a *API) run(ctx context.Context, action string, args json.RawMessage) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("runner failed")
		}
	}()
	if err = ctx.Err(); err != nil {
		return err
	}
	return a.cfg.Run(ctx, action, args)
}
func (a *API) get(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	x, err := a.lookup(r)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, x.Result)
}
func (a *API) approve(w http.ResponseWriter, r *http.Request) {
	if principal(r).Kind != nexus.PrincipalUser {
		fail(w, nexus.ErrForbidden)
		return
	}
	var req struct {
		InputHash string `json:"input_hash"`
		Approve   *bool  `json:"approve"`
	}
	if err := decode(w, r, &req); err != nil || req.Approve == nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	x, err := a.lookup(r)
	if err != nil {
		fail(w, err)
		return
	}
	if x.Status != "pending" || req.InputHash != x.InputHash {
		fail(w, nexus.ErrConflict)
		return
	}
	if !a.cfg.Clock().Before(x.ApprovalExpires) {
		x.Status = "expired"
		fail(w, nexus.ErrExpired)
		return
	}
	decision, err := a.cfg.Service.Authorize(r.Context(), x.actor, x.delegation, x.action)
	if err != nil || decision.Effect != "ask" || (decision.Approver != "user" && decision.Approver != "") {
		if err == nil {
			err = nexus.ErrForbidden
		}
		fail(w, err)
		return
	}
	status := "denied"
	if *req.Approve {
		status = "approved"
	}
	payload, _ := json.Marshal(map[string]string{"status": status, "input_hash": x.InputHash})
	_, err = a.cfg.Service.AppendEvents(r.Context(), nexus.SystemPrincipal(x.actor.AccountID), x.actor.SessionID, []nexus.EventInput{{Source: "hub", Kind: "execution.approval", InvocationID: x.ID, ClientEventID: "execution-approval:" + string(x.ID), Payload: payload}})
	if err != nil {
		fail(w, err)
		return
	}
	x.Status = status
	write(w, 200, x.Result)
}
func (a *API) cancel(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	x, err := a.lookup(r)
	if err != nil {
		fail(w, err)
		return
	}
	switch x.Status {
	case "running":
		x.Status = "cancelling"
		x.cancel()
	case "pending", "approved", "ready":
		x.Status = "cancelled"
	}
	write(w, 200, x.Result)
}
func cursor(r *http.Request) (int64, error) {
	v := r.URL.Query().Get("after")
	if v == "" {
		v = r.Header.Get("Last-Event-ID")
	}
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, nexus.ErrInvalid
	}
	return n, nil
}
func (a *API) events(w http.ResponseWriter, r *http.Request) {
	after, err := cursor(r)
	if err != nil {
		fail(w, err)
		return
	}
	events, next, err := a.cfg.Service.Events(r.Context(), principal(r), ids.Session(r.PathValue("session")), after, 100)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, map[string]any{"events": events, "next": next})
}
func (a *API) stream(w http.ResponseWriter, r *http.Request) {
	after, err := cursor(r)
	if err != nil {
		fail(w, err)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, nexus.ErrInvalid)
		return
	}
	// Presence was recorded by the request that opened this stream (ServeHTTP
	// touches every authenticated request). Nothing in the loop below touches
	// it again: a stream that stays open is not evidence that its reader is
	// alive. The stream ends after StreamLife and a live reader reopens it —
	// that reopening request is what says it is still there.
	life := a.cfg.StreamLife
	ctx, cancel := context.WithTimeout(r.Context(), life)
	defer cancel()
	// A blocked write to a reader that stopped reading must also end: the
	// server's write deadline is set a little past the stream's life.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(life + 10*time.Second))
	tick := time.NewTicker(a.cfg.Heartbeat)
	defer tick.Stop()
	started := false
	for {
		if ctx.Err() != nil {
			return // life is over; the reader reopens from its own cursor
		}
		changed := a.cfg.Service.Changed()
		// Re-authenticate at every wakeup, including heartbeat, for token expiry
		// and revocation. This is a credential check, not a presence report.
		p, authErr := a.cfg.Reauthenticate(r.WithContext(ctx))
		if authErr != nil || p != principal(r) {
			if !started {
				write(w, 401, map[string]string{"error": "unauthenticated"})
			}
			return
		}
		events, next, e := a.cfg.Service.Events(ctx, p, ids.Session(r.PathValue("session")), after, 100)
		if e != nil {
			if !started {
				fail(w, e)
			}
			return
		}
		if !started {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("X-Accel-Buffering", "no")
			started = true
			if _, e = fmt.Fprint(w, ": connected\n\n"); e != nil {
				return
			}
			flusher.Flush()
		}
		for _, event := range events {
			raw, _ := json.Marshal(event)
			if _, e = fmt.Fprintf(w, "id: %d\nevent: ledger\ndata: %s\n\n", event.Seq, raw); e != nil {
				return
			}
		}
		flusher.Flush()
		advanced := next > after
		after = next
		if advanced {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-tick.C:
			if _, e = fmt.Fprint(w, ": heartbeat\n\n"); e != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// ModelRelayNotAllowed is the fixed refusal of a root asking for the relayed
// default model by an account that may not use it (gate.ModelRelayNotAllowed).
const ModelRelayNotAllowed = "model_relay_not_allowed"
