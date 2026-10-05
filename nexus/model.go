// Package nexus implements the account-isolated Nexus domain and ledger.
// Store is a trusted persistence boundary, not an API for untrusted clients.
package nexus

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("conflict")
	ErrInvalid           = errors.New("invalid request")
	ErrForbidden         = errors.New("forbidden")
	ErrLimit             = errors.New("limit exceeded")
	ErrRevoked           = errors.New("delegation revoked")
	ErrExpired           = errors.New("delegation expired")
	ErrRunnerUnavailable = errors.New("runner unavailable; specify a live session with to_session")
)

type PrincipalKind string

const (
	PrincipalUser    PrincipalKind = "user"
	PrincipalSession PrincipalKind = "session"
	PrincipalSystem  PrincipalKind = "system"
)

type Principal struct {
	Kind      PrincipalKind `json:"kind"`
	AccountID ids.Account   `json:"account_id"`
	Email     string        `json:"email,omitempty"`
	SessionID ids.Session   `json:"session_id,omitempty"`
	// OwnBudgetAdmin is supplied only by live, verified Gate role lookup. Never
	// serialized into certificates, ledger actors, or accepted from HTTP input.
	OwnBudgetAdmin bool `json:"-"`
	// CredentialID is set only by executor (nte_) authentication. It binds the
	// principal to one stored executor credential (delegation, audience); never
	// serialized or accepted from HTTP input.
	CredentialID string `json:"-"`
}

func UserPrincipal(account ids.Account, email string) Principal {
	return Principal{Kind: PrincipalUser, AccountID: account, Email: email}
}
func SessionPrincipal(account ids.Account, session ids.Session) Principal {
	return Principal{Kind: PrincipalSession, AccountID: account, SessionID: session}
}
func SystemPrincipal(account ids.Account) Principal {
	return Principal{Kind: PrincipalSystem, AccountID: account}
}

type SessionKind string

const (
	Worker   SessionKind = "worker"
	Observer SessionKind = "observer"
)

type Runner string

const (
	Local     Runner = "local"
	Container Runner = "container"
	// Remote is a connection that Nexus itself serves (the remote MCP
	// endpoint, docs/nmcp-remote-endpoint.md): no container, no person's
	// terminal. Only B's own connector creates it; the public API refuses it,
	// and header authentication never yields a remote session principal.
	Remote Runner = "remote"
)

type SessionStatus string

const (
	SessionRequested SessionStatus = "requested"
	SessionRunning   SessionStatus = "running"
	SessionWaiting   SessionStatus = "waiting"
	SessionDone      SessionStatus = "done"
	SessionStopped   SessionStatus = "stopped"
	SessionSuspended SessionStatus = "suspended"
)

type Session struct {
	ID          ids.Session   `json:"id"`
	AccountID   ids.Account   `json:"account_id"`
	Kind        SessionKind   `json:"kind"`
	Runner      Runner        `json:"runner"`
	Title       string        `json:"title"`
	Status      SessionStatus `json:"status"`
	EntryTaskID ids.Task      `json:"entry_task_id,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	// SeenAt is a shared liveness hint, never an authority or attach lease.
	SeenAt    time.Time     `json:"seen_at,omitempty"`
	StoppedBy PrincipalKind `json:"stopped_by,omitempty"`
}

type Task struct {
	ID           ids.Task       `json:"id"`
	AccountID    ids.Account    `json:"account_id"`
	ParentID     ids.Task       `json:"parent_id,omitempty"`
	RootID       ids.Task       `json:"root_id"`
	Assignee     ids.Session    `json:"assignee"`
	DelegationID ids.Delegation `json:"delegation_id,omitempty"`
	No           int            `json:"no"`
	Kind         string         `json:"kind"`
	Title        string         `json:"title"`
	Status       string         `json:"status"`
	ActiveForm   string         `json:"active_form,omitempty"`
}

type Limits struct {
	ModelTokens    int64  `json:"model_tokens"`
	RuntimeMinutes int64  `json:"runtime_minutes"`
	SubSessions    int64  `json:"sub_sessions"`
	Spend          int64  `json:"spend"`
	Currency       string `json:"currency,omitempty"`
	MaxDepth       int    `json:"max_depth"`
}
type Usage struct {
	Consumed Limits `json:"consumed"`
	Reserved Limits `json:"reserved"`
	// UnlimitedBudget applies only to this root's model tokens/runtime. It is
	// server-side accounting, not a change to the sealed grant or permissions.
	UnlimitedBudget bool `json:"unlimited_budget,omitempty"`
}
type Rule struct {
	Action string `json:"action"`
	Effect string `json:"effect"`
}
type Policy struct {
	ID        ids.Policy  `json:"id"`
	AccountID ids.Account `json:"account_id"`
	Version   int         `json:"version"`
	Rules     []Rule      `json:"rules"`
	Approver  string      `json:"approver"`
}
type PolicyRef struct {
	ID      ids.Policy `json:"id"`
	Version int        `json:"version"`
	Hash    string     `json:"hash"`
}

// Delegation is the stored Mandate. The service issues immutable grants and
// checks the complete live ancestry. Only lifecycle fields change after issue;
// sealed snapshots are issued separately; user signatures remain a later phase.
type Delegation struct {
	ID           ids.Delegation `json:"id"`
	AccountID    ids.Account    `json:"account_id"`
	Principal    Principal      `json:"principal"`
	Delegator    Principal      `json:"delegator"`
	Delegate     ids.Session    `json:"delegate"`
	Task         ids.Task       `json:"task,omitempty"`
	ParentID     ids.Delegation `json:"parent_id,omitempty"`
	RootID       ids.Delegation `json:"root_id"`
	Depth        int            `json:"depth"`
	Scope        []string       `json:"scope"`
	Policy       PolicyRef      `json:"policy"`
	Limits       Limits         `json:"limits"`
	IssuedAt     time.Time      `json:"issued_at"`
	ExpiresAt    time.Time      `json:"expires_at"`
	EndedAt      *time.Time     `json:"ended_at,omitempty"`
	EndReason    string         `json:"end_reason,omitempty"`
	SupersededBy ids.Delegation `json:"superseded_by,omitempty"`
}

type Event struct {
	ID            ids.Event       `json:"id"`
	AccountID     ids.Account     `json:"account_id"`
	SessionID     ids.Session     `json:"session_id"`
	Seq           int64           `json:"seq"`
	Cursor        int64           `json:"cursor"`
	At            time.Time       `json:"at"`
	Source        string          `json:"source"`
	Kind          string          `json:"kind"`
	Actor         Principal       `json:"actor"`
	TaskID        ids.Task        `json:"task_id,omitempty"`
	InvocationID  ids.Invocation  `json:"invocation_id,omitempty"`
	ClientEventID string          `json:"client_event_id,omitempty"`
	Payload       json.RawMessage `json:"payload"`
	PayloadHash   string          `json:"payload_hash"`
	Redactions    int             `json:"redactions"`
	CausedBy      []ids.Event     `json:"caused_by,omitempty"`
}
type EventInput struct {
	Source        string          `json:"source,omitempty"`
	Kind          string          `json:"kind"`
	TaskID        ids.Task        `json:"task_id,omitempty"`
	InvocationID  ids.Invocation  `json:"invocation_id,omitempty"`
	ClientEventID string          `json:"client_event_id,omitempty"`
	Payload       json.RawMessage `json:"payload,omitempty"`
	CausedBy      []ids.Event     `json:"caused_by,omitempty"`
}
