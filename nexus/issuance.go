package nexus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/redact"
)

const (
	DefaultMaxDepth = 4
	MaxTTL          = 31 * 24 * time.Hour
	// UnlimitedModelTokens is the root-request wire value of limits.model_tokens
	// that asks for an unlimited owner root (decision 2026-10-04: cost limits are
	// enforced at the provider). Only the trusted HTTP adapter turns it into
	// RootRequest.UnlimitedModelTokens, and only for the verified owner person.
	UnlimitedModelTokens int64 = -1
)

// RootRequest is a human-issued grant. TTL is a Go duration; a future HTTP
// adapter must explicitly convert its wire representation.
type RootRequest struct {
	Title       string
	TaskID      ids.Task
	ToSessionID ids.Session
	Runner      Runner
	Scope       []string
	Rules       []Rule
	Approver    string
	Limits      Limits
	TTL         time.Duration
	// UnlimitedModelTokens asks for a root whose model-token budget never
	// refuses (stored as math.MaxInt64, usage still recorded). It is honoured
	// only when the actor carries OwnBudgetAdmin, which only the trusted Gate
	// owner check sets; Limits.ModelTokens must then be zero.
	UnlimitedModelTokens bool
}
type DelegateRequest struct {
	ParentID    ids.Delegation
	FromTaskID  ids.Task
	Title       string
	Brief       string
	ToSessionID ids.Session
	Runner      Runner
	Scope       []string
	Rules       []Rule
	Approver    string
	Limits      Limits
	TTL         time.Duration
}
type Issued struct {
	Task       Task       `json:"task"`
	Session    Session    `json:"session"`
	Delegation Delegation `json:"delegation"`
	Policy     Policy     `json:"policy"`
}

func delegationIn(tx Tx, account ids.Account, id ids.Delegation) (Delegation, error) {
	d, err := tx.Delegation(id)
	if err != nil {
		return Delegation{}, err
	}
	if d.AccountID != account {
		return Delegation{}, ErrNotFound
	}
	return d, nil
}

// hubEvent is only used by trusted domain mutations, in the SAME transaction.
// Never include credentials, raw certificates or key material in payload.
func hubEvent(tx Tx, actor Principal, session ids.Session, task ids.Task, kind string, payload any, now time.Time, caused ...ids.Event) (Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Event{}, err
	}
	clean, count, err := redact.JSON(raw)
	if err != nil {
		return Event{}, err
	}
	return tx.AppendEvent(Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: actor.AccountID, SessionID: session, TaskID: task, Source: "hub", Kind: kind, Actor: actor, At: now.UTC(), Payload: clean, PayloadHash: hashPayload(clean), Redactions: count, CausedBy: caused})
}
func cleanTitle(title string) (string, error) {
	if !utf8.ValidString(title) {
		return "", ErrInvalid
	}
	title, _ = redact.Text(strings.TrimSpace(title))
	if title == "" {
		return "", fmt.Errorf("%w: empty title", ErrInvalid)
	}
	return title, nil
}
func runnerOf(r Runner) (Runner, error) {
	switch r {
	case "", Container:
		return Container, nil
	case Local:
		return Local, nil
	case Remote:
		return Remote, nil
	default:
		return "", ErrInvalid
	}
}
func makePolicy(account ids.Account, rules []Rule, approver string) (Policy, error) {
	rr, err := normalizeRules(rules)
	if err != nil {
		return Policy{}, err
	}
	ap, err := normalizeApprover(approver)
	if err != nil {
		return Policy{}, err
	}
	return Policy{ID: ids.Policy(ids.New(ids.KindPolicy)), AccountID: account, Version: 1, Rules: rr, Approver: ap}, nil
}
func policyRef(p Policy) PolicyRef { return PolicyRef{ID: p.ID, Version: p.Version, Hash: p.Hash()} }
func issuanceSummary(d Delegation) any {
	// Deliberately omit scopes, rules and limits from the progress-visible ledger.
	return struct {
		ID       ids.Delegation `json:"delegation_id"`
		Parent   ids.Delegation `json:"parent_id,omitempty"`
		Delegate ids.Session    `json:"delegate"`
		Task     ids.Task       `json:"task_id,omitempty"`
		Expires  time.Time      `json:"expires_at"`
	}{d.ID, d.ParentID, d.Delegate, d.Task, d.ExpiresAt}
}
func nextNo(tasks []Task) int {
	n := 1
	for _, t := range tasks {
		if t.No >= n {
			n = t.No + 1
		}
	}
	return n
}
func terminalTask(status string) bool {
	return status == "done" || status == "failed" || status == "cancelled"
}

func (s *Service) CreateRoot(ctx context.Context, actor Principal, req RootRequest) (Issued, error) {
	if actor.Kind != PrincipalUser {
		return Issued{}, ErrForbidden
	}
	title, err := cleanTitle(req.Title)
	if err != nil {
		return Issued{}, err
	}
	scope, err := normalizeScopes(req.Scope)
	if err != nil {
		return Issued{}, err
	}
	p, err := makePolicy(actor.AccountID, req.Rules, req.Approver)
	if err != nil {
		return Issued{}, err
	}
	runner, err := runnerOf(req.Runner)
	if err != nil {
		return Issued{}, err
	}
	if req.UnlimitedModelTokens {
		if !actor.OwnBudgetAdmin {
			return Issued{}, ErrForbidden
		}
		if req.Limits.ModelTokens != 0 {
			return Issued{}, ErrInvalid
		}
		req.Limits.ModelTokens = math.MaxInt64
	}
	// The owner flag is a live Gate decision, never stored with the grant.
	actor.OwnBudgetAdmin = false
	if err = validLimits(req.Limits); err != nil {
		return Issued{}, err
	}
	if req.TTL < 0 || req.TTL > MaxTTL {
		return Issued{}, ErrInvalid
	}
	if req.TTL == 0 {
		req.TTL = MaxTTL
	}
	if req.Limits.MaxDepth == 0 || req.Limits.MaxDepth > DefaultMaxDepth {
		req.Limits.MaxDepth = DefaultMaxDepth
	}
	if req.TaskID != "" {
		if _, err = ids.ParseTask(string(req.TaskID)); err != nil {
			return Issued{}, ErrInvalid
		}
	}
	var out Issued
	err = s.update(ctx, actor, func(tx Tx) error {
		out = Issued{}
		now := s.now().UTC()
		tid := req.TaskID
		if tid == "" {
			tid = ids.Task(ids.New(ids.KindTask))
		}
		if _, err := tx.Task(tid); err == nil {
			return ErrConflict
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		session := Session{ID: ids.Session(ids.New(ids.KindSession)), AccountID: actor.AccountID, Kind: Worker, Runner: runner, Title: title, Status: SessionRequested, CreatedAt: now, UpdatedAt: now}
		if req.ToSessionID != "" {
			var err error
			session, err = sessionIn(tx, actor.AccountID, req.ToSessionID)
			if err != nil {
				return err
			}
			if session.Kind != Worker {
				return ErrInvalid
			}
			if (session.Runner == Remote) != (runner == Remote) {
				return ErrForbidden // only the connector issues roots to remote sessions
			}
			if session.Status == SessionSuspended {
				return ErrForbidden
			}
			if session.Status == SessionDone || session.Status == SessionStopped {
				session.Status = SessionRequested
			}
			session.UpdatedAt = now
		}
		if session.EntryTaskID == "" {
			session.EntryTaskID = tid
		}
		roots, err := tx.RootTasks(actor.AccountID)
		if err != nil {
			return err
		}
		did := ids.Delegation(ids.New(ids.KindDelegation))
		task := Task{ID: tid, AccountID: actor.AccountID, RootID: tid, Assignee: session.ID, DelegationID: did, No: nextNo(roots), Kind: "request", Title: title, Status: "pending"}
		d := Delegation{ID: did, AccountID: actor.AccountID, Principal: actor, Delegator: actor, Delegate: session.ID, Task: tid, RootID: did, Scope: scope, Policy: policyRef(p), Limits: req.Limits, IssuedAt: now, ExpiresAt: now.Add(req.TTL)}
		if err = tx.PutPolicy(p); err != nil {
			return err
		}
		if err = tx.PutSession(session); err != nil {
			return err
		}
		if err = tx.PutTask(task); err != nil {
			return err
		}
		if err = tx.PutDelegation(d); err != nil {
			return err
		}
		if req.UnlimitedModelTokens {
			// Marks the root as unlimited for accounting views; consumption is
			// still recorded against it like any other root.
			if err = tx.PutUsage(did, Usage{UnlimitedBudget: true}); err != nil {
				return err
			}
		}
		if _, err = hubEvent(tx, actor, session.ID, tid, "delegation.issued", issuanceSummary(d), now); err != nil {
			return err
		}
		out = Issued{Task: task, Session: session, Delegation: d, Policy: p}
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	return out, nil
}

func (s *Service) Delegate(ctx context.Context, actor Principal, req DelegateRequest) (Issued, error) {
	if actor.Kind != PrincipalUser && actor.Kind != PrincipalSession {
		return Issued{}, ErrForbidden
	}
	title, err := cleanTitle(req.Title)
	if err != nil {
		return Issued{}, err
	}
	if !utf8.ValidString(req.Brief) {
		return Issued{}, ErrInvalid
	}
	brief, _ := redact.Text(req.Brief)
	scope, err := normalizeScopes(req.Scope)
	if err != nil {
		return Issued{}, err
	}
	p, err := makePolicy(actor.AccountID, req.Rules, req.Approver)
	if err != nil {
		return Issued{}, err
	}
	if _, err := runnerOf(req.Runner); err != nil {
		return Issued{}, err
	}
	// Currency may be inherited below; other invalid amounts must be rejected now.
	check := req.Limits
	if check.Spend > 0 && check.Currency == "" {
		check.Currency = "inherited"
	}
	if err = validLimits(check); err != nil {
		return Issued{}, err
	}
	if req.TTL < 0 {
		return Issued{}, ErrInvalid
	}
	var out Issued
	err = s.update(ctx, actor, func(tx Tx) error {
		out = Issued{}
		now := s.now().UTC()
		parent, err := delegationIn(tx, actor.AccountID, req.ParentID)
		if err != nil {
			return err
		}
		if actor.Kind == PrincipalSession && actor.SessionID != parent.Delegate {
			return ErrForbidden
		}
		if err = liveChain(tx, actor.AccountID, parent, now); err != nil {
			return err
		}
		owner, err := sessionIn(tx, actor.AccountID, parent.Delegate)
		if err != nil {
			return err
		}
		if owner.Status == SessionSuspended || owner.Status == SessionDone || owner.Status == SessionStopped {
			return ErrForbidden
		}
		if parent.Task == "" || !covers(parent.Scope, "session:delegate") {
			return ErrForbidden
		}
		for _, sc := range scope {
			if !covers(parent.Scope, sc) {
				return fmt.Errorf("%w: scope %s", ErrForbidden, sc)
			}
		}
		depth := parent.Depth + 1
		if parent.Limits.MaxDepth < 1 || depth > DefaultMaxDepth {
			return fmt.Errorf("%w: no further delegation", ErrLimit)
		}
		limits := req.Limits
		if limits.MaxDepth == 0 || limits.MaxDepth > parent.Limits.MaxDepth-1 {
			limits.MaxDepth = parent.Limits.MaxDepth - 1
		}
		if limits.Spend > 0 {
			if limits.Currency == "" {
				limits.Currency = parent.Limits.Currency
			}
			if limits.Currency == "" || limits.Currency != parent.Limits.Currency {
				return ErrInvalid
			}
		} else {
			limits.Currency = ""
		}
		fromID := req.FromTaskID
		if fromID == "" {
			fromID = parent.Task
		}
		from, err := taskIn(tx, actor.AccountID, fromID)
		if err != nil {
			return err
		}
		if terminalTask(from.Status) {
			return ErrConflict
		}
		if from.Assignee != parent.Delegate {
			return ErrForbidden
		}
		gov, err := governingDelegation(tx, actor.AccountID, from)
		if err != nil {
			return err
		}
		if gov != parent.ID {
			return ErrForbidden
		}
		// Phase one has no runner registry or dispatcher. Never create an orphan
		// SessionRequested (or charge its slot) based on a caller's runner label.
		if req.ToSessionID == "" {
			if s.RefuseUnstartable && actor.Kind == PrincipalSession {
				return fmt.Errorf("%w: %s", ErrRunnerUnavailable, fmt.Sprintf(UnstartableMessage, title))
			}
			return ErrRunnerUnavailable
		}
		session, err := sessionIn(tx, actor.AccountID, req.ToSessionID)
		if err != nil {
			return err
		}
		if session.Kind != Worker || session.ID == parent.Delegate {
			return ErrInvalid
		}
		if session.Runner == Remote {
			return ErrForbidden // a remote connection holds only the connector's tool-only root
		}
		if session.Status == SessionDone || session.Status == SessionStopped || session.Status == SessionSuspended {
			return ErrForbidden
		}
		if session.SeenAt.IsZero() || now.Sub(session.SeenAt) >= PresenceGrace {
			return ErrRunnerUnavailable
		}
		session.UpdatedAt = now
		if err = sweepExpired(tx, actor.AccountID, parent.ID, now); err != nil {
			return err
		}
		// A sweep can stop an existing target if its last mandate just expired.
		if req.ToSessionID != "" {
			fresh, err := sessionIn(tx, actor.AccountID, session.ID)
			if err != nil {
				return err
			}
			if fresh.Status == SessionStopped || fresh.Status == SessionDone {
				return ErrForbidden
			}
		}
		usage, err := tx.Usage(parent.ID)
		if err != nil {
			return err
		}
		left, err := remaining(parent.Limits, usage)
		if err != nil {
			return err
		}
		need := limits

		if !fits(need, left) {
			return ErrLimit
		}
		usage.Reserved, err = addLimits(usage.Reserved, limits)
		if err != nil {
			return err
		}

		if err = tx.PutUsage(parent.ID, usage); err != nil {
			return err
		}
		expires := parent.ExpiresAt
		if req.TTL > 0 && now.Add(req.TTL).Before(expires) {
			expires = now.Add(req.TTL)
		}
		tid := ids.Task(ids.New(ids.KindTask))
		did := ids.Delegation(ids.New(ids.KindDelegation))
		siblings, err := tx.TasksByParent(from.ID)
		if err != nil {
			return err
		}
		task := Task{ID: tid, AccountID: actor.AccountID, ParentID: from.ID, RootID: from.RootID, Assignee: session.ID, DelegationID: did, No: nextNo(siblings), Kind: "delegated", Title: title, Status: "pending"}
		d := Delegation{ID: did, AccountID: actor.AccountID, Principal: parent.Principal, Delegator: actor, Delegate: session.ID, Task: tid, ParentID: parent.ID, RootID: parent.RootID, Depth: depth, Scope: scope, Policy: policyRef(p), Limits: limits, IssuedAt: now, ExpiresAt: expires}
		if session.EntryTaskID == "" {
			session.EntryTaskID = tid
		}
		if err = tx.PutPolicy(p); err != nil {
			return err
		}
		if err = tx.PutSession(session); err != nil {
			return err
		}
		if err = tx.PutTask(task); err != nil {
			return err
		}
		if err = tx.PutDelegation(d); err != nil {
			return err
		}
		issued, err := hubEvent(tx, actor, parent.Delegate, from.ID, "delegation.issued", issuanceSummary(d), now)
		if err != nil {
			return err
		}
		payload := map[string]any{"task_id": tid, "title": title, "brief": brief, "delegation_id": did, "from_session": parent.Delegate, "inbox": req.ToSessionID != ""}
		if _, err = hubEvent(tx, actor, session.ID, tid, "task.assigned", payload, now, issued.ID); err != nil {
			return err
		}
		out = Issued{Task: task, Session: session, Delegation: d, Policy: p}
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	return out, nil
}

// Steps inherit governance from the nearest ancestor with a mandate.
func governingDelegation(tx Tx, account ids.Account, task Task) (ids.Delegation, error) {
	seen := map[ids.Task]bool{}
	for {
		if task.AccountID != account {
			return "", ErrNotFound
		}
		if seen[task.ID] || len(seen) >= 64 {
			return "", ErrConflict
		}
		seen[task.ID] = true
		if task.DelegationID != "" {
			return task.DelegationID, nil
		}
		if task.ParentID == "" {
			return "", ErrForbidden
		}
		var err error
		task, err = taskIn(tx, account, task.ParentID)
		if err != nil {
			return "", err
		}
	}
}
