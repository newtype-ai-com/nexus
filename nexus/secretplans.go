package nexus

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/secretplan"
)

// Secret plan runs (design: docs/nexus-secret-fd-plan-design.md v3 + v4).
// A run is started once per (account, session, delegation, attempt) forever,
// releases its roles one at a time in plan order under CURRENT authority, and
// ends in a monotonic terminal outcome. Values never enter the ledger.

const (
	SecretPlanRunVersion = "newtype.secret-plan-run/1"
	ExecutorTokenPrefix  = "nte_"
	ReleaseWindow        = 10 * time.Second // authorised_until after a release
	FinishGrace          = 10 * time.Minute // read/finish after authority loss
	ExecutorMaxTTL       = 7 * 24 * time.Hour
)

// ExecutorCredential is the stored, hashed nte_ credential (decision 2026-10-04).
type ExecutorCredential struct {
	ID         string         `json:"id"`
	Verifier   string         `json:"verifier"` // sha256 hex of the token; the token is never stored
	AccountID  ids.Account    `json:"account_id"`
	SessionID  ids.Session    `json:"session_id"`
	Delegation ids.Delegation `json:"delegation_id"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	RevokedAt  *time.Time     `json:"revoked_at"`
}

type SecretPlanRole struct {
	Role            string     `json:"role"`
	Source          string     `json:"source"`
	Resource        string     `json:"resource"`
	FD              int64      `json:"fd"`
	Released        bool       `json:"released"`
	AuthorisedUntil *time.Time `json:"authorised_until"`
}

type SecretPlanRun struct {
	ID           ids.Run          `json:"id"`
	AccountID    ids.Account      `json:"account_id"`
	SessionID    ids.Session      `json:"session_id"`
	Delegation   ids.Delegation   `json:"delegation_id"`
	CredentialID string           `json:"credential_id"`
	Attempt      string           `json:"attempt"`
	PlanHash     string           `json:"plan_hash"`
	Plan         string           `json:"plan"` // the public canonical plan
	ApprovalID   ids.Approval     `json:"approval_id"`
	Status       string           `json:"status"` // started | completed | failed | unknown
	Deadline     time.Time        `json:"deadline"`
	Roles        []SecretPlanRole `json:"roles"`
	StartedAt    time.Time        `json:"started_at"`
	FinishedAt   *time.Time       `json:"finished_at"`
}

// SecretPlanRunView is the strict read form (all keys always present).
type SecretPlanRunView struct {
	Version    string           `json:"version"`
	RunID      ids.Run          `json:"run_id"`
	Attempt    string           `json:"attempt"`
	PlanHash   string           `json:"plan_hash"`
	Account    ids.Account      `json:"account"`
	Session    ids.Session      `json:"session"`
	Delegation ids.Delegation   `json:"delegation"`
	Status     string           `json:"status"`
	Deadline   string           `json:"deadline"`
	Roles      []SecretPlanRole `json:"roles"`
	FinishedAt *string          `json:"finished_at"`
}

// SecretRelease is what a release returns; ValueB64 only for nexus sources.
type SecretRelease struct {
	Version         string  `json:"version"`
	RunID           ids.Run `json:"run_id"`
	Role            string  `json:"role"`
	Value           []byte  `json:"-"`
	AuthorisedUntil string  `json:"authorised_until"`
}

func attemptKey(account ids.Account, session ids.Session, delegation ids.Delegation, attempt string) string {
	return string(account) + "|" + string(session) + "|" + string(delegation) + "|" + attempt
}

// SecretPlanAttemptKey is the store key of a run (one per attempt, forever).
func SecretPlanAttemptKey(r SecretPlanRun) string {
	return attemptKey(r.AccountID, r.SessionID, r.Delegation, r.Attempt)
}

func tokenVerifier(token string) string {
	s := sha256.Sum256([]byte(token))
	return hex.EncodeToString(s[:])
}

// IssueExecutorCredential (person only) binds a new nte_ token to one
// session and delegation. The token is returned ONCE to the caller, who must
// write it straight into its protected sink; only the verifier is stored.
func (s *Service) IssueExecutorCredential(ctx context.Context, actor Principal, session ids.Session, delegation ids.Delegation, ttl time.Duration) (ExecutorCredential, string, error) {
	if actor.Kind != PrincipalUser {
		return ExecutorCredential{}, "", ErrForbidden
	}
	if ttl <= 0 || ttl > ExecutorMaxTTL {
		return ExecutorCredential{}, "", ErrInvalid
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ExecutorCredential{}, "", ErrInvalid
	}
	token := ExecutorTokenPrefix + hex.EncodeToString(raw)
	clear(raw)
	var out ExecutorCredential
	err := s.update(ctx, actor, func(tx Tx) error {
		out = ExecutorCredential{}
		d, err := delegationIn(tx, actor.AccountID, delegation)
		if err != nil {
			return err
		}
		if d.Delegate != session {
			return ErrForbidden
		}
		if err := liveChain(tx, actor.AccountID, d, s.now()); err != nil {
			return err
		}
		now := s.now().UTC()
		exp := now.Add(ttl)
		if d.ExpiresAt.Before(exp) {
			exp = d.ExpiresAt
		}
		out = ExecutorCredential{ID: "exc_" + ids.New(ids.KindRun)[4:], Verifier: tokenVerifier(token), AccountID: actor.AccountID,
			SessionID: session, Delegation: delegation, CreatedAt: now, ExpiresAt: exp}
		return tx.PutExecutorCredential(out)
	})
	if err != nil {
		return ExecutorCredential{}, "", err
	}
	return out, token, nil
}

func (s *Service) RevokeExecutorCredential(ctx context.Context, actor Principal, id string) error {
	if actor.Kind != PrincipalUser {
		return ErrForbidden
	}
	return s.update(ctx, actor, func(tx Tx) error {
		c, err := tx.ExecutorCredential(id)
		if err != nil || c.AccountID != actor.AccountID {
			return ErrNotFound
		}
		if c.RevokedAt != nil {
			return nil
		}
		now := s.now().UTC()
		c.RevokedAt = &now
		return tx.PutExecutorCredential(c)
	})
}

// AuthenticateExecutor maps an nte_ token to a session principal bound to
// that credential. Liveness is re-checked inside every plan operation.
func (s *Service) AuthenticateExecutor(ctx context.Context, token string) (Principal, error) {
	if !strings.HasPrefix(token, ExecutorTokenPrefix) || len(token) != len(ExecutorTokenPrefix)+64 {
		return Principal{}, ErrForbidden
	}
	v := tokenVerifier(token)
	var out Principal
	err := s.store.View(ctx, func(tx Tx) error {
		c, err := tx.ExecutorCredentialByVerifier(v)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Verifier), []byte(v)) != 1 {
			return ErrForbidden
		}
		out = Principal{Kind: PrincipalSession, AccountID: c.AccountID, SessionID: c.SessionID, CredentialID: c.ID}
		return nil
	})
	if err != nil {
		return Principal{}, ErrForbidden
	}
	return out, nil
}

// executorIn re-reads the actor's credential inside the transaction. strict
// requires full current authority (start/release); otherwise only the
// read/finish grace for runs it already started.
func (s *Service) executorIn(tx Tx, actor Principal, strict bool, run *SecretPlanRun) (ExecutorCredential, error) {
	if actor.Kind != PrincipalSession || actor.CredentialID == "" {
		return ExecutorCredential{}, ErrForbidden
	}
	c, err := tx.ExecutorCredential(actor.CredentialID)
	if err != nil || c.AccountID != actor.AccountID || c.SessionID != actor.SessionID {
		return ExecutorCredential{}, ErrForbidden
	}
	// a run is bound to the exact credential tuple that started it; no other
	// credential (renewed, other delegation, same session) may act on it
	if run != nil && (run.CredentialID != c.ID || run.AccountID != c.AccountID || run.SessionID != c.SessionID || run.Delegation != c.Delegation) {
		return ExecutorCredential{}, ErrForbidden
	}
	now := s.now()
	if strict {
		if c.RevokedAt != nil || !now.Before(c.ExpiresAt) {
			return ExecutorCredential{}, ErrForbidden
		}
		return c, nil
	}
	if run == nil || now.After(run.Deadline.Add(FinishGrace)) {
		return ExecutorCredential{}, ErrForbidden
	}
	return c, nil
}

// planAuthority: exec:secret-plan must still be ask/user on the exact
// delegation, and every resource auto, or ask/user (discharged by the plan
// approval). Any other approver, deny, a dead chain or an inactive session
// refuses (decide checks chain and session).
func (s *Service) planAuthority(tx Tx, account ids.Account, d Delegation, resources []string) error {
	now := s.now()
	dec, err := decide(tx, account, d, "exec:secret-plan", now)
	if err != nil {
		return err
	}
	if dec.Effect != "ask" || (dec.Approver != "" && dec.Approver != "user") {
		return ErrForbidden
	}
	for _, r := range resources {
		dec, err := decide(tx, account, d, r, now)
		if err != nil {
			return err
		}
		switch {
		case dec.Effect == "auto":
		case dec.Effect == "ask" && (dec.Approver == "" || dec.Approver == "user"):
		default:
			return ErrForbidden
		}
	}
	return nil
}

func (s *Service) runView(r SecretPlanRun) SecretPlanRunView {
	v := SecretPlanRunView{Version: SecretPlanRunVersion, RunID: r.ID, Attempt: r.Attempt, PlanHash: r.PlanHash, Account: r.AccountID,
		Session: r.SessionID, Delegation: r.Delegation, Status: r.Status, Deadline: custodyTime(r.Deadline),
		Roles: append([]SecretPlanRole(nil), r.Roles...), FinishedAt: custodyTimePtr(r.FinishedAt)}
	if v.Status == "started" && !s.now().Before(r.Deadline) {
		v.Status = "unknown" // an expired started run is terminal for release; read lazily
	}
	return v
}

// StartSecretPlan consumes the plan's custody approval and opens the run, in
// one transaction. The attempt key is unique forever.
func (s *Service) StartSecretPlan(ctx context.Context, actor Principal, rawPlan []byte, approval ids.Approval) (SecretPlanRunView, error) {
	p, err := secretplan.Validate(rawPlan)
	if err != nil {
		return SecretPlanRunView{}, ErrInvalid
	}
	if p.Account != string(actor.AccountID) || p.Session != string(actor.SessionID) {
		return SecretPlanRunView{}, ErrForbidden
	}
	// The plan must name this Nexus: the sealing service's configured issuer
	// (the same origin its delegation certificates carry). One issuer per
	// store, so the attempt key need not carry it. Checked before the
	// approval is touched.
	if s.issuer == "" || p.Issuer != s.issuer {
		return SecretPlanRunView{}, ErrForbidden
	}
	var out SecretPlanRunView
	err = s.update(ctx, actor, func(tx Tx) error {
		out = SecretPlanRunView{}
		c, err := s.executorIn(tx, actor, true, nil)
		if err != nil {
			return err
		}
		if string(c.Delegation) != p.Delegation {
			return ErrForbidden
		}
		key := attemptKey(actor.AccountID, actor.SessionID, c.Delegation, p.Attempt)
		if _, err := tx.SecretPlanRunByAttempt(key); err == nil {
			return ErrConflict // never reopened, even with a new approval
		} else if err != ErrNotFound {
			return err
		}
		ap, err := custodyFor(tx, actor, approval)
		if err != nil {
			return err
		}
		if ap.Action != "exec:secret-plan" || ap.InputHash != p.Hash || ap.Delegation != c.Delegation || ap.Status != "approved" {
			return ErrConflict
		}
		// the person approved a plan that is valid at least as long as the
		// approval: an approval outliving its plan is refused (the CLI shows
		// and checks the same relation before deciding)
		if ap.ExpiresAt.After(time.Unix(p.ExpiresAt, 0)) {
			return ErrConflict
		}
		now := s.now()
		if !now.Before(ap.ExpiresAt) {
			return ErrExpired
		}
		d, err := delegationIn(tx, actor.AccountID, c.Delegation)
		if err != nil {
			return err
		}
		res := make([]string, 0, len(p.Roles))
		for _, r := range p.Roles {
			res = append(res, r.Resource)
		}
		if err := s.planAuthority(tx, actor.AccountID, d, res); err != nil {
			return err
		}
		// approval consumed here (same rules as UseCustodyApproval)
		usedAt := ceilSecond(now)
		ap.Status, ap.UsedAt = "used", &usedAt
		if err := tx.PutCustodyApproval(ap); err != nil {
			return err
		}
		deadline := time.Unix(p.ExpiresAt, 0).UTC()
		for _, cand := range []time.Time{ap.ExpiresAt, d.ExpiresAt, c.ExpiresAt, now.Add(time.Duration(p.Timeout) * time.Second)} {
			if cand.Before(deadline) {
				deadline = cand
			}
		}
		if !now.Before(deadline) {
			return ErrExpired
		}
		run := SecretPlanRun{ID: ids.Run(ids.New(ids.KindRun)), AccountID: actor.AccountID, SessionID: actor.SessionID, Delegation: c.Delegation,
			CredentialID: c.ID, Attempt: p.Attempt, PlanHash: p.Hash, Plan: string(rawPlan), ApprovalID: ap.ID, Status: "started",
			Deadline: floorSecond(deadline), StartedAt: now.UTC()}
		for _, r := range p.Roles {
			run.Roles = append(run.Roles, SecretPlanRole{Role: r.Role, Source: r.Source, Resource: r.Resource, FD: r.FD})
		}
		if err := tx.PutSecretPlanRun(key, run); err != nil {
			return err
		}
		if err := custodyEvent(tx, ap, "used", actor, now); err != nil {
			return err
		}
		out = s.runView(run)
		return nil
	})
	if err != nil {
		return SecretPlanRunView{}, err
	}
	return out, nil
}

func (s *Service) runFor(tx Tx, actor Principal, id ids.Run) (SecretPlanRun, error) {
	r, err := tx.SecretPlanRun(id)
	if err != nil || r.AccountID != actor.AccountID || r.SessionID != actor.SessionID {
		return SecretPlanRun{}, ErrNotFound
	}
	return r, nil
}

// ReleaseSecretPlanRole releases exactly the next role, once, under current
// authority. For a nexus source the value is decrypted in the same
// transaction (the per-name key is derived beforehand, outside it).
func (s *Service) ReleaseSecretPlanRole(ctx context.Context, actor Principal, id ids.Run, role string) (SecretRelease, error) {
	// Learn the role's source/name first (read-only) to derive a key outside the Tx.
	var name string
	var source string
	if err := s.view(ctx, actor, func(tx Tx) error {
		r, err := s.runFor(tx, actor, id)
		if err != nil {
			return err
		}
		p, err := secretplan.Validate([]byte(r.Plan))
		if err != nil {
			return ErrConflict
		}
		for _, pr := range p.Roles {
			if pr.Role == role {
				name, source = pr.Name, pr.Source
			}
		}
		return nil
	}); err != nil {
		return SecretRelease{}, err
	}
	if source == "" {
		return SecretRelease{}, ErrConflict
	}
	var key []byte
	if source == "nexus" {
		k, _, err := s.secretKey(ctx, actor.AccountID, name)
		if err != nil {
			return SecretRelease{}, err
		}
		key = k
		defer clear(key)
	}
	var out SecretRelease
	err := s.update(ctx, actor, func(tx Tx) error {
		clear(out.Value)
		out = SecretRelease{}
		r, err := s.runFor(tx, actor, id)
		if err != nil {
			return err
		}
		if _, err := s.executorIn(tx, actor, true, &r); err != nil {
			return err
		}
		now := s.now()
		if r.Status != "started" || !now.Before(r.Deadline) {
			return ErrConflict
		}
		next := -1
		for i, x := range r.Roles {
			if !x.Released {
				next = i
				break
			}
		}
		if next < 0 || r.Roles[next].Role != role {
			return ErrConflict // only the next role, once
		}
		p, err := secretplan.Validate([]byte(r.Plan))
		if err != nil || p.Hash != r.PlanHash {
			return ErrConflict
		}
		d, err := delegationIn(tx, actor.AccountID, r.Delegation)
		if err != nil {
			return err
		}
		if err := s.planAuthority(tx, actor.AccountID, d, []string{r.Roles[next].Resource}); err != nil {
			return err
		}
		pr := p.Roles[next]
		if pr.Source == "nexus" {
			sv, err := tx.SecretValue(actor.AccountID, pr.Name)
			if err != nil || sv.Deleted || sv.Version != pr.Generation {
				return ErrConflict // generation moved, deleted or missing
			}
			plain, err := openSecret(key, secretAAD(actor.AccountID, pr.Name, sv.Version), sv.Ciphertext)
			if err != nil || int64(len(plain)) > pr.MaxBytes {
				clear(plain)
				return ErrConflict
			}
			// plan/3: the stored value must match the role's payload schema
			// before it is released (the executor checks it again)
			if p.Version == 3 && secretplan.ValidatePayload(pr, plain) != nil {
				clear(plain)
				return ErrConflict
			}
			out.Value = plain
			usedAt := now.UTC()
			sv.UsedAt = &usedAt
			if err := tx.PutSecretValue(sv); err != nil {
				clear(plain)
				return err
			}
		}
		until := now.Add(ReleaseWindow)
		if r.Deadline.Before(until) {
			until = r.Deadline
		}
		until = floorSecond(until)
		r.Roles[next].Released, r.Roles[next].AuthorisedUntil = true, &until
		if err := tx.PutSecretPlanRun(attemptKey(r.AccountID, r.SessionID, r.Delegation, r.Attempt), r); err != nil {
			return err
		}
		out.Version, out.RunID, out.Role, out.AuthorisedUntil = SecretPlanRunVersion, r.ID, role, custodyTime(until)
		return nil
	})
	if err != nil {
		clear(out.Value)
		return SecretRelease{}, err
	}
	return out, nil
}

// FinishSecretPlan records the one terminal outcome. completed requires every
// role released; a credential that lost authority may still finish its own
// run as failed/unknown within the grace window.
func (s *Service) FinishSecretPlan(ctx context.Context, actor Principal, id ids.Run, outcome string) (SecretPlanRunView, error) {
	if outcome != "completed" && outcome != "failed" && outcome != "unknown" {
		return SecretPlanRunView{}, ErrInvalid
	}
	var out SecretPlanRunView
	err := s.update(ctx, actor, func(tx Tx) error {
		out = SecretPlanRunView{}
		r, err := s.runFor(tx, actor, id)
		if err != nil {
			return err
		}
		if _, err := s.executorIn(tx, actor, outcome == "completed", &r); err != nil {
			return err
		}
		if r.Status != "started" {
			return ErrConflict // terminal is monotonic; a duplicate finish is refused
		}
		// past the deadline a started run reads as unknown; only that outcome
		// may be persisted, so the observed status never changes afterwards
		if !s.now().Before(r.Deadline) && outcome != "unknown" {
			return ErrConflict
		}
		if outcome == "completed" {
			res := make([]string, 0, len(r.Roles))
			for _, x := range r.Roles {
				if !x.Released {
					return ErrConflict
				}
				res = append(res, x.Resource)
			}
			// completed needs the full current plan authority (chain, session,
			// rules), not only a live credential
			d, err := delegationIn(tx, actor.AccountID, r.Delegation)
			if err != nil {
				return err
			}
			if err := s.planAuthority(tx, actor.AccountID, d, res); err != nil {
				return err
			}
		}
		now := s.now().UTC()
		r.Status, r.FinishedAt = outcome, &now
		if err := tx.PutSecretPlanRun(attemptKey(r.AccountID, r.SessionID, r.Delegation, r.Attempt), r); err != nil {
			return err
		}
		out = s.runView(r)
		return nil
	})
	if err != nil {
		return SecretPlanRunView{}, err
	}
	return out, nil
}

// SecretPlanRun reads a run (its executor within the grace, or the person).
func (s *Service) SecretPlanRun(ctx context.Context, actor Principal, id ids.Run) (SecretPlanRunView, error) {
	var out SecretPlanRunView
	err := s.view(ctx, actor, func(tx Tx) error {
		r, err := tx.SecretPlanRun(id)
		if err != nil || r.AccountID != actor.AccountID {
			return ErrNotFound
		}
		if actor.Kind != PrincipalUser {
			if r.SessionID != actor.SessionID {
				return ErrNotFound
			}
			if _, err := s.executorIn(tx, actor, false, &r); err != nil {
				return err
			}
		}
		out = s.runView(r)
		return nil
	})
	return out, err
}

// SecretPlanRunByAttempt is the lookup after a lost start response.
func (s *Service) SecretPlanRunByAttempt(ctx context.Context, actor Principal, attempt string) (SecretPlanRunView, error) {
	var out SecretPlanRunView
	err := s.view(ctx, actor, func(tx Tx) error {
		if actor.Kind != PrincipalSession || actor.CredentialID == "" {
			return ErrForbidden
		}
		c, err := tx.ExecutorCredential(actor.CredentialID)
		if err != nil || c.AccountID != actor.AccountID {
			return ErrForbidden
		}
		r, err := tx.SecretPlanRunByAttempt(attemptKey(actor.AccountID, actor.SessionID, c.Delegation, attempt))
		if err != nil {
			return err
		}
		if _, err := s.executorIn(tx, actor, false, &r); err != nil {
			return err
		}
		out = s.runView(r)
		return nil
	})
	return out, err
}

// ---- storage rules shared by every Tx -------------------------------------

func ExecutorCredentialOK(x ExecutorCredential) bool {
	return strings.HasPrefix(x.ID, "exc_") && len(x.Verifier) == 64 && ids.Check(ids.KindAccount, string(x.AccountID)) == nil &&
		ids.Check(ids.KindSession, string(x.SessionID)) == nil && ids.Check(ids.KindDelegation, string(x.Delegation)) == nil &&
		x.CreatedAt.Before(x.ExpiresAt)
}

// ExecutorTransitionOK: only revocation may change a credential, once.
func ExecutorTransitionOK(old, next ExecutorCredential) bool {
	if old.Verifier != next.Verifier || old.AccountID != next.AccountID || old.SessionID != next.SessionID ||
		old.Delegation != next.Delegation || !old.CreatedAt.Equal(next.CreatedAt) || !old.ExpiresAt.Equal(next.ExpiresAt) {
		return false
	}
	if old.RevokedAt != nil {
		return next.RevokedAt != nil && old.RevokedAt.Equal(*next.RevokedAt)
	}
	return true
}

// SecretPlanRunNewOK: a new run is started, has no release or finish, and its
// whole identity is consistent with its own canonical plan.
func SecretPlanRunNewOK(x SecretPlanRun) bool {
	if x.Status != "started" || x.FinishedAt != nil || len(x.Roles) == 0 || !strings.HasPrefix(x.CredentialID, "exc_") ||
		ids.Check(ids.KindRun, string(x.ID)) != nil || ids.Check(ids.KindAccount, string(x.AccountID)) != nil ||
		ids.Check(ids.KindSession, string(x.SessionID)) != nil || ids.Check(ids.KindDelegation, string(x.Delegation)) != nil ||
		ids.Check(ids.KindApproval, string(x.ApprovalID)) != nil || x.StartedAt.IsZero() || !x.Deadline.After(x.StartedAt.Add(-time.Second)) {
		return false
	}
	p, err := secretplan.Validate([]byte(x.Plan))
	if err != nil || p.Hash != x.PlanHash || p.Attempt != x.Attempt || p.Account != string(x.AccountID) ||
		p.Session != string(x.SessionID) || p.Delegation != string(x.Delegation) || len(p.Roles) != len(x.Roles) {
		return false
	}
	for i, r := range x.Roles {
		pr := p.Roles[i]
		if r.Released || r.AuthorisedUntil != nil || r.Role != pr.Role || r.Source != pr.Source || r.Resource != pr.Resource || r.FD != pr.FD {
			return false
		}
	}
	return true
}

// SecretPlanRunTransitionOK: identity immutable. While started, a write
// either releases exactly the first unreleased role (authorised_until set,
// within [started_at−1s, deadline]: the service floors stored times to whole
// seconds, so one second of rounding is allowed deliberately) with nothing
// else changed, or records one
// terminal outcome with the roles unchanged (completed only when every role
// is released). A terminal record is frozen entirely.
//
// The store has no transaction clock: it enforces ordering and relations
// between stored times only. Current-time checks (release before deadline,
// authorised_until ≤ now+10s, credential liveness) are the service's, in the
// same transaction.
//
// The "unknown" a reader sees for an expired started run is a view
// projection; the service then persists only "unknown" for it (Finish), so
// the observed status never changes.
func SecretPlanRunTransitionOK(old, next SecretPlanRun) bool {
	if old.ID != next.ID || old.AccountID != next.AccountID || old.SessionID != next.SessionID || old.Delegation != next.Delegation ||
		old.CredentialID != next.CredentialID || old.Attempt != next.Attempt || old.PlanHash != next.PlanHash || old.Plan != next.Plan ||
		old.ApprovalID != next.ApprovalID || !old.Deadline.Equal(next.Deadline) || !old.StartedAt.Equal(next.StartedAt) || len(old.Roles) != len(next.Roles) {
		return false
	}
	changed := -1
	for i := range old.Roles {
		o, n := old.Roles[i], next.Roles[i]
		if o.Role != n.Role || o.Source != n.Source || o.Resource != n.Resource || o.FD != n.FD {
			return false
		}
		same := o.Released == n.Released && timePtrEqual(o.AuthorisedUntil, n.AuthorisedUntil)
		if same {
			continue
		}
		if changed >= 0 || o.Released || !n.Released || n.AuthorisedUntil == nil {
			return false // at most one change: unreleased -> released
		}
		changed = i
	}
	if old.Status != "started" {
		return changed < 0 && next.Status == old.Status && timePtrEqual(old.FinishedAt, next.FinishedAt)
	}
	if changed >= 0 {
		// the first unreleased role, with a bounded authorisation
		for j := 0; j < changed; j++ {
			if !old.Roles[j].Released {
				return false
			}
		}
		u := *next.Roles[changed].AuthorisedUntil
		return next.Status == "started" && next.FinishedAt == nil && !u.Before(old.StartedAt.Add(-time.Second)) && !u.After(old.Deadline)
	}
	switch next.Status {
	case "started":
		return next.FinishedAt == nil
	case "completed":
		for _, r := range next.Roles {
			if !r.Released {
				return false
			}
		}
		return next.FinishedAt != nil && !next.FinishedAt.Before(old.StartedAt.Add(-time.Second))
	case "failed", "unknown":
		return next.FinishedAt != nil && !next.FinishedAt.Before(old.StartedAt.Add(-time.Second))
	}
	return false
}
