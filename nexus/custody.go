package nexus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// CustodyVersion names the custody read contract. Every custody response
// carries it; a client that does not know the version refuses the response.
const CustodyVersion = "newtype.custody/1"

// CustodyListLimit bounds a by-hash listing. Above it the listing is refused
// (ErrConflict) rather than returned partially: "complete" must stay true.
const CustodyListLimit = 64

// CustodyApproval is an exact-input, single-use approval owned by Nexus. Only
// pending, approved, denied and used are stored; expired and revoked are read
// time conditions. There are no standing custody approvals.
type CustodyApproval struct {
	ID         ids.Approval   `json:"id"`
	AccountID  ids.Account    `json:"account_id"`
	SessionID  ids.Session    `json:"session_id"`
	Delegation ids.Delegation `json:"delegation_id"`
	Action     string         `json:"action"`
	InputHash  string         `json:"input_hash"`
	Status     string         `json:"status"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	DecidedAt  *time.Time     `json:"decided_at"`
	DecidedBy  string         `json:"decided_by"`
	UsedAt     *time.Time     `json:"used_at"`
}

// CustodyApprovalView is the wire form: every key is always present (no
// omitempty), booleans are literal and absent times are null.
type CustodyApprovalView struct {
	ID         ids.Approval   `json:"id"`
	SessionID  ids.Session    `json:"session_id"`
	Delegation ids.Delegation `json:"delegation_id"`
	Action     string         `json:"action"`
	InputHash  string         `json:"input_hash"`
	Status     string         `json:"status"`
	Standing   bool           `json:"standing"`
	Revoked    bool           `json:"revoked"`
	Usable     bool           `json:"usable"`
	CreatedAt  string         `json:"created_at"`
	ExpiresAt  string         `json:"expires_at"`
	DecidedAt  *string        `json:"decided_at"`
	DecidedBy  *string        `json:"decided_by"`
	UsedAt     *string        `json:"used_at"`
}

// CustodyDelegationView states a delegation's liveness explicitly. Ended and
// revoked are not synonyms: revoked is only end_reason "revoked".
type CustodyDelegationView struct {
	Version   string         `json:"version"`
	ID        ids.Delegation `json:"id"`
	Delegate  ids.Session    `json:"delegate"`
	ExpiresAt string         `json:"expires_at"`
	Ended     bool           `json:"ended"`
	EndReason *string        `json:"end_reason"`
	Revoked   bool           `json:"revoked"`
	Live      bool           `json:"live"`
	// SessionActive: the delegate session is neither suspended, stopped nor
	// done. Live describes the delegation chain only; consumption needs both.
	SessionActive bool `json:"session_active"`
}

func custodyTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Whole seconds, never toward "fresher": a start/decision/use instant is
// rounded UP, an expiry DOWN.
func ceilSecond(t time.Time) time.Time {
	t = t.UTC()
	if f := t.Truncate(time.Second); !f.Equal(t) {
		return f.Add(time.Second)
	}
	return t
}
func floorSecond(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }
func custodyTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := custodyTime(*t)
	return &s
}

// ValidCustodyHash accepts exactly "sha256:" + 64 lowercase hex. Every store
// implementation uses this one check.
func ValidCustodyHash(h string) bool { return validCustodyHash(h) }

// CustodyTransitionOK is the storage-level rule shared by every Tx. The
// identity of an approval (account, session, delegation, action, input hash,
// creation and expiry) never changes. The allowed status moves are exactly:
//
//	pending  -> pending (unchanged record)
//	pending  -> approved | denied   (decision fields set, no use)
//	approved -> approved (unchanged record)
//	approved -> used                (decision kept as is, use set)
//	denied, used -> the identical record (terminal history)
//
// Anything else, including clearing or rewriting decision/use evidence, is
// refused. A record is also internally consistent: pending has no decision
// or use; approved/denied have a decision and no use; used has both.
func CustodyTransitionOK(old, next CustodyApproval) bool {
	if old.AccountID != next.AccountID || old.SessionID != next.SessionID || old.Delegation != next.Delegation ||
		old.Action != next.Action || old.InputHash != next.InputHash || !old.CreatedAt.Equal(next.CreatedAt) || !old.ExpiresAt.Equal(next.ExpiresAt) {
		return false
	}
	if !custodyConsistent(next) {
		return false
	}
	sameDecision := timePtrEqual(old.DecidedAt, next.DecidedAt) && old.DecidedBy == next.DecidedBy
	sameUse := timePtrEqual(old.UsedAt, next.UsedAt)
	switch old.Status {
	case "pending":
		return (next.Status == "pending" && sameDecision && sameUse) || next.Status == "approved" || next.Status == "denied"
	case "approved":
		return (next.Status == "approved" || next.Status == "used") && sameDecision && (next.Status == "used" || sameUse)
	case "denied", "used":
		return next.Status == old.Status && sameDecision && sameUse
	}
	return false
}

func custodyConsistent(x CustodyApproval) bool {
	decided := x.DecidedAt != nil && x.DecidedBy != ""
	if (x.DecidedAt == nil) != (x.DecidedBy == "") {
		return false
	}
	switch x.Status {
	case "pending":
		return !decided && x.UsedAt == nil
	case "approved", "denied":
		return decided && x.UsedAt == nil
	case "used":
		return decided && x.UsedAt != nil && !x.UsedAt.Before(*x.DecidedAt)
	}
	return false
}

// custodyConsistentNew: the only valid first write is an empty pending record.
func custodyConsistentNew(x CustodyApproval) bool {
	return x.Status == "pending" && custodyConsistent(x)
}

// CustodyNewOK is the same first-write rule for other Tx implementations.
func CustodyNewOK(x CustodyApproval) bool { return custodyConsistentNew(x) }

func timePtrEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// validCustodyHash accepts exactly "sha256:" + 64 lowercase hex.
func validCustodyHash(h string) bool {
	rest, ok := strings.CutPrefix(h, "sha256:")
	if !ok || len(rest) != 64 || strings.ToLower(rest) != rest {
		return false
	}
	_, err := hex.DecodeString(rest)
	return err == nil
}

func (s *Service) custodyView(tx Tx, x CustodyApproval) CustodyApprovalView {
	now := s.now()
	v := CustodyApprovalView{ID: x.ID, SessionID: x.SessionID, Delegation: x.Delegation, Action: x.Action,
		InputHash: x.InputHash, Status: x.Status, CreatedAt: custodyTime(x.CreatedAt), ExpiresAt: custodyTime(x.ExpiresAt),
		DecidedAt: custodyTimePtr(x.DecidedAt), UsedAt: custodyTimePtr(x.UsedAt)}
	if x.DecidedBy != "" {
		by := x.DecidedBy
		v.DecidedBy = &by
	}
	d, err := delegationIn(tx, x.AccountID, x.Delegation)
	v.Revoked = err != nil || liveChain(tx, x.AccountID, d, now) != nil
	// A stored "used" (or "denied") is history and is never rewritten; only an
	// open approval reads as expired or revoked. Usable is the current validity.
	if x.Status == "pending" || x.Status == "approved" {
		switch {
		case v.Revoked:
			v.Status = "revoked"
		case !now.Before(x.ExpiresAt):
			v.Status = "expired"
		}
	}
	v.Usable = v.Status == "approved"
	if v.Usable {
		if _, err := s.custodyGate(tx, x.AccountID, x.SessionID, x.Delegation, x.Action); err != nil {
			v.Usable = false // e.g. the delegate session is suspended or the policy changed
		}
	}
	return v
}

// custodyGate: the delegation must be the session's own, live, and decide the
// action as ask with the person as approver. auto (no approval needed) and
// deny are both refused for custody.
func (s *Service) custodyGate(tx Tx, account ids.Account, session ids.Session, id ids.Delegation, action string) (Delegation, error) {
	d, err := delegationIn(tx, account, id)
	if err != nil {
		return Delegation{}, err
	}
	if d.Delegate != session {
		return Delegation{}, ErrForbidden
	}
	decision, err := decide(tx, account, d, action, s.now())
	if err != nil {
		return Delegation{}, err
	}
	if decision.Effect != "ask" || (decision.Approver != "" && decision.Approver != "user") {
		return Delegation{}, ErrForbidden
	}
	return d, nil
}

func custodyEvent(tx Tx, x CustodyApproval, phase string, actor Principal, now time.Time) error {
	raw, err := json.Marshal(struct {
		ID        ids.Approval `json:"approval_id"`
		Action    string       `json:"action"`
		InputHash string       `json:"input_hash"`
		Status    string       `json:"status"`
	}{x.ID, x.Action, x.InputHash, x.Status})
	if err != nil {
		return err
	}
	_, err = tx.AppendEvent(Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: x.AccountID, SessionID: x.SessionID,
		At: now.UTC(), Source: "hub", Kind: "custody_approval." + phase, Actor: actor,
		ClientEventID: "custody:" + string(x.ID) + ":" + phase, Payload: raw, PayloadHash: hashPayload(raw)})
	return err
}

func custodyFor(tx Tx, actor Principal, id ids.Approval) (CustodyApproval, error) {
	x, err := tx.CustodyApproval(id)
	if err != nil {
		return CustodyApproval{}, err
	}
	if x.AccountID != actor.AccountID {
		return CustodyApproval{}, ErrNotFound
	}
	if actor.Kind == PrincipalSession && x.SessionID != actor.SessionID {
		return CustodyApproval{}, ErrNotFound
	}
	return x, nil
}

// RequestCustodyApproval opens one pending approval for an exact input.
func (s *Service) RequestCustodyApproval(ctx context.Context, actor Principal, delegation ids.Delegation, action, inputHash string, ttl time.Duration) (CustodyApprovalView, error) {
	if actor.Kind != PrincipalSession {
		return CustodyApprovalView{}, ErrForbidden
	}
	if !validAction(action, false) || !validCustodyHash(inputHash) || ttl < time.Second || ttl > 24*time.Hour {
		return CustodyApprovalView{}, ErrInvalid
	}
	var out CustodyApprovalView
	err := s.update(ctx, actor, func(tx Tx) error {
		out = CustodyApprovalView{}
		if actor.CredentialID != "" {
			// an executor credential may only request plan approvals on its own delegation
			c, err := s.executorIn(tx, actor, true, nil)
			if err != nil || action != "exec:secret-plan" || c.Delegation != delegation {
				return ErrForbidden
			}
		}
		d, err := s.custodyGate(tx, actor.AccountID, actor.SessionID, delegation, action)
		if err != nil {
			return err
		}
		now := ceilSecond(s.now())
		existing, err := tx.CustodyApprovalsByHash(actor.AccountID, inputHash)
		if err != nil {
			return err
		}
		for _, old := range existing {
			if old.SessionID == actor.SessionID && old.Delegation == delegation && old.Action == action &&
				(old.Status == "pending" || old.Status == "approved") && s.now().Before(old.ExpiresAt) {
				return ErrConflict // exactly one open approval per exact input
			}
		}
		exp := floorSecond(s.now().Add(ttl))
		if d.ExpiresAt.Before(exp) {
			exp = floorSecond(d.ExpiresAt)
		}
		if !now.Before(exp) {
			return ErrExpired
		}
		x := CustodyApproval{ID: ids.Approval(ids.New(ids.KindApproval)), AccountID: actor.AccountID, SessionID: actor.SessionID,
			Delegation: delegation, Action: action, InputHash: inputHash, Status: "pending", CreatedAt: now, ExpiresAt: exp}
		if err := tx.PutCustodyApproval(x); err != nil {
			return err
		}
		if err := custodyEvent(tx, x, "requested", actor, now); err != nil {
			return err
		}
		out = s.custodyView(tx, x)
		return nil
	})
	if err != nil {
		return CustodyApprovalView{}, err
	}
	return out, nil
}

// DecideCustodyApproval is the person's decision on an exact input.
func (s *Service) DecideCustodyApproval(ctx context.Context, actor Principal, id ids.Approval, inputHash string, approve bool) (CustodyApprovalView, error) {
	if actor.Kind != PrincipalUser {
		return CustodyApprovalView{}, ErrForbidden
	}
	var out CustodyApprovalView
	err := s.update(ctx, actor, func(tx Tx) error {
		out = CustodyApprovalView{}
		x, err := custodyFor(tx, actor, id)
		if err != nil {
			return err
		}
		if x.Status != "pending" || x.InputHash != inputHash {
			return ErrConflict
		}
		now := ceilSecond(s.now())
		if !s.now().Before(x.ExpiresAt) {
			return ErrExpired
		}
		if _, err := s.custodyGate(tx, x.AccountID, x.SessionID, x.Delegation, x.Action); err != nil {
			return err
		}
		x.Status = "denied"
		if approve {
			x.Status = "approved"
		}
		x.DecidedAt, x.DecidedBy = &now, actor.Email
		if x.DecidedBy == "" {
			x.DecidedBy = "user"
		}
		if err := tx.PutCustodyApproval(x); err != nil {
			return err
		}
		if err := custodyEvent(tx, x, "decided", actor, now); err != nil {
			return err
		}
		out = s.custodyView(tx, x)
		return nil
	})
	if err != nil {
		return CustodyApprovalView{}, err
	}
	return out, nil
}

// UseCustodyApproval consumes the approval exactly once, in one transaction
// with every liveness and policy re-check. A second call is ErrConflict; the
// caller learns the outcome of an uncertain call only by reading it back.
func (s *Service) UseCustodyApproval(ctx context.Context, actor Principal, id ids.Approval, inputHash string) (CustodyApprovalView, error) {
	if actor.Kind != PrincipalSession {
		return CustodyApprovalView{}, ErrForbidden
	}
	var out CustodyApprovalView
	err := s.update(ctx, actor, func(tx Tx) error {
		out = CustodyApprovalView{}
		x, err := custodyFor(tx, actor, id)
		if err != nil {
			return err
		}
		if x.Status != "approved" || x.InputHash != inputHash {
			return ErrConflict
		}
		if !s.now().Before(x.ExpiresAt) {
			return ErrExpired
		}
		if _, err := s.custodyGate(tx, x.AccountID, x.SessionID, x.Delegation, x.Action); err != nil {
			return err
		}
		now := ceilSecond(s.now())
		x.Status, x.UsedAt = "used", &now
		if err := tx.PutCustodyApproval(x); err != nil {
			return err
		}
		if err := custodyEvent(tx, x, "used", actor, now); err != nil {
			return err
		}
		out = s.custodyView(tx, x)
		return nil
	})
	if err != nil {
		return CustodyApprovalView{}, err
	}
	return out, nil
}

func (s *Service) CustodyApproval(ctx context.Context, actor Principal, id ids.Approval) (CustodyApprovalView, error) {
	var out CustodyApprovalView
	err := s.view(ctx, actor, func(tx Tx) error {
		x, err := custodyFor(tx, actor, id)
		if err != nil {
			return err
		}
		if actor.CredentialID != "" {
			// an executor reads only its own delegation's plan approvals, and
			// only while its credential and the plan authority are current
			c, err := s.executorIn(tx, actor, true, nil)
			if err != nil || x.Action != "exec:secret-plan" || x.Delegation != c.Delegation {
				return ErrForbidden
			}
			if _, err := s.custodyGate(tx, actor.AccountID, actor.SessionID, x.Delegation, x.Action); err != nil {
				return ErrForbidden
			}
		}
		out = s.custodyView(tx, x)
		return nil
	})
	return out, err
}

// CustodyApprovals lists every approval for an exact input hash visible to the
// actor (a session sees its own requests, the person the whole account).
func (s *Service) CustodyApprovals(ctx context.Context, actor Principal, inputHash string) ([]CustodyApprovalView, error) {
	if !validCustodyHash(inputHash) {
		return nil, ErrInvalid
	}
	var out []CustodyApprovalView
	err := s.view(ctx, actor, func(tx Tx) error {
		out = []CustodyApprovalView{}
		all, err := tx.CustodyApprovalsByHash(actor.AccountID, inputHash)
		if err != nil {
			return err
		}
		for _, x := range all {
			if actor.Kind == PrincipalSession && x.SessionID != actor.SessionID {
				continue
			}
			if len(out) == CustodyListLimit {
				return ErrConflict // never a partial listing
			}
			out = append(out, s.custodyView(tx, x))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CustodyDelegation is readable by the delegate session itself (unlike
// DelegationInfo) and records no ledger event; it exposes liveness only.
func (s *Service) CustodyDelegation(ctx context.Context, actor Principal, id ids.Delegation) (CustodyDelegationView, error) {
	if actor.Kind != PrincipalSession && actor.Kind != PrincipalUser {
		return CustodyDelegationView{}, ErrForbidden
	}
	var out CustodyDelegationView
	err := s.view(ctx, actor, func(tx Tx) error {
		d, err := delegationIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if actor.Kind == PrincipalSession && d.Delegate != actor.SessionID {
			return ErrForbidden
		}
		out = CustodyDelegationView{Version: CustodyVersion, ID: d.ID, Delegate: d.Delegate, ExpiresAt: custodyTime(d.ExpiresAt),
			Ended: d.EndedAt != nil, Revoked: d.EndedAt != nil && d.EndReason == "revoked"}
		if d.EndedAt != nil {
			reason := d.EndReason
			out.EndReason = &reason
		}
		out.Live = liveChain(tx, actor.AccountID, d, s.now()) == nil
		if sess, err := sessionIn(tx, actor.AccountID, d.Delegate); err == nil {
			out.SessionActive = sess.Status != SessionSuspended && sess.Status != SessionDone && sess.Status != SessionStopped
		}
		return nil
	})
	if err != nil {
		return CustodyDelegationView{}, err
	}
	return out, nil
}
