package nexus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/redact"
)

// Execution grants (NMCP stage 3, decision 2026-10-04): a person lets Nexus messages
// from named sender sessions drive tool calls in one receiving session, inside a
// tool and path scope, for a bounded time and number of turns. A message stays a
// request, never authority: the receiving engine asks DecideExecutionGrant before
// every tool call of a Nexus-originated turn, and only "allow" runs without a
// person. Anything outside the grant is "ask" (the person decides locally, or the
// call is refused when nobody is present) or "deny".
//
// Storage is the receiving session's ledger, like durable executions: fixed keys
// "xgrant:<id>:issued|revoked", one "xgrant:<id>:turn:<n>" plus a
// "xgrant:<id>:src:<event>" index per counted source message, and one
// execution_grant.decided record per decision. No new table or migration.

const (
	maxGrantTTL      = 7 * 24 * time.Hour
	maxGrantTurns    = 1000
	maxGrantSenders  = 16
	maxGrantTools    = 32
	maxGrantPaths    = 16
	maxDecisionPaths = 32
)

// ExecutionGrant is issued by a person only. Paths are absolute, clean paths on the
// receiver's machine; "P/**" covers P and everything below it, otherwise exact.
type ExecutionGrant struct {
	ID         string         `json:"id"`
	AccountID  ids.Account    `json:"account_id"`
	Grantor    Principal      `json:"grantor"`
	Receiver   ids.Session    `json:"receiver"`
	Delegation ids.Delegation `json:"delegation_id"`
	Senders    []ids.Session  `json:"senders"`
	Tools      []string       `json:"tools"`
	Paths      []string       `json:"paths"`
	MaxTurns   int            `json:"max_turns"`
	IssuedAt   time.Time      `json:"issued_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Note       string         `json:"note,omitempty"`
	// Views only (computed, never stored in the issued record). IssuedSeq is the
	// ledger position of the issued record: a source message must come after it.
	Status    string `json:"status,omitempty"`
	TurnsUsed int    `json:"turns_used,omitempty"`
	IssuedSeq int64  `json:"issued_seq,omitempty"`
}

// GrantDecisionInput comes from the receiving engine before ONE tool call.
type GrantDecisionInput struct {
	SourceEvent ids.Event `json:"source_event"`
	SourceSeq   int64     `json:"source_seq"`
	Action      string    `json:"action"`
	Paths       []string  `json:"paths"`
	InputHash   string    `json:"input_hash"`
}

// GrantDecision: Effect is allow | ask | deny. Turn is the grant turn the source
// message was counted as (0 when nothing was counted).
type GrantDecision struct {
	Effect    string `json:"effect"`
	Reason    string `json:"reason,omitempty"`
	Turn      int    `json:"turn,omitempty"`
	TurnsLeft int    `json:"turns_left"`
}

func validGrantID(id string) bool { return ids.Check(ids.KindGrant, id) == nil }

func cleanGrantPath(p string, pattern bool) (string, bool) {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\r\n") || len(p) > 1024 {
		return "", false
	}
	base, deep := p, false
	if pattern && strings.HasSuffix(p, "/**") {
		base, deep = strings.TrimSuffix(p, "/**"), true
		if base == "" {
			return "", false // "/**" would cover the whole machine
		}
	}
	if strings.Contains(base, "*") || path.Clean(base) != base {
		return "", false
	}
	if deep {
		return base + "/**", true
	}
	return base, true
}

func grantCoversPath(patterns []string, p string) bool {
	for _, pat := range patterns {
		if base, deep := strings.CutSuffix(pat, "/**"); deep {
			if p == base || strings.HasPrefix(p, base+"/") {
				return true
			}
		} else if p == pat {
			return true
		}
	}
	return false
}

func grantCoversTool(tools []string, action string) bool {
	for _, t := range tools {
		if t == action || (strings.HasSuffix(t, "*") && strings.HasPrefix(action, strings.TrimSuffix(t, "*"))) {
			return true
		}
	}
	return false
}

func grantKey(id, part string) string { return "xgrant:" + id + ":" + part }

func grantEvent(tx Tx, g ExecutionGrant, kind, key string, actor Principal, payload any, now time.Time) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.AppendEvent(Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: g.AccountID, SessionID: g.Receiver,
		At: now.UTC(), Source: "hub", Kind: kind, Actor: actor, ClientEventID: key, Payload: raw, PayloadHash: hashPayload(raw)})
	return err
}

// grantIn reads the issued record and lifecycle of one grant in a session ledger.
func grantIn(tx Tx, account ids.Account, receiver ids.Session, id string) (ExecutionGrant, bool, error) {
	var g ExecutionGrant
	e, err := tx.EventByClientID(receiver, grantKey(id, "issued"))
	if err != nil {
		return g, false, err
	}
	if e.AccountID != account || e.Source != "hub" || e.Kind != "execution_grant.issued" || e.Actor.Kind != PrincipalUser {
		return g, false, ErrConflict
	}
	if json.Unmarshal(e.Payload, &g) != nil || g.ID != id || g.Receiver != receiver || g.AccountID != account {
		return ExecutionGrant{}, false, ErrConflict
	}
	g.IssuedSeq = e.Seq
	revoked := false
	if r, err := tx.EventByClientID(receiver, grantKey(id, "revoked")); err == nil {
		revoked = r.Source == "hub" && r.Kind == "execution_grant.revoked"
		if !revoked {
			return ExecutionGrant{}, false, ErrConflict
		}
	} else if !errors.Is(err, ErrNotFound) {
		return ExecutionGrant{}, false, err
	}
	return g, revoked, nil
}

func grantTurnsUsed(tx Tx, g ExecutionGrant) (int, error) {
	n := 0
	for n < g.MaxTurns {
		_, err := tx.EventByClientID(g.Receiver, grantKey(g.ID, "turn:"+strconv.Itoa(n+1)))
		if errors.Is(err, ErrNotFound) {
			break
		}
		if err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

func grantView(tx Tx, g ExecutionGrant, revoked bool, now time.Time) (ExecutionGrant, error) {
	used, err := grantTurnsUsed(tx, g)
	if err != nil {
		return g, err
	}
	g.TurnsUsed = used
	switch {
	case revoked:
		g.Status = "revoked"
	case !now.Before(g.ExpiresAt):
		g.Status = "expired"
	case used >= g.MaxTurns:
		g.Status = "exhausted"
	default:
		g.Status = "active"
	}
	return g, nil
}

// IssueExecutionGrant: a person only. The receiver must hold Delegation live; the
// grant never outlives it (revoking the delegation ends every grant on it).
func (s *Service) IssueExecutionGrant(ctx context.Context, actor Principal, g ExecutionGrant, ttl time.Duration) (ExecutionGrant, error) {
	if actor.Kind != PrincipalUser {
		return ExecutionGrant{}, ErrForbidden
	}
	if ttl <= 0 || ttl > maxGrantTTL || g.MaxTurns < 1 || g.MaxTurns > maxGrantTurns || len(g.Note) > 512 ||
		len(g.Senders) == 0 || len(g.Senders) > maxGrantSenders || len(g.Tools) == 0 || len(g.Tools) > maxGrantTools ||
		len(g.Paths) == 0 || len(g.Paths) > maxGrantPaths || ids.Check(ids.KindSession, string(g.Receiver)) != nil {
		return ExecutionGrant{}, ErrInvalid
	}
	seen := map[ids.Session]bool{}
	for _, sender := range g.Senders {
		if ids.Check(ids.KindSession, string(sender)) != nil || sender == g.Receiver || seen[sender] {
			return ExecutionGrant{}, ErrInvalid
		}
		seen[sender] = true
	}
	for _, t := range g.Tools {
		if !strings.HasPrefix(t, "tool:") || t == "tool:" || !validAction(t, true) {
			return ExecutionGrant{}, ErrInvalid
		}
	}
	paths := make([]string, 0, len(g.Paths))
	for _, p := range g.Paths {
		clean, ok := cleanGrantPath(p, true)
		if !ok {
			return ExecutionGrant{}, ErrInvalid
		}
		paths = append(paths, clean)
	}
	note, _ := redact.Text(strings.TrimSpace(g.Note))
	var out ExecutionGrant
	err := s.update(ctx, actor, func(tx Tx) error {
		out = ExecutionGrant{}
		if _, err := sessionIn(tx, actor.AccountID, g.Receiver); err != nil {
			return err
		}
		for _, sender := range g.Senders {
			from, err := sessionIn(tx, actor.AccountID, sender)
			if err != nil {
				return err
			}
			if from.Runner == Remote {
				return ErrForbidden // a remote MCP connection never drives local tool execution
			}
		}
		d, err := delegationIn(tx, actor.AccountID, g.Delegation)
		if err != nil {
			return err
		}
		if d.Delegate != g.Receiver {
			return ErrForbidden
		}
		now := s.now()
		if err = liveChain(tx, actor.AccountID, d, now); err != nil {
			return err
		}
		expires := now.Add(ttl)
		if !d.ExpiresAt.IsZero() && d.ExpiresAt.Before(expires) {
			expires = d.ExpiresAt
		}
		out = ExecutionGrant{ID: string(ids.New(ids.KindGrant)), AccountID: actor.AccountID, Grantor: actor, Receiver: g.Receiver,
			Delegation: d.ID, Senders: append([]ids.Session(nil), g.Senders...), Tools: append([]string(nil), g.Tools...),
			Paths: paths, MaxTurns: g.MaxTurns, IssuedAt: now.UTC(), ExpiresAt: expires.UTC(), Note: note}
		return grantEvent(tx, out, "execution_grant.issued", grantKey(out.ID, "issued"), actor, out, now)
	})
	if err != nil {
		return ExecutionGrant{}, err
	}
	out.Status = "active"
	return out, nil
}

// RevokeExecutionGrant: the person, or the receiving session giving it up.
func (s *Service) RevokeExecutionGrant(ctx context.Context, actor Principal, receiver ids.Session, id, reason string) (ExecutionGrant, error) {
	if !validGrantID(id) || ids.Check(ids.KindSession, string(receiver)) != nil || len(reason) > 256 {
		return ExecutionGrant{}, ErrInvalid
	}
	if actor.Kind != PrincipalUser && !(actor.Kind == PrincipalSession && actor.SessionID == receiver) {
		return ExecutionGrant{}, ErrForbidden
	}
	var out ExecutionGrant
	err := s.update(ctx, actor, func(tx Tx) error {
		g, revoked, err := grantIn(tx, actor.AccountID, receiver, id)
		if err != nil {
			return err
		}
		if !revoked {
			payload := map[string]string{"grant_id": id, "reason": strings.TrimSpace(reason)}
			if err = grantEvent(tx, g, "execution_grant.revoked", grantKey(id, "revoked"), actor, payload, s.now()); err != nil {
				return err
			}
		}
		out, err = grantView(tx, g, true, s.now())
		return err
	})
	return out, err
}

// ExecutionGrants lists the grants recorded in one session's ledger (the person,
// or that session itself).
func (s *Service) ExecutionGrants(ctx context.Context, actor Principal, receiver ids.Session) ([]ExecutionGrant, error) {
	if ids.Check(ids.KindSession, string(receiver)) != nil {
		return nil, ErrInvalid
	}
	if actor.Kind != PrincipalUser && !(actor.Kind == PrincipalSession && actor.SessionID == receiver) {
		return nil, ErrForbidden
	}
	var out []ExecutionGrant
	err := s.view(ctx, actor, func(tx Tx) error {
		out = []ExecutionGrant{}
		if _, err := sessionIn(tx, actor.AccountID, receiver); err != nil {
			return err
		}
		for after := int64(0); ; {
			events, err := tx.Events(receiver, after, MaxBatch)
			if err != nil {
				return err
			}
			for _, e := range events {
				after = e.Seq
				if e.Kind != "execution_grant.issued" || e.Source != "hub" {
					continue
				}
				id := strings.TrimSuffix(strings.TrimPrefix(e.ClientEventID, "xgrant:"), ":issued")
				g, revoked, err := grantIn(tx, actor.AccountID, receiver, id)
				if err != nil {
					return err
				}
				if g, err = grantView(tx, g, revoked, s.now()); err != nil {
					return err
				}
				out = append(out, g)
			}
			if len(events) < MaxBatch {
				return nil
			}
		}
	})
	return out, err
}

// DecideExecutionGrant: the receiving session asks before one tool call of a turn
// started by an inbox message. Order: grant live -> source message genuine, from an
// allowed sender, sent after the grant -> tool and every path inside the scope ->
// the delegation chain's own policy still allows the action -> the turn limit. Every
// decision (allow, ask, deny) is recorded as execution_grant.decided.
func (s *Service) DecideExecutionGrant(ctx context.Context, actor Principal, id string, in GrantDecisionInput) (GrantDecision, error) {
	if actor.Kind != PrincipalSession {
		return GrantDecision{Effect: "deny"}, ErrForbidden
	}
	if !validGrantID(id) || ids.Check(ids.KindEvent, string(in.SourceEvent)) != nil || in.SourceSeq < 1 ||
		!strings.HasPrefix(in.Action, "tool:") || !validAction(in.Action, false) || len(in.Paths) == 0 ||
		len(in.Paths) > maxDecisionPaths || len(in.InputHash) != 64 {
		return GrantDecision{Effect: "deny"}, ErrInvalid
	}
	if _, err := hex.DecodeString(in.InputHash); err != nil {
		return GrantDecision{Effect: "deny"}, ErrInvalid
	}
	for _, p := range in.Paths {
		if _, ok := cleanGrantPath(p, false); !ok {
			return GrantDecision{Effect: "deny"}, ErrInvalid
		}
	}
	var out GrantDecision
	err := s.update(ctx, actor, func(tx Tx) error {
		out = GrantDecision{Effect: "deny"}
		g, revoked, err := grantIn(tx, actor.AccountID, actor.SessionID, id)
		if err != nil {
			return err
		}
		now := s.now()
		used, err := grantTurnsUsed(tx, g)
		if err != nil {
			return err
		}
		out.TurnsLeft = g.MaxTurns - used
		record := func() error {
			payload := map[string]any{"grant_id": g.ID, "source_event": in.SourceEvent, "action": in.Action,
				"paths": in.Paths, "input_hash": in.InputHash, "effect": out.Effect, "reason": out.Reason, "turn": out.Turn}
			return grantEvent(tx, g, "execution_grant.decided", "", actor, payload, now)
		}
		deny := func(reason string) error { out.Effect, out.Reason = "deny", reason; return record() }
		ask := func(reason string) error { out.Effect, out.Reason = "ask", reason; return record() }
		switch {
		case revoked:
			return deny("grant revoked")
		case !now.Before(g.ExpiresAt):
			return deny("grant expired")
		}
		// the source message: exactly that event of this ledger, a genuine inbox
		// message from a granted sender session, sent after the grant was issued
		events, err := tx.Events(actor.SessionID, in.SourceSeq-1, 1)
		if err != nil {
			return err
		}
		if len(events) != 1 || events[0].ID != in.SourceEvent || events[0].Seq != in.SourceSeq {
			return deny("source message not found")
		}
		src := events[0]
		allowed := false
		for _, sender := range g.Senders {
			allowed = allowed || src.Actor.SessionID == sender
		}
		if !ForInbox(src) || src.Kind != "message" || src.Actor.Kind != PrincipalSession || !allowed {
			return deny("source is not a message from a granted sender")
		}
		// ledger order, not clocks: the message must follow the issued record
		if src.Seq <= g.IssuedSeq {
			return deny("message predates the grant")
		}
		if !grantCoversTool(g.Tools, in.Action) {
			return ask("tool outside the grant")
		}
		for _, p := range in.Paths {
			if !grantCoversPath(g.Paths, p) {
				return ask("path outside the grant")
			}
		}
		d, err := delegationIn(tx, actor.AccountID, g.Delegation)
		if err != nil {
			return err
		}
		policy, err := decide(tx, actor.AccountID, d, in.Action, now)
		if err != nil {
			if errors.Is(err, ErrRevoked) || errors.Is(err, ErrExpired) {
				return deny("delegation is no longer live")
			}
			return err
		}
		switch policy.Effect {
		case "deny":
			return deny("delegation policy denies: " + policy.Reason)
		case "ask":
			return ask("delegation policy requires approval")
		}
		// one turn per distinct source message
		if e, err := tx.EventByClientID(actor.SessionID, grantKey(g.ID, "src:"+string(src.ID))); err == nil {
			var p struct {
				Turn int `json:"turn"`
			}
			if json.Unmarshal(e.Payload, &p) != nil || p.Turn < 1 {
				return ErrConflict
			}
			out.Turn = p.Turn
		} else if !errors.Is(err, ErrNotFound) {
			return err
		} else {
			if used >= g.MaxTurns {
				return deny("turn limit reached")
			}
			out.Turn = used + 1
			turn := map[string]any{"grant_id": g.ID, "turn": out.Turn, "source_event": src.ID}
			if err = grantEvent(tx, g, "execution_grant.turn", grantKey(g.ID, "turn:"+strconv.Itoa(out.Turn)), actor, turn, now); err != nil {
				return err
			}
			if err = grantEvent(tx, g, "execution_grant.turn_source", grantKey(g.ID, "src:"+string(src.ID)), actor, turn, now); err != nil {
				return err
			}
			out.TurnsLeft = g.MaxTurns - out.Turn
		}
		out.Effect, out.Reason = "allow", ""
		return record()
	})
	if err != nil {
		return GrantDecision{Effect: "deny"}, err
	}
	return out, nil
}
