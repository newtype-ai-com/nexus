package nexus

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/seal"
)

// Certificate contains an immutable snapshot, not live authorization. Container
// credentials remain disabled until verified root passkey signatures exist.
type Certificate struct {
	Version   string              `json:"v"`
	ID        ids.Delegation      `json:"id"`
	Issuer    string              `json:"issuer"`
	AccountID ids.Account         `json:"account_id"`
	Principal Principal           `json:"principal"`
	Delegator Principal           `json:"delegator"`
	Delegate  CertificateDelegate `json:"delegate"`
	Task      *CertificateTask    `json:"task,omitempty"`
	ParentID  ids.Delegation      `json:"parent_id,omitempty"`
	RootID    ids.Delegation      `json:"root_id"`
	Depth     int                 `json:"depth"`
	Scope     []string            `json:"scope"`
	Policy    PolicyRef           `json:"policy"`
	Rules     []Rule              `json:"rules"`
	Approver  string              `json:"approver"`
	Limits    Limits              `json:"limits"`
	IssuedAt  time.Time           `json:"issued_at"`
	ExpiresAt time.Time           `json:"expires_at"`
	Chain     []CertLink          `json:"chain"`
}

type CertificateDelegate struct {
	SessionID ids.Session `json:"session_id"`
	Agent     string      `json:"agent"`
}

type CertificateTask struct {
	ID           ids.Task `json:"id"`
	Title        string   `json:"title"`
	ParentTaskID ids.Task `json:"parent_task_id,omitempty"`
}

type CertLink struct {
	ID        ids.Delegation `json:"id"`
	Delegator Principal      `json:"delegator"`
	Delegate  ids.Session    `json:"delegate"`
	TaskID    ids.Task       `json:"task_id,omitempty"`
	Scope     []string       `json:"scope"`
	Rules     []Rule         `json:"rules"`
	Approver  string         `json:"approver"`
	ExpiresAt time.Time      `json:"expires_at"`
}

type Credential struct {
	DelegationID ids.Delegation `json:"delegation_id"`
	TaskID       ids.Task       `json:"task_id,omitempty"`
	seal.Sealed
	ExpiresAt time.Time `json:"expires_at"`
}

// NewServiceWithSealing configures immutable keys before serving any requests.
// Existing NewService deliberately keeps credential issuance disabled.
func NewServiceWithSealing(store Store, clock func() time.Time, sealer *seal.Sealer, issuer string) (*Service, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || sealer == nil || sealer.Signer == nil || sealer.Deriver == nil {
		return nil, ErrInvalid
	}
	s := NewService(store, clock)
	copy := *sealer
	s.sealer, s.issuer = &copy, issuer
	return s, nil
}

func (s *Service) DelegationKeys() []seal.PublicKey {
	if s.sealer == nil {
		return nil
	}
	return s.sealer.Signer.Keys()
}

func certPolicy(tx Tx, d Delegation) (Policy, error) {
	p, err := tx.Policy(d.Policy.ID, d.Policy.Version)
	if err != nil {
		return Policy{}, err
	}
	if p.AccountID != d.AccountID || p.Hash() != d.Policy.Hash {
		return Policy{}, ErrConflict
	}
	if _, err := normalizeRules(p.Rules); err != nil {
		return Policy{}, ErrConflict
	}
	if _, err := normalizeApprover(p.Approver); err != nil {
		return Policy{}, ErrConflict
	}
	return p, nil
}

func certificate(tx Tx, d Delegation, issuer string) (Certificate, error) {
	p, err := certPolicy(tx, d)
	if err != nil {
		return Certificate{}, err
	}
	c := Certificate{Version: "newtype.delegation/2", ID: d.ID, Issuer: issuer, AccountID: d.AccountID, Principal: d.Principal, Delegator: d.Delegator, Delegate: CertificateDelegate{d.Delegate, "newtype"}, ParentID: d.ParentID, RootID: d.RootID, Depth: d.Depth, Scope: d.Scope, Policy: d.Policy, Rules: p.Rules, Approver: p.Approver, Limits: d.Limits, IssuedAt: d.IssuedAt, ExpiresAt: d.ExpiresAt, Chain: []CertLink{}}
	if d.Task != "" {
		t, err := taskIn(tx, d.AccountID, d.Task)
		if err != nil {
			return Certificate{}, err
		}
		c.Task = &CertificateTask{t.ID, t.Title, t.ParentID}
	}
	// liveChain was checked in this same transaction, including cycle bounds.
	for d.ParentID != "" {
		d, err = delegationIn(tx, d.AccountID, d.ParentID)
		if err != nil {
			return Certificate{}, err
		}
		p, err = certPolicy(tx, d)
		if err != nil {
			return Certificate{}, err
		}
		if d.Principal != c.Principal {
			return Certificate{}, ErrConflict
		}
		c.Chain = append(c.Chain, CertLink{d.ID, d.Delegator, d.Delegate, d.Task, d.Scope, p.Rules, p.Approver, d.ExpiresAt})
	}
	if d.ID != c.RootID || len(c.Chain) != c.Depth {
		return Certificate{}, ErrConflict
	}
	return c, nil
}

// Credentials issues only to the exact authenticated delegate, atomically with
// a metadata-only audit event. Nothing secret is ever passed to the Store.
func (s *Service) Credentials(ctx context.Context, actor Principal, session ids.Session) ([]Credential, error) {
	if actor.Kind != PrincipalSession || actor.SessionID != session {
		return nil, ErrForbidden
	}
	if s.sealer == nil {
		return nil, ErrInvalid
	}
	var out []Credential
	err := s.update(ctx, actor, func(tx Tx) error {
		out = nil // Store.Update may retry after a serialization failure.
		grants, err := held(tx, actor, s.now())
		if err != nil {
			return err
		}
		target, err := sessionIn(tx, actor.AccountID, session)
		if err != nil {
			return err
		}
		if target.Runner != Local {
			return ErrForbidden
		}
		issued := make([]map[string]string, 0, len(grants))
		for _, d := range grants {
			c, err := certificate(tx, d, s.issuer)
			if err != nil {
				return err
			}
			payload, err := json.Marshal(c)
			if err != nil {
				return err
			}
			sealed, err := s.sealer.Seal(ctx, string(actor.AccountID), string(d.ID), string(session), payload)
			if err != nil {
				return err
			}
			out = append(out, Credential{d.ID, d.Task, sealed, d.ExpiresAt})
			issued = append(issued, map[string]string{"delegation_id": string(d.ID), "kid": sealed.KID})
		}
		_, err = hubEvent(tx, actor, session, "", "credentials.issued", map[string]any{"issued": issued}, s.now())
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Can evaluates the immutable chain only. A caller must intersect this result
// with Nexus live authorization; revocation cannot be detected offline.
func (c Certificate) Can(action string, now time.Time) Decision {
	deny := Decision{Effect: "deny"}
	if !validAction(action, false) || c.Version != "newtype.delegation/2" || !now.Before(c.ExpiresAt) || len(c.Chain) != c.Depth {
		return deny
	}
	links := append([]CertLink{{Scope: c.Scope, Rules: c.Rules, Approver: c.Approver, ExpiresAt: c.ExpiresAt}}, c.Chain...)
	result := Decision{}
	rank := map[string]int{"": -1, "auto": 0, "ask": 1, "deny": 2}
	for _, link := range links {
		if !now.Before(link.ExpiresAt) {
			return deny
		}
		if required := requiredScope(action); required != "" && !covers(link.Scope, required) {
			return deny
		}
		if _, err := normalizeRules(link.Rules); err != nil {
			return deny
		}
		if _, err := normalizeApprover(link.Approver); err != nil {
			return deny
		}
		p := Policy{Rules: link.Rules, Approver: link.Approver}
		effect, mentioned := p.decide(action)
		if !mentioned {
			continue
		}
		if rank[effect] > rank[result.Effect] {
			result.Effect = effect
		}
		if effect == "ask" && (result.Approver == "" || p.Approver == "user" || p.Approver == "") {
			result.Approver = p.Approver
			if result.Approver == "" {
				result.Approver = "user"
			}
		}
	}
	if result.Effect == "" {
		return deny
	}
	if result.Effect != "ask" {
		result.Approver = ""
	}
	return result
}

// OpenCredential verifies the pinned server keys AND all caller-known identity
// bindings. It never fetches a signing key from the untrusted certificate.
func OpenCredential(credential Credential, keys []seal.PublicKey, account ids.Account, session ids.Session, issuer string, now time.Time) (Certificate, error) {
	jws, kid, err := seal.Open(credential.Sealed.Sealed, credential.Key)
	if err != nil {
		return Certificate{}, seal.ErrOpen
	}
	if kid != credential.KID+":"+string(credential.DelegationID)+":"+string(session) {
		return Certificate{}, seal.ErrOpen
	}
	payload, err := seal.Verify(jws, keys)
	if err != nil {
		return Certificate{}, seal.ErrOpen
	}
	var c Certificate
	if json.Unmarshal(payload, &c) != nil || c.Version != "newtype.delegation/2" || c.ID != credential.DelegationID || c.AccountID != account || c.Delegate.SessionID != session || c.Delegate.Agent != "newtype" || c.Issuer != issuer || !now.Before(c.ExpiresAt) || now.Before(c.IssuedAt) || !credential.ExpiresAt.Equal(c.ExpiresAt) || c.Depth != len(c.Chain) {
		return Certificate{}, seal.ErrOpen
	}
	if (c.Task == nil && credential.TaskID != "") || (c.Task != nil && c.Task.ID != credential.TaskID) {
		return Certificate{}, seal.ErrOpen
	}
	for _, link := range c.Chain {
		if !now.Before(link.ExpiresAt) {
			return Certificate{}, seal.ErrOpen
		}
	}
	return c, nil
}
