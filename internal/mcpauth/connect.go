package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/nexusops"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/internal/nmcp"
	"github.com/newtype-ai-com/nexus/nexus"
)

// RemoteRoot is the delegation of every remote connection: the same as the
// local `newtype nmcp serve` seat (tool-only, session:delegate one level, no
// model tokens).
var RemoteRoot = nexusops.Root{Scope: []string{"session:delegate"}, Limits: nexus.Limits{MaxDepth: 1}}

const (
	RemoteTTL      = 8 * time.Hour
	RemoteElicit   = 2 * time.Minute
	MailApprovalTT = 15 * time.Minute
)

// Connector turns a consent into one MCP server: it finds or creates the
// consent's remote session, issues it a fresh root, and runs the contract in
// process as that session (no token reaches /v1).
type Connector struct {
	Store   Store
	Service *nexus.Service
	Handler http.Handler // Nexus's own handler, for in-process calls
	Mail    nexusops.MailApprover
	Version string
}

// NewServer is nmcp.HTTPHandler.NewServer for owner = consent ID. It reuses
// the consent's live remote root (another hour at least) instead of issuing a
// new one on every initialize.
func (c *Connector) NewServer(ctx context.Context, consentID string) (*nmcp.Server, error) {
	consent, err := c.Store.Consent(ctx, consentID)
	if err != nil || consent.Revoked {
		return nil, errors.New("consent unavailable")
	}
	person := nexus.UserPrincipal(consent.Account, consent.Email)
	session, delegation, title, ok := c.liveRoot(ctx, person, consent)
	if !ok {
		req := nexus.RootRequest{Title: "mcp:" + consent.Name, Runner: nexus.Remote, ToSessionID: consent.Session, Scope: RemoteRoot.Scope, Limits: RemoteRoot.Limits, TTL: RemoteTTL}
		issued, err := c.Service.CreateRoot(ctx, person, req)
		if err != nil && consent.Session != "" && (errors.Is(err, nexus.ErrNotFound) || errors.Is(err, nexus.ErrForbidden)) {
			req.ToSessionID = "" // the old session is gone or suspended: a new one
			issued, err = c.Service.CreateRoot(ctx, person, req)
		}
		if err != nil {
			return nil, err
		}
		if issued.Session.Runner != nexus.Remote {
			return nil, errors.New("connection session is not remote")
		}
		session, delegation, title = issued.Session.ID, issued.Delegation.ID, issued.Session.Title
		consent.Session, consent.Delegation = session, delegation
		if err := c.Store.PutConsent(ctx, consent); err != nil {
			return nil, err
		}
	}
	sessionP := nexus.SessionPrincipal(consent.Account, session)
	seat, err := nexusops.InProcessSeat(nexusserver.InProcessEndpoint, nexusserver.InProcessToken,
		nexusserver.InProcess{Handler: c.Handler, Principal: person}, nexusserver.InProcess{Handler: c.Handler, Principal: sessionP},
		session, title, delegation)
	if err != nil {
		return nil, err
	}
	act := map[string]any{"sub": "person:" + string(consent.Account), "act": map[string]any{
		"sub": "mcp_client:" + consent.ClientID, "client_name": consent.Name, "consent": consent.ID,
		"act": map[string]any{"sub": "session:" + string(session), "delegation": string(delegation)}}}
	contract := &nexusops.Contract{Seat: seat, Record: true, Mail: c.Mail, Act: act, Email: consent.Email,
		ElicitedBy: "mcp_client:" + consent.ClientID + ":elicitation"}
	return &nmcp.Server{Tools: contract, Name: "newtype-nexus", Version: c.Version, ElicitWait: RemoteElicit}, nil
}

// liveRoot returns the consent's stored root when it is still the session's
// live, unended root with at least an hour left and the session is usable.
func (c *Connector) liveRoot(ctx context.Context, person nexus.Principal, consent Consent) (ids.Session, ids.Delegation, string, bool) {
	if consent.Session == "" || consent.Delegation == "" {
		return "", "", "", false
	}
	d, err := c.Service.DelegationInfo(ctx, person, consent.Delegation)
	if err != nil || d.Delegation.EndedAt != nil || d.Delegation.SupersededBy != "" || d.Delegation.Delegate != consent.Session ||
		time.Until(d.Delegation.ExpiresAt) < time.Hour {
		return "", "", "", false
	}
	sess, err := c.Service.Session(ctx, person, consent.Session)
	if err != nil || sess.Runner != nexus.Remote || sess.Status == nexus.SessionDone || sess.Status == nexus.SessionStopped || sess.Status == nexus.SessionSuspended {
		return "", "", "", false
	}
	return sess.ID, d.Delegation.ID, sess.Title, true
}

// MailApprovals is the server-side mail fallback of request_approval: B asks
// the approvals service (admin client) to mail the person, and consumes the
// decision once. The admin token never leaves the approvals client.
//
// The approvals service mails only its owner, so a person whose address is
// not Owner gets approval_unavailable instead of a mail to someone else.
// Every mail spends a slot of the approvals store's lifetime cap (shared with
// default-model approvals), so mail is a small daily budget: MailPerSessionDay
// per connection (one per consent) and MailPerDay overall. Open requests older
// than MailApprovalTT are dropped.
type MailApprovals struct {
	Approvals gate.ChangeApprovals
	Owner     string
	mu        sync.Mutex
	open      map[string]mailRequest
	sent      []sentMail
}

const (
	MailPerSessionDay = 3
	MailPerDay        = 10
)

type sentMail struct {
	session ids.Session
	at      time.Time
}

type mailRequest struct {
	id       string
	manifest string
	session  ids.Session
	created  time.Time
}

var errMailLimit = errors.New("mail approval budget used up")

func (m *MailApprovals) Ask(ctx context.Context, key string, req nexusops.MailRequest) (nexusops.MailStatus, error) {
	if m.Owner == "" || !sameEmail(req.Email, m.Owner) {
		return nexusops.MailStatus{}, errors.New("mail approvals reach only the owner")
	}
	now := time.Now()
	m.mu.Lock()
	if m.open == nil {
		m.open = map[string]mailRequest{}
	}
	for k, o := range m.open {
		if now.Sub(o.created) > MailApprovalTT {
			delete(m.open, k) // expired at the approvals service too
		}
	}
	m.sent = slices.DeleteFunc(m.sent, func(x sentMail) bool { return now.Sub(x.at) > 24*time.Hour })
	perSession := 0
	for _, x := range m.sent {
		if x.session == req.Session {
			perSession++
		}
	}
	open, ok := m.open[key]
	if !ok && (perSession >= MailPerSessionDay || len(m.sent) >= MailPerDay) {
		m.mu.Unlock()
		return nexusops.MailStatus{}, errMailLimit
	}
	if !ok {
		m.sent = append(m.sent, sentMail{session: req.Session, at: now})
	}
	m.mu.Unlock()
	if !ok {
		manifest, _ := json.Marshal(map[string]string{"session": string(req.Session), "session_name": req.Name, "action": req.Action, "server_effect": req.Effect, "reason": req.Reason})
		// A fresh ClientID per request: the approvals store keys idempotency
		// on Requester+ClientID for good.
		ch, err := m.Approvals.Begin(ctx, gate.ChangeInput{Requester: "nexus mcp " + req.Name, Kind: "mcp_approval", Target: req.Name + " · " + req.Action,
			Manifest: string(manifest), BaseState: "서버 판정 " + req.Effect, Impact: "이 연결 세션이 이 행동을 한 번 해도 된다는 사람의 결정(Nexus 위임은 넓어지지 않음)",
			Cost: "없음", Recovery: "거절하거나 무시하면 15분 뒤 만료", ClientID: random("mcpa_"), TTLSeconds: int64(MailApprovalTT / time.Second)})
		if err != nil {
			return nexusops.MailStatus{}, err
		}
		open = mailRequest{id: ch.ID, manifest: string(manifest), session: req.Session, created: now}
		m.mu.Lock()
		m.open[key] = open
		m.mu.Unlock()
		return nexusops.MailStatus{ID: ch.ID, Status: "pending"}, nil
	}
	ch, err := m.Approvals.Get(ctx, open.id)
	if err != nil {
		return nexusops.MailStatus{}, err
	}
	done := func(status string) (nexusops.MailStatus, error) {
		m.mu.Lock()
		delete(m.open, key)
		m.mu.Unlock()
		return nexusops.MailStatus{ID: open.id, Status: status, DecidedAt: ch.DecidedAt}, nil
	}
	switch ch.Status {
	case "approved":
		if _, err := m.Approvals.Consume(ctx, open.id, open.manifest); err != nil {
			return nexusops.MailStatus{}, err
		}
		_, _ = m.Approvals.Result(ctx, open.id, "used once")
		return done("approved")
	case "denied", "failed":
		return done("denied")
	case "expired", "consumed":
		return done("expired")
	}
	return nexusops.MailStatus{ID: open.id, Status: "pending"}, nil
}

// Endpoint is the whole remote MCP surface: discovery, OAuth, person routes
// and /mcp itself.
type Endpoint struct {
	Auth *Server
	MCP  *nmcp.HTTPHandler
}

// NewEndpoint ties the token check to the transport (owner = consent ID) and
// makes a revoked consent end its live sessions.
func NewEndpoint(auth *Server, conn *Connector, origins []string) *Endpoint {
	h := &nmcp.HTTPHandler{
		Authenticate: func(r *http.Request) (string, bool) {
			g, ok := auth.Check(r)
			return g.Consent.ID, ok
		},
		Challenge: auth.Challenge(),
		NewServer: conn.NewServer,
		Origins:   origins,
	}
	if auth.Record == nil {
		auth.Record = conn.record(auth.Store)
	}
	prev := auth.OnRevoke
	auth.OnRevoke = func(consent string) {
		h.DropOwner(consent)
		if prev != nil {
			prev(consent)
		}
	}
	return &Endpoint{Auth: auth, MCP: h}
}

// Routes mounts everything on mux.
func (e *Endpoint) Routes(mux *http.ServeMux) {
	e.Auth.Routes(mux)
	mux.Handle("/mcp", e.MCP)
}

// record writes a person's settings change into the ledgers where the person
// will look: each live remote connection session of the account and the
// person's operator seat (the CLI's default seat), as the person.
func (c *Connector) record(store Store) func(context.Context, nexus.Principal, string, map[string]any) {
	return func(ctx context.Context, p nexus.Principal, kind string, payload map[string]any) {
		raw, err := json.Marshal(payload)
		if err != nil {
			return
		}
		input := []nexus.EventInput{{Source: "user", Kind: kind, Payload: raw}}
		seen := map[ids.Session]bool{}
		if consents, err := store.Consents(ctx, p.AccountID); err == nil {
			for _, x := range consents {
				if x.Session != "" && !x.Revoked && !seen[x.Session] {
					seen[x.Session] = true
					_, _ = c.Service.AppendEvents(ctx, p, x.Session, input)
				}
			}
		}
		if op, err := c.Service.SessionByName(ctx, p, "operator"); err == nil && op != nil && !seen[op.ID] {
			_, _ = c.Service.AppendEvents(ctx, p, op.ID, input)
		}
	}
}
