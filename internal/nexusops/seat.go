// Package nexusops is the tool-only Nexus seat shared by `newtype nexus`
// (operator CLI) and `newtype nmcp serve` (stdio MCP server). A seat is one
// named local Nexus session held by the person's saved credentials through a
// model-free root: no model scope, no model tokens, no delegation scope unless
// the caller asks for exactly that. The server enforces every limit; this
// package only compiles fixed routes and never prints or returns credentials.
package nexusops

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/nexustransport"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
)

// Fixed, credential-free failures. Callers map them to their own text.
var (
	// ErrNotLive: the saved person login was refused (expired, revoked,
	// missing). The fix is a fresh login, which plain `newtype` offers.
	ErrNotLive = errors.New("nexus: saved login is not live")
	// ErrNotFound: the named session or event does not exist for this account.
	ErrNotFound = errors.New("nexus: not found")
	// ErrRefused: Nexus refused the action (outside the delegation, or not allowed).
	ErrRefused = errors.New("nexus: refused by Nexus")
	// ErrConflict: ambiguous name, recipient cannot receive, or a replay mismatch.
	ErrConflict = errors.New("nexus: conflict")
	// ErrInvalid: the request was malformed (bad ID, empty text, bad name).
	ErrInvalid = errors.New("nexus: invalid request")
	// ErrUnavailable: transport failure or server error; outcome may be unknown.
	ErrUnavailable = errors.New("nexus: unavailable; outcome unknown, do not resend")
)

// NoReplyPrefix marks a notice that expects no answer. Nexus has no wire field
// for it yet; the mark is a visible text convention, never authority.
const NoReplyPrefix = "[알림 · 답장 불필요] "

// DefaultTTL is the lifetime of a seat root; an expired seat is reissued on
// the next attach (same session, new root), never silently widened.
const DefaultTTL = 8 * time.Hour

// Identity is the saved person credential (licence key + login token).
type Identity struct {
	Endpoint string
	Key      string
	Login    string
}

// Root is what a seat root asks for. The zero value is the operator CLI seat:
// no scope at all (messages, peers, inbox and the own ledger need none).
type Root struct {
	Scope  []string
	Limits nexus.Limits
	Rules  []nexus.Rule
}

type Options struct {
	Transport http.RoundTripper // nil: default HTTPS transport
	TTL       time.Duration     // 0: DefaultTTL
	Root      Root
	// AlwaysIssue issues a fresh root on the (same) session even when a live
	// one exists, so the caller knows exactly which delegation it holds.
	AlwaysIssue bool
}

// Seat is one attached named session.
type Seat struct {
	person  *nexustransport.Client
	session *nexustransport.Client
	ID      ids.Session
	Name    string
	// Delegation is the root issued by this attach, or "" when an existing
	// live root was reused.
	Delegation ids.Delegation
	Reused     bool
}

// ValidName accepts a short session name: 1..60 runes, no control, format,
// path or query characters, no outer or double spaces. "tui" is the plain
// TUI's own root title and is refused so a seat never takes that session.
func ValidName(name string) bool {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 60 || strings.TrimSpace(name) != name || strings.Contains(name, "  ") || strings.Contains(name, "..") || strings.EqualFold(name, "tui") {
		return false
	}
	if _, err := ids.ParseSession(name); err == nil {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || (unicode.IsSpace(r) && r != ' ') || strings.ContainsRune(`/\?#%`, r) {
			return false
		}
	}
	return true
}

func client(id Identity, session ids.Session, rt http.RoundTripper) (*nexustransport.Client, error) {
	c, err := nexustransport.New(id.Endpoint, nexustransport.Auth{Token: id.Key, Login: id.Login, Session: string(session)})
	if err != nil {
		return nil, ErrInvalid
	}
	if rt != nil {
		c.WithTransport(rt)
	}
	return c, nil
}

// Map turns a transport error into one of the fixed errors above.
func Map(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var h *nexustransport.HTTPError
	if errors.As(err, &h) {
		switch h.Code {
		case 401:
			return ErrNotLive
		case 403, 429:
			return ErrRefused
		case 404:
			return ErrNotFound
		case 409:
			return ErrConflict
		case 400:
			return ErrInvalid
		}
	}
	return ErrUnavailable
}

// Person returns a client acting as the person (no session header): used for
// root issue, name lookup and ledger reads of the account's sessions.
func personClient(id Identity, rt http.RoundTripper) (*nexustransport.Client, error) {
	return client(id, "", rt)
}

// Attach finds the newest session titled name, keeps it when it still holds a
// live root, reissues a root for it when it does not, and otherwise creates a
// new session with a model-free root. One POST at most; no automatic retry.
func Attach(ctx context.Context, id Identity, name string, o Options) (*Seat, error) {
	if !ValidName(name) {
		return nil, ErrInvalid
	}
	if id.Login == "" {
		return nil, ErrNotLive
	}
	person, err := personClient(id, o.Transport)
	if err != nil {
		return nil, err
	}
	var found *nexus.Session
	if err := person.Do(ctx, "GET", "/v1/session-names/"+url.PathEscape(name), nil, &found); err != nil {
		if m := Map(err); !errors.Is(m, ErrNotFound) {
			return nil, m
		}
		found = nil
	}
	seat := &Seat{person: person, Name: name}
	var to ids.Session
	if found != nil && ids.Check(ids.KindSession, string(found.ID)) == nil && found.Runner == nexus.Local && found.Kind == nexus.Worker && found.Status != nexus.SessionSuspended {
		to = found.ID
		if !o.AlwaysIssue && found.Status != nexus.SessionDone && found.Status != nexus.SessionStopped {
			s, err := client(id, found.ID, o.Transport)
			if err != nil {
				return nil, err
			}
			var peers []nexus.Peer
			if err := s.Do(ctx, "GET", "/v1/peers", nil, &peers); err == nil {
				seat.session, seat.ID, seat.Reused = s, found.ID, true
				return seat, nil
			} else if m := Map(err); !errors.Is(m, ErrRefused) && !errors.Is(m, ErrNotLive) {
				return nil, m
			}
		}
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < time.Second || ttl > nexus.MaxTTL {
		return nil, ErrInvalid
	}
	scope := o.Root.Scope
	if scope == nil {
		scope = []string{}
	}
	wire := httpapi.RootWire{Title: name, TaskID: ids.Task(ids.New(ids.KindTask)), ToSessionID: to, Runner: nexus.Local, Scope: scope, Rules: o.Root.Rules, Limits: o.Root.Limits, TTLSeconds: int64(ttl / time.Second)}
	var out httpapi.GrantSummary
	if err := person.Do(ctx, "POST", "/v1/requests", wire, &out); err != nil {
		return nil, Map(err)
	}
	if ids.Check(ids.KindSession, string(out.Session.ID)) != nil || ids.Check(ids.KindDelegation, string(out.Delegation)) != nil || (to != "" && out.Session.ID != to) {
		return nil, ErrUnavailable
	}
	s, err := client(id, out.Session.ID, o.Transport)
	if err != nil {
		return nil, err
	}
	seat.session, seat.ID, seat.Delegation = s, out.Session.ID, out.Delegation
	return seat, nil
}

// Peers lists the account's live sessions as seen by this seat.
func (s *Seat) Peers(ctx context.Context) ([]nexus.Peer, error) {
	var out []nexus.Peer
	if err := s.session.Do(ctx, "GET", "/v1/peers", nil, &out); err != nil {
		return nil, Map(err)
	}
	return out, nil
}

// SendResult is the sender's view: identity and last observed status only.
type SendResult struct {
	Event  ids.Event   `json:"event_id"`
	To     ids.Session `json:"to"`
	Status string      `json:"status"`
}

// Send posts one message from this seat. to is a slv_ ID, a session name or
// a req_ task (its assignee). clientEvent makes a retry a replay, never a
// second message; pass "" to have one generated.
func (s *Seat) Send(ctx context.Context, to, text string, noReply bool, replyTo ids.Event, clientEvent string) (SendResult, error) {
	to, text = strings.TrimSpace(to), strings.TrimSpace(text)
	if to == "" || text == "" || len(text) > 60000 || (replyTo != "" && ids.Check(ids.KindEvent, string(replyTo)) != nil) || len(clientEvent) > 128 {
		return SendResult{}, ErrInvalid
	}
	if noReply && !strings.HasPrefix(text, NoReplyPrefix) {
		text = NoReplyPrefix + text
	}
	if clientEvent == "" {
		clientEvent = ids.New(ids.KindEvent)
	}
	wire := struct {
		To     string    `json:"to"`
		Text   string    `json:"text"`
		Reply  ids.Event `json:"reply_to,omitempty"`
		Client string    `json:"client_event_id"`
	}{to, text, replyTo, clientEvent}
	var sent nexus.Received
	if err := s.session.Do(ctx, "POST", "/v1/messages", wire, &sent); err != nil {
		return SendResult{}, Map(err)
	}
	if ids.Check(ids.KindEvent, string(sent.Event)) != nil || ids.Check(ids.KindSession, string(sent.To)) != nil {
		return SendResult{}, ErrUnavailable
	}
	out := SendResult{Event: sent.Event, To: sent.To, Status: "sent"}
	if st, err := s.Status(ctx, sent.To, sent.Event); err == nil {
		out.Status = st.Status
	}
	return out, nil
}

// Status reads the delivery state of a message this seat sent.
func (s *Seat) Status(ctx context.Context, to ids.Session, event ids.Event) (nexus.MessageStatus, error) {
	var st nexus.MessageStatus
	if ids.Check(ids.KindSession, string(to)) != nil || ids.Check(ids.KindEvent, string(event)) != nil {
		return st, ErrInvalid
	}
	if err := s.session.Query(ctx, "/v1/messages/"+string(event), url.Values{"to": {string(to)}}, &st); err != nil {
		return st, Map(err)
	}
	return st, nil
}

// Inbox returns this seat's mail after cursor (all pages, at most 1000
// items) and the next cursor. It changes no receipt.
func (s *Seat) Inbox(ctx context.Context, after int64) ([]nexus.Received, int64, error) {
	var all []nexus.Received
	for range 10 {
		var page struct {
			Messages []nexus.Received `json:"messages"`
			Next     int64            `json:"next"`
		}
		if err := s.session.Query(ctx, "/v1/inbox", url.Values{"after": {strconv.FormatInt(after, 10)}, "limit": {"100"}}, &page); err != nil {
			return nil, after, Map(err)
		}
		if page.Next < after {
			return nil, after, ErrUnavailable
		}
		all = append(all, page.Messages...)
		if page.Next == after || len(page.Messages) < 100 {
			return all, page.Next, nil
		}
		after = page.Next
	}
	return all, after, nil
}

// Delivered records that the message reached this seat's reader (a person's
// terminal or a client process). It is NOT a read receipt.
func (s *Seat) Delivered(ctx context.Context, event ids.Event) error {
	if ids.Check(ids.KindEvent, string(event)) != nil {
		return ErrInvalid
	}
	return Map(s.session.Do(ctx, "POST", "/v1/messages/delivered", nexus.Receipt{Event: event}, nil))
}

// Read records that the message entered a model's input as a tool result
// (turn is the req_ ID of that call). Only callers that actually returned the
// message to a model may call it.
func (s *Seat) Read(ctx context.Context, event ids.Event, turn ids.Task) error {
	if ids.Check(ids.KindEvent, string(event)) != nil || ids.Check(ids.KindTask, string(turn)) != nil {
		return ErrInvalid
	}
	return Map(s.session.Do(ctx, "POST", "/v1/messages/read", nexus.Receipt{Event: event, TurnID: string(turn)}, nil))
}

// Resolve turns a slv_ ID or a session name into a session ID (as the person).
func (s *Seat) Resolve(ctx context.Context, target string) (ids.Session, error) {
	target = strings.TrimSpace(target)
	if id, err := ids.ParseSession(target); err == nil {
		return id, nil
	}
	if target == "" || strings.Contains(target, "..") || strings.ContainsAny(target, `/\?#%`) {
		return "", ErrInvalid
	}
	var found *nexus.Session
	if err := s.person.Do(ctx, "GET", "/v1/session-names/"+url.PathEscape(target), nil, &found); err != nil {
		return "", Map(err)
	}
	if found == nil || ids.Check(ids.KindSession, string(found.ID)) != nil {
		return "", ErrNotFound
	}
	return found.ID, nil
}

// Log reads one page of a session's ledger as the person (the account's
// human principal sees its own sessions). It changes nothing.
func (s *Seat) Log(ctx context.Context, target ids.Session, after int64) ([]nexus.Event, int64, error) {
	if ids.Check(ids.KindSession, string(target)) != nil || after < 0 {
		return nil, after, ErrInvalid
	}
	var page struct {
		Events []nexus.Event `json:"events"`
		Next   int64         `json:"next"`
	}
	if err := s.person.Query(ctx, "/v1/sessions/"+string(target)+"/events", url.Values{"after": {strconv.FormatInt(after, 10)}}, &page); err != nil {
		return nil, after, Map(err)
	}
	return page.Events, page.Next, nil
}

// Retitle sets the Nexus title (the name peers see) of session, acting as
// that session: a session may rename only itself. Nexus refuses a title a
// live session of the account already has (ErrConflict).
func Retitle(ctx context.Context, id Identity, session ids.Session, title string, rt http.RoundTripper) error {
	title = strings.TrimSpace(title)
	if ids.Check(ids.KindSession, string(session)) != nil || title == "" || utf8.RuneCountInString(title) > 80 {
		return ErrInvalid
	}
	c, err := client(id, session, rt)
	if err != nil {
		return err
	}
	return Map(c.Do(ctx, "PATCH", "/v1/sessions/"+string(session), map[string]string{"title": title}, nil))
}

// InProcessSeat is a seat whose person and session requests are carried by
// in-process round trippers that already hold the principals (the remote MCP
// connector inside Nexus). token is only the placeholder bearer the client
// type requires; no credential is involved.
func InProcessSeat(endpoint, token string, person, session http.RoundTripper, id ids.Session, name string, delegation ids.Delegation) (*Seat, error) {
	if person == nil || session == nil || ids.Check(ids.KindSession, string(id)) != nil {
		return nil, ErrInvalid
	}
	p, err := nexustransport.New(endpoint, nexustransport.Auth{Token: token})
	if err != nil {
		return nil, ErrInvalid
	}
	s, err := nexustransport.New(endpoint, nexustransport.Auth{Token: token})
	if err != nil {
		return nil, ErrInvalid
	}
	return &Seat{person: p.WithTransport(person), session: s.WithTransport(session), ID: id, Name: name, Delegation: delegation}, nil
}
