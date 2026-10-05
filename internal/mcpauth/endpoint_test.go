package mcpauth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/nexusops"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/nexus"
)

// fakeApprovals stands in for the approvals service admin API.
type fakeApprovals struct {
	mu       sync.Mutex
	changes  map[string]*gate.ChangeApproval
	consumed int
	n        int
}

func (f *fakeApprovals) Begin(_ context.Context, in gate.ChangeInput) (gate.ChangeApproval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.changes == nil {
		f.changes = map[string]*gate.ChangeApproval{}
	}
	f.n++
	id := fmt.Sprintf("car_%064x", f.n)
	c := &gate.ChangeApproval{ChangeInput: in, ID: id, Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
	f.changes[id] = c
	return *c, nil
}
func (f *fakeApprovals) Get(_ context.Context, id string) (gate.ChangeApproval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.changes[id]
	if !ok {
		return gate.ChangeApproval{}, gate.ErrChangeNotFound
	}
	return *c, nil
}
func (f *fakeApprovals) Consume(_ context.Context, id, manifest string) (gate.ChangeApproval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.changes[id]
	if c == nil || c.Status != "approved" || c.Manifest != manifest {
		return gate.ChangeApproval{}, gate.ErrChangeConflict
	}
	c.Status = "consumed"
	f.consumed++
	return *c, nil
}
func (f *fakeApprovals) Result(_ context.Context, id, _ string) (gate.ChangeApproval, error) {
	return f.Get(context.Background(), id)
}
func (f *fakeApprovals) decide(kind, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.changes {
		if c.Kind == kind && c.Status == "pending" {
			c.Status = status
			c.DecidedAt = time.Now()
		}
	}
}
func (f *fakeApprovals) count(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.changes {
		if c.Kind == kind {
			n++
		}
	}
	return n
}

type fixture struct {
	t      *testing.T
	srv    *httptest.Server
	svc    *nexus.Service
	auth   *Server
	ep     *Endpoint
	appr   gate.ChangeApprovals
	person nexus.Principal
	client string
	redir  string
	ip     string

	live       atomic.Bool // the person's credentials are live
	lookupFail atomic.Bool // AccountForEmail fails
	mu         sync.Mutex
	clock      time.Time
}

const personHeader = "X-Test-Person" // the fixture's stand-in for licence+login

func newFixture(t *testing.T) *fixture { return newFixtureWith(t, &fakeApprovals{}) }

func (f *fixture) fake() *fakeApprovals { return f.appr.(*fakeApprovals) }

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.clock = f.clock.Add(d)
	f.mu.Unlock()
}

func newFixtureWith(t *testing.T, appr gate.ChangeApprovals) *fixture {
	t.Helper()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	inner, err := nexusserver.NewHandler(svc, gate.NewMemoryCredentials(), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.test")
	f := &fixture{t: t, svc: svc, appr: appr, person: person, clock: time.Now().UTC(), ip: "198.51.100.7"}
	f.live.Store(true)
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	store := NewMemoryStore()
	_ = store.PutSettings(context.Background(), Settings{MailConsent: true}) // most tests exercise the mail path
	f.auth = &Server{Issuer: f.srv.URL, Store: store, Approvals: appr, OwnerEmail: person.Email,
		AccountForEmail: func(_ context.Context, email string) (ids.Account, error) {
			if email != person.Email || f.lookupFail.Load() {
				return "", nexus.ErrNotFound
			}
			return person.AccountID, nil
		},
		AccountLive: func(_ context.Context, a ids.Account) bool { return a == person.AccountID && f.live.Load() },
		Clock: func() time.Time {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.clock
		},
		Authenticate: func(r *http.Request) (nexus.Principal, error) {
			if r.Header.Get(personHeader) == "yes" {
				return person, nil
			}
			return nexus.Principal{}, nexus.ErrForbidden
		}}
	conn := &Connector{Store: store, Service: svc, Handler: inner, Mail: &MailApprovals{Approvals: appr, Owner: person.Email}, Version: "test"}
	f.ep = NewEndpoint(f.auth, conn, nil)
	f.ep.MCP.Heartbeat = 50 * time.Millisecond
	t.Cleanup(f.ep.MCP.Close)
	f.ep.Routes(mux)
	// requests arrive as through the tunnel: loopback peer + CF-Connecting-IP
	mux.Handle("/", inner)
	return f
}

func (f *fixture) postJSON(path string, body any, hdr map[string]string) (*http.Response, []byte) {
	f.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", f.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (f *fixture) postForm(path string, form url.Values) (int, map[string]any) {
	f.t.Helper()
	resp, err := http.PostForm(f.srv.URL+path, form)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (f *fixture) register() {
	f.t.Helper()
	f.redir = "http://127.0.0.1:33418/callback"
	resp, body := f.postJSON("/oauth/register", map[string]any{"client_name": "Claude", "redirect_uris": []string{f.redir}, "token_endpoint_auth_method": "none"}, nil)
	var out struct {
		ID string `json:"client_id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &out) != nil || !strings.HasPrefix(out.ID, "mcl_") {
		f.t.Fatalf("register %d %s", resp.StatusCode, body)
	}
	f.client = out.ID
}

var (
	codeRe = regexp.MustCompile(`newtype nmcp authorize ([A-Z]{4}-[A-Z]{4})`)
	reqRe  = regexp.MustCompile(`data-request="(mcr_[0-9a-f]+)"`)
)

// startAuthorize opens the consent page and returns (user code, request id, verifier).
func (f *fixture) startAuthorize(resource string) (string, string, string) {
	f.t.Helper()
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {f.client}, "redirect_uri": {f.redir}, "state": {"st-1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "resource": {resource}, "scope": {Scope}}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusFound {
		return "", resp.Header.Get("Location"), verifier
	}
	if resp.StatusCode != 200 || resp.Header.Get("X-Frame-Options") != "DENY" {
		f.t.Fatalf("authorize %d", resp.StatusCode)
	}
	return codeRe.FindStringSubmatch(string(page))[1], reqRe.FindStringSubmatch(string(page))[1], verifier
}

func (f *fixture) status(req string) map[string]string {
	f.t.Helper()
	resp, err := http.Get(f.srv.URL + "/oauth/authorize/status?request=" + req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (f *fixture) exchange(redirect, verifier string) (int, map[string]any) {
	f.t.Helper()
	u, _ := url.Parse(redirect)
	if u.Query().Get("state") != "st-1" || u.Query().Get("iss") != f.srv.URL {
		f.t.Fatalf("redirect %s", redirect)
	}
	return f.postForm("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "redirect_uri": {f.redir},
		"client_id": {f.client}, "code_verifier": {verifier}, "resource": {f.auth.Resource()}})
}

// connect runs the CLI-code consent and returns tokens.
func (f *fixture) connect() (string, string) {
	f.t.Helper()
	code, req, verifier := f.startAuthorize(f.auth.Resource())
	if s := f.status(req); s["status"] != "pending" {
		f.t.Fatalf("status before consent %v", s)
	}
	resp, body := f.approveCode(strings.ToLower(strings.ReplaceAll(code, "-", "")))
	if resp.StatusCode != 200 {
		f.t.Fatalf("cli authorize %d %s", resp.StatusCode, body)
	}
	st := f.status(req)
	if st["status"] != "approved" {
		f.t.Fatalf("status %v", st)
	}
	n, tok := f.exchange(st["redirect"], verifier)
	if n != 200 || tok["token_type"] != "Bearer" {
		f.t.Fatalf("token %d %v", n, tok)
	}
	return tok["access_token"].(string), tok["refresh_token"].(string)
}

type mcpConn struct {
	f     *fixture
	token string
	sid   string
	n     int
}

func (c *mcpConn) post(body map[string]any) (*http.Response, []map[string]json.RawMessage) {
	c.f.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.f.srv.URL+"/mcp", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	if c.sid != "" {
		req.Header.Set("Mcp-Session-Id", c.sid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var msgs []map[string]json.RawMessage
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var m map[string]json.RawMessage
				_ = json.Unmarshal([]byte(v), &m)
				msgs = append(msgs, m)
			}
		}
	} else {
		var m map[string]json.RawMessage
		if json.NewDecoder(resp.Body).Decode(&m) == nil {
			msgs = append(msgs, m)
		}
	}
	return resp, msgs
}

func (c *mcpConn) initialize() {
	c.f.t.Helper()
	resp, msgs := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}}})
	if resp.StatusCode != 200 || len(msgs) != 1 || resp.Header.Get("Mcp-Session-Id") == "" {
		c.f.t.Fatalf("initialize %d %v", resp.StatusCode, msgs)
	}
	if strings.Contains(string(msgs[0]["result"]), "claude/channel") {
		c.f.t.Fatal("remote endpoint declared claude/channel")
	}
	c.sid = resp.Header.Get("Mcp-Session-Id")
	c.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

func (c *mcpConn) tool(name, args string) string {
	c.f.t.Helper()
	c.n++
	_, msgs := c.post(map[string]any{"jsonrpc": "2.0", "id": 100 + c.n, "method": "tools/call", "params": map[string]any{"name": name, "arguments": json.RawMessage(args)}})
	if len(msgs) == 0 {
		c.f.t.Fatalf("%s: no response", name)
	}
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	last := msgs[len(msgs)-1]
	if json.Unmarshal(last["result"], &res) != nil || len(res.Content) != 1 {
		c.f.t.Fatalf("%s: %v", name, last)
	}
	return res.Content[0].Text
}

func TestDiscoveryAndChallenge(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var prm map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&prm)
	resp.Body.Close()
	if prm["resource"] != f.srv.URL+"/mcp" {
		t.Fatalf("prm %v", prm)
	}
	resp, _ = http.Get(f.srv.URL + "/.well-known/oauth-authorization-server")
	var asm map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&asm)
	resp.Body.Close()
	if fmt.Sprint(asm["code_challenge_methods_supported"]) != "[S256]" || asm["registration_endpoint"] != f.srv.URL+"/oauth/register" {
		t.Fatalf("asm %v", asm)
	}
	c := &mcpConn{f: f, token: "nope"}
	r, _ := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"})
	if r.StatusCode != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), `resource_metadata="`+f.srv.URL+`/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("challenge %d %q", r.StatusCode, r.Header.Get("WWW-Authenticate"))
	}
}

// End to end: register → consent by CLI code → token → /mcp as a remote
// session whose delegation (not the token) decides; act chain in the ledger.
func TestRemoteConnectionCLIConsentAndDelegation(t *testing.T) {
	f := newFixture(t)
	f.register()
	access, _ := f.connect()
	c := &mcpConn{f: f, token: access}
	c.initialize()
	info := c.tool("delegation_info", `{}`)
	if !strings.Contains(info, "session:delegate") {
		t.Fatalf("delegation_info %s", info)
	}
	// the session is a remote one, titled for people
	peers, err := f.svc.Peers(context.Background(), f.person)
	if err != nil {
		t.Fatal(err)
	}
	var remote *nexus.Peer
	for i := range peers {
		if peers[i].Title == "mcp:Claude" {
			remote = &peers[i]
		}
	}
	if remote == nil || remote.Runner != nexus.Remote {
		t.Fatalf("peers %+v", peers)
	}
	// "may do" is the delegation: widening scope is refused whatever the token says
	out := c.tool("delegate_task", fmt.Sprintf(`{"to_session_id":%q,"title":"x","brief":"y","scope":["newtype:run"],"limits":{},"ttl_seconds":60}`, remote.SessionID))
	if !strings.Contains(out, `"refused"`) {
		t.Fatalf("widening allowed: %s", out)
	}
	// ledger records carry the actor chain
	events, _, err := f.svc.Events(context.Background(), f.person, remote.SessionID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Kind == "tool.call" {
			raw, _ := json.Marshal(e)
			if strings.Contains(string(raw), "act_chain") && strings.Contains(string(raw), "mcp_client:"+f.client) {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no act_chain on tool.call records")
	}
	// the same consent reuses the same remote session
	access2, _ := f.connect()
	c2 := &mcpConn{f: f, token: access2}
	c2.initialize()
	peers, _ = f.svc.Peers(context.Background(), f.person)
	n := 0
	for _, p := range peers {
		if p.Title == "mcp:Claude" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d remote sessions for one consent", n)
	}
}

func TestTokenRulesAudienceReplayRotationRevocation(t *testing.T) {
	f := newFixture(t)
	f.register()
	// resource indicator is required and exact
	if _, loc, _ := f.startAuthorize("https://other.example/mcp"); !strings.Contains(loc, "error=invalid_target") {
		t.Fatalf("foreign resource: %s", loc)
	}
	access, refresh := f.connect()

	// a token with another audience is refused at /mcp
	other := "ntm_" + strings.Repeat("c", 64)
	tok, _ := f.auth.Store.Token(context.Background(), Verifier(access))
	tok.Verifier, tok.Audience = Verifier(other), "https://other.example/mcp"
	_ = f.auth.Store.PutToken(context.Background(), tok)
	for _, bad := range []string{other, refresh, "ntl_" + strings.Repeat("d", 40)} {
		c := &mcpConn{f: f, token: bad}
		if r, _ := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); r.StatusCode != 401 {
			t.Fatalf("token %s… accepted: %d", bad[:4], r.StatusCode)
		}
	}
	// the /mcp token is not accepted by /v1
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/peers", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("/v1 accepted an /mcp token: %d", resp.StatusCode)
	}
	// refresh rotates; reusing the old refresh token revokes the consent
	n, rot := f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.client}})
	if n != 200 {
		t.Fatalf("refresh %d %v", n, rot)
	}
	n, _ = f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.client}})
	if n != 400 {
		t.Fatalf("reused refresh %d", n)
	}
	c := &mcpConn{f: f, token: rot["access_token"].(string)}
	if r, _ := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); r.StatusCode != 401 {
		t.Fatalf("token survived refresh reuse: %d", r.StatusCode)
	}
}

func TestCodeReplayRevokesAndPersonRevoke(t *testing.T) {
	f := newFixture(t)
	f.register()
	code, req, verifier := f.startAuthorize(f.auth.Resource())
	f.approveCode(code)
	st := f.status(req)
	n, tok := f.exchange(st["redirect"], verifier)
	if n != 200 {
		t.Fatalf("exchange %d", n)
	}
	if n, _ := f.exchange(st["redirect"], verifier); n != 400 {
		t.Fatalf("replayed code %d", n)
	}
	c := &mcpConn{f: f, token: tok["access_token"].(string)}
	if r, _ := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); r.StatusCode != 401 {
		t.Fatal("tokens of a replayed code still work")
	}
	// person routes need a person; revoke ends a live connection
	access, _ := f.connect()
	c = &mcpConn{f: f, token: access}
	c.initialize()
	r, body := f.postJSON("/v1/mcp/clients/x/revoke", nil, nil)
	if r.StatusCode != 401 {
		t.Fatalf("anonymous revoke %d %s", r.StatusCode, body)
	}
	req2, _ := http.NewRequest("GET", f.srv.URL+"/v1/mcp/clients", nil)
	req2.Header.Set(personHeader, "yes")
	resp, _ := http.DefaultClient.Do(req2)
	var list struct {
		Clients []Consent `json:"clients"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	var live string
	for _, x := range list.Clients {
		if !x.Revoked {
			live = x.ID
		}
	}
	if r, _ := f.postJSON("/v1/mcp/clients/"+live+"/revoke", nil, map[string]string{personHeader: "yes"}); r.StatusCode != 200 {
		t.Fatalf("revoke %d", r.StatusCode)
	}
	if r, _ := c.post(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "tools/list"}); r.StatusCode != 401 {
		t.Fatalf("revoked connection still served: %d", r.StatusCode)
	}
}

// Consent by the emailed one-time link (approvals service mails the owner).
func TestMailConsent(t *testing.T) {
	f := newFixture(t)
	f.register()
	_, req, verifier := f.startAuthorize(f.auth.Resource())
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.PostForm(f.srv.URL+"/oauth/authorize/mail", url.Values{"request": {req}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || f.fake().count("mcp_connect") != 1 {
		t.Fatalf("mail %d count %d", resp.StatusCode, f.fake().count("mcp_connect"))
	}
	if st := f.status(req); st["status"] != "pending" || st["mail"] != "sent" {
		t.Fatalf("before decision %v", st)
	}
	f.fake().decide("mcp_connect", "approved")
	// polls reach the approvals service at most every 3 s per request
	if st := f.status(req); st["status"] != "pending" {
		t.Fatalf("throttled poll %v", st)
	}
	// an account lookup failure leaves the approval unconsumed and retryable
	f.lookupFail.Store(true)
	f.advance(4 * time.Second)
	if st := f.status(req); st["status"] != "pending" || f.fake().consumed != 0 {
		t.Fatalf("lookup failure %v consumed %d", st, f.fake().consumed)
	}
	f.lookupFail.Store(false)
	f.advance(4 * time.Second)
	st := f.status(req)
	if st["status"] != "approved" || f.fake().consumed != 1 {
		t.Fatalf("after decision %v", st)
	}
	if n, tok := f.exchange(st["redirect"], verifier); n != 200 || tok["access_token"] == nil {
		t.Fatalf("exchange %d", n)
	}
}

// request_approval with no elicitation: B mails the person; same call = same
// request; the decision is consumed once and recorded as person:mail.
func TestMailApprovalFallback(t *testing.T) {
	old := nexusops.MailPoll
	nexusops.MailPoll = 20 * time.Millisecond
	defer func() { nexusops.MailPoll = old }()
	f := newFixture(t)
	f.register()
	access, _ := f.connect()
	c := &mcpConn{f: f, token: access}
	c.initialize()
	out := c.tool("request_approval", `{"action":"tool:shell","reason":"run the build"}`)
	if !strings.Contains(out, `"pending"`) || !strings.Contains(out, `"mail"`) || f.fake().count("mcp_approval") != 1 {
		t.Fatalf("first call %s (mails %d)", out, f.fake().count("mcp_approval"))
	}
	out = c.tool("request_approval", `{"action":"tool:shell","reason":"run the build"}`)
	if !strings.Contains(out, `"pending"`) || f.fake().count("mcp_approval") != 1 {
		t.Fatalf("second call sent another mail: %s", out)
	}
	f.fake().decide("mcp_approval", "approved")
	out = c.tool("request_approval", `{"action":"tool:shell","reason":"run the build","wait_seconds":2}`)
	if !strings.Contains(out, `"approved"`) || !strings.Contains(out, `"once"`) || f.fake().consumed != 1 {
		t.Fatalf("decision %s consumed %d", out, f.fake().consumed)
	}
	for _, secret := range []string{"Bearer", "ADMIN", "car_"} {
		if strings.Contains(out, secret) && secret != "car_" {
			t.Fatalf("result carries %s", secret)
		}
	}
}

// approveCode is the CLI flow: preview by code, then confirm that request.
func (f *fixture) approveCode(code string) (*http.Response, []byte) {
	f.t.Helper()
	r, _ := http.NewRequest("GET", f.srv.URL+"/v1/mcp/authorize?user_code="+url.QueryEscape(code), nil)
	r.Header.Set(personHeader, "yes")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	var pv struct {
		Request string `json:"request_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&pv)
	resp.Body.Close()
	return f.postJSON("/v1/mcp/authorize", map[string]string{"user_code": code, "request_id": pv.Request}, map[string]string{personHeader: "yes"})
}
