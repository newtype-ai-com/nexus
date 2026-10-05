package mcpauth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/nexusops"
	"github.com/newtype-ai-com/nexus/nexus"
)

// fileApprovals drives the real approvals journal (gate.FileChangeStore), as
// the approvals service does: Begin + mail delivered, a person's decision by
// link token, Consume, Result.
type fileApprovals struct {
	s      *gate.FileChangeStore
	mu     sync.Mutex
	tokens map[string]string
}

func newFileApprovals(t *testing.T) *fileApprovals {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir()) // no symlink ancestors (macOS /var)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "approvals")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := gate.OpenFileChangeStore(filepath.Join(dir, "changes.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &fileApprovals{s: s, tokens: map[string]string{}}
}

func (f *fileApprovals) Begin(_ context.Context, in gate.ChangeInput) (gate.ChangeApproval, error) {
	a, tok, err := f.s.Begin(in, time.Now())
	if err != nil {
		return a, err
	}
	if tok != "" {
		if err := f.s.Delivery(a.ID, true); err != nil {
			return a, err
		}
		f.mu.Lock()
		f.tokens[a.ID] = tok
		f.mu.Unlock()
	}
	return a, nil
}
func (f *fileApprovals) Get(_ context.Context, id string) (gate.ChangeApproval, error) {
	return f.s.Get(id, time.Now())
}
func (f *fileApprovals) Consume(_ context.Context, id, manifest string) (gate.ChangeApproval, error) {
	return f.s.Consume(id, manifest, time.Now())
}
func (f *fileApprovals) Result(_ context.Context, id, result string) (gate.ChangeApproval, error) {
	return f.s.Result(id, result, time.Now())
}
func (f *fileApprovals) approveAll(t *testing.T, kind string) int {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for id, tok := range f.tokens {
		a, err := f.s.Get(id, time.Now())
		if err != nil || a.Kind != kind || a.Status != "pending" {
			continue
		}
		if _, err := f.s.Decide(id, tok, a.Digest, true, "127.0.0.1", "test", time.Now()); err != nil {
			t.Fatal(err)
		}
		n++
	}
	return n
}

// HIGH 1: both mail flows work more than once against the real journal
// (its idempotency key is Requester+ClientID, kept for good).
func TestMailFlowsRepeatAgainstRealApprovalsJournal(t *testing.T) {
	old := nexusops.MailPoll
	nexusops.MailPoll = 10 * time.Millisecond
	defer func() { nexusops.MailPoll = old }()
	fa := newFileApprovals(t)
	f := newFixtureWith(t, fa)
	f.register()
	for round := range 2 { // two mail consents in a row
		if round > 0 {
			f.advance(24*time.Hour + time.Minute) // past the per-client daily mail limit (the client is consented now)
		}
		_, req, verifier := f.startAuthorize(f.auth.Resource())
		f.mailFor(req)
		if n := fa.approveAll(t, "mcp_connect"); n != 1 {
			t.Fatalf("round %d: %d pending mail consents", round, n)
		}
		f.advance(4 * time.Second)
		st := f.status(req)
		if st["status"] != "approved" {
			t.Fatalf("round %d: %v", round, st)
		}
		if n, _ := f.exchange(st["redirect"], verifier); n != 200 {
			t.Fatalf("round %d exchange %d", round, n)
		}
	}
	access, _ := f.connect()
	c := &mcpConn{f: f, token: access}
	c.initialize()
	for round := range 2 { // the same approval request twice: a new mail after the first is used
		out := c.tool("request_approval", `{"action":"tool:shell","reason":"run the build"}`)
		if !strings.Contains(out, `"pending"`) {
			t.Fatalf("round %d first call %s", round, out)
		}
		if n := fa.approveAll(t, "mcp_approval"); n != 1 {
			t.Fatalf("round %d: %d pending approval mails", round, n)
		}
		out = c.tool("request_approval", `{"action":"tool:shell","reason":"run the build","wait_seconds":2}`)
		if !strings.Contains(out, `"approved"`) {
			t.Fatalf("round %d decision %s", round, out)
		}
	}
}

func (f *fixture) mailFor(req string) {
	f.t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.PostForm(f.srv.URL+"/oauth/authorize/mail", url.Values{"request": {req}})
	if err != nil {
		f.t.Fatal(err)
	}
	resp.Body.Close()
}

// MEDIUM 2: two parallel refreshes with one token: at most one succeeds, and
// the reuse ends the consent.
func TestParallelRefreshIsAReuse(t *testing.T) {
	f := newFixture(t)
	f.register()
	_, refresh := f.connect()
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _ = f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.client}})
		}()
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok > 1 {
		t.Fatalf("both parallel refreshes succeeded: %v", codes)
	}
	consents, _ := f.auth.Store.Consents(context.Background(), f.person.AccountID)
	if len(consents) != 1 || !consents[0].Revoked {
		t.Fatalf("reuse did not revoke the consent: %+v", consents)
	}
}

// MEDIUM 3: the person can preview a code (client, redirect, time, IP) before
// confirming; the mail names the code and the redirect host.
func TestCodePreviewAndMailContent(t *testing.T) {
	f := newFixture(t)
	f.register()
	code, req, _ := f.startAuthorize(f.auth.Resource())
	r, _ := http.NewRequest("GET", f.srv.URL+"/v1/mcp/authorize?user_code="+url.QueryEscape(code), nil)
	r.Header.Set(personHeader, "yes")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	var pv map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pv)
	resp.Body.Close()
	if resp.StatusCode != 200 || pv["client_name"] != "Claude" || pv["redirect_host"] != "127.0.0.1:33418" || pv["requester_ip"] == "" || pv["requested_at"] == nil {
		t.Fatalf("preview %d %v", resp.StatusCode, pv)
	}
	if st := f.status(req); st["status"] != "pending" {
		t.Fatal("a preview approved the request")
	}
	f.mailFor(req)
	var target, impact string
	for _, c := range f.fake().changes {
		if c.Kind == "mcp_connect" {
			target, impact = c.Target, c.Impact
		}
	}
	if !strings.Contains(target, code) || !strings.Contains(target, "127.0.0.1:33418") || !strings.Contains(impact, code) {
		t.Fatalf("mail target %q impact %q", target, impact)
	}
}

// MEDIUM 4: flooding limits.
func TestFloodingLimits(t *testing.T) {
	f := newFixture(t)
	f.register()
	// pending requests per client
	for i := range maxPendingPerClient {
		if code, _, _ := f.startAuthorize(f.auth.Resource()); code == "" {
			t.Fatalf("authorize %d refused early", i)
		}
	}
	verifier := strings.Repeat("v", 50)
	_ = verifier
	q := url.Values{"response_type": {"code"}, "client_id": {f.client}, "redirect_uri": {f.redir}, "code_challenge": {strings.Repeat("c", 43)}, "code_challenge_method": {"S256"}, "resource": {f.auth.Resource()}}
	resp, _ := http.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("pending cap per client not enforced: %d", resp.StatusCode)
	}
	// connect mails: one per client per hour
	f.auth.mu.Lock()
	var reqs []string
	for id, p := range f.auth.pending {
		if p.ClientID == f.client {
			reqs = append(reqs, id)
		}
	}
	f.auth.mu.Unlock()
	f.mailFor(reqs[0])
	f.mailFor(reqs[1])
	if n := f.fake().count("mcp_connect"); n != 1 {
		t.Fatalf("%d connect mails for one client within an hour", n)
	}
	// registrations per IP
	n429 := false
	for range maxRegsPerIPHour + 1 {
		raw, _ := json.Marshal(map[string]any{"client_name": "x", "redirect_uris": []string{"https://example.test/cb"}})
		r, _ := http.NewRequest("POST", f.srv.URL+"/oauth/register", bytes.NewReader(raw))
		r.Header.Set("CF-Connecting-IP", "203.0.113.9")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 429 {
			n429 = true
		}
	}
	if !n429 {
		t.Fatal("no per-IP registration limit")
	}
	// a registration that never got a consent expires
	f.redir = "https://late.example/cb"
	resp2, body := f.postJSON("/oauth/register", map[string]any{"client_name": "late", "redirect_uris": []string{f.redir}}, map[string]string{"CF-Connecting-IP": "203.0.113.10"})
	var reg struct {
		ID string `json:"client_id"`
	}
	if resp2.StatusCode != 201 || json.Unmarshal(body, &reg) != nil {
		t.Fatalf("register %d", resp2.StatusCode)
	}
	f.advance(ClientTTL + time.Minute)
	q.Set("client_id", reg.ID)
	q.Set("redirect_uri", f.redir)
	resp, _ = http.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expired registration still usable: %d", resp.StatusCode)
	}
}

// H1: request_approval mail is a small daily budget per connection.
func TestMailApprovalsDailyBudget(t *testing.T) {
	f := newFixture(t)
	f.register()
	access, _ := f.connect()
	c := &mcpConn{f: f, token: access}
	c.initialize()
	for i := range MailPerSessionDay {
		if out := c.tool("request_approval", `{"action":"tool:shell","reason":"reason `+string(rune('a'+i))+`"}`); !strings.Contains(out, `"pending"`) {
			t.Fatalf("mail %d: %s", i, out)
		}
	}
	if out := c.tool("request_approval", `{"action":"tool:shell","reason":"one too many"}`); !strings.Contains(out, "approval_unavailable") {
		t.Fatalf("budget not enforced: %s", out)
	}
	if n := f.fake().count("mcp_approval"); n != MailPerSessionDay {
		t.Fatalf("%d mails", n)
	}
}

// H1: the global daily budget across connections.
func TestMailApprovalsGlobalDailyBudget(t *testing.T) {
	appr := &fakeApprovals{}
	m := &MailApprovals{Approvals: appr, Owner: "owner@example.test"}
	n := 0
	for s := range 6 {
		for r := range MailPerSessionDay {
			_, err := m.Ask(context.Background(), fmt.Sprintf("k%d-%d", s, r), nexusops.MailRequest{Email: "owner@example.test", Session: nexus.SessionPrincipal("", ids.Session(fmt.Sprintf("slv_%d", s))).SessionID, Action: "a", Reason: "r"})
			if err == nil {
				n++
			}
		}
	}
	if n != MailPerDay || appr.count("mcp_approval") != MailPerDay {
		t.Fatalf("%d mails sent, budget %d", n, MailPerDay)
	}
	if _, err := m.Ask(context.Background(), "x", nexusops.MailRequest{Email: "someone@example.test"}); err == nil {
		t.Fatal("mailed a non-owner request")
	}
}

// H1 (a): mail consent is off unless enabled; the page has no mail button.
func TestMailConsentOffByDefault(t *testing.T) {
	f := newFixture(t)
	_ = f.auth.Store.PutSettings(context.Background(), Settings{}) // the default: off
	f.register()
	verifier := strings.Repeat("v", 50)
	_ = verifier
	q := url.Values{"response_type": {"code"}, "client_id": {f.client}, "redirect_uri": {f.redir}, "code_challenge": {strings.Repeat("c", 43)}, "code_challenge_method": {"S256"}, "resource": {f.auth.Resource()}}
	resp, _ := http.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(page), "/oauth/authorize/mail") {
		t.Fatal("mail button shown while mail consent is off")
	}
	req := reqRe.FindStringSubmatch(string(page))[1]
	f.mailFor(req)
	if n := f.fake().count("mcp_connect"); n != 0 {
		t.Fatalf("%d consent mails while off", n)
	}
}

// M1: IPv6 limits key on the /64; an unpolled pending request is dropped.
func TestIPv6PrefixLimitsAndIdlePending(t *testing.T) {
	f := newFixture(t)
	n429 := false
	for i := range maxRegsPerIPHour + 1 {
		_, body := f.postJSON("/oauth/register", map[string]any{"client_name": "x", "redirect_uris": []string{"https://example.test/cb"}},
			map[string]string{"CF-Connecting-IP": fmt.Sprintf("2001:db8:1:2::%x", i+1)})
		if strings.Contains(string(body), "too many registrations") {
			n429 = true
		}
	}
	if !n429 {
		t.Fatal("IPv6 addresses in one /64 were limited separately")
	}
	f.register()
	_, req, _ := f.startAuthorize(f.auth.Resource())
	f.advance(pendingIdle + time.Second)
	if st := f.status(req); st["status"] != "expired" {
		t.Fatalf("idle pending request kept: %v", st)
	}
	if ipKey("2001:db8:1:2::1") != ipKey("2001:db8:1:2:ffff::9") || ipKey("2001:db8:1:3::1") == ipKey("2001:db8:1:2::1") || ipKey("192.0.2.1") != "192.0.2.1" {
		t.Fatal("ipKey")
	}
}

// The confirmation binds to the previewed request.
func TestAuthorizeNeedsThePreviewedRequest(t *testing.T) {
	f := newFixture(t)
	f.register()
	code, _, _ := f.startAuthorize(f.auth.Resource())
	if r, _ := f.postJSON("/v1/mcp/authorize", map[string]string{"user_code": code}, map[string]string{personHeader: "yes"}); r.StatusCode != 400 {
		t.Fatalf("confirm without request id: %d", r.StatusCode)
	}
	if r, _ := f.postJSON("/v1/mcp/authorize", map[string]string{"user_code": code, "request_id": "mcr_" + strings.Repeat("0", 64)}, map[string]string{personHeader: "yes"}); r.StatusCode != 404 {
		t.Fatalf("confirm with another request id: %d", r.StatusCode)
	}
	if r, _ := f.approveCode(code); r.StatusCode != 200 {
		t.Fatalf("previewed confirm: %d", r.StatusCode)
	}
}

// MEDIUM 5: a consent stops working when the person's credentials do, and a
// refresh cannot extend it past its absolute end.
func TestConsentFollowsCredentialsAndHasAnEnd(t *testing.T) {
	f := newFixture(t)
	f.register()
	access, refresh := f.connect()
	c := &mcpConn{f: f, token: access}
	if r, _ := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); r.StatusCode == 401 {
		t.Fatal("live consent refused")
	}
	f.live.Store(false)
	f.advance(livenessCache + time.Second)
	if r, _ := c.post(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "ping"}); r.StatusCode != 401 {
		t.Fatalf("consent outlived credentials: %d", r.StatusCode)
	}
	if n, _ := f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.client}}); n != 400 {
		t.Fatalf("refresh with dead credentials: %d", n)
	}
	f.live.Store(true)
	f.advance(livenessCache + time.Second)
	_, refresh2 := f.connect()
	tok, _ := f.auth.Store.Token(context.Background(), Verifier(refresh2))
	cons, _ := f.auth.Store.Consent(context.Background(), tok.ConsentID)
	if tok.Expires.After(cons.Expires) || cons.Expires.Sub(cons.Created) != ConsentTTL {
		t.Fatalf("refresh %v beyond consent end %v", tok.Expires, cons.Expires)
	}
	f.advance(ConsentTTL)
	if n, _ := f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh2}, "client_id": {f.client}}); n != 400 {
		t.Fatalf("refresh past the consent's end: %d", n)
	}
}

// LOW 6: initialize reuses the live remote root.
func TestInitializeReusesTheLiveRoot(t *testing.T) {
	f := newFixture(t)
	f.register()
	access, _ := f.connect()
	for range 3 {
		c := &mcpConn{f: f, token: access}
		c.initialize()
	}
	tok, _ := f.auth.Store.Token(context.Background(), Verifier(access))
	cons, _ := f.auth.Store.Consent(context.Background(), tok.ConsentID)
	events, _, err := f.svc.Events(context.Background(), f.person, cons.Session, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	issued := 0
	for _, e := range events {
		if e.Kind == "delegation.issued" {
			issued++
		}
	}
	if issued != 1 {
		t.Fatalf("%d roots issued for 3 initializes", issued)
	}
}

// LOW 7: nobody else can target a remote session.
func TestRemoteSessionCannotBeTargeted(t *testing.T) {
	f := newFixture(t)
	f.register()
	access, _ := f.connect()
	(&mcpConn{f: f, token: access}).initialize()
	tok, _ := f.auth.Store.Token(context.Background(), Verifier(access))
	cons, _ := f.auth.Store.Consent(context.Background(), tok.ConsentID)
	ctx := context.Background()
	if _, err := f.svc.CreateRoot(ctx, f.person, nexus.RootRequest{Title: "widen", ToSessionID: cons.Session, Runner: nexus.Local, Scope: []string{"newtype:run"}}); err == nil {
		t.Fatal("a person root widened a remote session")
	}
	other, err := f.svc.CreateRoot(ctx, f.person, nexus.RootRequest{Title: "other", Runner: nexus.Local, Scope: []string{"session:delegate"}, Limits: nexus.Limits{MaxDepth: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Delegate(ctx, nexus.SessionPrincipal(f.person.AccountID, other.Session.ID), nexus.DelegateRequest{ParentID: other.Delegation.ID,
		Title: "x", ToSessionID: cons.Session, Scope: []string{}, TTL: time.Minute}); err == nil {
		t.Fatal("another session delegated to a remote session")
	}
}

// LOW 8 + 10: a remote elicitation answer is the client's, not a person's;
// an open GET stream ends once its token is revoked.
func TestRemoteElicitationAttributionAndStreamRevocation(t *testing.T) {
	f := newFixture(t)
	f.register()
	access, _ := f.connect()
	c := &mcpConn{f: f, token: access}
	resp, msgs := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"elicitation": map[string]any{}}}})
	if resp.StatusCode != 200 || len(msgs) != 1 {
		t.Fatal("initialize")
	}
	c.sid = resp.Header.Get("Mcp-Session-Id")
	c.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": "request_approval", "arguments": map[string]string{"action": "tool:shell", "reason": "build"}}})
	req, _ := http.NewRequest("POST", f.srv.URL+"/mcp", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", c.sid)
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	sc := bufio.NewScanner(stream.Body)
	next := func() map[string]json.RawMessage {
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var m map[string]json.RawMessage
				_ = json.Unmarshal([]byte(v), &m)
				return m
			}
		}
		t.Fatal("stream ended")
		return nil
	}
	ask := next()
	c.post(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(ask["id"]), "result": map[string]any{"action": "accept", "content": map[string]string{"decision": "once"}}})
	final := next()
	if !strings.Contains(string(final["result"]), "mcp_client:"+f.client) || strings.Contains(string(final["result"]), "person (MCP elicitation)") {
		t.Fatalf("attribution %s", final["result"])
	}

	// GET stream, then revoke the access token: the stream ends at a heartbeat
	g, _ := http.NewRequest("GET", f.srv.URL+"/mcp", nil)
	g.Header.Set("Authorization", "Bearer "+access)
	g.Header.Set("Accept", "text/event-stream")
	g.Header.Set("Mcp-Session-Id", c.sid)
	gs, err := http.DefaultClient.Do(g)
	if err != nil || gs.StatusCode != 200 {
		t.Fatalf("GET stream %v", err)
	}
	defer gs.Body.Close()
	_ = f.auth.Store.RevokeToken(context.Background(), Verifier(access))
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := gs.Body.Read(buf); err != nil {
				close(done)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("GET stream survived token revocation")
	}
}

// The mail-consent switch: person-only, owner-only to change, durable, on the
// ledger, and the page and authorizeMail follow it.
func TestMailConsentSetting(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_ = f.auth.Store.PutSettings(ctx, Settings{})
	f.auth.settingsAt = time.Time{}
	put := func(on bool, hdr map[string]string) int {
		raw, _ := json.Marshal(map[string]bool{"mail_consent": on})
		r, _ := http.NewRequest("PUT", f.srv.URL+"/v1/mcp/settings", bytes.NewReader(raw))
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// no person (anonymous, or an /mcp token): refused
	if n := put(true, nil); n != 401 {
		t.Fatalf("anonymous put %d", n)
	}
	f.register()
	access, _ := f.connect()
	if n := put(true, map[string]string{"Authorization": "Bearer " + access}); n != 401 {
		t.Fatalf("ntm_ put %d", n)
	}
	// a person who is not the owner: refused
	owner := f.auth.OwnerEmail
	f.auth.OwnerEmail = "someone-else@example.test"
	if n := put(true, map[string]string{personHeader: "yes"}); n != 403 {
		t.Fatalf("non-owner put %d", n)
	}
	f.auth.OwnerEmail = owner
	// the operator seat exists: the change lands on its ledger
	op, err := f.svc.CreateRoot(ctx, f.person, nexus.RootRequest{Title: "operator", Runner: nexus.Local, Scope: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if n := put(true, map[string]string{personHeader: "yes"}); n != 200 {
		t.Fatalf("owner put %d", n)
	}
	v, _ := f.auth.Store.Settings(ctx)
	if !v.MailConsent || v.UpdatedBy != owner {
		t.Fatalf("not persisted: %+v", v)
	}
	events, _, _ := f.svc.Events(ctx, f.person, op.Session.ID, 0, 100)
	found := false
	for _, e := range events {
		if e.Kind == "mcp.settings.changed" {
			found = true
		}
	}
	if !found {
		t.Fatal("settings change not on the ledger")
	}
	// on: the page offers the mail button and authorizeMail sends
	_, req, _ := f.startAuthorize(f.auth.Resource())
	resp, _ := http.Get(f.srv.URL + "/oauth/authorize?request=" + req)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "/oauth/authorize/mail") {
		t.Fatal("mail button missing while on")
	}
	f.mailFor(req)
	if n := f.fake().count("mcp_connect"); n != 1 {
		t.Fatalf("%d mails while on", n)
	}
	// off again: no button, no mail
	if n := put(false, map[string]string{personHeader: "yes"}); n != 200 {
		t.Fatal("off")
	}
	f.advance(24*time.Hour + time.Minute)
	_, req2, _ := f.startAuthorize(f.auth.Resource())
	resp, _ = http.Get(f.srv.URL + "/oauth/authorize?request=" + req2)
	page, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(page), "/oauth/authorize/mail") {
		t.Fatal("mail button shown while off")
	}
	f.mailFor(req2)
	if n := f.fake().count("mcp_connect"); n != 1 {
		t.Fatalf("%d mails after turning off", n)
	}
	// GET shows the state to a person only
	r, _ := http.NewRequest("GET", f.srv.URL+"/v1/mcp/settings", nil)
	if resp, _ := http.DefaultClient.Do(r); resp.StatusCode != 401 {
		t.Fatalf("anonymous get %d", resp.StatusCode)
	}
}

// Consent mails: 3 per day overall, 1 per client per day (24 h window).
func TestConsentMailsDailyBudget(t *testing.T) {
	f := newFixture(t)
	for i := range 5 {
		f.redir = fmt.Sprintf("https://c%d.example/cb", i)
		_, body := f.postJSON("/oauth/register", map[string]any{"client_name": fmt.Sprintf("c%d", i), "redirect_uris": []string{f.redir}}, nil)
		var reg struct {
			ID string `json:"client_id"`
		}
		_ = json.Unmarshal(body, &reg)
		f.client = reg.ID
		_, req, _ := f.startAuthorize(f.auth.Resource())
		f.mailFor(req)
		if i == 0 {
			_, again, _ := f.startAuthorize(f.auth.Resource())
			f.mailFor(again) // the same client again the same day: no mail
		}
	}
	if n := f.fake().count("mcp_connect"); n != maxConnectMailsDay {
		t.Fatalf("%d consent mails in a day, budget %d", n, maxConnectMailsDay)
	}
	f.advance(24*time.Hour + time.Minute)
	f.register() // the earlier registrations expired unconsented
	_, req, _ := f.startAuthorize(f.auth.Resource())
	f.mailFor(req)
	if n := f.fake().count("mcp_connect"); n != maxConnectMailsDay+1 {
		t.Fatalf("budget did not renew after 24h: %d", n)
	}
}

func TestSameEmailRefusesUnicodeFolds(t *testing.T) {
	if !sameEmail("Owner@Example.TEST", "owner@example.test") || sameEmail("ownſr@example.test", "owner@example.test") || sameEmail("owner@example.teſt", "owner@example.tesst") || sameEmail("", "") {
		t.Fatal("sameEmail")
	}
	if sameEmail("Kate@example.test", "kate@example.test") {
		t.Fatal("Kelvin sign matched k")
	}
}
