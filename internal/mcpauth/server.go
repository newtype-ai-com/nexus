package mcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

const (
	Scope      = "nexus:connect"
	AccessTTL  = time.Hour
	RefreshTTL = 30 * 24 * time.Hour
	CodeTTL    = 60 * time.Second
	PendingTTL = 15 * time.Minute
	// ConsentTTL is the absolute life of a consent: refresh never extends it.
	ConsentTTL = 90 * 24 * time.Hour
	// ClientTTL: a registration that never got a consent is purged after it.
	ClientTTL = 24 * time.Hour

	// Limits against unauthenticated flooding (also protects the approvals
	// service's permanent request cap, shared with default-model approvals).
	maxPending          = 64
	pendingIdle         = 2 * time.Minute // a request nobody polls is dropped
	maxPendingPerClient = 5
	maxPendingPerIP     = 10
	maxRegsMin          = 60
	maxRegsPerIPHour    = 10
	maxConnectMailsDay  = 3 // consent mails per day overall (and 1 per client per day)
	livenessCache       = time.Minute
	accessPfx           = "ntm_"
	refreshPfx          = "ntr_"
	codePfx             = "mca_"
	clientPfx           = "mcl_"
	consentPfx          = "mcc_"
	pendingPfx          = "mcr_"
	userCodeABC         = "BCDFGHJKLMNPQRSTVWXZ"
)

// Server is the authorization server and resource check for /mcp.
type Server struct {
	Issuer string // e.g. https://lic.newtype-ai.com (the resource is Issuer+"/mcp")
	Store  Store
	// Approvals (B's admin client to the approvals service) enables the
	// emailed one-time consent link; the approvals service mails OwnerEmail
	// and AccountForEmail turns that address into the consenting account.
	Approvals       gate.ChangeApprovals
	OwnerEmail      string
	AccountForEmail func(context.Context, string) (ids.Account, error)
	// Authenticate is Nexus's own request authentication, used for the
	// person routes under /v1/mcp (CLI code confirmation, consent list/revoke).
	Authenticate func(*http.Request) (nexus.Principal, error)
	// OnRevoke ends live MCP sessions of a revoked consent.
	OnRevoke func(consentID string)
	// AccountLive says whether the account still holds a live licence and
	// login that pass the server's admission policy (owner-only). A consent
	// never outlives its person's credentials: Check and refresh ask it
	// (cached for a minute). Nil: no consent works.
	AccountLive func(ctx context.Context, account ids.Account) bool
	// Record writes a person's settings change into the ledger (NewEndpoint
	// sets it: the account's remote connection sessions and operator seat).
	Record func(ctx context.Context, p nexus.Principal, kind string, payload map[string]any)
	Clock  func() time.Time
	// CIMD fetches OAuth Client ID Metadata Documents for URL-formatted
	// client_ids (nil: a default SSRF-hardened fetcher).
	CIMD *CIMDFetcher

	mu          sync.Mutex
	pending     map[string]*pending
	regs        []time.Time
	regsByIP    map[string][]time.Time
	mails       []time.Time
	mailsClient map[string]time.Time
	live        map[ids.Account]liveEntry
	settings    Settings
	settingsAt  time.Time
}

type liveEntry struct {
	ok    bool
	until time.Time
}

type pending struct {
	ID         string
	ClientID   string
	ClientName string
	// ClientDomain is the verified host of a metadata-document client_id
	// (empty for a dynamically registered client, whose name is unverified).
	ClientDomain string
	Redirect     string
	Challenge    string
	State        string
	UserCode     string
	Created      time.Time
	IP           string
	Expires      time.Time
	LastPoll     time.Time // last approvals-service poll
	LastSeen     time.Time // last status poll by the consent page
	Status       string    // pending | approved | denied | issued
	Account      ids.Account
	Email        string
	Via          string
	ChangeID     string
	Manifest     string
	Back         string // redirect with code once issued
}

func (s *Server) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}

// Resource is the protected resource identifier (the audience of tokens).
func (s *Server) Resource() string { return strings.TrimRight(s.Issuer, "/") + "/mcp" }

func (s *Server) metadataURL() string {
	return strings.TrimRight(s.Issuer, "/") + "/.well-known/oauth-protected-resource/mcp"
}

// Challenge is the WWW-Authenticate value for a 401 from /mcp.
func (s *Server) Challenge() string {
	return `Bearer resource_metadata="` + s.metadataURL() + `", scope="` + Scope + `"`
}

// Grant is what a valid access token proves: this person let this client
// connect. It says nothing about what the connection may do.
type Grant struct {
	Consent Consent
}

// Check validates a /mcp request's bearer token (exactly one header, the
// access-token prefix, live, unexpired, audience = this resource, scope, live
// consent). Tokens for other audiences and every other credential fail.
func (s *Server) Check(r *http.Request) (Grant, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || r.URL.Query().Has("access_token") {
		return Grant{}, false
	}
	scheme, tok, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || !strings.HasPrefix(tok, accessPfx) || len(tok) > 200 {
		return Grant{}, false
	}
	t, err := s.Store.Token(r.Context(), Verifier(tok))
	if err != nil || t.Kind != "access" || t.Revoked || !s.now().Before(t.Expires) || t.Audience != s.Resource() || !slices.Contains(strings.Fields(t.Scope), Scope) {
		return Grant{}, false
	}
	c, err := s.Store.Consent(r.Context(), t.ConsentID)
	if err != nil || !s.consentUsable(r.Context(), c) || c.Account != t.Account || c.ClientID != t.ClientID {
		return Grant{}, false
	}
	return Grant{Consent: c}, true
}

// consentUsable: not revoked, within its absolute life, and its person still
// holds live credentials that pass admission.
func (s *Server) consentUsable(ctx context.Context, c Consent) bool {
	if c.Revoked || !s.now().Before(c.Expires) {
		return false
	}
	return s.accountLive(ctx, c.Account)
}

func (s *Server) accountLive(ctx context.Context, account ids.Account) bool {
	if s.AccountLive == nil {
		return false
	}
	now := s.now()
	s.mu.Lock()
	e, ok := s.live[account]
	s.mu.Unlock()
	if ok && now.Before(e.until) {
		return e.ok
	}
	live := s.AccountLive(ctx, account)
	s.mu.Lock()
	if s.live == nil {
		s.live = map[ids.Account]liveEntry{}
	}
	s.live[account] = liveEntry{ok: live, until: now.Add(livenessCache)}
	s.mu.Unlock()
	return live
}

// clientIP is the requester address: Cloudflare's header when the request
// came through the loopback tunnel (B binds loopback only), else the peer.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if cf := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); cf != nil {
			return cf.String()
		}
	}
	return host
}

// ipKey is the rate-limit key of an address: IPv4 as is, IPv6 by its /64
// (one host usually owns a whole /64).
func ipKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// stalePending: expired, or still pending but no longer polled by its page.
func stalePending(p *pending, now time.Time) bool {
	return !now.Before(p.Expires) || (p.Status == "pending" && now.Sub(p.LastSeen) > pendingIdle)
}

// usableClient: registered, and either consented once or still young.
func (s *Server) usableClient(ctx context.Context, id string) (Client, bool) {
	c, err := s.Store.Client(ctx, id)
	if err != nil || (!c.Consented && !s.now().Before(c.Created.Add(ClientTTL))) {
		return Client{}, false
	}
	return c, true
}

// Sweep drops expired pending requests and purges never-consented clients.
func (s *Server) Sweep(ctx context.Context) {
	now := s.now()
	s.mu.Lock()
	for id, p := range s.pending {
		if stalePending(p, now) {
			delete(s.pending, id)
		}
	}
	for a, e := range s.live {
		if !now.Before(e.until) {
			delete(s.live, a)
		}
	}
	s.mu.Unlock()
	_ = s.Store.PurgeClients(ctx, now.Add(-ClientTTL))
}

// Routes mounts the discovery documents, the OAuth endpoints and the person
// routes on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authorizationServer)
	mux.HandleFunc("POST /oauth/register", s.register)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("GET /oauth/authorize.js", s.authorizeJS)
	mux.HandleFunc("POST /oauth/authorize/mail", s.authorizeMail)
	mux.HandleFunc("GET /oauth/authorize/status", s.authorizeStatus)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revoke)
	mux.HandleFunc("GET /v1/mcp/authorize", s.personPreview)
	mux.HandleFunc("POST /v1/mcp/authorize", s.personAuthorize)
	mux.HandleFunc("GET /v1/mcp/clients", s.personClients)
	mux.HandleFunc("GET /v1/mcp/settings", s.getSettings)
	mux.HandleFunc("PUT /v1/mcp/settings", s.putSettings)
	mux.HandleFunc("POST /v1/mcp/clients/{consent}/revoke", s.personRevoke)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code int, kind, desc string) {
	writeJSON(w, code, map[string]string{"error": kind, "error_description": desc})
}

func (s *Server) protectedResource(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"resource": s.Resource(), "authorization_servers": []string{strings.TrimRight(s.Issuer, "/")},
		"scopes_supported": []string{Scope}, "bearer_methods_supported": []string{"header"}, "resource_name": "Newtype Nexus"})
}

func (s *Server) authorizationServer(w http.ResponseWriter, _ *http.Request) {
	iss := strings.TrimRight(s.Issuer, "/")
	writeJSON(w, 200, map[string]any{"issuer": iss, "authorization_endpoint": iss + "/oauth/authorize", "token_endpoint": iss + "/oauth/token",
		"registration_endpoint": iss + "/oauth/register", "revocation_endpoint": iss + "/oauth/revoke", "scopes_supported": []string{Scope},
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"},
		"revocation_endpoint_auth_methods_supported": []string{"none"}, "authorization_response_iss_parameter_supported": true,
		"client_id_metadata_document_supported": true})
}

// validRedirect accepts https URLs and loopback http (RFC 8252), no fragment,
// no userinfo.
func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil || u.Host == "" || len(raw) > 2000 {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}
	return false
}

// loopbackRedirect reports whether u is an http redirect to a loopback host
// (localhost, 127.0.0.0/8, ::1).
func loopbackRedirect(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// matchRedirect: exact string match against a registered (or metadata-
// declared) redirect URI, except that a loopback http redirect matches a
// registered loopback URI on any port (RFC 8252 §7.3: native clients bind an
// ephemeral port). Scheme, host, path and query must still be equal.
func matchRedirect(registered []string, got string) bool {
	if slices.Contains(registered, got) {
		return true
	}
	g, err := url.Parse(got)
	if err != nil || !validRedirect(got) || !loopbackRedirect(g) {
		return false
	}
	for _, r := range registered {
		u, err := url.Parse(r)
		if err != nil || !loopbackRedirect(u) {
			continue
		}
		if strings.EqualFold(u.Hostname(), g.Hostname()) && u.EscapedPath() == g.EscapedPath() && u.RawQuery == g.RawQuery {
			return true
		}
	}
	return false
}

func validName(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > 100 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// allowRegistration spends one slot of the registration budget (per minute
// overall, per hour per address). A metadata-document fetch spends one too:
// both are unauthenticated requests that make the server do work.
func (s *Server) allowRegistration(r *http.Request) bool {
	now := s.now()
	ip := ipKey(clientIP(r))
	s.mu.Lock()
	s.regs = slices.DeleteFunc(s.regs, func(t time.Time) bool { return now.Sub(t) > time.Minute })
	if s.regsByIP == nil {
		s.regsByIP = map[string][]time.Time{}
	}
	for k, v := range s.regsByIP {
		if v = slices.DeleteFunc(v, func(t time.Time) bool { return now.Sub(t) > time.Hour }); len(v) == 0 {
			delete(s.regsByIP, k)
		} else {
			s.regsByIP[k] = v
		}
	}
	limited := len(s.regs) >= maxRegsMin || len(s.regsByIP[ip]) >= maxRegsPerIPHour
	if !limited {
		s.regs = append(s.regs, now)
		s.regsByIP[ip] = append(s.regsByIP[ip], now)
	}
	s.mu.Unlock()
	return !limited
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if !s.allowRegistration(r) {
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations from this address; retry in an hour, or use a client_id metadata document URL")
		return
	}
	var in struct {
		Name         string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		GrantTypes   []string `json:"grant_types"`
		Response     []string `json:"response_types"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		oauthError(w, 400, "invalid_client_metadata", "the body must be a JSON object of client metadata (RFC 7591), at most 16 KB")
		return
	}
	if in.Name == "" {
		in.Name = "MCP client"
	}
	if !validName(in.Name) || len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > 5 {
		oauthError(w, 400, "invalid_client_metadata", "client_name (1-100 printable characters) and 1..5 redirect_uris are required")
		return
	}
	for _, u := range in.RedirectURIs {
		if !validRedirect(u) {
			oauthError(w, 400, "invalid_redirect_uri", "redirect_uris must be https URLs or http URLs on localhost/127.0.0.1/[::1], without a fragment or userinfo: "+u)
			return
		}
	}
	if in.AuthMethod != "" && in.AuthMethod != "none" {
		oauthError(w, 400, "invalid_client_metadata", "only public clients are supported: token_endpoint_auth_method must be none")
		return
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, 400, "invalid_client_metadata", "unsupported grant type "+strconv.Quote(g)+"; supported: authorization_code, refresh_token")
			return
		}
	}
	for _, rt := range in.Response {
		if rt != "code" {
			oauthError(w, 400, "invalid_client_metadata", "unsupported response type "+strconv.Quote(rt)+"; supported: code")
			return
		}
	}
	c := Client{ID: random(clientPfx), Name: in.Name, RedirectURIs: in.RedirectURIs, Created: now}
	if err := s.Store.PutClient(r.Context(), c); err != nil {
		oauthError(w, 500, "server_error", "the registration could not be stored; retry shortly")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"client_id": c.ID, "client_id_issued_at": now.Unix(), "client_name": c.Name,
		"redirect_uris": c.RedirectURIs, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "none"})
}

func userCode() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, userCodeABC[int(v)%len(userCodeABC)])
	}
	return string(out)
}

func normalizeCode(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if len(s) != 8 {
		return ""
	}
	return s[:4] + "-" + s[4:]
}

func redirectWith(base string, q url.Values) string {
	u, _ := url.Parse(base)
	v := u.Query()
	for k, vals := range q {
		for _, x := range vals {
			v.Add(k, x)
		}
	}
	u.RawQuery = v.Encode()
	return u.String()
}

func securePage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}

var errorPage = template.Must(template.New("e").Parse(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Nexus 연결</title><body style="font-family:system-ui;max-width:36rem;margin:3rem auto;padding:0 1rem"><h1>연결할 수 없습니다</h1><p>{{.}}</p></body>`))

var consentPage = template.Must(template.New("c").Parse(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Nexus 연결 허락</title>
<body style="font-family:system-ui;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5">
<h1>Nexus 에 연결하려 합니다</h1>
{{if .Domain}}<p id="client"><b>{{.Domain}}</b> 의 클라이언트 — "{{.ClientName}}" (자칭) 이(가) Newtype Nexus 계정에 연결하려 합니다.</p>
<ul><li>확인된 클라이언트 도메인: <code>{{.Domain}}</code> (클라이언트 메타데이터 문서의 주소)</li><li>이름 "{{.ClientName}}" 은 그 도메인이 스스로 밝힌 것입니다</li>{{else}}<p id="client"><b>확인되지 않은 클라이언트</b> — "{{.ClientName}}" (자칭) 이(가) Newtype Nexus 계정에 연결하려 합니다.</p>
<ul><li>클라이언트 도메인: 확인되지 않음 (스스로 등록한 클라이언트라 이름은 클라이언트가 정한 것입니다)</li>{{end}}
<li>돌아갈 곳: <code>{{.Host}}</code></li></ul>
{{if .Warn}}<p style="color:#b00000"><b>주의</b>: {{.Warn}}</p>{{end}}
<p>연결하면 이 클라이언트용 세션이 하나 만들어지고, 그 세션은 <b>도구 전용 위임</b>(모델 없음, 다른 세션에 일을 맡기는 것 한 단계)만 받습니다. 그 밖의 일은 사람의 승인이 필요합니다. 언제든 <code>newtype nmcp revoke</code> 로 끊을 수 있습니다.</p>
<h2>확인 방법</h2>
<p>1. 터미널에서 (로그인된 newtype):</p><pre style="font-size:1.4rem">newtype nmcp authorize {{.UserCode}}</pre>
{{if .Mail}}<p>2. 또는 계정 이메일로 받은 확인 링크에서 허락:</p><form method="post" action="/oauth/authorize/mail"><input type="hidden" name="request" value="{{.ID}}"><button>확인 메일 보내기</button></form>{{end}}
<p id="status" data-request="{{.ID}}">기다리는 중… 이 페이지는 확인되면 자동으로 넘어갑니다.</p>
<p style="color:#666;font-size:.9rem">이 연결을 요청하지 않았다면 이 창을 닫으세요. 이 페이지를 여는 것만으로는 아무것도 허락되지 않습니다.</p>
<script src="/oauth/authorize.js"></script></body>`))

const authorizeScript = `(function(){var el=document.getElementById('status');if(!el)return;var id=el.getAttribute('data-request');
function tick(){fetch('/oauth/authorize/status?request='+encodeURIComponent(id),{cache:'no-store'}).then(function(r){return r.json()}).then(function(s){
if(s.status==='approved'&&s.redirect){el.textContent='허락되었습니다. 돌아갑니다…';location.replace(s.redirect);return}
if(s.status==='denied'||s.status==='expired'){el.textContent=s.status==='denied'?'거절되었습니다.':'시간이 지났습니다. 클라이언트에서 다시 시작하세요.';return}
if(s.mail==='sent'){el.textContent='확인 메일을 보냈습니다. 메일의 링크에서 허락하세요…'}setTimeout(tick,2000)}).catch(function(){setTimeout(tick,4000)})}tick()})();`

func (s *Server) authorizeJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(authorizeScript))
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fail := func(msg string) {
		securePage(w)
		w.WriteHeader(400)
		_ = errorPage.Execute(w, msg)
	}
	if id := q.Get("request"); id != "" { // back from the mail button
		p := s.lookupPending(id)
		if p == nil {
			fail("이 연결 요청은 없거나 끝났습니다. 클라이언트에서 다시 시작하세요.")
			return
		}
		s.renderConsent(w, p)
		return
	}
	c, domain, msg := s.authorizeClient(r, q.Get("client_id"))
	if msg != "" {
		fail(msg)
		return
	}
	redirect := q.Get("redirect_uri")
	if !matchRedirect(c.RedirectURIs, redirect) {
		fail("돌아갈 주소(redirect_uri)가 클라이언트가 등록·선언한 것과 다릅니다. 클라이언트 설정을 확인하세요. / The redirect_uri does not match one the client registered or declared.")
		return
	}
	back := func(kind string) {
		http.Redirect(w, r, redirectWith(redirect, url.Values{"error": {kind}, "state": {q.Get("state")}, "iss": {strings.TrimRight(s.Issuer, "/")}}), http.StatusFound)
	}
	switch {
	case q.Get("response_type") != "code":
		back("unsupported_response_type")
		return
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 || len(q.Get("code_challenge")) > 128:
		back("invalid_request")
		return
	case q.Get("resource") != s.Resource():
		back("invalid_target")
		return
	case q.Get("scope") != "" && q.Get("scope") != Scope:
		back("invalid_scope")
		return
	}
	now := s.now()
	p := &pending{ID: random(pendingPfx), ClientID: c.ID, ClientName: c.Name, ClientDomain: domain, Redirect: redirect, Challenge: q.Get("code_challenge"), State: q.Get("state"),
		UserCode: userCode(), Created: now, IP: clientIP(r), Expires: now.Add(PendingTTL), LastSeen: now, Status: "pending"}
	s.mu.Lock()
	if s.pending == nil {
		s.pending = map[string]*pending{}
	}
	perClient, perIP := 0, 0
	for id, x := range s.pending {
		if stalePending(x, now) {
			delete(s.pending, id)
			continue
		}
		if x.Status != "pending" {
			continue
		}
		if clientLimitKey(x.ClientID, x.IP) == clientLimitKey(p.ClientID, p.IP) {
			perClient++
		}
		if ipKey(x.IP) == ipKey(p.IP) {
			perIP++
		}
	}
	full := len(s.pending) >= maxPending || perClient >= maxPendingPerClient || perIP >= maxPendingPerIP
	if !full {
		s.pending[p.ID] = p
	}
	s.mu.Unlock()
	if full {
		fail("지금은 연결 요청이 너무 많습니다. 잠시 뒤 다시 하세요.")
		return
	}
	s.renderConsent(w, p)
}

// authorizeClient finds the client of an authorization request: a URL
// client_id through its metadata document (domain = the URL host), otherwise
// a registered mcl_ client (no verified domain). msg is the page's error.
func (s *Server) authorizeClient(r *http.Request, id string) (Client, string, string) {
	if IsCIMDClientID(id) {
		if _, err := ParseCIMDURL(id); err != nil {
			return Client{}, "", "client_id 가 올바른 메타데이터 문서 URL 이 아닙니다. / " + err.Error()
		}
		f := s.cimd()
		if !f.Cached(id) && !s.allowRegistration(r) {
			return Client{}, "", "지금은 연결 요청이 너무 많습니다. 잠시 뒤 다시 하세요. / Too many new clients from this address; retry later."
		}
		md, err := f.Fetch(r.Context(), id)
		if err != nil {
			return Client{}, "", "클라이언트 메타데이터 문서를 받아들일 수 없습니다. 클라이언트 제공자에게 알리세요. / " + err.Error()
		}
		return Client{ID: id, Name: md.ClientName, RedirectURIs: md.RedirectURIs}, md.Domain, ""
	}
	c, ok := s.usableClient(r.Context(), id)
	if !ok {
		return Client{}, "", "등록되지 않았거나 만료된 클라이언트입니다. 클라이언트에서 연결을 다시 시작하세요(다시 등록됩니다). / Unknown or expired client_id; start the connection again so the client registers anew."
	}
	return c, "", ""
}

func (s *Server) cimd() *CIMDFetcher {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CIMD == nil {
		s.CIMD = &CIMDFetcher{}
	}
	return s.CIMD
}

func redirectHost(redirect string) string {
	if u, err := url.Parse(redirect); err == nil {
		return u.Host
	}
	return ""
}

func (s *Server) renderConsent(w http.ResponseWriter, p *pending) {
	securePage(w)
	_ = consentPage.Execute(w, map[string]any{"ClientName": p.ClientName, "Domain": p.ClientDomain, "Warn": brandWarning(p.ClientName, p.ClientDomain),
		"Host": redirectHost(p.Redirect), "UserCode": p.UserCode, "ID": p.ID, "Mail": s.mailConsent()})
}

// brands maps a well-known product word in a client_name to the domains that
// may use it. A self-chosen name with such a word from another (or no
// verified) domain gets a warning on the consent page and in the CLI.
var brands = []struct {
	words   []string
	domains []string
}{
	{[]string{"claude", "anthropic"}, []string{"claude.ai", "claude.com", "anthropic.com"}},
	{[]string{"openai", "chatgpt", "gpt"}, []string{"openai.com", "chatgpt.com"}},
	{[]string{"google", "gemini"}, []string{"google.com"}},
}

func brandWarning(name, domain string) string {
	low := strings.ToLower(name)
	for _, b := range brands {
		for _, w := range b.words {
			if !strings.Contains(low, w) {
				continue
			}
			for _, d := range b.domains {
				if domain == d || strings.HasSuffix(domain, "."+d) {
					return ""
				}
			}
			shown := domain
			if shown == "" {
				shown = "확인되지 않음 / not verified"
			}
			return "이름에 \"" + w + "\" 이(가) 있지만 클라이언트 도메인(" + shown + ")은 그 회사의 도메인이 아닙니다. 직접 시작한 연결이 아니면 허락하지 마세요. / The name mentions \"" + w + "\" but the client domain is not that company's."
		}
	}
	return ""
}

// clientLimitKey keys the per-client pending and mail limits. A registered
// (mcl_) client is one caller's own registration; a metadata-document
// client_id is public and shared by every user of that client, so its limits
// are per (client_id, requester address): one requester cannot use them up
// for everyone. The per-address and global caps still apply.
func clientLimitKey(clientID, ip string) string {
	if IsCIMDClientID(clientID) {
		return clientID + "\x00" + ipKey(ip)
	}
	return clientID
}

// mailConsent: the approvals client exists and the person's switch is on
// (read from the store, cached for a few seconds; any error means off).
func (s *Server) mailConsent() bool {
	if s.Approvals == nil {
		return false
	}
	return s.currentSettings(context.Background()).MailConsent
}

func (s *Server) currentSettings(ctx context.Context) Settings {
	now := s.now()
	s.mu.Lock()
	if now.Sub(s.settingsAt) < 5*time.Second && !s.settingsAt.IsZero() {
		v := s.settings
		s.mu.Unlock()
		return v
	}
	s.mu.Unlock()
	v, err := s.Store.Settings(ctx)
	if err != nil {
		return Settings{}
	}
	s.mu.Lock()
	s.settings, s.settingsAt = v, now
	s.mu.Unlock()
	return v
}

func (s *Server) lookupPending(id string) *pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[id]
	if p == nil || stalePending(p, s.now()) {
		return nil
	}
	p.LastSeen = s.now()
	return p
}

// authorizeMail sends the emailed one-time link (through the approvals
// service, which mails the owner address). Once per request.
func (s *Server) authorizeMail(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	p := s.lookupPending(r.FormValue("request"))
	if p == nil || !s.mailConsent() {
		securePage(w)
		w.WriteHeader(400)
		_ = errorPage.Execute(w, "이 연결 요청은 없거나 끝났습니다.")
		return
	}
	now := s.now()
	s.mu.Lock()
	s.mails = slices.DeleteFunc(s.mails, func(t time.Time) bool { return now.Sub(t) > 24*time.Hour })
	if s.mailsClient == nil {
		s.mailsClient = map[string]time.Time{}
	}
	for k, t := range s.mailsClient {
		if now.Sub(t) > 24*time.Hour {
			delete(s.mailsClient, k)
		}
	}
	mailKey := clientLimitKey(p.ClientID, p.IP)
	_, clientMailed := s.mailsClient[mailKey]
	send := p.ChangeID == "" && p.Status == "pending" && !clientMailed && len(s.mails) < maxConnectMailsDay
	if send {
		p.ChangeID = "sending"
		s.mails = append(s.mails, now)
		s.mailsClient[mailKey] = now
	}
	s.mu.Unlock()
	if send {
		host := p.Redirect
		if u, err := url.Parse(p.Redirect); err == nil {
			host = u.Host
		}
		manifest, _ := json.Marshal(map[string]string{"request": p.ID, "user_code": p.UserCode, "client_id": p.ClientID, "client_name": p.ClientName, "client_domain": p.ClientDomain,
			"redirect_uri": p.Redirect, "requester_ip": p.IP, "requested_at": p.Created.Format(time.RFC3339), "resource": s.Resource()})
		// ClientID is the pending request: the approvals store keys
		// idempotency on Requester+ClientID for good, so it must be unique.
		ch, err := s.Approvals.Begin(r.Context(), gate.ChangeInput{Requester: "nexus mcp", Kind: "mcp_connect",
			Target:   clientDomainNote(p.ClientDomain) + " · 이름(자칭) " + p.ClientName + " · 코드 " + p.UserCode + " · 돌아갈 곳 " + host,
			Manifest: string(manifest), BaseState: "연결 없음 · 요청 IP " + p.IP + " · " + p.Created.Format(time.RFC3339),
			Impact: "동의 페이지에 보이는 코드가 " + p.UserCode + " 이고 돌아갈 곳이 " + host + " 일 때만 승인하세요. 승인하면 이 클라이언트가 도구 전용 Nexus 세션으로 연결됩니다(모델 없음, 위임 안에서만).",
			Cost:   "없음", Recovery: "newtype nmcp revoke 로 언제든 끊기", ClientID: p.ID, TTLSeconds: int64(PendingTTL / time.Second)})
		s.mu.Lock()
		if err != nil {
			p.ChangeID = ""
		} else {
			p.ChangeID, p.Manifest = ch.ID, string(manifest)
		}
		s.mu.Unlock()
	}
	http.Redirect(w, r, "/oauth/authorize?"+url.Values{"request": {p.ID}}.Encode()+"#mail", http.StatusSeeOther)
}

// authorizeStatus is polled by the consent page; once approved (CLI code or
// mail) it issues the one-time code and returns the client redirect.
func (s *Server) authorizeStatus(w http.ResponseWriter, r *http.Request) {
	p := s.lookupPending(r.URL.Query().Get("request"))
	if p == nil {
		writeJSON(w, 200, map[string]string{"status": "expired"})
		return
	}
	now := s.now()
	s.mu.Lock()
	changeID, manifest, status := p.ChangeID, p.Manifest, p.Status
	poll := status == "pending" && strings.HasPrefix(changeID, "car_") && s.Approvals != nil && now.Sub(p.LastPoll) >= 3*time.Second
	if poll {
		p.LastPoll = now // the approvals service is asked at most every 3 s per request
	}
	s.mu.Unlock()
	if poll {
		if ch, err := s.Approvals.Get(r.Context(), changeID); err == nil {
			switch ch.Status {
			case "approved":
				// Resolve the account first: a failure leaves the approval
				// unconsumed, so the next poll retries.
				if s.AccountForEmail == nil {
					break
				}
				account, err := s.AccountForEmail(r.Context(), s.OwnerEmail)
				if err != nil || !s.accountLive(r.Context(), account) {
					break
				}
				if _, err := s.Approvals.Consume(r.Context(), changeID, manifest); err == nil {
					s.mu.Lock()
					if p.Status == "pending" {
						p.Status, p.Account, p.Email, p.Via = "approved", account, s.OwnerEmail, "mail"
					}
					s.mu.Unlock()
					_, _ = s.Approvals.Result(r.Context(), changeID, "connected")
				}
			case "denied", "expired":
				s.mu.Lock()
				p.Status = "denied"
				s.mu.Unlock()
			}
		}
	}
	s.mu.Lock()
	status = p.Status
	s.mu.Unlock()
	switch status {
	case "approved":
		back, err := s.issueCode(r.Context(), p)
		if err != nil {
			writeJSON(w, 200, map[string]string{"status": "pending"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "approved", "redirect": back})
	case "issued":
		s.mu.Lock()
		back := p.Back
		s.mu.Unlock()
		writeJSON(w, 200, map[string]string{"status": "approved", "redirect": back})
	case "denied":
		writeJSON(w, 200, map[string]string{"status": "denied"})
	default:
		mail := ""
		if strings.HasPrefix(changeID, "car_") {
			mail = "sent"
		}
		writeJSON(w, 200, map[string]string{"status": "pending", "mail": mail})
	}
}

// issueCode reuses the person's live consent for this client (one remote
// session per consent) or creates one, then issues a one-time code.
func (s *Server) issueCode(ctx context.Context, p *pending) (string, error) {
	s.mu.Lock()
	if p.Status != "approved" {
		back := p.Back
		s.mu.Unlock()
		return back, nil
	}
	p.Status = "issuing"
	s.mu.Unlock()
	restore := func() {
		s.mu.Lock()
		p.Status = "approved"
		s.mu.Unlock()
	}
	consents, err := s.Store.Consents(ctx, p.Account)
	if err != nil {
		restore()
		return "", err
	}
	var consent *Consent
	for i := range consents {
		if consents[i].ClientID == p.ClientID && !consents[i].Revoked && s.now().Before(consents[i].Expires) {
			consent = &consents[i]
		}
	}
	if consent == nil {
		now := s.now()
		c := Consent{ID: random(consentPfx), ClientID: p.ClientID, Name: p.ClientName, Account: p.Account, Email: p.Email, Via: p.Via, Created: now, Expires: now.Add(ConsentTTL)}
		if err := s.Store.PutConsent(ctx, c); err != nil {
			restore()
			return "", err
		}
		consent = &c
	}
	if !IsCIMDClientID(p.ClientID) { // metadata-document clients have no registration row
		if err := s.Store.MarkConsented(ctx, p.ClientID); err != nil {
			restore()
			return "", err
		}
	}
	code := random(codePfx)
	if err := s.Store.PutCode(ctx, Code{Verifier: Verifier(code), ClientID: p.ClientID, Redirect: p.Redirect, Challenge: p.Challenge, Resource: s.Resource(),
		Scope: Scope, ConsentID: consent.ID, Expires: s.now().Add(CodeTTL)}); err != nil {
		restore()
		return "", err
	}
	back := redirectWith(p.Redirect, url.Values{"code": {code}, "state": {p.State}, "iss": {strings.TrimRight(s.Issuer, "/")}})
	s.mu.Lock()
	p.Status, p.Back = "issued", back
	s.mu.Unlock()
	return back, nil
}

func clientDomainNote(domain string) string {
	if domain == "" {
		return "도메인 확인 안 됨"
	}
	return "확인된 도메인 " + domain
}

func pkceOK(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func (s *Server) issueTokens(ctx context.Context, w http.ResponseWriter, c Consent) {
	access, refresh := random(accessPfx), random(refreshPfx)
	now := s.now()
	base := Token{ClientID: c.ClientID, ConsentID: c.ID, Account: c.Account, Email: c.Email, Audience: s.Resource(), Scope: Scope}
	a, rf := base, base
	a.Verifier, a.Kind, a.Expires = Verifier(access), "access", now.Add(AccessTTL)
	rf.Verifier, rf.Kind, rf.Expires = Verifier(refresh), "refresh", now.Add(RefreshTTL)
	if c.Expires.Before(rf.Expires) {
		rf.Expires = c.Expires // a consent's absolute end is never extended
	}
	if c.Expires.Before(a.Expires) {
		a.Expires = c.Expires
	}
	if s.Store.PutToken(ctx, a) != nil || s.Store.PutToken(ctx, rf) != nil {
		oauthError(w, 500, "server_error", "the tokens could not be stored; retry the token request")
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int64(AccessTTL / time.Second), "refresh_token": refresh, "scope": Scope})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/x-www-form-urlencoded" {
		oauthError(w, 400, "invalid_request", "the token request body must be application/x-www-form-urlencoded (RFC 6749 §3.2)")
		return
	}
	if r.ParseForm() != nil {
		oauthError(w, 400, "invalid_request", "the form body could not be parsed (at most 16 KB)")
		return
	}
	f := r.PostForm
	if res := f.Get("resource"); res != "" && res != s.Resource() {
		oauthError(w, 400, "invalid_target", "resource must be "+s.Resource())
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		code, err := s.Store.TakeCode(r.Context(), Verifier(f.Get("code")))
		if errors.Is(err, ErrUsed) {
			_ = s.Store.RevokeConsent(r.Context(), code.ConsentID) // a replayed code revokes what it issued
			if s.OnRevoke != nil {
				s.OnRevoke(code.ConsentID)
			}
			oauthError(w, 400, "invalid_grant", "code already used")
			return
		}
		if err != nil || !s.now().Before(code.Expires) || code.ClientID != f.Get("client_id") || code.Redirect != f.Get("redirect_uri") || code.Resource != s.Resource() || !pkceOK(f.Get("code_verifier"), code.Challenge) {
			oauthError(w, 400, "invalid_grant", "the authorization code is unknown or expired, or client_id, redirect_uri or code_verifier does not match the authorization request; start the authorization again")
			return
		}
		c, err := s.Store.Consent(r.Context(), code.ConsentID)
		if err != nil || !s.consentUsable(r.Context(), c) {
			oauthError(w, 400, "invalid_grant", "the consent was revoked or expired, or the account's Nexus login is no longer live; authorize again")
			return
		}
		s.issueTokens(r.Context(), w, c)
	case "refresh_token":
		// Refresh does not re-fetch or re-check a metadata-document client's
		// document: the consent (and its absolute end) is what refresh relies
		// on, and the document was verified when the person consented.
		tok := f.Get("refresh_token")
		t, err := s.Store.Token(r.Context(), Verifier(tok))
		if err != nil || t.Kind != "refresh" || !strings.HasPrefix(tok, refreshPfx) || t.ClientID != f.Get("client_id") {
			oauthError(w, 400, "invalid_grant", "the refresh token is unknown or was issued to another client_id; authorize again")
			return
		}
		if t.Revoked { // reuse of a rotated refresh token: revoke the whole consent
			_ = s.Store.RevokeConsent(r.Context(), t.ConsentID)
			if s.OnRevoke != nil {
				s.OnRevoke(t.ConsentID)
			}
			oauthError(w, 400, "invalid_grant", "refresh token reused")
			return
		}
		c, err := s.Store.Consent(r.Context(), t.ConsentID)
		if err != nil || !s.consentUsable(r.Context(), c) || !s.now().Before(t.Expires) {
			oauthError(w, 400, "invalid_grant", "the consent was revoked or expired, or the account's Nexus login is no longer live; authorize again")
			return
		}
		// Atomic: of two parallel uses only one retires the token; the other
		// is a reuse and ends the consent.
		if err := s.Store.ConsumeRefresh(r.Context(), t.Verifier); err != nil {
			if errors.Is(err, ErrUsed) {
				_ = s.Store.RevokeConsent(r.Context(), t.ConsentID)
				if s.OnRevoke != nil {
					s.OnRevoke(t.ConsentID)
				}
				oauthError(w, 400, "invalid_grant", "refresh token reused")
				return
			}
			oauthError(w, 500, "server_error", "the refresh token could not be rotated; retry the refresh once")
			return
		}
		s.issueTokens(r.Context(), w, c)
	default:
		oauthError(w, 400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

// revoke (RFC 7009) always answers 200; revoking a refresh token ends the
// whole consent (the grant), an access token only itself.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	tok := r.FormValue("token")
	if t, err := s.Store.Token(r.Context(), Verifier(tok)); err == nil {
		if t.Kind == "refresh" {
			_ = s.Store.RevokeConsent(r.Context(), t.ConsentID)
			if s.OnRevoke != nil {
				s.OnRevoke(t.ConsentID)
			}
		} else {
			_ = s.Store.RevokeToken(r.Context(), t.Verifier)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
}

func (s *Server) person(w http.ResponseWriter, r *http.Request) (nexus.Principal, bool) {
	if s.Authenticate == nil {
		writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
		return nexus.Principal{}, false
	}
	p, err := s.Authenticate(r)
	if err != nil || p.Kind != nexus.PrincipalUser || p.CredentialID != "" || p.Email == "" {
		writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
		return nexus.Principal{}, false
	}
	return p, true
}

// personPreview shows what a code would allow before the person confirms it
// (device-code phishing: the person compares client and redirect host).
func (s *Server) personPreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.person(w, r); !ok {
		return
	}
	code := normalizeCode(r.URL.Query().Get("user_code"))
	now := s.now()
	s.mu.Lock()
	var hit pending
	found := false
	for _, x := range s.pending {
		if code != "" && x.UserCode == code && x.Status == "pending" && now.Before(x.Expires) {
			hit, found = *x, true
		}
	}
	s.mu.Unlock()
	if !found {
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(w, 200, map[string]any{"request_id": hit.ID, "client_name": hit.ClientName, "client_id": hit.ClientID, "client_domain": hit.ClientDomain,
		"client_verified": hit.ClientDomain != "", "client_warning": brandWarning(hit.ClientName, hit.ClientDomain), "redirect_host": redirectHost(hit.Redirect), "redirect_uri": hit.Redirect,
		"requested_at": hit.Created, "requester_ip": hit.IP, "expires_at": hit.Expires})
}

// personAuthorize: `newtype nmcp authorize CODE` with a live login confirms a
// pending consent for the caller's own account.
func (s *Server) personAuthorize(w http.ResponseWriter, r *http.Request) {
	p, ok := s.person(w, r)
	if !ok {
		return
	}
	var in struct {
		Code    string `json:"user_code"`
		Request string `json:"request_id"` // the request the person previewed
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if json.NewDecoder(r.Body).Decode(&in) != nil || normalizeCode(in.Code) == "" || !strings.HasPrefix(in.Request, pendingPfx) {
		writeJSON(w, 400, map[string]string{"error": "invalid"})
		return
	}
	code := normalizeCode(in.Code)
	now := s.now()
	s.mu.Lock()
	var hit *pending
	if x := s.pending[in.Request]; x != nil && x.UserCode == code && x.Status == "pending" && !stalePending(x, now) {
		hit = x // approves exactly what was previewed, nothing that reused the code since
	}
	if hit != nil {
		hit.Status, hit.Account, hit.Email, hit.Via = "approved", p.AccountID, p.Email, "cli"
	}
	s.mu.Unlock()
	if hit == nil {
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(w, 200, map[string]string{"client_name": hit.ClientName, "client_domain": hit.ClientDomain, "redirect_host": redirectHost(hit.Redirect), "status": "approved"})
}

func (s *Server) personClients(w http.ResponseWriter, r *http.Request) {
	p, ok := s.person(w, r)
	if !ok {
		return
	}
	list, err := s.Store.Consents(r.Context(), p.AccountID)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "unavailable"})
		return
	}
	if list == nil {
		list = []Consent{}
	}
	writeJSON(w, 200, map[string]any{"clients": list})
}

func (s *Server) personRevoke(w http.ResponseWriter, r *http.Request) {
	p, ok := s.person(w, r)
	if !ok {
		return
	}
	id := r.PathValue("consent")
	c, err := s.Store.Consent(r.Context(), id)
	if err != nil || c.Account != p.AccountID {
		writeJSON(w, 404, map[string]string{"error": "not_found"})
		return
	}
	if err := s.Store.RevokeConsent(r.Context(), id); err != nil {
		writeJSON(w, 503, map[string]string{"error": "unavailable"})
		return
	}
	if s.OnRevoke != nil {
		s.OnRevoke(id)
	}
	writeJSON(w, 200, map[string]string{"status": "revoked", "consent_id": id})
}

func (s *Server) settingsView(v Settings) map[string]any {
	return map[string]any{"mail_consent": v.MailConsent, "mail_available": s.Approvals != nil, "updated_at": v.UpdatedAt, "updated_by": v.UpdatedBy,
		"note": "mail_consent: 동의 페이지에 확인 메일 버튼을 보입니다 · 누구든 동의 페이지를 열면 owner 에게 메일을 보내게 할 수 있습니다(하루 예산 안에서)"}
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.person(w, r); !ok {
		return
	}
	v, err := s.Store.Settings(r.Context())
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "unavailable"})
		return
	}
	writeJSON(w, 200, s.settingsView(v))
}

// putSettings: the owner person only (the mail goes to the owner). Session
// principals and /mcp tokens never reach here (person auth refuses them).
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.person(w, r)
	if !ok {
		return
	}
	if s.OwnerEmail == "" || !sameEmail(p.Email, s.OwnerEmail) {
		writeJSON(w, 403, map[string]string{"error": "owner_only"})
		return
	}
	var in struct {
		MailConsent *bool `json:"mail_consent"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || in.MailConsent == nil {
		writeJSON(w, 400, map[string]string{"error": "invalid"})
		return
	}
	old, err := s.Store.Settings(r.Context())
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "unavailable"})
		return
	}
	v := old
	v.MailConsent, v.UpdatedAt, v.UpdatedBy = *in.MailConsent, s.now(), p.Email
	if err := s.Store.PutSettings(r.Context(), v); err != nil {
		writeJSON(w, 503, map[string]string{"error": "unavailable"})
		return
	}
	s.mu.Lock()
	s.settings, s.settingsAt = v, s.now()
	s.mu.Unlock()
	if s.Record != nil {
		s.Record(r.Context(), p, "mcp.settings.changed", map[string]any{"setting": "mail_consent", "from": old.MailConsent, "to": v.MailConsent, "by": p.Email})
	}
	writeJSON(w, 200, s.settingsView(v))
}

// sameEmail compares addresses after trimming and ASCII lowercasing; any
// non-ASCII address never matches (no Unicode case-folding lookalikes such
// as "ſ" for "s"). Same rule as gate.SameEmail.
func sameEmail(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" {
		return false
	}
	for _, s := range []string{a, b} {
		for i := 0; i < len(s); i++ {
			if s[i] >= 0x80 {
				return false
			}
		}
	}
	return strings.ToLower(a) == strings.ToLower(b)
}
