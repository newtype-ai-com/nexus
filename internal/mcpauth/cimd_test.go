package mcpauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cimdHost serves client metadata documents over TLS. The test certificate
// is valid for example.com; LookupIP maps example.com to the loopback test
// server and AllowAddr admits loopback for it (production refuses loopback).
type cimdHost struct {
	srv     *httptest.Server
	mux     *http.ServeMux
	fetches atomic.Int32
}

func newCIMDHost(t *testing.T) *cimdHost {
	t.Helper()
	h := &cimdHost{mux: http.NewServeMux()}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.fetches.Add(1)
		h.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// url is https://example.com + path (the fetcher dials the test port).
func (h *cimdHost) url(path string) string {
	return "https://example.com" + path
}

func (h *cimdHost) port() string {
	u, _ := url.Parse(h.srv.URL)
	return u.Port()
}

func (h *cimdHost) doc(path string, md map[string]any, header map[string]string) {
	h.mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for k, v := range header {
			w.Header().Set(k, v)
		}
		_ = json.NewEncoder(w).Encode(md)
	})
}

func (h *cimdHost) fetcher() *CIMDFetcher {
	pool := x509.NewCertPool()
	pool.AddCert(h.srv.Certificate())
	return &CIMDFetcher{
		TLS: &tls.Config{RootCAs: pool},
		LookupIP: func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "example.com":
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			case "other.example.com":
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return nil, &CIMDError{"no such host"}
		},
		AllowAddr: func(a netip.Addr) bool { return a.IsLoopback() },
		DialPort:  h.port(),
	}
}

func claudeCodeDoc(id string, redirects ...string) map[string]any {
	if len(redirects) == 0 {
		redirects = []string{"http://localhost/callback", "http://127.0.0.1/callback"}
	}
	return map[string]any{"client_id": id, "client_name": "Claude Code", "redirect_uris": redirects,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"}
}

// The AS metadata advertises CIMD and keeps DCR and "none".
func TestMetadataAdvertisesCIMD(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var asm map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&asm)
	if asm["client_id_metadata_document_supported"] != true || asm["registration_endpoint"] == nil {
		t.Fatalf("asm %v", asm)
	}
	if methods, _ := asm["token_endpoint_auth_methods_supported"].([]any); len(methods) != 1 || methods[0] != "none" {
		t.Fatalf("auth methods %v", asm["token_endpoint_auth_methods_supported"])
	}
	// the protected resource names exactly one authorization server (Claude uses the first)
	resp, err = http.Get(f.srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var prm map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&prm)
	if as, _ := prm["authorization_servers"].([]any); len(as) != 1 || as[0] != f.srv.URL || asm["issuer"] != as[0] {
		t.Fatalf("authorization_servers %v (issuer %v)", prm["authorization_servers"], asm["issuer"])
	}
}

// Happy path: a URL client_id → its document is fetched once → consent shows
// the verified domain → a loopback redirect on another port matches → tokens,
// refresh, /mcp. No registration row is written.
func TestCIMDClientConnects(t *testing.T) {
	f := newFixture(t)
	h := newCIMDHost(t)
	f.auth.CIMD = h.fetcher()
	id := h.url("/oauth/claude-code-client-metadata")
	h.doc("/oauth/claude-code-client-metadata", claudeCodeDoc(id), map[string]string{"Cache-Control": "max-age=600"})
	f.client, f.redir = id, "http://localhost:51234/callback" // the document declares http://localhost/callback

	code, req, verifier := f.startAuthorize(f.auth.Resource())
	r, _ := http.NewRequest("GET", f.srv.URL+"/v1/mcp/authorize?user_code="+url.QueryEscape(code), nil)
	r.Header.Set(personHeader, "yes")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	var pv map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pv)
	resp.Body.Close()
	if pv["client_domain"] != "example.com" || pv["client_verified"] != true || pv["redirect_host"] != "localhost:51234" || pv["client_name"] != "Claude Code" {
		t.Fatalf("preview %v", pv)
	}
	if resp, body := f.postJSON("/v1/mcp/authorize", map[string]string{"user_code": code, "request_id": pv["request_id"].(string)}, map[string]string{personHeader: "yes"}); resp.StatusCode != 200 || !strings.Contains(string(body), "example.com") {
		t.Fatalf("authorize %d %s", resp.StatusCode, body)
	}
	st := f.status(req)
	n, tok := f.exchange(st["redirect"], verifier)
	if n != 200 || tok["access_token"] == nil {
		t.Fatalf("token %d %v", n, tok)
	}
	// a second authorization uses the cached document
	f.startAuthorize(f.auth.Resource())
	if got := h.fetches.Load(); got != 1 {
		t.Fatalf("document fetched %d times", got)
	}
	if _, err := f.auth.Store.Client(context.Background(), id); err == nil {
		t.Fatal("a metadata-document client was stored as a registration")
	}
	n, again := f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {id}})
	if n != 200 || again["access_token"] == nil {
		t.Fatalf("refresh %d %v", n, again)
	}
	c := &mcpConn{f: f, token: again["access_token"].(string)}
	c.initialize()
	if out := c.tool("nexus_peers", `{}`); strings.Contains(out, `"error"`) {
		t.Fatalf("peers %s", out)
	}
}

// The consent page names the verified client domain and the redirect host; a
// registered (DCR) client is shown as unverified.
func TestConsentPageShowsDomain(t *testing.T) {
	f := newFixture(t)
	h := newCIMDHost(t)
	f.auth.CIMD = h.fetcher()
	id := h.url("/client.json")
	h.doc("/client.json", claudeCodeDoc(id), nil)
	page := func() string {
		q := url.Values{"response_type": {"code"}, "client_id": {f.client}, "redirect_uri": {f.redir}, "code_challenge": {strings.Repeat("a", 43)},
			"code_challenge_method": {"S256"}, "resource": {f.auth.Resource()}}
		resp, err := http.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	f.client, f.redir = id, "http://127.0.0.1:40000/callback"
	if p := page(); !strings.Contains(p, "확인된 클라이언트 도메인: <code>example.com</code>") || !strings.Contains(p, "<code>127.0.0.1:40000</code>") {
		t.Fatalf("CIMD consent page:\n%s", p)
	}
	f.register()
	if p := page(); !strings.Contains(p, "확인되지 않음") {
		t.Fatalf("DCR consent page:\n%s", p)
	}
}

// The hosted redirect https://claude.ai/api/mcp/auth_callback works with both
// DCR and CIMD (exact match, https).
func TestHostedClaudeRedirect(t *testing.T) {
	const hosted = "https://claude.ai/api/mcp/auth_callback"
	f := newFixture(t)
	resp, body := f.postJSON("/oauth/register", map[string]any{"client_name": "Claude", "redirect_uris": []string{hosted}, "token_endpoint_auth_method": "none"}, nil)
	var reg struct {
		ID string `json:"client_id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &reg) != nil {
		t.Fatalf("register %d %s", resp.StatusCode, body)
	}
	f.client, f.redir = reg.ID, hosted
	if access, _ := f.connect(); access == "" {
		t.Fatal("no token over DCR")
	}

	h := newCIMDHost(t)
	f.auth.CIMD = h.fetcher()
	id := h.url("/oauth/claude-ai")
	h.doc("/oauth/claude-ai", claudeCodeDoc(id, hosted), nil)
	f.client = id
	if access, _ := f.connect(); access == "" {
		t.Fatal("no token over CIMD")
	}
	// exact match for https: another path or port is refused
	f.redir = "https://claude.ai/api/mcp/other"
	q := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {f.redir}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {f.auth.Resource()}}
	r, _ := http.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatalf("other https redirect %d", r.StatusCode)
	}
}

func TestCIMDRefusals(t *testing.T) {
	h := newCIMDHost(t)
	ok := h.url("/ok.json")
	h.doc("/ok.json", claudeCodeDoc(ok), nil)
	h.doc("/mismatch.json", claudeCodeDoc("https://evil.example/client.json"), nil)
	h.doc("/secret.json", func() map[string]any {
		d := claudeCodeDoc(h.url("/secret.json"))
		d["client_secret"] = "s"
		return d
	}(), nil)
	h.doc("/basic.json", func() map[string]any {
		d := claudeCodeDoc(h.url("/basic.json"))
		d["token_endpoint_auth_method"] = "client_secret_basic"
		return d
	}(), nil)
	h.doc("/badredirect.json", claudeCodeDoc(h.url("/badredirect.json"), "http://evil.example/callback"), nil)
	h.mux.HandleFunc("GET /html.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_ = json.NewEncoder(w).Encode(claudeCodeDoc(h.url("/html.json")))
	})
	h.mux.HandleFunc("GET /big.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		d := claudeCodeDoc(h.url("/big.json"))
		d["padding"] = strings.Repeat("x", 70<<10)
		_ = json.NewEncoder(w).Encode(d)
	})
	h.mux.HandleFunc("GET /redirect.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example.com/ok.json", http.StatusFound)
	})
	h.mux.HandleFunc("GET /same.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok.json", http.StatusFound) // same host: still refused
	})
	h.mux.HandleFunc("GET /dup.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"client_id":"https://evil.example/x","client_id":"`+h.url("/dup.json")+`","client_name":"C","redirect_uris":["http://localhost/cb"]}`)
	})
	h.mux.HandleFunc("GET /case.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Client_ID":"`+h.url("/case.json")+`","client_name":"C","redirect_uris":["http://localhost/cb"]}`)
	})
	h.mux.HandleFunc("GET /slow.json", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	})

	f := h.fetcher()
	if _, err := f.Fetch(context.Background(), ok); err != nil {
		t.Fatalf("happy path: %v", err)
	}
	f.Timeout = 300 * time.Millisecond
	for path, want := range map[string]string{
		"/mismatch.json":    "does not equal",
		"/secret.json":      "client_secret",
		"/basic.json":       "token_endpoint_auth_method",
		"/badredirect.json": "redirect_uris",
		"/html.json":        "content type",
		"/big.json":         "larger than",
		"/redirect.json":    "redirects are not followed",
		"/same.json":        "redirects are not followed",
		"/dup.json":         "duplicate keys",
		"/case.json":        "no \"client_id\" key",
		"/slow.json":        "timed out",
		"/missing.json":     "HTTP 404",
	} {
		_, err := f.Fetch(context.Background(), h.url(path))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v (want %q)", path, err, want)
		}
	}

	// SSRF: the production address check refuses private, loopback,
	// link-local and mapped addresses, by literal and by resolution, and a
	// mixed answer (public + private) as a rebinding attempt.
	strict := h.fetcher()
	strict.AllowAddr = nil
	for _, c := range []struct {
		host  string
		addrs []string
	}{
		{"example.com", []string{"127.0.0.1"}},
		{"example.com", []string{"10.1.2.3"}},
		{"example.com", []string{"192.168.0.10"}},
		{"example.com", []string{"169.254.169.254"}},
		{"example.com", []string{"100.64.0.1"}},
		{"example.com", []string{"::1"}},
		{"example.com", []string{"fd00::1"}},
		{"example.com", []string{"fe80::1"}},
		{"example.com", []string{"::ffff:127.0.0.1"}},
		{"example.com", []string{"::7f00:1"}},           // IPv4-compatible ::127.0.0.1 (::/96)
		{"example.com", []string{"::ffff:0:a00:1"}},     // IPv4-translated (::ffff:0:0:0/96)
		{"example.com", []string{"::ffff:0:5db8:d822"}}, // translated form of a public address: still refused
		{"example.com", []string{"93.184.216.34", "10.0.0.1"}},
	} {
		strict.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, a := range c.addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
		strict.cache = nil
		if _, err := strict.Fetch(context.Background(), ok); err == nil || !strings.Contains(err.Error(), "does not resolve to a public address") {
			t.Fatalf("%v: %v", c.addrs, err)
		}
	}
	for _, lit := range []string{"https://127.0.0.1/client.json", "https://[::1]/client.json", "https://169.254.169.254/latest", "https://10.0.0.1/c"} {
		if _, err := strict.Fetch(context.Background(), lit); err == nil || !strings.Contains(err.Error(), "does not resolve to a public address") {
			t.Fatalf("%s: %v", lit, err)
		}
	}
	if !PublicAddr(netip.MustParseAddr("93.184.216.34")) || !PublicAddr(netip.MustParseAddr("2606:2800:220:1::1")) {
		t.Fatal("public addresses refused")
	}

	// malformed client_id URLs never reach the network
	before := h.fetches.Load()
	for _, bad := range []string{"https://example.com", "https://example.com/", "https://u:p@example.com/c", "https://example.com/c#f",
		"https://example.com/c?x=1", "https://example.com/a/../c", "http://example.com/c", "https://example.com:8443/c", "https://example.com:80/c"} {
		if _, err := ParseCIMDURL(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	if h.fetches.Load() != before {
		t.Fatal("a malformed URL was fetched")
	}
	if _, err := ParseCIMDURL("https://example.com:443/c"); err != nil {
		t.Fatalf("explicit 443 refused: %v", err)
	}
	// L1: an unresolvable name and a private answer give the same error
	strict.LookupIP = func(context.Context, string) ([]netip.Addr, error) { return nil, &CIMDError{"nxdomain"} }
	_, e1 := strict.Fetch(context.Background(), ok)
	strict.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}
	_, e2 := strict.Fetch(context.Background(), ok)
	if e1 == nil || e2 == nil || e1.Error() != e2.Error() {
		t.Fatalf("resolution errors differ: %v / %v", e1, e2)
	}
}

// A refused document fails the authorization with a page naming the reason.
// Failures are never cached (draft §5.2); each retry refetches, within the
// registration rate limit.
func TestCIMDFailureAtAuthorize(t *testing.T) {
	f := newFixture(t)
	h := newCIMDHost(t)
	f.auth.CIMD = h.fetcher()
	id := h.url("/mismatch.json")
	h.doc("/mismatch.json", claudeCodeDoc("https://elsewhere.example/client.json"), nil)
	q := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {"http://localhost:1/callback"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "resource": {f.auth.Resource()}}
	for range 3 {
		resp, err := http.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 || !strings.Contains(string(b), "does not equal") {
			t.Fatalf("authorize %d %s", resp.StatusCode, b)
		}
	}
	if n := h.fetches.Load(); n != 3 {
		t.Fatalf("fetched %d times", n)
	}
}

func TestCacheTTLFollowsHeaders(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		h    map[string]string
		want time.Duration
	}{
		{nil, time.Hour},
		{map[string]string{"Cache-Control": "public, max-age=120"}, 2 * time.Minute},
		{map[string]string{"Cache-Control": "max-age=99999999"}, 24 * time.Hour},
		{map[string]string{"Cache-Control": "no-store"}, 0},
		{map[string]string{"Cache-Control": "no-cache, max-age=600"}, 0},
		{map[string]string{"Expires": now.Add(10 * time.Minute).Format(http.TimeFormat)}, 10 * time.Minute},
		{map[string]string{"Expires": "0"}, 0},
	} {
		h := http.Header{}
		for k, v := range c.h {
			h.Set(k, v)
		}
		if got := cacheTTL(h, now); got != c.want {
			t.Fatalf("%v: %v want %v", c.h, got, c.want)
		}
	}
	// the cache is bounded
	f := &CIMDFetcher{}
	for i := range cimdMaxEntries + 20 {
		f.store("https://example.com/"+string(rune('a'+i%26))+strings.Repeat("x", i), cimdEntry{expires: time.Now().Add(time.Hour), added: time.Now()})
	}
	if len(f.cache) > cimdMaxEntries {
		t.Fatalf("cache holds %d", len(f.cache))
	}
}

// RFC 8252 §7.3: a loopback http redirect matches on any port; everything
// else is an exact match.
func TestLoopbackRedirectIgnoresPort(t *testing.T) {
	reg := []string{"http://localhost/callback", "http://127.0.0.1:33418/callback", "http://[::1]/cb", "https://claude.ai/api/mcp/auth_callback"}
	for got, want := range map[string]bool{
		"http://localhost/callback":                    true,
		"http://localhost:51234/callback":              true,
		"http://127.0.0.1:9/callback":                  true,
		"http://127.0.0.1/callback":                    true,
		"http://[::1]:8080/cb":                         true,
		"https://claude.ai/api/mcp/auth_callback":      true,
		"http://localhost:51234/other":                 false,
		"http://localhost:51234/callback?x=1":          false,
		"http://127.0.0.1:9/cb":                        false,
		"http://[::1]:8080/callback":                   false,
		"http://localhost.evil.example/callback":       false,
		"https://localhost/callback":                   false,
		"https://claude.ai:8443/api/mcp/auth_callback": false,
		"https://claude.ai/api/mcp/auth_callback/":     false,
		"http://claude.ai/api/mcp/auth_callback":       false,
	} {
		if matchRedirect(reg, got) != want {
			t.Fatalf("%s: want %v", got, want)
		}
	}
	// localhost and 127.0.0.1 are not interchangeable (both are declared by Claude Code)
	if matchRedirect([]string{"http://localhost/callback"}, "http://127.0.0.1:5/callback") {
		t.Fatal("localhost matched 127.0.0.1")
	}
}

// The token endpoint takes form-encoded bodies (and says so otherwise); an
// unknown refresh token is invalid_grant.
func TestTokenEndpointFormAndInvalidGrant(t *testing.T) {
	f := newFixture(t)
	f.register()
	_, refresh := f.connect()
	resp, body := f.postJSON("/oauth/token", map[string]string{"grant_type": "refresh_token", "refresh_token": refresh, "client_id": f.client}, nil)
	if resp.StatusCode != 400 || !strings.Contains(string(body), "x-www-form-urlencoded") {
		t.Fatalf("JSON token body %d %s", resp.StatusCode, body)
	}
	n, out := f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"ntr_" + strings.Repeat("0", 64)}, "client_id": {f.client}})
	if n != 400 || out["error"] != "invalid_grant" || out["error_description"] == "" {
		t.Fatalf("unknown refresh %d %v", n, out)
	}
	n, out = f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"mcl_other"}})
	if n != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("other client %d %v", n, out)
	}
	// a valid form-encoded refresh (charset parameter allowed)
	req, _ := http.NewRequest("POST", f.srv.URL+"/oauth/token", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.client}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("form refresh %d", r.StatusCode)
	}
}

// Discovery, token and refresh answer well within Claude's limits (10 s for
// discovery/registration/token, 30 s for refresh).
func TestAuthEndpointsAnswerQuickly(t *testing.T) {
	f := newFixture(t)
	start := time.Now()
	for _, p := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server"} {
		r, err := http.Get(f.srv.URL + p)
		if err != nil || r.StatusCode != 200 {
			t.Fatalf("%s %v", p, err)
		}
		r.Body.Close()
	}
	f.register()
	_, refresh := f.connect()
	if n, _ := f.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {f.client}}); n != 200 {
		t.Fatalf("refresh %d", n)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("auth flow took %s", d)
	}
	if cimdTimeout > 5*time.Second {
		t.Fatal("metadata fetch may exceed 5 s")
	}
}

// M1: a requester who hangs up, or a fetch that times out, never leaves a
// failure behind for the legitimate client; concurrent misses fetch once.
func TestCIMDCancelledFetchDoesNotPoisonCache(t *testing.T) {
	h := newCIMDHost(t)
	id := h.url("/claude.json")
	slow := atomic.Bool{}
	h.mux.HandleFunc("GET /claude.json", func(w http.ResponseWriter, r *http.Request) {
		if slow.Load() {
			time.Sleep(400 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claudeCodeDoc(id))
	})
	f := h.fetcher()

	// an already-cancelled request context: the fetch still completes and is cached
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Fetch(ctx, id); err != nil {
		t.Fatalf("cancelled requester failed the fetch: %v", err)
	}
	if !f.Cached(id) {
		t.Fatal("success not cached")
	}

	// a timeout is not cached: the next request fetches again and succeeds
	f.cache = nil
	slow.Store(true)
	f.Timeout = 100 * time.Millisecond
	if _, err := f.Fetch(context.Background(), id); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("slow fetch: %v", err)
	}
	if f.Cached(id) {
		t.Fatal("a timeout was cached")
	}
	slow.Store(false)
	f.Timeout = 0
	if _, err := f.Fetch(context.Background(), id); err != nil {
		t.Fatalf("after a timeout: %v", err)
	}

	// singleflight: parallel misses share one fetch
	f.cache = nil
	slow.Store(true)
	before := h.fetches.Load()
	errs := make(chan error, 8)
	for range 8 {
		go func() { _, err := f.Fetch(context.Background(), id); errs <- err }()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := h.fetches.Load() - before; n != 1 {
		t.Fatalf("%d fetches for parallel misses", n)
	}

	// a full cache of other entries evicts the oldest, and failures never enter it
	f.cache = nil
	_, _ = f.Fetch(context.Background(), id)
	_, _ = f.Fetch(context.Background(), h.url("/missing.json"))
	if len(f.cache) != 1 || !f.Cached(id) {
		t.Fatalf("cache %v", f.cache)
	}
}

// M2: the per-client pending and mail limits of a public metadata-document
// client_id are per requester address: one address cannot block another.
func TestCIMDPerClientLimitsArePerAddress(t *testing.T) {
	f := newFixture(t)
	h := newCIMDHost(t)
	f.auth.CIMD = h.fetcher()
	id := h.url("/claude.json")
	h.doc("/claude.json", claudeCodeDoc(id), nil)
	authorize := func(ip string) (int, string) {
		q := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {"http://localhost:5000/callback"}, "code_challenge": {strings.Repeat("c", 43)},
			"code_challenge_method": {"S256"}, "resource": {f.auth.Resource()}}
		r, _ := http.NewRequest("GET", f.srv.URL+"/oauth/authorize?"+q.Encode(), nil)
		r.Header.Set("CF-Connecting-IP", ip)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		m := reqRe.FindStringSubmatch(string(b))
		if m == nil {
			return resp.StatusCode, ""
		}
		return resp.StatusCode, m[1]
	}
	var fromA []string
	for i := range maxPendingPerClient {
		code, req := authorize("203.0.113.1")
		if code != 200 {
			t.Fatalf("A #%d: %d", i, code)
		}
		fromA = append(fromA, req)
	}
	if code, _ := authorize("203.0.113.1"); code != 400 {
		t.Fatalf("A over its per-client cap: %d", code)
	}
	code, fromB := authorize("203.0.113.2")
	if code != 200 {
		t.Fatalf("B blocked by A's pendings: %d", code)
	}
	f.mailFor(fromA[0])
	f.mailFor(fromB)
	if n := f.fake().count("mcp_connect"); n != 2 {
		t.Fatalf("A's mail locked B's mail path: %d mails", n)
	}
}

// M3: the verified domain is the consent headline; the name is shown as
// claimed, and a brand name from a foreign domain is flagged.
func TestConsentHeadlineIsTheDomain(t *testing.T) {
	f := newFixture(t)
	h := newCIMDHost(t)
	f.auth.CIMD = h.fetcher()
	id := h.url("/fake.json")
	h.doc("/fake.json", claudeCodeDoc(id), nil) // example.com calling itself "Claude Code"
	q := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {"http://localhost:5000/callback"}, "code_challenge": {strings.Repeat("c", 43)},
		"code_challenge_method": {"S256"}, "resource": {f.auth.Resource()}}
	resp, err := http.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(b)
	head := page[strings.Index(page, `<p id="client">`):]
	head = head[:strings.Index(head, "</p>")]
	if !strings.HasPrefix(head, `<p id="client"><b>example.com</b>`) || !strings.Contains(head, `"Claude Code" (자칭)`) {
		t.Fatalf("headline %q", head)
	}
	if strings.Contains(page, "<b>Claude Code</b>") || !strings.Contains(page, "주의") {
		t.Fatalf("page:\n%s", page)
	}
	if brandWarning("Claude Code", "claude.ai") != "" || brandWarning("Claude", "api.anthropic.com") != "" || brandWarning("My Tool", "example.com") != "" {
		t.Fatal("false brand warning")
	}
	if brandWarning("ChatGPT helper", "") == "" || brandWarning("Gemini", "evilgoogle.com") == "" {
		t.Fatal("missed brand warning")
	}
}
