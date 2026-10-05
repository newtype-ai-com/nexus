package mcpauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-
// document; MCP 2025-11-25 and later): a client_id that is an https URL names
// a JSON document, served at that URL, describing the client. The document is
// fetched on demand at /oauth/authorize and cached; nothing is stored in the
// mcp_oauth_clients table (its IDs are mcl_ only). Consents, codes and tokens
// keep the URL as their client_id (text columns, no schema change).
//
// The fetch is an outbound request chosen by an unauthenticated caller, so it
// is SSRF-hardened: https only, every resolved address must be public unicast,
// the dial is pinned to the checked address, redirects may not leave the
// host, and time, size and content type are bounded.

const (
	cimdTimeout    = 5 * time.Second
	cimdMaxBytes   = 64 << 10
	cimdMaxEntries = 256
	cimdDefaultTTL = time.Hour
	cimdMaxTTL     = 24 * time.Hour
	cimdMaxURL     = 2000
)

// CIMDError says why a client metadata document was refused.
type CIMDError struct{ Reason string }

func (e *CIMDError) Error() string { return "client metadata document: " + e.Reason }

func cimdErr(format string, a ...any) error { return &CIMDError{Reason: fmt.Sprintf(format, a...)} }

// IsCIMDClientID reports whether client_id is shaped like a metadata document
// URL (as opposed to a registered mcl_ ID). Validity is checked by ParseCIMDURL.
func IsCIMDClientID(id string) bool { return strings.HasPrefix(id, "https://") }

// ParseCIMDURL validates a URL-formatted client_id: https, a host, a path
// other than "/", no userinfo, fragment, query or dot segments.
func ParseCIMDURL(raw string) (*url.URL, error) {
	if len(raw) > cimdMaxURL {
		return nil, cimdErr("client_id URL is longer than %d characters", cimdMaxURL)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return nil, cimdErr("client_id must be an https URL")
	}
	if u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, cimdErr("client_id URL must not contain userinfo or a fragment")
	}
	if u.RawQuery != "" || strings.Contains(raw, "?") {
		return nil, cimdErr("client_id URL must not contain a query")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, cimdErr("client_id URL must contain a path")
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." || strings.EqualFold(seg, "%2e") || strings.EqualFold(seg, "%2e%2e") {
			return nil, cimdErr("client_id URL must not contain dot segments")
		}
	}
	if u.Hostname() == "" {
		return nil, cimdErr("client_id URL has no host")
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, cimdErr("client_id URL must use the default https port 443")
	}
	return u, nil
}

// ClientMetadata is the accepted part of a client metadata document.
type ClientMetadata struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Response     []string `json:"response_types"`
	AuthMethod   string   `json:"token_endpoint_auth_method"`
	ClientSecret *string  `json:"client_secret"`
	// Domain is the verified host of the client_id URL (not from the document).
	Domain string `json:"-"`
}

// validate checks a document against draft-ietf-oauth-client-id-metadata-
// document for a public client: client_id equals the URL, a name, 1..10
// redirect URIs (https or loopback http), no secret, auth method none.
func (m *ClientMetadata) validate(clientID string) error {
	if m.ClientID != clientID {
		return cimdErr("client_id in the document does not equal the URL it was fetched from")
	}
	if !validName(m.ClientName) {
		return cimdErr("client_name is missing or invalid")
	}
	if len(m.RedirectURIs) == 0 || len(m.RedirectURIs) > 10 {
		return cimdErr("redirect_uris must list 1..10 URIs")
	}
	for _, r := range m.RedirectURIs {
		if !validRedirect(r) {
			return cimdErr("redirect_uris must be https or loopback http URLs without a fragment")
		}
	}
	if m.ClientSecret != nil {
		return cimdErr("a client metadata document must not contain client_secret")
	}
	if m.AuthMethod != "" && m.AuthMethod != "none" {
		return cimdErr("token_endpoint_auth_method must be none (public clients only)")
	}
	for _, g := range m.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			return cimdErr("unsupported grant type %q", g)
		}
	}
	for _, rt := range m.Response {
		if rt != "code" {
			return cimdErr("unsupported response type %q", rt)
		}
	}
	return nil
}

type cimdEntry struct {
	md      ClientMetadata
	err     error
	expires time.Time
	added   time.Time
}

// CIMDFetcher fetches and caches client metadata documents.
type CIMDFetcher struct {
	// LookupIP resolves a host (nil: net.DefaultResolver).
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// AllowAddr says whether an address may be dialed (nil: PublicAddr).
	AllowAddr func(netip.Addr) bool
	// TLS is the client TLS configuration (nil: system roots). Tests set
	// RootCAs; ServerName is always the URL host.
	TLS     *tls.Config
	Timeout time.Duration // nil: 5 s
	Clock   func() time.Time
	// DialPort overrides the port dialed (tests only; the URL itself may
	// name no port but 443).
	DialPort string

	mu       sync.Mutex
	cache    map[string]cimdEntry
	inflight map[string]*cimdCall
}

// cimdCall is one fetch in flight; concurrent requests for the same client_id
// wait for it instead of fetching again (singleflight).
type cimdCall struct {
	done chan struct{}
	md   ClientMetadata
	err  error
}

func (f *CIMDFetcher) now() time.Time {
	if f.Clock != nil {
		return f.Clock()
	}
	return time.Now()
}

// PublicAddr refuses every address that is not public unicast: loopback,
// private (RFC 1918, ULA), link-local, multicast, unspecified, CGNAT, the
// documentation, benchmarking and reserved ranges, and IPv4-mapped forms of them.
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fec0::/10",
		"::/96", "::ffff:0:0:0/96", // IPv4-compatible and IPv4-translated forms
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func (f *CIMDFetcher) allow(a netip.Addr) bool {
	if f.AllowAddr != nil {
		return f.AllowAddr(a.Unmap())
	}
	return PublicAddr(a)
}

// errNoPublicAddr is the one answer for "does not resolve" and "resolves to
// a non-public address", so the refusal is no oracle for internal DNS names.
func errNoPublicAddr(host string) error {
	return cimdErr("client_id host %s does not resolve to a public address", host)
}

// resolve returns one dialable address for host, refusing the host when any
// of its addresses is not allowed (a mixed answer is a rebinding attempt).
func (f *CIMDFetcher) resolve(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if !f.allow(a) {
			return netip.Addr{}, errNoPublicAddr(host)
		}
		return a.Unmap(), nil
	}
	lookup := f.LookupIP
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, errNoPublicAddr(host)
	}
	for _, a := range addrs {
		if !f.allow(a) {
			return netip.Addr{}, errNoPublicAddr(host)
		}
	}
	return addrs[0].Unmap(), nil
}

// Fetch returns the validated metadata for a URL-formatted client_id, from the
// cache when fresh. Only successes are cached (draft-ietf-oauth-client-id-
// metadata-document §5.2: error responses and invalid documents are not
// cached), so a cancelled, slow or failed fetch never blocks a legitimate
// client afterwards; repeated misses are bounded by the caller's rate limit.
// The fetch runs detached from ctx's cancellation (a requester who hangs up
// cannot fail it for the others waiting) and is bounded by the fetcher's own
// timeout. Concurrent misses for one client_id share a single fetch.
func (f *CIMDFetcher) Fetch(ctx context.Context, clientID string) (ClientMetadata, error) {
	now := f.now()
	f.mu.Lock()
	if e, ok := f.cache[clientID]; ok && now.Before(e.expires) {
		f.mu.Unlock()
		return e.md, nil
	}
	if c, ok := f.inflight[clientID]; ok {
		f.mu.Unlock()
		<-c.done
		return c.md, c.err
	}
	if f.inflight == nil {
		f.inflight = map[string]*cimdCall{}
	}
	c := &cimdCall{done: make(chan struct{})}
	f.inflight[clientID] = c
	f.mu.Unlock()

	md, ttl, err := f.fetch(context.WithoutCancel(ctx), clientID)
	if err != nil {
		var ce *CIMDError
		if !errors.As(err, &ce) {
			err = cimdErr("fetch failed")
		}
		md = ClientMetadata{}
	} else if ttl > 0 {
		f.store(clientID, cimdEntry{md: md, expires: now.Add(ttl), added: now})
	}
	c.md, c.err = md, err
	f.mu.Lock()
	delete(f.inflight, clientID)
	f.mu.Unlock()
	close(c.done)
	return md, err
}

// Cached reports whether a fresh document is cached, so the caller can
// rate-limit only the fetches that reach the network.
func (f *CIMDFetcher) Cached(clientID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.cache[clientID]
	return ok && f.now().Before(e.expires)
}

// store keeps a fetched document (successes only). When the cache is full,
// expired entries go first, then the oldest.
func (f *CIMDFetcher) store(key string, e cimdEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cache == nil {
		f.cache = map[string]cimdEntry{}
	}
	if _, ok := f.cache[key]; !ok && len(f.cache) >= cimdMaxEntries {
		now := f.now()
		var oldest string
		for k, x := range f.cache {
			if !now.Before(x.expires) {
				delete(f.cache, k)
				continue
			}
			if oldest == "" || x.added.Before(f.cache[oldest].added) {
				oldest = k
			}
		}
		if len(f.cache) >= cimdMaxEntries && oldest != "" {
			delete(f.cache, oldest)
		}
	}
	f.cache[key] = e
}

func (f *CIMDFetcher) fetch(ctx context.Context, clientID string) (ClientMetadata, time.Duration, error) {
	u, err := ParseCIMDURL(clientID)
	if err != nil {
		return ClientMetadata{}, 0, err
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = cimdTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr, err := f.resolve(ctx, u.Hostname())
	if err != nil {
		return ClientMetadata{}, 0, err
	}
	port := "443"
	dialPort := port
	if f.DialPort != "" {
		dialPort = f.DialPort
	}
	pinned := net.JoinHostPort(addr.String(), dialPort)
	want := u.Host
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if f.TLS != nil {
		tlsConf = f.TLS.Clone()
	}
	tlsConf.ServerName = u.Hostname()
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: nil, // never through an environment proxy
		DialContext: func(ctx context.Context, network, hostport string) (net.Conn, error) {
			if hostport != want && hostport != net.JoinHostPort(u.Hostname(), port) {
				return nil, cimdErr("connection to another host refused")
			}
			return dialer.DialContext(ctx, "tcp", pinned) // the checked address, never a fresh lookup
		},
		TLSClientConfig:        tlsConf,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout,
		// draft-ietf-oauth-client-id-metadata-document-02 §5: "The
		// authorization server MUST NOT automatically follow HTTP redirects
		// when fetching the Client ID Metadata Document."
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return cimdErr("redirects are not followed (the document must be served at the client_id URL itself)")
		}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ClientMetadata{}, 0, cimdErr("client_id URL cannot be requested")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "newtype-nexus-oauth/1 (client-id-metadata-document)")
	resp, err := client.Do(req)
	if err != nil {
		var ce *CIMDError
		if errors.As(err, &ce) {
			return ClientMetadata{}, 0, ce
		}
		var ne net.Error
		if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) {
			return ClientMetadata{}, 0, cimdErr("fetch timed out after %s", timeout)
		}
		return ClientMetadata{}, 0, cimdErr("fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ClientMetadata{}, 0, cimdErr("the document URL answered HTTP %d", resp.StatusCode)
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (mt != "application/json" && !(strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))) {
		return ClientMetadata{}, 0, cimdErr("content type must be application/json")
	}
	if resp.ContentLength > cimdMaxBytes {
		return ClientMetadata{}, 0, cimdErr("document larger than %d bytes", cimdMaxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil {
		return ClientMetadata{}, 0, cimdErr("document could not be read")
	}
	if len(body) > cimdMaxBytes {
		return ClientMetadata{}, 0, cimdErr("document larger than %d bytes", cimdMaxBytes)
	}
	md, err := decodeMetadata(body)
	if err != nil {
		return ClientMetadata{}, 0, err
	}
	if err := md.validate(clientID); err != nil {
		return ClientMetadata{}, 0, err
	}
	md.Domain = strings.ToLower(u.Hostname())
	return md, cacheTTL(resp.Header, f.now()), nil
}

// decodeMetadata reads the document as a JSON object whose keys are unique
// and exactly cased: encoding/json alone would merge duplicates (last wins)
// and match "Client_ID" to client_id.
func decodeMetadata(body []byte) (ClientMetadata, error) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) != nil || raw == nil {
		return ClientMetadata{}, cimdErr("document is not a JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return ClientMetadata{}, cimdErr("document is not a JSON object")
	}
	n := 0
	for d.More() {
		var skip json.RawMessage
		if _, err := d.Token(); err != nil || d.Decode(&skip) != nil {
			return ClientMetadata{}, cimdErr("document is not valid JSON")
		}
		n++
	}
	if n != len(raw) {
		return ClientMetadata{}, cimdErr("document has duplicate keys")
	}
	if _, ok := raw["client_id"]; !ok {
		return ClientMetadata{}, cimdErr("document has no \"client_id\" key")
	}
	var md ClientMetadata
	for k, v := range raw {
		var dst any
		switch k {
		case "client_id":
			dst = &md.ClientID
		case "client_name":
			dst = &md.ClientName
		case "redirect_uris":
			dst = &md.RedirectURIs
		case "grant_types":
			dst = &md.GrantTypes
		case "response_types":
			dst = &md.Response
		case "token_endpoint_auth_method":
			dst = &md.AuthMethod
		case "client_secret":
			return ClientMetadata{}, cimdErr("a client metadata document must not contain client_secret")
		default:
			continue // other metadata (logo_uri, client_uri, …) is not used
		}
		if json.Unmarshal(v, dst) != nil {
			return ClientMetadata{}, cimdErr("%s has the wrong type", k)
		}
	}
	return md, nil
}

// cacheTTL follows the response's caching headers: no-store / no-cache /
// max-age=0 → not cached; max-age (or Expires) → that long, capped at a day;
// otherwise an hour.
func cacheTTL(h http.Header, now time.Time) time.Duration {
	cc := strings.ToLower(h.Get("Cache-Control"))
	maxAge := time.Duration(-1)
	for _, d := range strings.Split(cc, ",") {
		d = strings.TrimSpace(d)
		switch {
		case d == "no-store" || d == "no-cache":
			return 0
		case strings.HasPrefix(d, "max-age="):
			if n, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(d, "max-age="), `"`), 10, 64); err == nil && n >= 0 {
				maxAge = time.Duration(min(n, int64(cimdMaxTTL/time.Second))) * time.Second
			}
		}
	}
	if maxAge < 0 {
		if exp, err := http.ParseTime(h.Get("Expires")); err == nil {
			maxAge = max(exp.Sub(now), 0)
		} else if h.Get("Expires") != "" {
			maxAge = 0 // an invalid Expires means already expired (RFC 9111 §5.3)
		}
	}
	if maxAge < 0 {
		return cimdDefaultTTL
	}
	return min(maxAge, cimdMaxTTL)
}
