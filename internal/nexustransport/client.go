// Package nexustransport contains the credential boundary shared by Inbox and tools.
package nexustransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Auth is explicit process configuration, never model input. Agent and local
// licence+login identities are mutually exclusive. No token is persisted.
type Auth struct {
	Token, Login, Session string
	// Wake is host-owned and never part of identity or persisted credentials.
	Wake *WakeSignal
}

func (a Auth) Validate() error {
	valid := func(s string) bool {
		if len(s) == 0 || len(s) > 4096 {
			return false
		}
		for _, b := range []byte(s) {
			if b <= 32 || b >= 127 {
				return false
			}
		}
		return true
	}
	if !valid(a.Token) {
		return errors.New("Nexus session token is missing or invalid")
	}
	if a.Login == "" && a.Session == "" {
		return nil
	}
	if strings.HasPrefix(a.Token, "nta_") || !valid(a.Login) {
		return errors.New("Nexus local authentication requires licence and login credentials")
	}
	if a.Session != "" && ids.Check(ids.KindSession, a.Session) != nil {
		return errors.New("invalid Nexus authenticated session")
	}
	return nil
}
func (a Auth) Apply(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+a.Token)
	if a.Login != "" {
		r.Header.Set("X-Newtype-Login", a.Login)
	}
	if a.Session != "" {
		r.Header.Set("X-Newtype-Session", a.Session)
	}
}

// Namespace includes every identity component; it is hashed by checkpoint storage.
func (a Auth) Namespace() string { return a.Token + "\x00" + a.Login + "\x00" + a.Session }
func Base(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return "", errors.New("Nexus endpoint must be a base URL without credentials, query or fragment")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ((ip == nil || !ip.IsLoopback()) && u.Hostname() != "localhost") {
			return "", errors.New("Nexus endpoint requires HTTPS or HTTP loopback (localhost, 127.0.0.1, [::1])")
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}
func HTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type Client struct {
	base    string
	auth    Auth
	http    *http.Client
	maxBody int64 // response cap; 0 = the general 1 MiB
}

// NewBounded is New with a dedicated timeout and response cap (the custody
// profile uses 15 s / 64 KiB); other clients keep the general limits.
func NewBounded(endpoint string, auth Auth, timeout time.Duration, maxBody int64) (*Client, error) {
	if timeout <= 0 || maxBody <= 0 {
		return nil, errors.New("invalid client bounds")
	}
	c, err := New(endpoint, auth)
	if err != nil {
		return nil, err
	}
	c.http.Timeout, c.maxBody = timeout, maxBody
	return c, nil
}

func New(endpoint string, auth Auth) (*Client, error) {
	base, err := Base(endpoint)
	if err != nil {
		return nil, err
	}
	if err = auth.Validate(); err != nil {
		return nil, err
	}
	client := HTTPClient()
	client.Transport = WakeTransport{Origin: base, Signal: auth.Wake}
	return &Client{base: base, auth: auth, http: client}, nil
}

// WithTransport replaces the base round tripper (tests and fixed-origin
// callers); wake observation and the no-redirect policy are kept.
func (c *Client) WithTransport(rt http.RoundTripper) *Client {
	c.http.Transport = WakeTransport{Base: rt, Origin: c.base, Signal: c.auth.Wake}
	return c
}

type HTTPError struct{ Code int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Nexus request rejected (HTTP %d); mutation outcome may require status lookup", e.Code)
}

// Do has no automatic retry, including POST. Paths must be compiled by trusted
// adapters, not supplied by models. Error bodies and transport URLs stay private.
func (c *Client) Do(ctx context.Context, method, path string, input, output any) error {
	return c.do(ctx, method, path, nil, input, output)
}

// Query performs a read-only request with separately encoded query values.
// Callers own the route; model input must never become a path or query key.
func (c *Client) Query(ctx context.Context, path string, query url.Values, output any) error {
	return c.do(ctx, "GET", path, query, nil, output)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, input, output any) error {
	if !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#") || strings.Contains(path, "..") {
		return errors.New("invalid Nexus route")
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil || len(body) > 64<<10 {
			return errors.New("invalid or oversized Nexus request")
		}
	}
	endpoint := c.base + path
	if len(query) != 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid Nexus request")
	}
	c.auth.Apply(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("Nexus transport failed; mutation outcome unknown, do not retry with a new ID")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Translate one exact public protocol label, never arbitrary error text.
		if resp.StatusCode == http.StatusConflict {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1025))
			var envelope struct {
				Error string `json:"error"`
			}
			if readErr == nil && len(raw) <= 1024 && json.Unmarshal(raw, &envelope) == nil && envelope.Error == "runner_unavailable_specify_live_session" {
				return fmt.Errorf(nexus.UnstartableMessage, "a new session")
			}
		}
		return &HTTPError{resp.StatusCode}
	}
	limit := int64(1 << 20)
	if c.maxBody > 0 {
		limit = c.maxBody
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return errors.New("Nexus response interrupted or oversized")
	}
	if output == nil {
		return nil
	}
	if json.Unmarshal(raw, output) != nil {
		return errors.New("invalid Nexus response")
	}
	return nil
}

// Stream opens a server-sent event stream (GET, no client timeout: the server
// ends every stream after its own life). lastEventID is the reader's cursor.
// A non-2xx answer is returned as *HTTPError with the body closed. The caller
// closes the returned body.
func (c *Client) Stream(ctx context.Context, path string, lastEventID int64) (io.ReadCloser, error) {
	if !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#") || strings.Contains(path, "..") {
		return nil, errors.New("invalid Nexus route")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, errors.New("invalid Nexus request")
	}
	c.auth.Apply(req)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", fmt.Sprint(lastEventID))
	stream := *c.http
	stream.Timeout = 0
	resp, err := stream.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("Nexus stream failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, &HTTPError{resp.StatusCode}
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		resp.Body.Close()
		return nil, errors.New("invalid Nexus stream type")
	}
	return resp.Body, nil
}
