package nexusserver

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/nexus"
)

type inProcessKey struct{}

// InProcessEndpoint is the base URL in-process clients use; nothing listens
// there, the RoundTripper hands the request to the handler directly.
const InProcessEndpoint = "http://127.0.0.1:1"

// InProcessToken is the placeholder bearer of in-process clients (the client
// type requires one). Over the network it is just an unknown token (401).
const InProcessToken = "nexus-in-process-placeholder"

// inProcessPrincipal returns the principal an in-process caller attached to
// the request context. A network request cannot carry a Go context value, so
// only code inside this process (the remote MCP connector) can set it.
func inProcessPrincipal(r *http.Request) (nexus.Principal, bool) {
	p, ok := r.Context().Value(inProcessKey{}).(nexus.Principal)
	return p, ok
}

// withInProcess puts an attached principal ahead of header authentication.
func withInProcess(auth func(*http.Request) (nexus.Principal, error)) func(*http.Request) (nexus.Principal, error) {
	return func(r *http.Request) (nexus.Principal, error) {
		if p, ok := inProcessPrincipal(r); ok {
			return p, nil
		}
		return auth(r)
	}
}

// refuseMCPTokens keeps OAuth tokens issued for /mcp out of every other route:
// a token is accepted only by its own audience (never passed through).
func refuseMCPTokens(auth func(*http.Request) (nexus.Principal, error)) func(*http.Request) (nexus.Principal, error) {
	return func(r *http.Request) (nexus.Principal, error) {
		for _, v := range r.Header.Values("Authorization") {
			if strings.HasPrefix(v, "Bearer ntm_") || strings.HasPrefix(v, "Bearer ntr_") {
				return nexus.Principal{}, gate.ErrUnauthenticated
			}
		}
		return auth(r)
	}
}

// InProcess is a RoundTripper that serves requests with handler as principal p,
// without the network and without any credential: the request's own
// Authorization and identity headers are removed first, so the only identity
// is p. Responses stream (event streams work); closing the body ends the
// handler's request context.
type InProcess struct {
	Handler   http.Handler
	Principal nexus.Principal
}

type pipeResponse struct {
	header  http.Header
	status  int
	pw      *io.PipeWriter
	started chan struct{}
	sent    http.Header
}

func (w *pipeResponse) Header() http.Header { return w.header }
func (w *pipeResponse) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status, w.sent = code, w.header.Clone()
	close(w.started)
}
func (w *pipeResponse) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.pw.Write(p)
}
func (w *pipeResponse) Flush() {} // the pipe has no buffer

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelBody) Close() error { b.cancel(); return b.ReadCloser.Close() }

func (t InProcess) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(context.WithValue(r.Context(), inProcessKey{}, t.Principal))
	req := r.Clone(ctx)
	for _, h := range []string{"Authorization", "X-Newtype-Login", "X-Newtype-Session"} {
		req.Header.Del(h)
	}
	if r.Body != nil {
		raw, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			cancel()
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = int64(len(raw))
	}
	req.RequestURI = r.URL.RequestURI()
	req.RemoteAddr = "127.0.0.1:0"
	pr, pw := io.Pipe()
	w := &pipeResponse{header: http.Header{}, pw: pw, started: make(chan struct{})}
	go func() {
		defer func() {
			w.WriteHeader(http.StatusOK)
			pw.Close()
		}()
		t.Handler.ServeHTTP(w, req)
	}()
	select {
	case <-w.started:
	case <-r.Context().Done():
		cancel()
		pr.Close()
		return nil, r.Context().Err()
	}
	return &http.Response{StatusCode: w.status, Status: http.StatusText(w.status), Header: w.sent, Body: cancelBody{pr, cancel}, Request: r,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, ContentLength: -1}, nil
}

// PersonAuth is Nexus's own request authentication (in-process principal,
// /mcp tokens refused, executor or Gate) for routes mounted beside the API,
// such as the remote MCP endpoint's person routes.
func PersonAuth(service *nexus.Service, credentials gate.CredentialStore) func(*http.Request) (nexus.Principal, error) {
	return withInProcess(refuseMCPTokens(executorOrGate(service, gate.NexusAuth{Store: credentials, Service: service}.Authenticate)))
}
