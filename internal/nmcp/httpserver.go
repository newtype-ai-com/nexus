package nmcp

// Streamable HTTP transport (MCP 2025-06-18 / 2025-11-25) for the same Server:
// each MCP session runs one unchanged Server whose input is a pipe and whose
// output is a dispatcher. A response goes to the POST that carries its id and
// counts as written only after that POST's SSE event was flushed (so "read"
// receipts still mean "handed to the client"); server requests and
// notifications go to the newest open POST stream, else to the GET stream
// (kept for resume with Last-Event-ID). Design: docs/nmcp-remote-endpoint.md §1.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPHandler serves POST/GET/DELETE on one MCP endpoint path.
type HTTPHandler struct {
	// Authenticate returns the connection owner (an opaque key such as
	// account+client_id) or false; the handler then answers 401 with Challenge
	// as the WWW-Authenticate value. Required.
	Authenticate func(*http.Request) (owner string, ok bool)
	Challenge    string
	// NewServer builds the Server for a new MCP session of owner (its Tools
	// act as that owner's connection session). Required.
	NewServer func(ctx context.Context, owner string) (*Server, error)
	// Origins allowed when a browser sends Origin; requests without Origin pass.
	Origins []string
	// Limits (0 = defaults): sessions per owner 16, total 1024, idle 30 min.
	MaxPerOwner int
	MaxSessions int
	Idle        time.Duration
	Heartbeat   time.Duration // GET stream comment interval (0 = 30 s)

	mu       sync.Mutex
	sessions map[string]*httpSession
	starting map[string]int // owner -> sessions being created (slots reserved)
}

const (
	maxBody    = 4 << 20
	replayKeep = 256
	ackTimeout = 15 * time.Second
)

type sseEvent struct {
	id   int64 // 0 = not resumable (POST stream)
	data []byte
}

type postStream struct {
	ch chan sseEvent // server requests/notifications while the POST is open
}

type waiter struct {
	line chan []byte // the response line
	ack  chan bool   // whether it was flushed to the client
}

type httpSession struct {
	id      string
	owner   string
	in      *io.PipeWriter
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	waiters map[string]*waiter
	posts   []*postStream
	get     chan sseEvent // open GET stream, or nil
	replay  []sseEvent
	nextEv  int64
	used    time.Time
}

func (h *HTTPHandler) heartbeat() time.Duration {
	if h.Heartbeat > 0 {
		return h.Heartbeat
	}
	return 30 * time.Second
}

func newSessionID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func httpFail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": rpcError{codeInvalidRequest, msg}})
	_, _ = w.Write(raw)
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !slices.Contains(h.Origins, origin) {
		httpFail(w, http.StatusForbidden, "origin not allowed: this endpoint accepts browser requests only from its allowed origins")
		return
	}
	owner, ok := h.Authenticate(r)
	if !ok {
		if h.Challenge != "" {
			w.Header().Set("WWW-Authenticate", h.Challenge)
		}
		httpFail(w, http.StatusUnauthorized, "unauthorized: a valid Bearer access token is required; the WWW-Authenticate header names the resource metadata for OAuth discovery")
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !slices.Contains(Versions, v) {
		httpFail(w, http.StatusBadRequest, "unsupported MCP-Protocol-Version: supported versions are "+strings.Join(Versions, ", "))
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.post(w, r, owner)
	case http.MethodGet:
		h.getStream(w, r, owner)
	case http.MethodDelete:
		s := h.session(r, owner)
		if s == nil {
			httpFail(w, http.StatusNotFound, "unknown session: the Mcp-Session-Id is unknown or has ended; send a new initialize without Mcp-Session-Id")
			return
		}
		h.drop(s)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		httpFail(w, http.StatusMethodNotAllowed, "method not allowed: use POST, GET or DELETE")
	}
}

// session finds the caller's session; another owner's ID is unknown (404).
func (h *HTTPHandler) session(r *http.Request, owner string) *httpSession {
	id := r.Header.Get("Mcp-Session-Id")
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[id]
	if s == nil || s.owner != owner {
		return nil
	}
	s.mu.Lock()
	s.used = time.Now()
	s.mu.Unlock()
	return s
}

func (h *HTTPHandler) drop(s *httpSession) {
	h.mu.Lock()
	if h.sessions[s.id] == s {
		delete(h.sessions, s.id)
	}
	h.mu.Unlock()
	s.in.Close() // input ends: calls in flight get the Server's grace, then cancel
	go func() {
		select {
		case <-s.done:
		case <-time.After(ShutdownGrace + time.Second):
		}
		s.cancel()
	}()
}

// DropOwner ends every session of owner (a revoked consent).
func (h *HTTPHandler) DropOwner(owner string) {
	h.mu.Lock()
	var mine []*httpSession
	for _, s := range h.sessions {
		if s.owner == owner {
			mine = append(mine, s)
		}
	}
	h.mu.Unlock()
	for _, s := range mine {
		h.drop(s)
	}
}

// Close ends every session (server shutdown).
func (h *HTTPHandler) Close() {
	h.mu.Lock()
	all := make([]*httpSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		all = append(all, s)
	}
	h.mu.Unlock()
	for _, s := range all {
		h.drop(s)
	}
}

// Sweep drops sessions idle longer than Idle with no open GET stream.
func (h *HTTPHandler) Sweep(now time.Time) {
	idle := h.Idle
	if idle == 0 {
		idle = 30 * time.Minute
	}
	h.mu.Lock()
	var stale []*httpSession
	for _, s := range h.sessions {
		s.mu.Lock()
		if s.get == nil && len(s.posts) == 0 && now.Sub(s.used) > idle {
			stale = append(stale, s)
		}
		s.mu.Unlock()
	}
	h.mu.Unlock()
	for _, s := range stale {
		h.drop(s)
	}
}

func (h *HTTPHandler) start(owner string) (*httpSession, error) {
	maxOwner, maxAll := h.MaxPerOwner, h.MaxSessions
	if maxOwner == 0 {
		maxOwner = 16
	}
	if maxAll == 0 {
		maxAll = 1024
	}
	h.mu.Lock()
	if h.sessions == nil {
		h.sessions = map[string]*httpSession{}
		h.starting = map[string]int{}
	}
	n, all := h.starting[owner], len(h.sessions)
	for _, st := range h.starting {
		all += st
	}
	for _, s := range h.sessions {
		if s.owner == owner {
			n++
		}
	}
	full := n >= maxOwner || all >= maxAll
	if !full {
		h.starting[owner]++ // the slot is reserved under the lock
	}
	h.mu.Unlock()
	if full {
		return nil, errors.New("too many sessions")
	}
	release := func() {
		h.mu.Lock()
		if h.starting[owner]--; h.starting[owner] <= 0 {
			delete(h.starting, owner)
		}
		h.mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := h.NewServer(ctx, owner)
	if err != nil {
		cancel()
		release()
		return nil, err
	}
	inR, inW := io.Pipe()
	s := &httpSession{id: newSessionID(), owner: owner, in: inW, cancel: cancel, done: make(chan struct{}), waiters: map[string]*waiter{}, used: time.Now()}
	go func() {
		defer close(s.done)
		_ = srv.Serve(ctx, inR, s)
		inR.Close()
	}()
	h.mu.Lock()
	h.sessions[s.id] = s
	if h.starting[owner]--; h.starting[owner] <= 0 {
		delete(h.starting, owner)
	}
	h.mu.Unlock()
	return s, nil
}

// Write receives one JSON-RPC line from the Server (its output).
func (s *httpSession) Write(p []byte) (int, error) {
	line := bytes.TrimSpace(p)
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if json.Unmarshal(line, &m) != nil {
		return 0, errors.New("invalid output line")
	}
	if m.Method == "" { // a response: only its own POST may carry it
		s.mu.Lock()
		w := s.waiters[string(m.ID)]
		delete(s.waiters, string(m.ID))
		s.mu.Unlock()
		if w == nil {
			return 0, errors.New("no open request for this response")
		}
		w.line <- append([]byte(nil), line...)
		select {
		case ok := <-w.ack:
			if !ok {
				return 0, errors.New("response not delivered")
			}
			return len(p), nil
		case <-time.After(ackTimeout):
			return 0, errors.New("response not delivered")
		}
	}
	// a server request or notification
	s.mu.Lock()
	defer s.mu.Unlock()
	data := append([]byte(nil), line...)
	if n := len(s.posts); n > 0 {
		select {
		case s.posts[n-1].ch <- sseEvent{data: data}:
			return len(p), nil
		default:
		}
	}
	s.nextEv++
	ev := sseEvent{id: s.nextEv, data: data}
	s.replay = append(s.replay, ev)
	if len(s.replay) > replayKeep {
		s.replay = s.replay[len(s.replay)-replayKeep:]
	}
	if s.get != nil {
		select {
		case s.get <- ev:
		default: // a slow reader resumes from the replay buffer
		}
	}
	return len(p), nil
}

func acceptsBoth(r *http.Request) bool {
	a := r.Header.Get("Accept")
	return strings.Contains(a, "*/*") || (strings.Contains(a, "application/json") && strings.Contains(a, "text/event-stream"))
}

func writeEvent(w http.ResponseWriter, ev sseEvent) error {
	var err error
	if ev.id > 0 {
		_, err = fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", ev.id, ev.data)
	} else {
		_, err = fmt.Fprintf(w, "event: message\ndata: %s\n\n", ev.data)
	}
	if err == nil {
		err = http.NewResponseController(w).Flush()
	}
	return err
}

func (h *HTTPHandler) post(w http.ResponseWriter, r *http.Request, owner string) {
	if !acceptsBoth(r) {
		httpFail(w, http.StatusNotAcceptable, "Accept must include application/json and text/event-stream")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		httpFail(w, http.StatusRequestEntityTooLarge, "message too large: one JSON-RPC message is limited to "+strconv.Itoa(maxBody>>10)+" KiB")
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		httpFail(w, http.StatusBadRequest, "batch requests are not supported: send one JSON-RPC message per POST")
		return
	}
	var msg request
	if json.Unmarshal(body, &msg) != nil {
		httpFail(w, http.StatusBadRequest, "parse error: the body is not a valid JSON-RPC message")
		return
	}
	isRequest := msg.Method != "" && validID(msg.ID)
	var s *httpSession
	if msg.Method == "initialize" && r.Header.Get("Mcp-Session-Id") == "" {
		if s, err = h.start(owner); err != nil {
			httpFail(w, http.StatusServiceUnavailable, "session unavailable: the Nexus connection session could not be opened (the consent may be revoked, or the account login is no longer live); reconnect the connector or retry later")
			return
		}
		w.Header().Set("Mcp-Session-Id", s.id)
	} else if s = h.session(r, owner); s == nil {
		if r.Header.Get("Mcp-Session-Id") == "" {
			httpFail(w, http.StatusBadRequest, "Mcp-Session-Id required: send initialize first and repeat the returned Mcp-Session-Id header on later requests")
		} else {
			httpFail(w, http.StatusNotFound, "unknown session: the Mcp-Session-Id is unknown or has ended; send a new initialize without Mcp-Session-Id")
		}
		return
	}
	line := append(body, '\n')
	if !isRequest { // notification or a response to our request
		if _, err := s.in.Write(line); err != nil {
			httpFail(w, http.StatusNotFound, "session ended: send a new initialize without Mcp-Session-Id")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	key := string(msg.ID)
	wt := &waiter{line: make(chan []byte, 1), ack: make(chan bool, 1)}
	ps := &postStream{ch: make(chan sseEvent, 16)}
	s.mu.Lock()
	if s.waiters[key] != nil {
		s.mu.Unlock()
		httpFail(w, http.StatusBadRequest, "duplicate request id in flight: use a new JSON-RPC id for each request")
		return
	}
	s.waiters[key] = wt
	s.posts = append(s.posts, ps)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.waiters[key] == wt {
			delete(s.waiters, key)
		}
		s.posts = slices.DeleteFunc(s.posts, func(p *postStream) bool { return p == ps })
		s.mu.Unlock()
	}()
	if _, err := s.in.Write(line); err != nil {
		httpFail(w, http.StatusNotFound, "session ended: send a new initialize without Mcp-Session-Id")
		return
	}
	quick := msg.Method == "initialize" || msg.Method == "ping" || msg.Method == "tools/list" || strings.HasPrefix(msg.Method, "resources/") && msg.Method != "resources/read"
	started := false
	start := func() {
		if !started {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Accel-Buffering", "no")
			w.WriteHeader(http.StatusOK)
			started = true
		}
	}
	if !quick {
		// long calls (nexus_inbox waits up to 300 s): open the stream now and
		// keep it alive through proxies with comment lines
		start()
		if http.NewResponseController(w).Flush() != nil {
			h.cancelCall(s, msg.ID)
			return
		}
	}
	tick := time.NewTicker(h.heartbeat())
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if !h.stillOwner(r, owner) { // the token was revoked or expired
				h.cancelCall(s, msg.ID)
				return
			}
			if started {
				if _, err := io.WriteString(w, ": heartbeat\n\n"); err != nil || http.NewResponseController(w).Flush() != nil {
					h.cancelCall(s, msg.ID)
					return
				}
			}
		case resp := <-wt.line:
			if quick && !started {
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write(resp)
				wt.ack <- err == nil && http.NewResponseController(w).Flush() == nil
				return
			}
			start()
			wt.ack <- writeEvent(w, sseEvent{data: resp}) == nil
			return
		case ev := <-ps.ch:
			start()
			if writeEvent(w, ev) != nil {
				h.cancelCall(s, msg.ID)
				return
			}
		case <-r.Context().Done():
			h.cancelCall(s, msg.ID) // the client left: no response, nothing marked read
			return
		case <-s.done:
			if !started {
				httpFail(w, http.StatusNotFound, "session ended: send a new initialize without Mcp-Session-Id")
			}
			return
		}
	}
}

// stillOwner re-checks the request's credential at each heartbeat, so an open
// stream ends soon after its token stops being valid.
func (h *HTTPHandler) stillOwner(r *http.Request, owner string) bool {
	o, ok := h.Authenticate(r)
	return ok && o == owner
}

func (h *HTTPHandler) cancelCall(s *httpSession, id json.RawMessage) {
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": id, "reason": "client disconnected"}})
	s.mu.Lock()
	delete(s.waiters, string(id))
	s.mu.Unlock()
	go func() { _, _ = s.in.Write(append(raw, '\n')) }()
}

func (h *HTTPHandler) getStream(w http.ResponseWriter, r *http.Request, owner string) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") && !strings.Contains(r.Header.Get("Accept"), "*/*") {
		httpFail(w, http.StatusNotAcceptable, "Accept must include text/event-stream")
		return
	}
	s := h.session(r, owner)
	if s == nil {
		httpFail(w, http.StatusNotFound, "unknown session: the Mcp-Session-Id is unknown or has ended; send a new initialize without Mcp-Session-Id")
		return
	}
	var after int64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			httpFail(w, http.StatusBadRequest, "invalid Last-Event-ID: expected a non-negative integer event id")
			return
		}
		after = n
	}
	ch := make(chan sseEvent, 64)
	s.mu.Lock()
	if s.get != nil {
		s.mu.Unlock()
		httpFail(w, http.StatusConflict, "a stream is already open for this session: close it before opening another GET stream")
		return
	}
	s.get = ch
	var backlog []sseEvent
	for _, ev := range s.replay {
		if ev.id > after {
			backlog = append(backlog, ev)
		}
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.get == ch {
			s.get = nil
		}
		s.used = time.Now()
		s.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, ": connected\n\n"); err != nil || http.NewResponseController(w).Flush() != nil {
		return
	}
	last := after
	for _, ev := range backlog {
		if writeEvent(w, ev) != nil {
			return
		}
		last = ev.id
	}
	tick := time.NewTicker(h.heartbeat())
	defer tick.Stop()
	for {
		select {
		case ev := <-ch:
			if ev.id <= last {
				continue
			}
			if writeEvent(w, ev) != nil {
				return
			}
			last = ev.id
		case <-tick.C:
			if !h.stillOwner(r, owner) { // the token was revoked or expired
				return
			}
			if _, err := io.WriteString(w, ": heartbeat\n\n"); err != nil || http.NewResponseController(w).Flush() != nil {
				return
			}
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		}
	}
}
