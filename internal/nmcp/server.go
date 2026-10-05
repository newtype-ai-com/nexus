// Package nmcp is the stdio MCP server for the NMCP tool contract (stage 1):
// JSON-RPC 2.0, one message per line, on stdin/stdout. stdout carries only
// JSON-RPC; diagnostics go to a separate writer as fixed short lines.
package nmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/nexusops"
)

// Versions this server speaks, newest first. The client's requested version
// is echoed when supported; otherwise the newest is offered.
var Versions = []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethod         = -32601
	codeParams         = -32602
	codeNotInitialized = -32002
	maxLine            = 4 << 20
)

// ShutdownGrace is how long calls in flight may finish after stdin ends.
var ShutdownGrace = 5 * time.Second

// Caller is the tool contract the server exposes (nexusops.Contract).
type Caller interface {
	Call(ctx context.Context, name string, args json.RawMessage) nexusops.Result
}

type Server struct {
	Tools   Caller
	Name    string // serverInfo.name
	Version string // serverInfo.version
	Diag    io.Writer
	// Channel declares Claude Code's experimental "claude/channel" capability
	// and pushes a receipt-free "new Nexus mail" notice into the session
	// (claude --channels / --dangerously-load-development-channels server:NAME).
	Channel bool
	// ElicitWait bounds one elicitation (0 = ElicitTimeout); the remote
	// endpoint uses 2 minutes and then falls back to mail.
	ElicitWait time.Duration

	mu          sync.Mutex // serializes writes to out
	out         io.Writer
	initialized bool
	calls       map[string]context.CancelFunc
	wg          sync.WaitGroup

	// Stages 2-3 (2026-10-04): what the client declared at initialize.
	elicitation bool // client capability "elicitation": request_approval asks the person through it
	tasksOn     bool // negotiated version >= 2025-11-25: task-augmented tools/call (Tasks extension)
	nextID      int64
	pending     map[string]chan rpcResponse // server -> client requests awaiting their response
	tasks       map[string]*task
	serveCtx    context.Context

	// Sync (2026-10-04): resource subscriptions and push, all receipt-free.
	subs      map[string]string // subscribed URI -> last task view ("" for the inbox)
	watching  bool
	announced map[ids.Event]bool // unread events already announced
	channelOn bool
	bg        sync.WaitGroup // the ledger watcher
}

// ElicitTimeout bounds how long request_approval waits for the person.
var ElicitTimeout = 10 * time.Minute

// taskTools may run as durable task handles when the client augments the call.
var taskTools = map[string]bool{"task_status": true, "nexus_inbox": true}

type rpcResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// task is one task-augmented tools/call (MCP Tasks, 2025-11-25): created at once,
// worked in the background, its result fetched with tasks/result. In-process:
// handles do not survive a server restart.
type task struct {
	ID        string
	Status    string // working | completed | failed | cancelled
	Created   time.Time
	Updated   time.Time
	TTL       time.Duration
	cancel    context.CancelFunc
	done      chan struct{}
	text      string
	isErr     bool
	after     func(context.Context) error
	delivered bool // result handed to the client once (read receipts recorded then)
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) diag(text string) {
	if s.Diag != nil {
		fmt.Fprintln(s.Diag, text)
	}
}

// write sends one message; it reports whether the whole line was written.
func (s *Server) write(v any) bool {
	raw, err := json.Marshal(v)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.out.Write(append(raw, '\n'))
	return err == nil
}

func (s *Server) reply(id json.RawMessage, result any) bool {
	return s.write(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *Server) fail(id json.RawMessage, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcError{code, message}})
}

func validID(id json.RawMessage) bool {
	if len(id) == 0 {
		return false
	}
	var v any
	if json.Unmarshal(id, &v) != nil {
		return false
	}
	switch v.(type) {
	case string, float64:
		return true
	}
	return false
}

// Serve reads requests until in ends or ctx is done, then waits for calls.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.out = out
	s.calls = map[string]context.CancelFunc{}
	s.pending = map[string]chan rpcResponse{}
	s.tasks = map[string]*task{}
	s.subs = map[string]string{}
	s.announced = map[ids.Event]bool{}
	ctx, cancel := context.WithCancel(ctx)
	s.serveCtx = ctx
	defer func() {
		// Input ended: let calls in flight finish for a short grace (their
		// responses may still be read), then cancel the rest.
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(ShutdownGrace):
		}
		cancel()
		s.wg.Wait()
		s.bg.Wait()
	}()
	r := bufio.NewReaderSize(in, 64<<10)
	for {
		line, err := readLine(r)
		if len(bytes.TrimSpace(line)) > 0 {
			s.handle(ctx, line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		part, isPrefix, err := r.ReadLine()
		buf = append(buf, part...)
		if len(buf) > maxLine {
			// drain the rest of the oversized line
			for isPrefix && err == nil {
				_, isPrefix, err = r.ReadLine()
			}
			return []byte("\x00oversized"), err
		}
		if err != nil || !isPrefix {
			return buf, err
		}
	}
}

func (s *Server) handle(ctx context.Context, line []byte) {
	trimmed := bytes.TrimSpace(line)
	if string(trimmed) == "\x00oversized" {
		s.fail(nil, codeInvalidRequest, "message too large: one JSON-RPC message is limited to 4 MiB")
		return
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		s.fail(nil, codeInvalidRequest, "batch requests are not supported: send one JSON-RPC message at a time")
		return
	}
	var req request
	if err := json.Unmarshal(trimmed, &req); err != nil {
		s.fail(nil, codeParse, "parse error: the message is not valid JSON")
		return
	}
	// A response to one of our own requests (elicitation/create): id, no method.
	if req.Method == "" && validID(req.ID) {
		var r rpcResponse
		if json.Unmarshal(trimmed, &r) == nil && (r.Result != nil || r.Error != nil) {
			s.mu.Lock()
			ch := s.pending[string(req.ID)]
			delete(s.pending, string(req.ID))
			s.mu.Unlock()
			if ch != nil {
				ch <- r
			}
			return // responses are never answered; unknown ids are dropped
		}
	}
	isNotification := len(req.ID) == 0
	if isNotification {
		if req.JSONRPC == "2.0" && req.Method != "" {
			s.notification(req) // never answered
		}
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" || !validID(req.ID) {
		id := req.ID
		if !validID(id) {
			id = nil
		}
		s.fail(id, codeInvalidRequest, "invalid request: jsonrpc \"2.0\", a method and a string or number id are required")
		return
	}
	switch req.Method {
	case "initialize":
		s.initialize(req)
	case "ping":
		s.reply(req.ID, map[string]any{})
	case "tools/list":
		if !s.ready(req) {
			return
		}
		s.list(req)
	case "tools/call":
		if !s.ready(req) {
			return
		}
		s.call(ctx, req)
	case "tasks/get", "tasks/result", "tasks/cancel", "tasks/list":
		if !s.ready(req) {
			return
		}
		if !s.tasksEnabled() {
			s.fail(req.ID, codeMethod, "method not found: "+req.Method)
			return
		}
		s.taskMethod(req)
	case "resources/list", "resources/templates/list", "resources/read", "resources/subscribe", "resources/unsubscribe":
		if !s.ready(req) {
			return
		}
		s.resourceMethod(ctx, req)
	default:
		s.fail(req.ID, codeMethod, "method not found: "+req.Method)
	}
}

func (s *Server) ready(req request) bool {
	s.mu.Lock()
	ok := s.initialized
	s.mu.Unlock()
	if !ok {
		s.fail(req.ID, codeNotInitialized, "server not initialized: send initialize first")
	}
	return ok
}

func (s *Server) notification(req request) {
	switch req.Method {
	case "notifications/initialized":
		s.mu.Lock()
		channel := s.channelOn
		s.mu.Unlock()
		if channel {
			s.startWatch()
		}
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(req.Params, &p) == nil && len(p.RequestID) > 0 {
			s.mu.Lock()
			if cancel := s.calls[string(p.RequestID)]; cancel != nil {
				cancel()
			}
			s.mu.Unlock()
		}
	}
	// other notifications are ignored (no response to a notification)
}

func (s *Server) initialize(req request) {
	var p struct {
		Version      string                     `json:"protocolVersion"`
		Capabilities map[string]json.RawMessage `json:"capabilities"`
	}
	if len(req.Params) > 0 && json.Unmarshal(req.Params, &p) != nil {
		s.fail(req.ID, codeParams, "invalid initialize params: expected protocolVersion (string) and capabilities (object)")
		return
	}
	version := Versions[0]
	for _, v := range Versions {
		if v == p.Version {
			version = v
		}
	}
	_, elicitation := p.Capabilities["elicitation"]
	tasksOn := version >= "2025-11-25" // the Tasks extension exists from this revision
	watch := s.watcher() != nil
	s.mu.Lock()
	s.initialized = true
	s.elicitation = elicitation
	s.tasksOn = tasksOn
	s.channelOn = s.Channel && watch
	s.mu.Unlock()
	capabilities := map[string]any{"tools": map[string]any{"listChanged": false}}
	if watch {
		capabilities["resources"] = map[string]any{"subscribe": true, "listChanged": false}
	}
	if s.Channel && watch {
		capabilities["experimental"] = map[string]any{"claude/channel": map[string]any{}}
	}
	if tasksOn {
		capabilities["tasks"] = map[string]any{"list": map[string]any{}, "cancel": map[string]any{},
			"requests": map[string]any{"tools": map[string]any{"call": map[string]any{}}}}
	}
	instructions := Instructions
	if s.Channel && watch {
		instructions += "\n" + ChannelInstructions
	}
	s.reply(req.ID, map[string]any{
		"protocolVersion": version,
		"capabilities":    capabilities,
		"serverInfo":      map[string]string{"name": s.Name, "version": s.Version},
		"instructions":    instructions,
	})
}

// annotations is a tool's MCP annotations: the human title and the hints.
type annotations struct {
	Title string `json:"title"`
	nexusops.Hint
}

func (s *Server) list(req request) {
	tools := make([]map[string]any, 0, len(nexusops.Defs))
	tasksOn := s.tasksEnabled()
	for _, d := range nexusops.Defs {
		tool := map[string]any{"name": d.Name, "title": d.Title, "description": d.Description, "inputSchema": d.InputSchema,
			"annotations": annotations{Title: d.Title, Hint: nexusops.Hints[d.Name]}}
		if tasksOn && taskTools[d.Name] {
			tool["execution"] = map[string]any{"taskSupport": "optional"}
		}
		tools = append(tools, tool)
	}
	s.reply(req.ID, map[string]any{"tools": tools})
}

func (s *Server) call(ctx context.Context, req request) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Task      *struct {
			TTL *int64 `json:"ttl"`
		} `json:"task"`
	}
	if json.Unmarshal(req.Params, &p) != nil || p.Name == "" {
		s.fail(req.ID, codeParams, "invalid tools/call params: expected {\"name\": string, \"arguments\": object}")
		return
	}
	if nexusops.Canonical(p.Name) == "" {
		s.fail(req.ID, codeParams, "unknown tool: "+p.Name+" (tools/list returns the available tools)")
		return
	}
	if p.Task != nil {
		if !s.tasksEnabled() || !taskTools[nexusops.Canonical(p.Name)] {
			s.fail(req.ID, codeParams, "this tool cannot run as a task: only task_status and nexus_inbox accept a task-augmented call (protocol 2025-11-25 or later); call it without \"task\"")
			return
		}
		ttl := 10 * time.Minute
		if p.Task.TTL != nil && *p.Task.TTL >= 1000 && *p.Task.TTL <= int64(time.Hour/time.Millisecond) {
			ttl = time.Duration(*p.Task.TTL) * time.Millisecond
		}
		s.startTask(req, p.Name, p.Arguments, ttl)
		return
	}
	callCtx, cancel := context.WithCancel(s.withElicitor(ctx))
	key := string(req.ID)
	s.mu.Lock()
	s.calls[key] = cancel
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.calls, key)
			s.mu.Unlock()
			cancel()
		}()
		r := s.Tools.Call(callCtx, p.Name, p.Arguments)
		if callCtx.Err() != nil && ctx.Err() == nil {
			return // cancelled by the client: no response, nothing marked read
		}
		text, isErr := r.Text()
		ok := s.reply(req.ID, map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isErr})
		// "Read" = the message entered the model input: only after the
		// result was actually handed to the client.
		if ok && r.After != nil {
			if err := r.After(context.WithoutCancel(ctx)); err != nil {
				s.diag("nmcp: 읽음 기록 실패(결과는 전달됨)")
			}
		}
	}()
}

func (s *Server) tasksEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tasksOn
}

// withElicitor lets request_approval ask the person through elicitation/create,
// only when the client declared the capability (otherwise the contract's message
// path decides; exactly one path per call).
func (s *Server) withElicitor(ctx context.Context) context.Context {
	s.mu.Lock()
	on := s.elicitation
	s.mu.Unlock()
	if !on {
		return ctx
	}
	return nexusops.WithElicitor(ctx, func(ctx context.Context, message string, schema map[string]any) (string, map[string]any, error) {
		raw, err := s.ask(ctx, "elicitation/create", map[string]any{"message": message, "requestedSchema": schema})
		if err != nil {
			return "", nil, err
		}
		var out struct {
			Action  string         `json:"action"`
			Content map[string]any `json:"content"`
		}
		if json.Unmarshal(raw, &out) != nil || (out.Action != "accept" && out.Action != "decline" && out.Action != "cancel") {
			return "", nil, errors.New("nmcp: invalid elicitation result")
		}
		return out.Action, out.Content, nil
	})
}

// ask sends one server -> client request and waits for its response.
func (s *Server) ask(ctx context.Context, method string, params any) (json.RawMessage, error) {
	s.mu.Lock()
	s.nextID++
	id := fmt.Sprintf("%q", fmt.Sprintf("nmcp-%d", s.nextID))
	ch := make(chan rpcResponse, 1)
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()
	if !s.write(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "method": method, "params": params}) {
		return nil, errors.New("nmcp: request not written")
	}
	wait := s.ElicitWait
	if wait <= 0 {
		wait = ElicitTimeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.Error != nil || r.Result == nil {
			return nil, errors.New("nmcp: client refused the request")
		}
		return r.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errors.New("nmcp: no answer")
	}
}

func taskView(t *task) map[string]any {
	return map[string]any{"taskId": t.ID, "status": t.Status, "createdAt": t.Created.Format(time.RFC3339Nano),
		"lastUpdatedAt": t.Updated.Format(time.RFC3339Nano), "ttl": t.TTL.Milliseconds(), "pollInterval": 1000}
}

// purge drops finished tasks whose TTL has passed (caller holds s.mu).
func (s *Server) purge(now time.Time) {
	for id, t := range s.tasks {
		if t.Status != "working" && now.After(t.Created.Add(t.TTL)) {
			delete(s.tasks, id)
		}
	}
}

// startTask answers a task-augmented tools/call at once with the task handle and
// runs the call in the background (server lifetime, cancelled by tasks/cancel).
func (s *Server) startTask(req request, name string, args json.RawMessage, ttl time.Duration) {
	now := time.Now().UTC()
	ctx, cancel := context.WithCancel(s.withElicitor(s.serveCtx))
	s.mu.Lock()
	s.purge(now)
	s.nextID++
	t := &task{ID: fmt.Sprintf("task-%d-%d", s.nextID, now.UnixNano()), Status: "working", Created: now, Updated: now, TTL: ttl,
		cancel: cancel, done: make(chan struct{})}
	s.tasks[t.ID] = t
	view := taskView(t)
	s.mu.Unlock()
	s.reply(req.ID, map[string]any{"task": view})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		r := s.Tools.Call(ctx, name, args)
		text, isErr := r.Text()
		s.mu.Lock()
		if t.Status == "working" {
			t.Status, t.text, t.isErr, t.after = "completed", text, isErr, r.After
			if ctx.Err() != nil {
				t.Status, t.after = "cancelled", nil // nothing is marked read for a cancelled task
			}
		}
		t.Updated = time.Now().UTC()
		s.mu.Unlock()
		close(t.done)
	}()
}

func (s *Server) taskMethod(req request) {
	var p struct {
		TaskID string `json:"taskId"`
	}
	if len(req.Params) > 0 && json.Unmarshal(req.Params, &p) != nil {
		s.fail(req.ID, codeParams, "invalid task params: expected {\"taskId\": string}")
		return
	}
	s.mu.Lock()
	s.purge(time.Now().UTC())
	if req.Method == "tasks/list" {
		list := []map[string]any{}
		for _, t := range s.tasks {
			list = append(list, taskView(t))
		}
		s.mu.Unlock()
		s.reply(req.ID, map[string]any{"tasks": list})
		return
	}
	t := s.tasks[p.TaskID]
	if t == nil {
		s.mu.Unlock()
		s.fail(req.ID, codeParams, "unknown task: the taskId does not exist or its ttl has passed (tasks/list shows current tasks)")
		return
	}
	switch req.Method {
	case "tasks/get":
		view := taskView(t)
		s.mu.Unlock()
		s.reply(req.ID, view)
	case "tasks/cancel":
		if t.Status == "working" {
			t.Status, t.Updated = "cancelled", time.Now().UTC()
			t.cancel()
		}
		view := taskView(t)
		s.mu.Unlock()
		s.reply(req.ID, view)
	case "tasks/result":
		s.mu.Unlock()
		s.wg.Add(1)
		go func() { // blocks until the task ends: never in the read loop
			defer s.wg.Done()
			select {
			case <-t.done:
			case <-s.serveCtx.Done():
				return
			}
			s.mu.Lock()
			status, text, isErr, after, first := t.Status, t.text, t.isErr, t.after, !t.delivered
			if status == "completed" {
				t.delivered = true
			}
			s.mu.Unlock()
			if status != "completed" {
				s.fail(req.ID, codeParams, "task "+status+": it has no result (start the call again to get one)")
				return
			}
			ok := s.reply(req.ID, map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isErr,
				"_meta": map[string]any{"io.modelcontextprotocol/related-task": map[string]string{"taskId": t.ID}}})
			// read receipts: only once the result was actually handed over, and once
			if ok && first && after != nil {
				if err := after(context.WithoutCancel(s.serveCtx)); err != nil {
					s.diag("nmcp: 읽음 기록 실패(결과는 전달됨)")
				}
			}
		}()
	}
}
