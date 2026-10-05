package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/redact"
)

type Options struct {
	Model                 Model
	Tools                 Toolset
	Binder                Binder
	WorkDir               string
	SessionDir            string // Empty keeps conversation records in memory only.
	Language              string
	ModelName             string
	MaxRounds             int
	ContextTokens         int
	RetryDelay            time.Duration // Zero defaults to two seconds; negative disables delay.
	EnableBackgroundTurns bool          // Explicit host opt-in; consume NextBackgroundTurn.
	EnableInboxTurns      bool          // Independent opt-in, never an approval.
	ModelInbox            ModelInbox    // Same authenticated queue as Binding.Inbox.
	// PlanVerifier is a separately authorized, tool-free verifier. Nil fails
	// closed for semantic completion; it never falls back to the working model.
	PlanVerifier PlanVerifier
	PlanEvidence *EvidenceCollector
	// ExecutionContext is an irreversible work lifetime, independent of the UI.
	// CheckExecution must be local, concurrency-safe and nonblocking; errors are
	// deliberately not reflected to the model. Neither field grants authority.
	ExecutionContext context.Context
	CheckExecution   func() error
}

type Engine struct {
	mu                      sync.Mutex
	opts                    Options
	active                  *turn
	closed                  bool
	records                 map[string]SessionRecord
	maintenanceCancel       context.CancelFunc
	maintenanceDone         chan struct{}
	background              *backgroundQueue
	planVerificationEnabled map[string]bool                  // process-local human opt-in; never restored from disk
	planVerificationStates  map[string]PlanVerificationState // counters only; never authority
	inboxAttempted          map[string]bool                  // protected by mu; not a read receipt
	saveResults             map[string]error                 // last turn save outcome per conversation; protected by mu
	executionCtx            context.Context
	executionCancel         context.CancelFunc
	stopExecutionWatch      func() bool
	suspendOnce             sync.Once
	suspendErr              error
	// journal (M19-B) records tool starts durably before Tool.Run when
	// SessionDir is set; nil-safe and inert for the memory-only engine.
	journal *toolJournal
	// language is the answer language ("ko" or "en"); SetLanguage changes it
	// from the next model request on.
	language atomic.Value
}

type turn struct {
	engine         *Engine
	request        ChatRequest
	ctx            context.Context
	cancel         context.CancelFunc
	events         chan Event
	finished       chan struct{}
	approvals      map[string]pendingApproval // protected by engine.mu
	record         TurnRecord
	answer         string
	status         string
	err            error
	backgroundTurn bool
	inboxTurn      bool
	// inboxSources are the authenticated source messages an inbox turn was
	// given (from the queue, never from text or history). Person-started and
	// background turns have none. Owned by the turn goroutine.
	inboxSources []InboxMessage
	planGated    bool // buffer tentative answers until the plan stop gate accepts
	completion   BackgroundCompletion
	// approvalDenied records that a person (or a cancelled wait) refused an
	// approval in this turn; self-conscious continuation stops for a person.
	approvalDenied atomic.Bool
}

func New(opts Options) (*Engine, error) {
	if opts.Model == nil {
		return nil, errors.New("no model backend")
	}
	if opts.WorkDir == "" {
		opts.WorkDir = "."
	}
	wd, err := filepath.Abs(opts.WorkDir)
	if err != nil {
		return nil, err
	}
	wd, err = filepath.EvalSymlinks(wd)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(wd)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("work directory is not a directory")
	}
	opts.WorkDir = wd
	if opts.MaxRounds <= 0 {
		opts.MaxRounds = 50
	}
	if opts.ModelName == "" {
		opts.ModelName = "host"
	}
	if opts.Language == "" {
		opts.Language = "ko"
	}
	if opts.RetryDelay == 0 {
		opts.RetryDelay = 2 * time.Second
	}
	if opts.SessionDir != "" {
		opts.SessionDir, err = filepath.Abs(opts.SessionDir)
		if err != nil {
			return nil, err
		}
		if err = os.MkdirAll(opts.SessionDir, 0700); err != nil {
			return nil, err
		}
	}
	parent := opts.ExecutionContext
	if parent == nil {
		parent = context.Background()
	}
	work, cancel := context.WithCancel(parent)
	e := &Engine{opts: opts, records: map[string]SessionRecord{}, background: &backgroundQueue{wake: make(chan struct{})}, executionCtx: work, executionCancel: cancel}
	e.language.Store(opts.Language)
	e.journal = newToolJournal(opts.SessionDir, opts.WorkDir)
	e.stopExecutionWatch = context.AfterFunc(work, func() { _ = e.SuspendExecution() })
	return e, nil
}

var conversationID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func validConversation(id string) bool {
	return conversationID.MatchString(id) && id != "." && id != ".."
}

// ErrModelBusy refuses a backend swap while a turn or maintenance is running.
var ErrModelBusy = errors.New("model backend cannot change while a turn is running")

// SetModel replaces the model backend between turns only. Conversation history
// is provider-neutral (Message/ToolCall), so the next turn simply renders it in
// the new backend's wire format. Turns read opts.Model only after acquiring mu
// to start, so a swap under mu with no active turn or maintenance is race-free.
func (e *Engine) SetModel(model Model, name string) error {
	if model == nil {
		return errors.New("no model backend")
	}
	if name == "" {
		name = "host"
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	if e.active != nil || e.maintenanceDone != nil {
		return ErrModelBusy
	}
	e.opts.Model, e.opts.ModelName = model, name
	return nil
}

// SendMessage starts a single turn. Consume its channel through done; channels
// are closed after done. Close/Cancel remain safe if the consumer stops reading.
func (e *Engine) SendMessage(request ChatRequest) (<-chan Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ch, err := e.sendMessageLocked(request)
	if err == nil {
		go e.active.run()
	}
	return ch, err
}

// Caller holds e.mu and starts the returned turn after finalizing metadata.
func (e *Engine) sendMessageLocked(request ChatRequest) (<-chan Event, error) {
	if e.closed {
		return nil, ErrClosed
	}
	if err := e.checkExecution(context.Background()); err != nil {
		return nil, err
	}
	if e.active != nil || e.maintenanceDone != nil {
		return nil, ErrTurnInProgress
	}
	if !validConversation(request.SessionID) {
		request.SessionID = ids.New(ids.KindConv)
	}
	if request.TaskID == "" {
		request.TaskID = ids.New(ids.KindTask)
	}
	if ids.Check(ids.KindTask, request.TaskID) != nil {
		return nil, errors.New("bad_task_id")
	}
	if request.ParentTaskID != "" && ids.Check(ids.KindTask, request.ParentTaskID) != nil {
		return nil, errors.New("bad_task_id")
	}
	// Changing the workspace on a request must not widen the configured boundary.
	if request.WorkDir != "" {
		wd, err := filepath.Abs(request.WorkDir)
		if err != nil {
			return nil, errors.New("bad_work_dir")
		}
		wd, err = filepath.EvalSymlinks(wd)
		if err != nil || wd != e.opts.WorkDir {
			return nil, errors.New("bad_work_dir: use a separate engine for another workspace")
		}
	}
	if err := ValidateImages(request.Images); err != nil {
		return nil, err
	}
	activeFiles, err := NormalizeActiveFiles(e.opts.WorkDir, request.ActiveFiles)
	if err != nil {
		return nil, err
	}
	request.ActiveFiles = activeFiles
	request.Images = append([]Image(nil), request.Images...)
	request.WorkDir = e.opts.WorkDir
	ctx, cancel := context.WithCancel(e.executionCtx)
	t := &turn{engine: e, request: request, ctx: ctx, cancel: cancel, events: make(chan Event, 256), finished: make(chan struct{}), approvals: map[string]pendingApproval{}}
	e.active = t
	return t.events, nil
}

func (e *Engine) Cancel() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.maintenanceCancel != nil {
		e.maintenanceCancel()
	}
	if e.active != nil {
		e.active.cancel()
	}
	// An explicit user cancellation must not immediately spawn queued work.
	e.background.clear("", false)
}
func (e *Engine) SendApproval(id string, approved bool) error {
	return e.answerApproval(id, approvalAnswer{granted: approved})
}

// SendApprovalForSession grants one approval that offered the "this session"
// choice (Approval.SessionOption) and tells the asking code the person chose
// it. What "this session" covers is the asking code's local decision; it
// never widens any server-side grant. Other approvals refuse it.
func (e *Engine) SendApprovalForSession(id string) error {
	return e.answerApproval(id, approvalAnswer{granted: true, session: true})
}

func (e *Engine) answerApproval(id string, answer approvalAnswer) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active == nil {
		return errors.New("no active approval")
	}
	p, ok := e.active.approvals[id]
	if !ok {
		return errors.New("unknown or expired approval")
	}
	if answer.session && !p.sessionOption {
		return errors.New("approval does not offer a session choice")
	}
	delete(e.active.approvals, id)
	p.ch <- answer
	return nil
}

type approvalAnswer struct{ granted, session bool }

type pendingApproval struct {
	ch            chan approvalAnswer
	sessionOption bool
}

func (e *Engine) HealthCheck() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	return nil
}
func (e *Engine) Close() error {
	e.stopExecutionWatch()
	e.mu.Lock()
	e.closed = true
	e.executionCancel()
	e.background.clear("", true)
	t := e.active
	done := e.maintenanceDone
	if e.maintenanceCancel != nil {
		e.maintenanceCancel()
	}
	if t != nil {
		t.cancel()
	}
	e.mu.Unlock()
	if t != nil {
		<-t.finished
	}
	if done != nil {
		<-done
	}
	suspendErr := e.SuspendExecution()
	if e.opts.Tools != nil {
		return errors.Join(suspendErr, e.opts.Tools.Close())
	}
	return suspendErr
}

func clean(s string) string { v, _ := redact.Text(s); return v }
func cleanData(data map[string]any) map[string]any {
	raw, err := json.Marshal(data)
	if err != nil {
		return map[string]any{"content": "[withheld: invalid event]"}
	}
	raw, _, err = redact.JSON(raw)
	if err != nil {
		return map[string]any{"content": "[withheld: invalid event]"}
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return map[string]any{"content": "[withheld]"}
	}
	return out
}
func (t *turn) event(kind string, data map[string]any) Event {
	return Event{Type: kind, SessionID: t.request.SessionID, TaskID: t.request.TaskID, EventID: ids.New(ids.KindEvent), Data: cleanData(data)}
}
func (t *turn) emit(kind string, data map[string]any) {
	// Reserve three slots for error/content_done/done even when cancelled with an
	// abandoned consumer. The producer is single-threaded, including tool Emit.
	for len(t.events) >= cap(t.events)-3 {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
	select {
	case <-t.ctx.Done():
		return
	default:
		t.events <- t.event(kind, data)
	}
}
func (t *turn) approve(ctx context.Context, a Approval) bool {
	a.SessionOption = false
	granted, _ := t.approveChoice(ctx, a)
	return granted
}

// approveChoice asks the person; with a.SessionOption the person may also
// answer "for this session", reported as forSession (only with granted).
func (t *turn) approveChoice(ctx context.Context, a Approval) (granted, forSession bool) {
	if t.engine.checkExecution(ctx) != nil {
		return false, false
	}
	a.ToolCallID = ids.New(ids.KindApproval)
	ch := make(chan approvalAnswer, 1)
	e := t.engine
	e.mu.Lock()
	t.approvals[a.ToolCallID] = pendingApproval{ch: ch, sessionOption: a.SessionOption}
	e.mu.Unlock()
	defer func() { e.mu.Lock(); delete(t.approvals, a.ToolCallID); e.mu.Unlock() }()
	needed := map[string]any{"tool_call_id": a.ToolCallID, "tool_name": a.ToolName, "description": a.Description, "command": a.Command, "risk": a.Risk, "class": a.Class}
	if a.SessionOption {
		needed["session_option"] = true
	}
	t.emit("approval_needed", needed)
	select {
	case answer := <-ch:
		granted := answer.granted && t.engine.checkExecution(ctx) == nil
		if !granted {
			t.approvalDenied.Store(true)
		}
		return granted, granted && answer.session
	case <-ctx.Done():
		return false, false
	}
}
func (t *turn) run() {
	start := time.Now()
	t.record = TurnRecord{At: start.UTC(), TaskID: t.request.TaskID, User: clean(t.request.Message), Mode: normaliseMode(t.request.PromptType)}
	if t.backgroundTurn || t.inboxTurn {
		// Automatic turns are never autonomous, whatever a request carries.
		t.record.Mode = ModeAuto
	}
	defer func() {
		if recover() != nil {
			t.status = "engine_error"
			t.err = errors.New("engine execution panicked")
		}
		if t.ctx.Err() != nil {
			t.status = "cancelled"
		}
		if t.planGated && t.status != "verified_done" && t.status != "waiting_person" && t.status != "blocked_no_progress" && t.status != "blocked_unresolved_plan" {
			t.answer = "Plan execution stopped without verified completion: " + t.status + "."
		}
		t.record.Assistant = clean(t.answer)
		t.record.Status = t.status
		t.record.MS = time.Since(start).Milliseconds()
		if err := t.engine.saveTurn(t.request, t.record); err != nil && t.err == nil {
			t.err = fmt.Errorf("session save failed: %w", err)
			t.status = "session_error"
		}
		t.cancel()
		e := t.engine
		e.mu.Lock()
		t.approvals = map[string]pendingApproval{}
		e.active = nil
		if t.err != nil && t.status != "cancelled" {
			t.events <- t.event("error", map[string]any{"code": t.status, "message": t.err.Error()})
		}
		t.events <- t.event("content_done", map[string]any{"content": t.answer})
		t.events <- t.event("done", map[string]any{"session_id": t.request.SessionID, "task_id": t.request.TaskID, "status": t.status})
		close(t.events)
		close(t.finished)
		e.background.signal()
		e.mu.Unlock()
	}()
	// Emit start even if Cancel won the scheduling race.
	t.events <- t.event("stream_start", map[string]any{"session_id": t.request.SessionID, "task_id": t.request.TaskID, "parent_task_id": t.request.ParentTaskID})
	if t.backgroundTurn {
		t.emit("background_completed", map[string]any{"job_id": t.completion.JobID, "pid": t.completion.PID, "status": t.completion.Status, "exit_code": t.completion.ExitCode, "output": t.completion.Output, "parent_task_id": t.request.ParentTaskID})
	}
	t.loop()
}

// normaliseMode maps a request prompt type to a turn mode. Only the exact
// self-conscious value selects autonomous continuation; anything else —
// including legacy agent/ask/plan values from older clients — is auto. The
// host (TUI) is responsible for only sending self-conscious for a turn a
// person started after a person-typed activation.
func normaliseMode(mode string) string {
	if mode == ModeSelfConscious {
		return ModeSelfConscious
	}
	return ModeAuto
}

// SetLanguage sets the answer language ("en" is English, anything else
// Korean) for every later model request; a turn already running keeps its
// system prompt. Safe for concurrent use.
func (e *Engine) SetLanguage(lang string) {
	if lang != "en" {
		lang = "ko"
	}
	e.language.Store(lang)
}

// Language is the current answer language ("ko" or "en").
func (e *Engine) Language() string {
	if lang, ok := e.language.Load().(string); ok && lang != "" {
		return lang
	}
	if e.opts.Language == "" {
		return "ko"
	}
	return e.opts.Language
}
