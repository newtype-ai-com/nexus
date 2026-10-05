// Package core implements the in-process agent runtime. It has no dependency on
// Nexus, a JavaScript runtime, or a sidecar transport.
package core

import (
	"context"
	"encoding/json"
	"errors"
)

var (
	ErrTurnInProgress = errors.New("a turn is already in progress")
	ErrClosed         = errors.New("engine is closed")
)

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Images     []Image    `json:"images,omitempty"`
	// Inbox provenance is process-local, never accepted from history or a model.
	inboxID      string
	inboxContent string
	inboxSource  InboxMessage
}
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	// Signature is an opaque provider token that must be echoed back with
	// this call (Gemini 3 thoughtSignature); empty for other providers.
	Signature string `json:"signature,omitempty"`
}
type ToolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}
type Usage struct {
	InputTokens       int `json:"input_tokens"`
	OutputTokens      int `json:"output_tokens"`
	PromptTotalTokens int `json:"prompt_total_tokens,omitempty"`
	CacheReadTokens   int `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens  int `json:"cache_write_tokens,omitempty"`
	ReasoningTokens   int `json:"reasoning_tokens,omitempty"`
}
type ModelRequest struct {
	Model          string     `json:"model"`
	Messages       []Message  `json:"messages"`
	Tools          []ToolSpec `json:"tools,omitempty"`
	MaxTokens      int        `json:"max_tokens"`
	Stream         bool       `json:"stream"`
	SessionID      string     `json:"session_id,omitempty"`
	TaskID         string     `json:"task_id,omitempty"`
	InvocationID   string     `json:"invocation_id,omitempty"`
	AgentSessionID string     `json:"agent_session_id,omitempty"`
}
type ModelResponse struct {
	Content      string
	FinishReason string
	ToolCalls    []ToolCall
	Usage        Usage
}

// Chat implementations must stop on context cancellation and call onToken
// synchronously (never after Chat returns). Content is the complete response.
type Model interface {
	Chat(context.Context, ModelRequest, func(string)) (ModelResponse, error)
}
type ContextSizer interface{ ContextWindow() int }
type ToolCaller interface{ SupportsNativeTools() bool }

type ChatRequest struct {
	SessionID    string  `json:"session_id,omitempty"`
	TaskID       string  `json:"task_id,omitempty"`
	ParentTaskID string  `json:"parent_task_id,omitempty"`
	Message      string  `json:"message"`
	Images       []Image `json:"images,omitempty"`
	WorkDir      string  `json:"work_dir,omitempty"`
	PromptType   string  `json:"prompt_type,omitempty"`
	// ActiveFiles is advisory prompt scope, not permission to access paths.
	ActiveFiles []string `json:"active_files,omitempty"`
}
type Event struct {
	Type      string         `json:"type"`
	SessionID string         `json:"session_id"`
	TaskID    string         `json:"task_id"`
	EventID   string         `json:"event_id"`
	Data      map[string]any `json:"data"`
}
type Approval struct {
	ToolCallID  string `json:"tool_call_id"`
	ToolName    string `json:"tool_name"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	Risk        string `json:"risk"`
	// Class is set by the code that asks, never by the model. Only
	// ApprovalLocal may be answered automatically by a host in auto mode; an
	// empty or unknown class always requires a person.
	Class string `json:"class,omitempty"`
	// SessionOption (set by the asking code, never the model) also offers the
	// person "for this session" (ToolContext.ApproveChoice). Its scope is a
	// local decision of the asking code and never widens a server grant.
	SessionOption bool `json:"session_option,omitempty"`
}

// Approval classes. Anything other than ApprovalLocal stays human-only.
const (
	ApprovalLocal    = "local"    // local file/shell/memory change confirmation
	ApprovalSecret   = "secret"   // local action that resolves a registered secret
	ApprovalRemote   = "remote"   // Nexus request (authority, delegation, send, execute)
	ApprovalExternal = "external" // MCP or other third-party tool; effects unknown
	ApprovalCustody  = "custody"  // custody-related tool; always a person
	// ApprovalGrant: a local call of an inbox-originated turn that the
	// execution grant did not cover (Nexus answered "ask"), or the person's
	// confirmation of issuing/revoking a grant (TUI execution_grant tool).
	// Human-only: no mode answers it.
	ApprovalGrant = "grant"
	// ApprovalUpdate: installing a new Newtype client release or restarting
	// into it (TUI client_update tool). Human-only: no mode answers it.
	ApprovalUpdate = "update"
)

type confirmedClassKey struct{}

// WithConfirmedClass marks ctx for one tool call: the code that asked already
// obtained a granted confirmation of this class for exactly this call, so the
// consuming tool need not ask the same person the same question again. Only
// host/tool code sets it (never model input); it does not widen policy.
func WithConfirmedClass(ctx context.Context, class string) context.Context {
	return context.WithValue(ctx, confirmedClassKey{}, class)
}

// ConfirmedClass reports whether ctx carries a granted confirmation of class.
func ConfirmedClass(ctx context.Context, class string) bool {
	got, _ := ctx.Value(confirmedClassKey{}).(string)
	return class != "" && got == class
}

// Turn modes. The TUI exposes exactly these two; every other prompt type
// (including the removed agent/ask/plan values) is treated as ModeAuto.
const (
	ModeAuto          = "auto"
	ModeSelfConscious = "self-conscious"
)

// ToolContext contains only turn-scoped capabilities, not global settings.
type ToolContext struct {
	WorkDir   string
	SessionID string
	TurnID    string
	// RemoteTask is supplied only by a trusted Binder, not model arguments.
	RemoteTask string
	Mode       string
	Approve    func(context.Context, Approval) bool
	// ApproveChoice asks like Approve and also reports whether the person
	// chose "for this session" (offered only with Approval.SessionOption).
	ApproveChoice func(context.Context, Approval) (granted, forSession bool)
	Secret        func(context.Context, string) (string, error)
	Emit          func(string, map[string]any)
	// UpdateWorkPlan records model claims in an engine-owned ledger only when
	// the person explicitly enabled work-plan verification. It grants no authority.
	UpdateWorkPlan func(context.Context, []WorkPlanTask) error
	// RegisterBackground is session-scoped, unlike Emit/Approve/Secret.
	RegisterBackground BackgroundRegister
}
type Tool struct {
	Spec     ToolSpec
	ReadOnly bool
	// RequiresGate marks external tools that must use Binding.Gate, even when
	// supplied by Binding.Tools. Missing Gate fails closed for these tools.
	RequiresGate bool
	// PersonOnly marks a tool that acts only for a person typing in this turn
	// (for example issuing an execution grant or changing a setting). The
	// engine never offers or runs it in an inbox-originated or background
	// turn; the tool keeps its own refusal as a backstop.
	PersonOnly bool
	Run        func(context.Context, ToolContext, json.RawMessage) (string, error)
}
type Toolset interface {
	Tools() []Tool
	Close() error
}
type Binding struct {
	Note          string
	Session       string
	Task          string
	Tools         []Tool
	Gate          func(context.Context, string, json.RawMessage) (bool, string)
	Secret        func(context.Context, string) (string, error)
	Notices       func(context.Context) []string
	Interjections func() []string
	// Inbox is explicitly opt-in and shared with the authenticated receiver.
	// Notices/Interjections and display-only polling never acknowledge it.
	Inbox ModelInbox
	// InboxNote, when set, is called in an inbox-originated turn each time new
	// source messages enter the turn. It gets the authenticated sources (event,
	// seq, sender, sender kind and title; never message text) and returns a
	// system note built from them and host state (such as execution grants).
	// An empty note adds nothing.
	InboxNote func(context.Context, []InboxMessage) string
}
type BindRequest struct{ Conversation, Task, Message string }
type Binder interface {
	Bind(context.Context, BindRequest) (*Binding, error)
}
type BinderFunc func(context.Context, BindRequest) (*Binding, error)

func (f BinderFunc) Bind(ctx context.Context, r BindRequest) (*Binding, error) { return f(ctx, r) }
