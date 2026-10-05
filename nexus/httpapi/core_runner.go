package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/core"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/redact"
)

type executionKey struct{}
type executionIdentity struct {
	actor           nexus.Principal
	delegation      ids.Delegation
	invocation      ids.Invocation
	approved        bool
	approvalExpires time.Time
	clock           func() time.Time
}

// CoreRunnerConfig is deliberately model-only: there are no filesystem tools,
// secrets, client-selected workspace, session persistence or inherited Binder.
// Model is a trusted, concurrency-safe dependency (use a fake for local tests).
// Fixed HTTP execution cost is NOT provider usage accounting. Do not use this
// adapter as a paid Gate proxy until reservation/settlement is implemented.
type CoreRunnerConfig struct {
	Service   *nexus.Service
	Model     core.Model
	ModelName string
	WorkDir   string
}

// NewCoreRunner runs an isolated, in-memory core.Engine per accepted invocation.
// Only {"message":"..."} is accepted as args. Core output/errors stay private;
// the HTTP adapter publishes only status. Approval authorizes this exact outer
// model action/input, never arbitrary model-produced tools or other models.
func NewCoreRunner(cfg CoreRunnerConfig) (Runner, error) {
	if cfg.Service == nil || cfg.Model == nil || strings.TrimSpace(cfg.ModelName) != cfg.ModelName || cfg.ModelName == "" || strings.ContainsAny(cfg.ModelName, "* \t\r\n") {
		return nil, nexus.ErrInvalid
	}
	return func(ctx context.Context, action string, raw json.RawMessage) error {
		identity, ok := ctx.Value(executionKey{}).(executionIdentity)
		if !ok || identity.actor.Kind != nexus.PrincipalSession || action != "model:"+cfg.ModelName {
			return nexus.ErrForbidden
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(raw) > 64<<10 {
			return nexus.ErrInvalid
		}
		_, count, err := redact.JSON(raw)
		if err != nil || count != 0 {
			return nexus.ErrInvalid
		}
		var input struct {
			Message string `json:"message"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || strings.TrimSpace(input.Message) == "" {
			return nexus.ErrInvalid
		}
		model := guardedModel{cfg: cfg, identity: identity, action: action, outer: ctx}
		engine, err := core.New(core.Options{
			Model: model, ModelName: cfg.ModelName, WorkDir: cfg.WorkDir,
			MaxRounds: 1, RetryDelay: -1,
			Binder: core.BinderFunc(func(context.Context, core.BindRequest) (*core.Binding, error) {
				return &core.Binding{Session: string(identity.actor.SessionID)}, nil
			}),
		})
		if err != nil {
			return errors.New("core initialization failed")
		}
		defer engine.Close()
		// Local conversation IDs are not Nexus session IDs. No client ID can load
		// another principal's history; each engine is discarded after this turn.
		conversation := "conv_" + strings.TrimPrefix(string(identity.invocation), "inv_")
		events, err := engine.SendMessage(core.ChatRequest{SessionID: conversation, Message: input.Message, PromptType: core.ModeAuto})
		if err != nil {
			return errors.New("core start failed")
		}
		cancelled := ctx.Done()
		status := ""
		done := false
		for {
			select {
			case <-cancelled:
				engine.Cancel()
				cancelled = nil // drain through done; do not strand the producer
			case event, open := <-events:
				if !open {
					if err := ctx.Err(); err != nil {
						return err
					}
					// Core currently uses an empty status for normal completion.
					if !done || status != "" {
						return errors.New("core execution failed")
					}
					return nil
				}
				if event.Type == "approval_needed" {
					id, _ := event.Data["tool_call_id"].(string)
					_ = engine.SendApproval(id, false)
				}
				if event.Type == "done" {
					status, _ = event.Data["status"].(string)
					done = true
				}
			}
		}
	}, nil
}

type guardedModel struct {
	cfg      CoreRunnerConfig
	identity executionIdentity
	action   string
	outer    context.Context
}

func (m guardedModel) Chat(ctx context.Context, req core.ModelRequest, onToken func(string)) (core.ModelResponse, error) {
	if err := m.outer.Err(); err != nil {
		return core.ModelResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return core.ModelResponse{}, err
	}
	// Approval is bounded at each provider attempt, not just at HTTP admission.
	// In-flight calls are not retroactively revoked; subsequent retries fail closed.
	if m.identity.approved && (m.identity.clock == nil || !m.identity.clock().Before(m.identity.approvalExpires)) {
		return core.ModelResponse{}, nexus.ErrExpired
	}
	decision, err := m.cfg.Service.Authorize(ctx, m.identity.actor, m.identity.delegation, m.action)
	if err != nil {
		return core.ModelResponse{}, err
	}
	if req.Model != m.cfg.ModelName || (decision.Effect != "auto" && !(decision.Effect == "ask" && m.identity.approved && (decision.Approver == "" || decision.Approver == "user"))) {
		return core.ModelResponse{}, nexus.ErrForbidden
	}
	return m.cfg.Model.Chat(ctx, req, onToken)
}
