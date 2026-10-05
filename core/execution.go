package core

import (
	"context"
	"errors"
)

// ErrExecutionSuspended never includes a remote body, secret, or policy detail.
var ErrExecutionSuspended = errors.New("execution suspended; fresh authorization required")

func (e *Engine) checkExecution(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.executionCtx.Err() != nil {
		return ErrExecutionSuspended
	}
	if e.opts.CheckExecution != nil && e.opts.CheckExecution() != nil {
		e.executionCancel() // sticky: a later positive check cannot revive this engine
		return ErrExecutionSuspended
	}
	if e.executionCtx.Err() != nil {
		return ErrExecutionSuspended
	}
	return nil
}

// SuspendExecution is irreversible and does not delete sessions, plans, read
// state or process logs. It stops new work first, then cancels owned work.
// A nil return is not proof that arbitrary external descendants were stopped.
func (e *Engine) SuspendExecution() error {
	e.executionCancel()
	e.suspendOnce.Do(func() { e.suspendErr = e.suspendExecution() })
	return e.suspendErr
}

func (e *Engine) suspendExecution() error {
	e.mu.Lock()
	if e.active != nil {
		e.active.cancel()
	}
	if e.maintenanceCancel != nil {
		e.maintenanceCancel()
	}
	e.background.clear("", true)
	e.mu.Unlock()
	if tools, ok := e.opts.Tools.(interface{ SuspendExecution() error }); ok {
		return tools.SuspendExecution()
	}
	return nil
}

// executionModel also protects budget summaries, which bypass callModel.
// It is not installed as opts.Model so optional provider interfaces are retained.
type executionModel struct{ engine *Engine }

func (m executionModel) Chat(ctx context.Context, r ModelRequest, emit func(string)) (ModelResponse, error) {
	e := m.engine
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.executionCtx, cancel)
	defer func() { stop(); cancel() }()
	if err := e.checkExecution(ctx); err != nil {
		return ModelResponse{}, err
	}
	response, err := e.opts.Model.Chat(ctx, r, func(s string) {
		if emit != nil && e.checkExecution(ctx) == nil {
			emit(s)
		}
	})
	if denied := e.checkExecution(ctx); denied != nil {
		// Preserve returned usage for accounting, but never accept late success.
		return ModelResponse{Usage: response.Usage}, denied
	}
	return response, err
}
