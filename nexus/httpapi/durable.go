package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// MeteredRunner reports cumulative provider tokens across all attempts. A
// negative usage means unknown and retains the full admission ceiling.
type MeteredRunner func(context.Context, string, json.RawMessage) (int64, error)

func durableResult(x nexus.ExecutionState) Result {
	return Result{ID: x.ID, Status: x.Status, InputHash: x.InputHash, ApprovalExpires: x.ApprovalExpires}
}

func (a *API) durableExecute(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind != nexus.PrincipalSession {
		fail(w, nexus.ErrForbidden)
		return
	}
	id, err := ids.ParseInvocation(r.PathValue("id"))
	if err != nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	var req request
	if err = decode(w, r, &req); err != nil {
		fail(w, err)
		return
	}
	cost, ok := a.cfg.Actions[req.Action]
	if !ok {
		fail(w, nexus.ErrForbidden)
		return
	}
	if _, err = ids.ParseDelegation(string(req.Delegation)); err != nil || len(req.Args) == 0 || !json.Valid(req.Args) {
		fail(w, nexus.ErrInvalid)
		return
	}
	var compact bytes.Buffer
	_ = json.Compact(&compact, req.Args)
	req.Args = compact.Bytes()
	sum := sha256.Sum256(req.Args)
	x, err := a.cfg.Service.PrepareExecution(r.Context(), p, nexus.ExecutionState{ID: id, Delegation: req.Delegation, Action: req.Action, InputHash: hex.EncodeToString(sum[:]), Budget: cost, Metered: a.cfg.RunMetered != nil}, a.cfg.ApprovalTTL)
	if err != nil {
		fail(w, err)
		return
	}
	if (x.Status == "pending" || x.Status == "approved") && !a.cfg.Clock().Before(x.ApprovalExpires) {
		x.Status = "expired"
	}
	if x.Status == "pending" {
		write(w, 202, durableResult(x))
		return
	}
	if x.Status == "running" || x.Status == "cancelling" {
		write(w, 409, durableResult(x))
		return
	}
	if x.Status != "ready" && x.Status != "approved" {
		write(w, 200, durableResult(x))
		return
	}
	approved := x.Status == "approved"
	x, fresh, err := a.cfg.Service.StartExecution(r.Context(), p, id)
	if err != nil {
		fail(w, err)
		return
	}
	if !fresh {
		write(w, 409, durableResult(x))
		return
	}
	ctx, cancel := context.WithCancel(context.WithValue(r.Context(), executionKey{}, executionIdentity{actor: p, delegation: x.Delegation, invocation: id, approved: approved, approvalExpires: x.ApprovalExpires, clock: a.cfg.Clock}))
	stop := a.watchExecution(ctx, cancel, r, x, approved)
	used, runErr := a.runMeasured(ctx, x.Action, req.Args)
	wasCancelled := ctx.Err() != nil
	cancel()
	<-stop
	status := "completed"
	if wasCancelled || errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		status = "cancelled"
	} else if runErr != nil {
		status = "failed"
	}
	persistCtx, done := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer done()
	settled, err := a.cfg.Service.SettleExecution(persistCtx, nexus.SystemPrincipal(p.AccountID), p.SessionID, id, status, used)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, durableResult(settled))
}
func (a *API) runMeasured(ctx context.Context, action string, args json.RawMessage) (used int64, err error) {
	used = -1
	defer func() {
		if recover() != nil {
			used = -1
			err = errors.New("runner failed")
		}
	}()
	if a.cfg.RunMetered != nil {
		return a.cfg.RunMetered(ctx, action, args)
	}
	return -1, a.run(ctx, action, args)
}
func (a *API) watchExecution(ctx context.Context, cancel context.CancelFunc, r *http.Request, x nexus.ExecutionState, approved bool) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(a.cfg.RecheckInterval)
		defer tick.Stop()
		for {
			changed := a.cfg.Service.Changed()
			p, err := a.cfg.Reauthenticate(r.WithContext(ctx))
			if err != nil || p != x.Actor {
				cancel()
				return
			}
			d, err := a.cfg.Service.Authorize(ctx, x.Actor, x.Delegation, x.Action)
			if err != nil || (d.Effect != "auto" && !(d.Effect == "ask" && approved && (d.Approver == "" || d.Approver == "user"))) || (approved && !a.cfg.Clock().Before(x.ApprovalExpires)) {
				cancel()
				return
			}
			latest, err := a.cfg.Service.Execution(ctx, x.Actor, x.ID)
			if err != nil || latest.Status != "running" {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-changed:
			case <-tick.C:
			}
		}
	}()
	return done
}
func (a *API) durableGet(w http.ResponseWriter, r *http.Request) {
	id, err := ids.ParseInvocation(r.PathValue("id"))
	if err != nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	x, err := a.cfg.Service.Execution(r.Context(), principal(r), id)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, durableResult(x))
}
func (a *API) durableApprove(w http.ResponseWriter, r *http.Request) {
	id, err := ids.ParseInvocation(r.PathValue("id"))
	if err != nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	var req struct {
		InputHash string `json:"input_hash"`
		Approve   *bool  `json:"approve"`
	}
	if err = decode(w, r, &req); err != nil || req.Approve == nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	x, err := a.cfg.Service.DecideExecution(r.Context(), principal(r), id, req.InputHash, *req.Approve)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, durableResult(x))
}
func (a *API) durableCancel(w http.ResponseWriter, r *http.Request) {
	id, err := ids.ParseInvocation(r.PathValue("id"))
	if err != nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	x, err := a.cfg.Service.CancelExecution(r.Context(), principal(r), id)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, durableResult(x))
}
