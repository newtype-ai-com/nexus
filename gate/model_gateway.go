package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/modelerror"
	"github.com/newtype-ai-com/nexus/internal/streamprogress"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/redact"
)

// ModelConfig is trusted deployment configuration. Every call must name a live
// session and delegation; unmetered user-only model access is deliberately closed.
type ModelConfig struct {
	Service           *nexus.Service
	Store             CredentialStore
	Upstream, Key     string // full upstream chat/completions or responses URL
	Models            []string
	Budget            int64 // conservative admission ceiling, never supplied by the caller
	MaxOutput         int64
	Transport         http.RoundTripper
	TurnLimit         time.Duration
	StreamIdleTimeout time.Duration // zero is five minutes; trusted config may shorten only
	CallBudgetFile    string        // optional pre-provisioned persistent upstream POST cap
	Logger            *slog.Logger  // defaults to slog.Default; only bounded error labels
	// Access (decision 2026-10-05): when set, only the owner and the designated
	// users may use the relay; everyone else gets 403 model_relay_not_allowed.
	Access *ModelAccess
	// Owner limits (decision 2026-10-04). When OwnerEmail is set, a call made with
	// that owner's own person credentials (OwnerPerson: licence + login, never
	// nta_/nte_) skips CallBudgetFile and the monthly account quota, and uses
	// OwnerBudget/OwnerMaxOutput instead of Budget/MaxOutput. OwnerBudget 0 is
	// DefaultOwnerTokenCeiling. OwnerMaxOutput 0 injects no output cap: the
	// client's own cap (if any) is passed through under the protocol's name
	// and counted in the ceiling check. Every other caller is unchanged.
	OwnerEmail     string
	OwnerBudget    int64
	OwnerMaxOutput int64
}
type ModelHandler struct {
	cfg    ModelConfig
	client *http.Client
	models map[string]bool
	// M21: pre-output rate-limit retry policy and the per-quota-domain hold
	// (this handler = one upstream + one credential). Tests shorten retry.
	retry retryPolicy
	pace  pacing
	// up is the provider endpoint and credential as one immutable snapshot.
	// A call loads it once and finishes on it even if the operator swaps it
	// mid-flight; budgets, models and limits stay in cfg and never change.
	up atomic.Pointer[modelUpstream]
}

// modelUpstream is never mutated after publication; SwapUpstream replaces it.
type modelUpstream struct {
	upstream, key string
	source        string // "env" or "operator"
	updatedAt     time.Time
	updatedBy     string
}

func (u *modelUpstream) protocol() string {
	if strings.HasSuffix(u.upstream, "/responses") {
		return "responses"
	}
	return "chat/completions"
}

// validModelUpstream is the one upstream URL rule for startup and swaps.
func validModelUpstream(upstream string) error {
	u, err := url.Parse(upstream)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("gate: invalid model configuration")
	}
	if !strings.HasSuffix(u.Path, "/chat/completions") && !strings.HasSuffix(u.Path, "/responses") {
		return errors.New("gate: unsupported model protocol")
	}
	return nil
}

// validModelKey bounds a provider key to printable ASCII without spaces; it is
// only ever sent as a Bearer value and must not be able to split a header.
func validModelKey(key string) bool {
	if len(key) < 16 || len(key) > 1024 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return false
		}
	}
	return true
}

func NewModelHandler(cfg ModelConfig) (*ModelHandler, error) {
	u, err := url.Parse(cfg.Upstream)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || cfg.Service == nil || cfg.Store == nil || cfg.Key == "" || cfg.Budget <= 0 || cfg.MaxOutput <= 0 || cfg.MaxOutput > cfg.Budget || len(cfg.Models) == 0 {
		return nil, errors.New("gate: invalid model configuration")
	}
	if err := validModelUpstream(cfg.Upstream); err != nil {
		return nil, err
	}
	models := map[string]bool{}
	for _, m := range cfg.Models {
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$`).MatchString(m) {
			return nil, errors.New("gate: invalid model name")
		}
		models[m] = true
	}
	if cfg.TurnLimit == 0 {
		cfg.TurnLimit = 15 * time.Minute
	}
	if cfg.TurnLimit < time.Second || cfg.TurnLimit > 15*time.Minute {
		return nil, errors.New("gate: invalid turn limit")
	}
	if cfg.StreamIdleTimeout == 0 {
		cfg.StreamIdleTimeout = streamprogress.GateIdleTimeout
	}
	if cfg.StreamIdleTimeout < 0 || cfg.StreamIdleTimeout > streamprogress.GateIdleTimeout {
		return nil, errors.New("gate: invalid stream idle timeout")
	}
	if cfg.CallBudgetFile != "" {
		if err := checkModelCallBudget(cfg.CallBudgetFile, false); err != nil {
			return nil, err
		}
	}
	cfg.OwnerEmail = strings.ToLower(strings.TrimSpace(cfg.OwnerEmail))
	if cfg.OwnerEmail != "" {
		if cfg.OwnerBudget == 0 {
			cfg.OwnerBudget = DefaultOwnerTokenCeiling
		}
		if !validEmail(cfg.OwnerEmail) || strings.Contains(cfg.OwnerEmail, "*") || cfg.OwnerBudget <= 0 || cfg.OwnerMaxOutput < 0 || cfg.OwnerMaxOutput > cfg.OwnerBudget {
			return nil, errors.New("gate: invalid owner model limits")
		}
	}
	h := &ModelHandler{cfg: cfg, models: models, retry: defaultRetryPolicy(), client: &http.Client{Transport: cfg.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	h.up.Store(&modelUpstream{upstream: cfg.Upstream, key: cfg.Key, source: "env"})
	return h, nil
}

// SwapUpstream atomically replaces the provider endpoint and key as one
// snapshot. In-flight calls keep the snapshot they loaded; budgets, model
// names and limits are untouched. The previous provider's rate-limit hold is
// dropped because the new endpoint/credential is a different quota domain.
func (h *ModelHandler) SwapUpstream(upstream, key, source string, at time.Time, by string) error {
	if h == nil || validModelUpstream(upstream) != nil || !validModelKey(key) || (source != "env" && source != "operator") {
		return errors.New("gate: invalid model configuration")
	}
	h.up.Store(&modelUpstream{upstream: upstream, key: key, source: source, updatedAt: at.UTC(), updatedBy: by})
	h.pace.reset()
	return nil
}

// Protocol is the protocol of the current upstream snapshot.
func (h *ModelHandler) Protocol() string { return h.up.Load().protocol() }

// ProtocolRoute serves only while the current upstream speaks protocol, so a
// deployment can mount both routes and follow an operator protocol change.
func (h *ModelHandler) ProtocolRoute(protocol string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.Protocol() != protocol {
			w.Header().Set("Cache-Control", "no-store")
			gateError(w, 404, "not_found")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// reservationCoversRetry is the accounting basis for one more dispatch of the
// same body inside this invocation's reservation: the input estimate (bytes)
// for every dispatch so far plus one more must still fit under the reserved
// budget after the output cap and envelope margin. Without that basis the
// refusal is relayed instead of retried. Refused dispatches are charged at
// this estimate on settlement (a 429 is not assumed to be free).
func (h *ModelHandler) reservationCoversRetry(inputBytes int, retries int) bool {
	return reservationCovers(inputBytes, retries, h.cfg.Budget, h.cfg.MaxOutput)
}
func reservationCovers(inputBytes int, retries int, budget, maxOutput int64) bool {
	return int64(inputBytes)*int64(retries+2) <= budget-maxOutput-1024
}

// clientOutputCap is the smallest positive output cap the client sent under
// any of the three names (0: none). A present but non-positive or
// non-integer value is invalid.
func clientOutputCap(body map[string]json.RawMessage) (int64, bool) {
	var out int64
	for _, key := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		v, ok := body[key]
		if !ok {
			continue
		}
		var n int64
		if json.Unmarshal(v, &n) != nil || n <= 0 {
			return 0, false
		}
		if out == 0 || n < out {
			out = n
		}
	}
	return out, true
}
func (h *ModelHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		gateError(rw, 405, "method_not_allowed")
		return
	}
	// One snapshot for the whole call, including retries: an operator swap
	// never splits a turn between two providers or two credentials.
	up := h.up.Load()
	logger := h.cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// One "model relay timing" line per call, written last (after settlement).
	timing := newModelTiming(r.Context())
	sw := &statusWriter{ResponseWriter: rw}
	var w http.ResponseWriter = sw
	var (
		model, outcome = "", "rejected"
		stream, owner  bool
		retries        int
		used           = int64(-1)
	)
	defer func() {
		timing.log(logger, model, up.protocol(), stream, sw.code, outcome, retries, owner, used)
	}()
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.TurnLimit)
	defer cancel()
	r = r.WithContext(ctx)
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(2 * time.Minute))
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(h.cfg.TurnLimit + time.Minute))
	auth := NexusAuth{Store: h.cfg.Store, Service: h.cfg.Service}
	var actor nexus.Principal
	var err error
	timing.add(&timing.auth, func() { actor, err = auth.Authenticate(r) })
	if err != nil {
		gateError(w, 401, "unauthenticated")
		return
	}
	if actor.Kind != nexus.PrincipalSession {
		gateError(w, 403, "session_required")
		return
	}
	// Owner limits are decided here from server-side credential records only.
	if h.cfg.OwnerEmail != "" {
		timing.add(&timing.auth, func() {
			account, ok := OwnerPerson(r, h.cfg.Store, h.cfg.OwnerEmail, time.Now())
			owner = ok && account == actor.AccountID
		})
	}
	if h.cfg.Access != nil && !owner && !h.cfg.Access.Allowed(actor.AccountID) {
		gateError(w, 403, ModelRelayNotAllowed) // defence in depth: roots are refused first
		return
	}
	budget, maxOutput := h.cfg.Budget, h.cfg.MaxOutput
	if owner {
		budget, maxOutput = h.cfg.OwnerBudget, h.cfg.OwnerMaxOutput
	}
	var wake bool
	timing.add(&timing.auth, func() { wake = h.cfg.Service.WakeHint(r.Context(), actor) })
	if wake {
		w.Header().Set(nexus.WakeHeader, "1")
	}
	delegation, err := ids.ParseDelegation(r.Header.Get("X-Newtype-Delegation"))
	if err != nil || len(r.Header.Values("X-Newtype-Delegation")) != 1 {
		gateError(w, 400, "delegation_required")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, 8<<20))
	if err != nil {
		gateError(w, 413, "invalid_request")
		return
	}
	if _, _, err = redact.JSON(raw); err != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil || body == nil {
		gateError(w, 400, "invalid_request")
		return
	}
	// Reject provider-side state, hosted tools, remote media and multi-choice
	// expansion: these can spend tokens outside a single text-turn reservation.
	allowed := map[string]bool{"model": true, "messages": true, "input": true, "instructions": true, "tools": true, "tool_choice": true, "parallel_tool_calls": true, "stream": true, "stream_options": true, "max_tokens": true, "max_completion_tokens": true, "max_output_tokens": true, "temperature": true, "top_p": true, "reasoning": true, "text": true, "store": true}
	for key := range body {
		if !allowed[key] {
			gateError(w, 400, "invalid_request")
			return
		}
	}
	// Stateless Responses clients explicitly send store:false. Never allow
	// provider-side persistence, which escapes the local turn/account boundary.
	if s, ok := body["store"]; ok {
		if string(bytes.TrimSpace(s)) != "false" {
			gateError(w, 400, "invalid_request")
			return
		}
	}
	var tools []struct {
		Type string `json:"type"`
	}
	if t, ok := body["tools"]; ok {
		if json.Unmarshal(t, &tools) != nil {
			gateError(w, 400, "invalid_request")
			return
		}
		for _, tool := range tools {
			if tool.Type != "function" {
				gateError(w, 400, "invalid_request")
				return
			}
		}
	}
	if containsRemoteModelInput(body) {
		gateError(w, 400, "invalid_request")
		return
	}
	model = h.cfg.Models[0]
	if m, ok := body["model"]; ok && json.Unmarshal(m, &model) != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	if model == "" {
		model = h.cfg.Models[0]
	}
	if !h.models[model] {
		gateError(w, 400, "invalid_request")
		return
	}
	body["model"], _ = json.Marshal(model)
	// The owner with no configured output cap keeps the client's own cap.
	reserveOutput := maxOutput
	if maxOutput == 0 {
		clientCap, ok := clientOutputCap(body)
		if !ok {
			gateError(w, 400, "invalid_request")
			return
		}
		reserveOutput = clientCap
	}
	// Do not let alternate limits override the server's output cap.
	for _, key := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		delete(body, key)
	}
	limit := "max_completion_tokens"
	if strings.HasSuffix(up.upstream, "/responses") {
		limit = "max_output_tokens"
	}
	if reserveOutput > 0 {
		body[limit], _ = json.Marshal(reserveOutput)
	}
	if s, ok := body["stream"]; ok && json.Unmarshal(s, &stream) != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	if stream && strings.HasSuffix(up.upstream, "/chat/completions") {
		body["stream_options"] = json.RawMessage(`{"include_usage":true}`)
	}
	raw, err = json.Marshal(body)
	if err != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	// For the supported text-only protocols UTF-8 byte count is a conservative
	// input-token bound; reserve extra envelope overhead. No hosted/remote input.
	if int64(len(raw)) > budget-reserveOutput || budget-reserveOutput-int64(len(raw)) < 1024 {
		gateError(w, 413, "token_ceiling_exceeded")
		return
	}
	sum := sha256.Sum256(raw)
	invocation := ids.Invocation(ids.New(ids.KindInvocation))
	var state nexus.ExecutionState
	timing.add(&timing.prepare, func() {
		state, err = h.cfg.Service.PrepareExecution(ctx, actor, nexus.ExecutionState{ID: invocation, Delegation: delegation, Action: "model:" + model, InputHash: hex.EncodeToString(sum[:]), Budget: budget, Metered: true, Owner: owner}, time.Minute)
	})
	if err != nil || state.Status != "ready" {
		gateError(w, 403, "out_of_scope")
		return
	}
	var started nexus.ExecutionState
	var fresh bool
	timing.add(&timing.prepare, func() { started, fresh, err = h.cfg.Service.StartExecution(ctx, actor, invocation) })
	if errors.Is(err, nexus.ErrLimit) {
		gateError(w, 403, "limit_reached")
		return
	}
	if err != nil || !fresh {
		gateError(w, 403, "out_of_scope")
		return
	}
	w.Header().Set("X-Newtype-Invocation", string(invocation))
	status := "failed"
	defer func() {
		settle, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		timing.add(&timing.settle, func() {
			_, _ = h.cfg.Service.SettleExecution(settle, nexus.SystemPrincipal(actor.AccountID), actor.SessionID, invocation, status, used)
		})
		outcome = status
	}()
	// Revalidate the original credentials and exact delegation during a long stream.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				p, e := auth.Reauthenticate(r)
				if e != nil || p != actor {
					cancel()
					return
				}
				d, e := h.cfg.Service.Authorize(ctx, actor, delegation, "model:"+model)
				if e != nil || d.Effect != "auto" {
					cancel()
					return
				}
			}
		}
	}()
	req, err := http.NewRequestWithContext(ctx, "POST", up.upstream, bytes.NewReader(raw))
	if err != nil {
		gateError(w, 502, "model_unavailable")
		return
	}
	req.Header.Set("Authorization", "Bearer "+up.key)
	req.Header.Set("Content-Type", "application/json")
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	var watch *streamprogress.Watch
	var deferStop func()
	startWatch := func() {
		watch = streamprogress.NewWatch(ctx, h.cfg.StreamIdleTimeout)
		// A blocked downstream Write needs an I/O deadline, not just cancellation.
		stopped := make(chan struct{})
		stop := context.AfterFunc(watch.Context(), func() {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now())
			close(stopped)
		})
		var once sync.Once
		deferStop = func() {
			once.Do(func() {
				if !stop() {
					<-stopped
				}
			})
		}
	}
	if stream {
		startWatch()
		req = req.WithContext(watch.Context())
	}
	defer func() {
		if deferStop != nil {
			deferStop()
		}
		if watch != nil {
			if e := watch.Finish(); e != nil {
				status = "failed"
				used = -1
				if errors.Is(e, streamprogress.ErrIdleTimeout) {
					logger.Warn("model stream stalled", "outcome", "model_failed", "failed", "no_progress", "last_event", watch.Last())
				}
			}
		}
	}()
	// M21: dispatch, and when the upstream refuses the turn for its rate limit
	// before any output, wait and send the same body again — bounded, within
	// this invocation's reservation, with live authority, and never after a
	// byte of output or a committed downstream header. Nothing below writes to
	// w until the loop has decided what to relay.
	pol := h.retry
	retryDeadline := pol.now().Add(pol.budget)
	var waited time.Duration
	var refusedInput int64 // conservative input charge for refused dispatches
	var res *http.Response
	defer func() {
		timing.endUpstream() // an abort mid-body still closes the dispatch
		if res != nil {
			_ = res.Body.Close()
		}
	}()
	dispatches := 0
	retryCtx := req.Context()
	var prefix []byte
	var src io.Reader
	limited := false
	for {
		if res != nil {
			res.Body.Close() // the refusal we are retrying past
			res = nil
		}
		// Shared hold for this quota domain: never past this request's budget.
		var slept time.Duration
		var herr error
		timing.add(&timing.pace, func() { slept, herr = h.pace.wait(retryCtx, pol, retryDeadline) })
		waited += slept
		if herr != nil {
			if retryCtx.Err() != nil {
				return // caller gone or turn limit: settle as failed, relay nothing
			}
			if dispatches == 0 {
				used = 0
			} // prior refusals retain their charge
			w.Header().Set("X-Newtype-Model-Retry", "exhausted")
			logger.Warn("model relay rate limited", "outcome", "rate_limited", "retries", retries, "waited", waited.Round(time.Second).String())
			gateError(w, 429, "rate_limited")
			return
		}
		// Every provider dispatch counts against the provisioned call budget.
		if h.cfg.CallBudgetFile != "" && !owner { // the owner is not on the call ledger
			var err error
			timing.add(&timing.budget, func() { err = checkModelCallBudget(h.cfg.CallBudgetFile, true) })
			if err != nil {
				if retries == 0 {
					used = 0 // no provider dispatch took place
				}
				gateError(w, 403, "model_call_budget_unavailable")
				return
			}
		}
		{
			// A first dispatch can also have waited in the shared hold.
			// Re-dispatch only with the same live credentials and exact delegation
			// still authorising this model, re-checked right before the call.
			var p nexus.Principal
			var d nexus.Decision
			var pe, de error
			timing.add(&timing.auth, func() {
				p, pe = auth.Reauthenticate(r)
				if pe == nil && p == actor {
					d, de = h.cfg.Service.Authorize(ctx, actor, delegation, "model:"+model)
				}
			})
			if pe != nil || p != actor {
				gateError(w, 401, "unauthenticated")
				return
			}
			if de != nil || d.Effect != "auto" {
				gateError(w, 403, "out_of_scope")
				return
			}
			req.Body = io.NopCloser(bytes.NewReader(raw))
			req.ContentLength = int64(len(raw))
		}
		if retryCtx.Err() != nil {
			return
		}
		var err error
		dispatches++
		timing.dispatch()
		res, err = h.client.Do(req)
		timing.headers()
		if err != nil {
			// Transport failure: unknown outcome, never re-executed.
			gateError(w, 502, "model_unavailable")
			return
		}
		if watch == nil && strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
			startWatch()
			retryCtx = watch.Context()
			req = req.WithContext(retryCtx)
		}
		if watch != nil {
			res.Body = watch.WrapBody(res.Body)
		}
		res.Body = timing.body(res.Body)
		limited = false
		prefix, src = nil, res.Body
		var after time.Duration
		if res.StatusCode == 429 {
			limited = true
			after, _ = parseRetryAfter(res.Header.Get("Retry-After"), pol.now())
		} else if res.StatusCode == 200 && strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
			// Read the opening of the stream (bounded) to tell a pre-output
			// refusal from an answer. Reading goes through the watched body, so
			// the stall watch sees it; keepalives still do not count as progress.
			var v peekVerdict
			prefix, src, v = peekStream(res.Body, nil)
			limited = v == peekLimited
			after, _ = parseRetryAfter(res.Header.Get("Retry-After"), pol.now())
		}
		if !limited {
			break
		}
		wait, ok := pol.wait(retries, waited, after)
		if ok && (pol.now().Add(wait).After(retryDeadline) || !reservationCovers(len(raw), retries, started.Budget, reserveOutput)) {
			ok = false
		}
		if !ok {
			break // budget or reservation spent: the refusal goes through as it came
		}
		timing.endUpstream() // the refusal is decided; the wait is pace_wait
		h.pace.hold(pol.now(), wait)
		refusedInput += int64(len(raw))
		var serr error
		timing.add(&timing.pace, func() { serr = pol.sleep(retryCtx, wait) })
		if serr != nil {
			return
		}
		waited += wait
		retries++
	}
	if limited {
		// A rate-limit refusal we could not retry past: the client must not
		// start its own retry ladder on top of ours.
		w.Header().Set("X-Newtype-Model-Retry", "exhausted")
		logger.Warn("model relay rate limited", "outcome", "rate_limited", "retries", retries, "waited", waited.Round(time.Second).String())
	} else if retries > 0 {
		logger.Info("model relay retried", "outcome", "dispatched", "retries", retries, "waited", waited.Round(time.Second).String())
	}
	if res.StatusCode != 200 {
		if res.StatusCode == 429 {
			if retry := res.Header.Get("Retry-After"); retry != "" {
				w.Header().Set("Retry-After", retry)
			}
			gateError(w, 429, "rate_limited")
		} else if res.StatusCode == 400 || res.StatusCode == 422 {
			gateError(w, res.StatusCode, "invalid_request")
		} else {
			gateError(w, 502, "model_unavailable")
		}
		return
	}
	content := res.Header.Get("Content-Type")
	if !strings.HasPrefix(content, "application/json") && !strings.HasPrefix(content, "text/event-stream") {
		gateError(w, 502, "model_unavailable")
		return
	}
	w.Header().Set("Content-Type", content)
	w.Header().Set("X-Newtype-Model", model)
	observer := modelErrorObserver{sse: strings.HasPrefix(content, "text/event-stream"), report: func(d modelerror.Detail) {
		logger.Warn("model stream error", "outcome", "model_failed", "failed", d.FailureCode(), "type", d.Type, "transient", d.Transient)
	}}
	if prefix != nil {
		src = io.MultiReader(bytes.NewReader(prefix), src)
	}
	tail := make([]byte, 0, 256<<10)
	buf := make([]byte, 32<<10)
	for {
		n, readErr := src.Read(buf)
		if readErr != nil {
			timing.endUpstream()
		}
		if n > 0 {
			observer.write(buf[:n])
			tail = append(tail, buf[:n]...)
			if len(tail) > 256<<10 {
				tail = tail[len(tail)-(256<<10):]
			}
			if _, err = w.Write(buf[:n]); err != nil {
				status = "cancelled"
				return
			}
			if err = http.NewResponseController(w).Flush(); err != nil {
				status = "cancelled"
				return
			}
		}
		if readErr == io.EOF {
			if ctx.Err() != nil {
				panic(http.ErrAbortHandler)
			}
			if deferStop != nil {
				deferStop()
			}
			if watch != nil && watch.Finish() != nil {
				panic(http.ErrAbortHandler)
			}
			observer.end()
			if !observer.failed {
				status = "completed"
			}
			used = modelUsage(tail, strings.HasPrefix(content, "text/event-stream"))
			if used >= 0 && refusedInput > 0 {
				used += refusedInput // refused dispatches are not assumed free
			}
			return
		}
		if readErr != nil {
			// Do not turn a truncated upstream SSE into a clean HTTP EOF.
			panic(http.ErrAbortHandler)
		}
	}
}

func containsRemoteModelInput(body map[string]json.RawMessage) bool {
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			if typ, ok := x["type"].(string); ok && (strings.Contains(typ, "image") || strings.Contains(typ, "audio") || strings.Contains(typ, "video") || strings.Contains(typ, "file")) {
				return true
			}
			for k, child := range x {
				if k == "file_id" || k == "image_url" || k == "file_url" {
					return true
				}
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range x {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	for _, key := range []string{"messages", "input"} {
		var value any
		if raw, ok := body[key]; ok {
			if json.Unmarshal(raw, &value) != nil || walk(value) {
				return true
			}
		}
	}
	return false
}

// Only top-level protocol usage is trusted, never a usage-shaped string inside
// generated content. Incomplete/oversized tails conservatively retain the ceiling.
func modelUsage(raw []byte, sse bool) int64 {
	parse := func(raw []byte) int64 {
		var obj struct {
			Usage *struct {
				Total      *int64 `json:"total_tokens"`
				Input      *int64 `json:"input_tokens"`
				Output     *int64 `json:"output_tokens"`
				Prompt     *int64 `json:"prompt_tokens"`
				Completion *int64 `json:"completion_tokens"`
			} `json:"usage"`
			Response json.RawMessage `json:"response"`
			Type     string          `json:"type"`
		}
		if json.Unmarshal(raw, &obj) != nil {
			return -1
		}
		if obj.Type == "response.completed" && len(obj.Response) > 0 {
			return modelUsage(obj.Response, false)
		}
		u := obj.Usage
		if u == nil {
			return -1
		}
		// Sum one complete protocol pair, not both aliases. Cache/reasoning
		// detail counters are subsets, not extra tokens. Conflicting totals or
		// incomplete pairs are unknown usage and retain the reserved ceiling.
		pair := func(a, b *int64) (int64, bool) {
			if a == nil || b == nil || *a < 0 || *b < 0 || *a > 1<<50 || *b > 1<<50 {
				return 0, false
			}
			return *a + *b, true
		}
		var sum int64
		hasPair := false
		for _, parts := range [][2]*int64{{u.Input, u.Output}, {u.Prompt, u.Completion}} {
			if parts[0] == nil && parts[1] == nil {
				continue
			}
			n, ok := pair(parts[0], parts[1])
			if !ok || (hasPair && sum != n) {
				return -1
			}
			sum, hasPair = n, true
		}
		if u.Total != nil {
			if *u.Total < 0 || *u.Total > 1<<51 || (hasPair && *u.Total != sum) {
				return -1
			}
			return *u.Total
		}
		if !hasPair {
			return -1
		}
		return sum
	}
	if !sse {
		return parse(raw)
	}
	used := int64(-1)
	terminal := false
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.HasPrefix(line, []byte("data:")) {
			data := bytes.TrimSpace(line[5:])
			if bytes.Equal(data, []byte("[DONE]")) {
				terminal = true
			}
			var event struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &event) == nil && event.Type == "response.completed" {
				terminal = true
			}
			if n := parse(data); n >= 0 {
				used = n
			}
		}
	}
	if !terminal {
		return -1
	}
	return used
}
