package gate

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Integration tests: a real ModelHandler over an httptest upstream that scripts
// its answers per call, with the retry policy shortened to milliseconds. No
// real model, network, key or clock.

type retryFixture struct {
	t        *testing.T
	svc      *nexus.Service
	user     nexus.Principal
	root     nexus.Issued
	key      string
	login    string
	upstream *httptest.Server
	handler  *ModelHandler
	logs     bytes.Buffer
	calls    atomic.Int32
	bodies   [][]byte
	mu       sync.Mutex
	// answers scripts the upstream: index = call number (0-based); the last
	// entry repeats.
	answers []func(w http.ResponseWriter, call int)
	slept   []time.Duration
}

func newRetryFixture(t *testing.T, responses bool, answers ...func(w http.ResponseWriter, call int)) *retryFixture {
	t.Helper()
	ctx := context.Background()
	f := &retryFixture{t: t, svc: nexus.NewService(nexus.NewMemStore(), nil), answers: answers}
	creds := NewMemoryCredentials()
	f.user = nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
	root, err := f.svc.CreateRoot(ctx, f.user, nexus.RootRequest{Title: "fixture", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:*", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 60000}})
	if err != nil {
		t.Fatal(err)
	}
	f.root = root
	f.key, f.login = "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{f.key: "licence", f.login: "login"} {
		if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: f.user.AccountID, Email: f.user.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n := int(f.calls.Add(1)) - 1
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		if len(f.answers) == 0 {
			w.WriteHeader(500)
			return
		}
		i := n
		if i >= len(f.answers) {
			i = len(f.answers) - 1
		}
		f.answers[i](w, n)
	}))
	t.Cleanup(f.upstream.Close)
	path := "/chat/completions"
	if responses {
		path = "/responses"
	}
	h, err := NewModelHandler(ModelConfig{Service: f.svc, Store: creds, Upstream: f.upstream.URL + path, Key: "PRIVATE_KEY_fixture", Models: []string{"fixture"}, Budget: 20000, MaxOutput: 100, Transport: f.upstream.Client().Transport, Logger: slog.New(slog.NewJSONHandler(&f.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	// Short waits; allow TLS/race scheduling overhead inside the wall deadline.
	// The exact production 90s budget is tested separately with the policy clock.
	h.retry = retryPolicy{waits: []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}, budget: 500 * time.Millisecond, now: time.Now, sleep: func(ctx context.Context, d time.Duration) error {
		f.mu.Lock()
		f.slept = append(f.slept, d)
		f.mu.Unlock()
		return sleepCtx(ctx, d)
	}}
	f.handler = h
	return f
}

func (f *retryFixture) request(body string) *http.Request {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("X-Newtype-Login", f.login)
	r.Header.Set("X-Newtype-Session", string(f.root.Session.ID))
	r.Header.Set("X-Newtype-Delegation", string(f.root.Delegation.ID))
	return r
}

func (f *retryFixture) serve(body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, f.request(body))
	return w
}

func (f *retryFixture) execution(w *httptest.ResponseRecorder) nexus.ExecutionState {
	f.t.Helper()
	id := ids.Invocation(w.Header().Get("X-Newtype-Invocation"))
	state, err := f.svc.Execution(context.Background(), f.user, id)
	if err != nil {
		f.t.Fatalf("execution %q: %v", id, err)
	}
	return state
}

func refuse429(after string) func(http.ResponseWriter, int) {
	return func(w http.ResponseWriter, _ int) {
		if after != "" {
			w.Header().Set("Retry-After", after)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":{"code":"rate_limit_exceeded","message":"PRIVATE UPSTREAM BODY"}}`))
	}
}

const jsonOK = `{"id":"x","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`

func answerJSON(w http.ResponseWriter, _ int) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(jsonOK))
}

const sseCreated = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"PRIVATE_ID\"}}\n\n"
const sseLimit = "event: error\ndata: {\"type\":\"error\",\"error\":{\"code\":\"rate_limit_exceeded\",\"message\":\"PRIVATE BODY\"}}\n\n"
const sseText = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n"
const sseDone = "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":1,\"total_tokens\":6}}}\n\n"

func answerSSE(raw string) func(http.ResponseWriter, int) {
	return func(w http.ResponseWriter, _ int) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, raw)
	}
}

const chatBody = `{"model":"fixture","messages":[{"role":"user","content":"PRIVATE PROMPT"}]}`
const responsesBody = `{"model":"fixture","input":[{"role":"user","content":"PRIVATE PROMPT"}],"stream":true,"store":false}`

func TestM21HTTP429RetriesSameBody(t *testing.T) {
	f := newRetryFixture(t, false, refuse429(""), refuse429(""), answerJSON)
	w := f.serve(chatBody)
	if w.Code != 200 || w.Body.String() != jsonOK {
		t.Fatalf("relay after retries: %d %s", w.Code, w.Body.String())
	}
	if f.calls.Load() != 3 {
		t.Fatalf("dispatches %d, want 3", f.calls.Load())
	}
	// The same body every time: no regeneration, no mutation.
	for i := 1; i < len(f.bodies); i++ {
		if !bytes.Equal(f.bodies[i], f.bodies[0]) {
			t.Fatal("retry body differs from the original")
		}
	}
	// The waits followed the (shortened) table: 5ms then 10ms.
	if len(f.slept) != 2 || f.slept[0] != 5*time.Millisecond || f.slept[1] != 10*time.Millisecond {
		t.Fatalf("waits %v", f.slept)
	}
	if w.Header().Get("X-Newtype-Model-Retry") != "" {
		t.Fatal("successful relay carried the exhausted marker")
	}
	state := f.execution(w)
	if state.Status != "completed" {
		t.Fatalf("settlement: %+v", state)
	}
	// Refused dispatches are charged at the input estimate, never assumed free.
	if state.Charged <= 6 {
		t.Fatalf("refused dispatches not charged: %+v", state)
	}
}

func TestM21PreOutputRateLimitRetries(t *testing.T) {
	f := newRetryFixture(t, true, answerSSE(sseCreated+sseLimit), answerSSE(sseCreated+sseText+sseDone))
	w := f.serve(responsesBody)
	if w.Code != 200 || w.Body.String() != sseCreated+sseText+sseDone {
		t.Fatalf("second stream not relayed exactly once: %d %q", w.Code, w.Body.String())
	}
	if f.calls.Load() != 2 {
		t.Fatalf("dispatches %d, want 2", f.calls.Load())
	}
	if strings.Contains(w.Body.String(), "rate_limit_exceeded") {
		t.Fatal("refused prefix leaked into the relayed answer")
	}
	if state := f.execution(w); state.Status != "completed" {
		t.Fatalf("settlement: %+v", state)
	}
	if !strings.Contains(f.logs.String(), `"outcome":"dispatched"`) || !strings.Contains(f.logs.String(), `"retries":1`) {
		t.Fatalf("retry not logged: %s", f.logs.String())
	}
}

func TestM21PartialOutputNeverReplays(t *testing.T) {
	for name, first := range map[string]string{
		"text":      sseText,
		"tool":      "data: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"{\"}\n\n",
		"reasoning": "data: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"...\"}\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			raw := sseCreated + first + sseLimit
			f := newRetryFixture(t, true, answerSSE(raw), answerSSE(sseCreated+sseText+sseDone))
			w := f.serve(responsesBody)
			if w.Code != 200 || w.Body.String() != raw {
				t.Fatalf("stream with output not relayed as it came: %d %q", w.Code, w.Body.String())
			}
			if f.calls.Load() != 1 {
				t.Fatalf("replayed after output: %d dispatches", f.calls.Load())
			}
			if w.Header().Get("X-Newtype-Model-Retry") != "" {
				t.Fatal("output stream marked as exhausted rate limit")
			}
			if state := f.execution(w); state.Status != "failed" {
				t.Fatalf("failed stream settled as %+v", state)
			}
		})
	}
	// After the first byte reached the client nothing is replayed either: a
	// stream that fails late is relayed and settled failed, one dispatch.
	f := newRetryFixture(t, true, answerSSE(sseCreated+sseText+sseLimit))
	w := f.serve(responsesBody)
	if f.calls.Load() != 1 || w.Code != 200 {
		t.Fatal("late failure replayed")
	}
}

func TestM21RetryRechecksAuthorityAndCallBudget(t *testing.T) {
	t.Run("revoked during wait", func(t *testing.T) {
		f := newRetryFixture(t, false, refuse429(""), answerJSON)
		f.handler.retry.sleep = func(ctx context.Context, d time.Duration) error {
			// The owner revokes the delegation while the gateway waits.
			if _, err := f.svc.Revoke(context.Background(), f.user, f.root.Delegation.ID, "revoked during retry wait"); err != nil {
				t.Error(err)
			}
			return nil
		}
		w := f.serve(chatBody)
		if f.calls.Load() != 1 {
			t.Fatalf("re-dispatched without live authority: %d", f.calls.Load())
		}
		if w.Code != 401 && w.Code != 403 {
			t.Fatalf("revoked turn answered %d", w.Code)
		}
	})
	t.Run("call budget per dispatch", func(t *testing.T) {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, "calls.jsonl")
		if err := InitializeModelCallBudget(file, ModelCallBudgetHeader{1, "fixture", 1, time.Now().UTC().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		f := newRetryFixture(t, false, refuse429(""), answerJSON)
		f.handler.cfg.CallBudgetFile = file
		w := f.serve(chatBody)
		if f.calls.Load() != 1 {
			t.Fatalf("second dispatch bypassed the call budget: %d", f.calls.Load())
		}
		if w.Code != 403 || !strings.Contains(w.Body.String(), "model_call_budget_unavailable") {
			t.Fatalf("budget exhaustion answered %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("cancelled during wait", func(t *testing.T) {
		f := newRetryFixture(t, false, refuse429(""), answerJSON)
		ctx, cancel := context.WithCancel(context.Background())
		f.handler.retry.sleep = func(c context.Context, d time.Duration) error { cancel(); return c.Err() }
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, f.request(chatBody).WithContext(ctx))
		if f.calls.Load() != 1 {
			t.Fatalf("re-dispatched after cancellation: %d", f.calls.Load())
		}
		if state := f.execution(w); state.Status == "completed" {
			t.Fatalf("cancelled turn settled completed: %+v", state)
		}
	})
	t.Run("expired reservation basis", func(t *testing.T) {
		// A body so large that a second dispatch would not fit under the
		// reservation: the refusal is relayed instead of retried.
		f := newRetryFixture(t, false, refuse429(""), answerJSON)
		// Budget 20000 − MaxOutput 100 − margin 1024 = 18876 bytes for inputs; one
		// dispatch of ~9.7KB fits admission, two do not.
		big := `{"model":"fixture","messages":[{"role":"user","content":"` + strings.Repeat("P", 9600) + `"}]}`
		w := f.serve(big)
		if f.calls.Load() != 1 || w.Code != 429 {
			t.Fatalf("retried without reservation basis: calls=%d code=%d", f.calls.Load(), w.Code)
		}
	})
}

func TestM21InvocationSettlesOnce(t *testing.T) {
	f := newRetryFixture(t, false, refuse429(""), refuse429(""), answerJSON)
	w := f.serve(chatBody)
	if f.calls.Load() != 3 || w.Code != 200 {
		t.Fatalf("calls=%d code=%d", f.calls.Load(), w.Code)
	}
	invocation := w.Header().Get("X-Newtype-Invocation")
	if len(w.Header().Values("X-Newtype-Invocation")) != 1 || invocation == "" {
		t.Fatal("invocation header")
	}
	// One invocation, settled once, completed: the ledger has one start and
	// one settlement for it, three upstream dispatches notwithstanding.
	events, _, err := f.svc.Events(context.Background(), f.user, f.root.Session.ID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	starts, settles := 0, 0
	for _, e := range events {
		if strings.Contains(string(e.Payload), invocation) {
			switch {
			case strings.Contains(e.Kind, "start"):
				starts++
			case strings.Contains(e.Kind, "settle") || strings.Contains(e.Kind, "complete"):
				settles++
			}
		}
	}
	if starts > 1 || settles > 1 {
		t.Fatalf("invocation accounted more than once: starts=%d settles=%d", starts, settles)
	}
	// Budget exhausted on refusals: the final refusal is relayed, settled failed
	// (never completed), still one invocation.
	g := newRetryFixture(t, false, refuse429(""))
	w = g.serve(chatBody)
	if w.Code != 429 || g.calls.Load() != 5 { // 1 + 4 retries
		t.Fatalf("exhausted ladder: code=%d calls=%d", w.Code, g.calls.Load())
	}
	if state := g.execution(w); state.Status == "completed" {
		t.Fatalf("relayed refusal settled completed: %+v", state)
	}
	if w.Header().Get("X-Newtype-Model-Retry") != "exhausted" {
		t.Fatal("final refusal lacks the exhausted marker")
	}
	if !strings.Contains(g.logs.String(), `"outcome":"rate_limited"`) || !strings.Contains(g.logs.String(), `"retries":4`) {
		t.Fatalf("exhaustion not logged: %s", g.logs.String())
	}
}

func TestM21FinalRateLimitDoesNotMultiplyCoreRetries(t *testing.T) {
	// Gate side: when its budget is spent the refusal carries the marker and
	// the upstream Retry-After, so a client can tell "already waited" from a
	// fresh refusal. (The core side of the same name lives in package core.)
	f := newRetryFixture(t, false, refuse429("7"))
	f.handler.retry.budget = 0 // nothing may be waited: relay at once
	w := f.serve(chatBody)
	if w.Code != 429 || f.calls.Load() != 1 || w.Header().Get("X-Newtype-Model-Retry") != "exhausted" || w.Header().Get("Retry-After") != "7" {
		t.Fatalf("final refusal shape: code=%d calls=%d headers=%v", w.Code, f.calls.Load(), w.Header())
	}
	if strings.Contains(w.Body.String(), "PRIVATE") {
		t.Fatal("upstream body leaked")
	}
	// A Retry-After longer than the remaining budget is never retried early.
	g := newRetryFixture(t, false, refuse429("3600"), answerJSON)
	w = g.serve(chatBody)
	if w.Code != 429 || g.calls.Load() != 1 || len(g.slept) != 0 {
		t.Fatalf("retried earlier than Retry-After: code=%d calls=%d slept=%v", w.Code, g.calls.Load(), g.slept)
	}
}

func TestM21NonstreamAndOriginalBytesPreserved(t *testing.T) {
	// Non-stream JSON: no peeking, 429 retried, final JSON bytes exact.
	f := newRetryFixture(t, false, refuse429(""), answerJSON)
	w := f.serve(chatBody)
	if w.Code != 200 || w.Body.String() != jsonOK || f.calls.Load() != 2 {
		t.Fatalf("json relay: %d %q calls=%d", w.Code, w.Body.String(), f.calls.Load())
	}
	// A JSON body that merely mentions rate limits is not a refusal.
	g := newRetryFixture(t, false, func(w http.ResponseWriter, _ int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"rate_limit_exceeded"}}],"usage":{"total_tokens":3}}`))
	})
	if w := g.serve(chatBody); w.Code != 200 || g.calls.Load() != 1 {
		t.Fatal("json answer mistaken for a refusal")
	}
	// SSE that fails for another reason before output: relayed byte-exact,
	// once, not retried, settled failed.
	failed := sseCreated + "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"server_error\",\"message\":\"PRIVATE\"}}}\n\n"
	h := newRetryFixture(t, true, answerSSE(failed), answerSSE(sseCreated+sseText+sseDone))
	w = h.serve(responsesBody)
	if w.Code != 200 || w.Body.String() != failed || h.calls.Load() != 1 {
		t.Fatalf("failed stream altered: %d %q calls=%d", w.Code, w.Body.String(), h.calls.Load())
	}
	// A long opening (beyond the peek bound) is relayed intact.
	long := strings.Repeat("data: {\"type\":\"response.in_progress\"}\n\n", modelPeekMax/40+10) + sseText + sseDone
	k := newRetryFixture(t, true, answerSSE(long))
	w = k.serve(responsesBody)
	if w.Code != 200 || w.Body.String() != long || k.calls.Load() != 1 {
		t.Fatalf("long prefix altered: len=%d/%d calls=%d", w.Body.Len(), len(long), k.calls.Load())
	}
	// Exhausted SSE refusal: relayed as it came, with the marker.
	m := newRetryFixture(t, true, answerSSE(sseCreated+sseLimit))
	w = m.serve(responsesBody)
	if w.Code != 200 || w.Body.String() != sseCreated+sseLimit || m.calls.Load() != 5 || w.Header().Get("X-Newtype-Model-Retry") != "exhausted" {
		t.Fatalf("exhausted SSE refusal: %d %q calls=%d", w.Code, w.Body.String(), m.calls.Load())
	}
}

func TestM21RetryLogsContainNoSecrets(t *testing.T) {
	f := newRetryFixture(t, true, answerSSE(sseCreated+sseLimit), answerSSE(sseCreated+sseText+sseDone))
	w := f.serve(responsesBody)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	text := f.logs.String()
	for _, secret := range []string{"PRIVATE", "PROMPT", "ntl_", "ntg_", f.upstream.URL, string(f.root.Session.ID), string(f.root.Delegation.ID), "Bearer"} {
		if strings.Contains(text, secret) {
			t.Fatalf("log contains %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, `"retries":1`) || !strings.Contains(text, `"waited":"`) || !strings.Contains(text, `"outcome":"dispatched"`) {
		t.Fatalf("log lacks the fixed fields: %s", text)
	}
	g := newRetryFixture(t, false, refuse429("2"))
	g.serve(chatBody)
	text = g.logs.String()
	if strings.Contains(text, "PRIVATE") || !strings.Contains(text, `"outcome":"rate_limited"`) {
		t.Fatalf("exhaustion log: %s", text)
	}
}
