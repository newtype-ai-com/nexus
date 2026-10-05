package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// timingLines returns every "model relay timing" record in the JSON log.
func timingLines(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(logs.Bytes(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if rec["msg"] == "model relay timing" {
			out = append(out, rec)
		}
	}
	return out
}

func msField(t *testing.T, rec map[string]any, key string) float64 {
	t.Helper()
	v, ok := rec[key].(float64)
	if !ok {
		t.Fatalf("timing field %s missing: %v", key, rec)
	}
	return v
}

func TestModelTimingStreamUpstreamDelay(t *testing.T) {
	const head, tail = 150 * time.Millisecond, 100 * time.Millisecond
	f := newRetryFixture(t, true, func(w http.ResponseWriter, _ int) {
		time.Sleep(head)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sseCreated+sseText)
		w.(http.Flusher).Flush()
		time.Sleep(tail)
		_, _ = io.WriteString(w, sseDone)
	})
	r := f.request(responsesBody)
	r = r.WithContext(withPublicTiming(r.Context(), publicTiming{start: time.Now().Add(-40 * time.Millisecond), admission: 30 * time.Millisecond}))
	w := &bytes.Buffer{}
	rec := newRecorder(w)
	f.handler.ServeHTTP(rec, r)
	if rec.code != 200 {
		t.Fatal(rec.code)
	}
	lines := timingLines(t, &f.logs)
	if len(lines) != 1 {
		t.Fatalf("want one timing line, got %d: %s", len(lines), f.logs.String())
	}
	l := lines[0]
	if fb := msField(t, l, "upstream_first_byte"); fb < float64(head.Milliseconds()) {
		t.Fatalf("upstream_first_byte %v < %v", fb, head)
	}
	if tot := msField(t, l, "upstream_total"); tot < float64((head + tail).Milliseconds()) {
		t.Fatalf("upstream_total %v < %v", tot, head+tail)
	}
	if a := msField(t, l, "admission_db"); a != 30 {
		t.Fatalf("admission_db %v, want 30 from the request context", a)
	}
	if total := msField(t, l, "total"); total < float64((head + tail + 40*time.Millisecond).Milliseconds()) {
		t.Fatalf("total %v does not start at request entry", total)
	}
	for _, k := range []string{"auth_db", "prepare_db", "budget_check", "pace_wait", "settle_db"} {
		if msField(t, l, k) < 0 {
			t.Fatalf("%s negative: %v", k, l)
		}
	}
	if l["model"] != "fixture" || l["protocol"] != "responses" || l["stream"] != true || l["status"] != float64(200) || l["outcome"] != "completed" || l["retries"] != float64(0) || l["owner"] != false || l["tokens_total"] != float64(6) {
		t.Fatalf("labels: %v", l)
	}
}

func TestModelTimingJSONUpstreamDelay(t *testing.T) {
	const delay = 120 * time.Millisecond
	f := newRetryFixture(t, false, func(w http.ResponseWriter, n int) {
		time.Sleep(delay)
		answerJSON(w, n)
	})
	if w := f.serve(chatBody); w.Code != 200 {
		t.Fatal(w.Code)
	}
	lines := timingLines(t, &f.logs)
	if len(lines) != 1 {
		t.Fatalf("lines: %s", f.logs.String())
	}
	l := lines[0]
	if msField(t, l, "upstream_first_byte") < float64(delay.Milliseconds()) || msField(t, l, "upstream_total") < float64(delay.Milliseconds()) {
		t.Fatalf("upstream fields below the upstream delay: %v", l)
	}
	if msField(t, l, "admission_db") != -1 || l["stream"] != false || l["protocol"] != "chat/completions" {
		t.Fatalf("labels: %v", l)
	}
}

func TestModelTimingFailureAndRetryLogged(t *testing.T) {
	// Retries past one refusal: pace_wait covers the retry sleep.
	f := newRetryFixture(t, false, refuse429(""), answerJSON)
	if w := f.serve(chatBody); w.Code != 200 {
		t.Fatal(w.Code)
	}
	l := timingLines(t, &f.logs)
	if len(l) != 1 || l[0]["retries"] != float64(1) || msField(t, l[0], "pace_wait") < 5 {
		t.Fatalf("retry timing: %s", f.logs.String())
	}
	// A refusal relayed after the retry budget is still one line, as a failure.
	g := newRetryFixture(t, false, refuse429("2"))
	if w := g.serve(chatBody); w.Code != 429 {
		t.Fatal(w.Code)
	}
	l = timingLines(t, &g.logs)
	if len(l) != 1 || l[0]["status"] != float64(429) || l[0]["outcome"] != "failed" {
		t.Fatalf("failure timing: %s", g.logs.String())
	}
	// Rejected before any execution (bad credentials): one line, no secrets.
	h := newRetryFixture(t, false, answerJSON)
	r := h.request(chatBody)
	r.Header.Set("Authorization", "Bearer ntl_"+strings.Repeat("z", 64))
	rec := newRecorder(&bytes.Buffer{})
	h.handler.ServeHTTP(rec, r)
	l = timingLines(t, &h.logs)
	if rec.code != 401 || len(l) != 1 || l[0]["status"] != float64(401) || l[0]["outcome"] != "rejected" {
		t.Fatalf("rejection timing: %d %s", rec.code, h.logs.String())
	}
}

func TestModelTimingLogsNoSecrets(t *testing.T) {
	f := newRetryFixture(t, true, answerSSE(sseCreated+sseLimit), answerSSE(sseCreated+sseText+sseDone))
	if w := f.serve(responsesBody); w.Code != 200 {
		t.Fatal(w.Code)
	}
	g := newRetryFixture(t, false, answerJSON)
	if w := g.serve(chatBody); w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, fx := range []*retryFixture{f, g} {
		text := fx.logs.String()
		if len(timingLines(t, &fx.logs)) != 1 {
			t.Fatalf("no timing line: %s", text)
		}
		for _, secret := range []string{fx.key, fx.login, "ntl_", "ntg_", "PRIVATE", "PROMPT", "hello", "Bearer", fx.upstream.URL, fx.user.Email, string(fx.user.AccountID), string(fx.root.Session.ID), string(fx.root.Delegation.ID)} {
			if strings.Contains(text, secret) {
				t.Fatalf("timing log contains %q: %s", secret, text)
			}
		}
	}
}

// recorder is a minimal flushable ResponseWriter that is not an
// httptest.ResponseRecorder, so the relay's status capture is exercised.
type recorder struct {
	h    http.Header
	body *bytes.Buffer
	code int
}

func newRecorder(b *bytes.Buffer) *recorder { return &recorder{h: http.Header{}, body: b} }
func (r *recorder) Header() http.Header     { return r.h }
func (r *recorder) WriteHeader(c int) {
	if r.code == 0 {
		r.code = c
	}
}
func (r *recorder) Write(p []byte) (int, error) {
	if r.code == 0 {
		r.code = 200
	}
	return r.body.Write(p)
}
func (r *recorder) Flush() {}
