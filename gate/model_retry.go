package gate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/internal/modelerror"
	"github.com/newtype-ai-com/nexus/internal/streamprogress"
)

// M21 — when the upstream refuses a turn for its rate limit BEFORE any
// output, the gateway waits and sends the same body again instead of handing
// the refusal to a client that would retry in 2 and 4 seconds and make the
// minute worse. The pacing design (peekStream/retryWait/Pacing) is checked
// here against Newtype's own accounting and authority contracts.
//
// What never retries: anything after the first byte of model output (text,
// tool call, reasoning), anything after the downstream header was committed,
// transport failures, 5xx, authentication refusals, malformed or ambiguous
// streams, oversized prefixes, EOF. A retry is the same request body to the
// same upstream; it is not a new reservation and not a new invocation.

// Host-fixed defaults: four more tries at 5/10/20/40s, 90s of waiting in all
// for one turn (shared-hold waiting included). A model argument cannot change
// them; tests inject smaller values through retryPolicy fields.
var modelRetryWaits = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second}

const modelRetryBudget = 90 * time.Second

// modelPeekMax bounds how much of a stream is read before deciding: the
// Responses API echoes the request in its opening events, so a refusal can sit
// behind tens of kilobytes. Beyond this the stream is relayed as it is.
const modelPeekMax = 512 << 10

// modelPeekLine bounds one SSE line while peeking; a longer line is not a
// refusal we can read, so it is relayed, never retried.
const modelPeekLine = 64 << 10

// retryAfterMax caps a Retry-After we will believe; anything longer is "do
// not retry within this turn's budget".
const retryAfterMax = 24 * time.Hour

type retryPolicy struct {
	waits  []time.Duration
	budget time.Duration
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
}

func defaultRetryPolicy() retryPolicy {
	return retryPolicy{waits: modelRetryWaits, budget: modelRetryBudget, now: time.Now, sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// wait is how long to wait before retry number n (0-based) when `waited` has
// been spent so far, and whether to retry at all. A Retry-After longer than
// the table's wait replaces it; one that does not fit in the remaining budget
// ends retrying — we never retry EARLIER than the upstream asked.
func (p retryPolicy) wait(n int, waited, after time.Duration) (time.Duration, bool) {
	if n < 0 || n >= len(p.waits) {
		return 0, false
	}
	wait := p.waits[n]
	if after > wait {
		wait = after
	}
	if wait <= 0 || waited+wait > p.budget {
		return 0, false
	}
	return wait, true
}

// parseRetryAfter reads a Retry-After header as delta-seconds or an HTTP-date.
// Absent, negative, zero, non-numeric, overflowing or absurd values yield
// (0,false): the caller then uses its own table. It never trusts the header
// for more than retryAfterMax.
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false
	}
	if strings.Trim(h, "0123456789") == "" && (len(h) > 18) {
		return retryAfterMax, true // positive numeric overflow is a long hint
	}
	if len(h) > 64 {
		return 0, false
	}
	if n, err := strconv.ParseInt(h, 10, 64); err == nil {
		if n <= 0 {
			return 0, false
		}
		if n > int64(retryAfterMax/time.Second) {
			return retryAfterMax, true // beyond every retry budget: never retry early
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(h); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			return 0, false
		}
		if d > retryAfterMax {
			return retryAfterMax, true
		}
		return d, true
	}
	return 0, false
}

// pacing is the gateway's hold on turns while the upstream refuses them: a
// refusal says the quota window is spent, and more turns in it only fail too.
// One pacing per ModelHandler, i.e. per (upstream, credential) quota domain.
// It is process-local: several Gate processes do not share it (documented).
type pacing struct {
	mu    sync.Mutex
	until time.Time
}

// hold keeps turns waiting until now+d, if that is later than they already
// wait. Holds only ever move later; nothing here grows a queue.
// reset drops the hold when the quota domain (upstream + credential) changes.
func (p *pacing) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.until = time.Time{}
}

func (p *pacing) hold(now time.Time, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if until := now.Add(d); until.After(p.until) {
		p.until = until
	}
}

// errHoldExceedsBudget says the shared hold reaches past what this request may
// still wait: the request must not wait and must relay its refusal instead.
var errHoldExceedsBudget = errors.New("gate: rate-limit hold exceeds this request's budget")

// wait returns when the hold has passed, re-reading it after every sleep so an
// extension taken while waiting is honoured (no busy loop: each sleep is for
// the remaining hold). It never waits past deadline — then it fails with
// errHoldExceedsBudget — and it is cancellable through ctx.
func (p *pacing) wait(ctx context.Context, pol retryPolicy, deadline time.Time) (time.Duration, error) {
	var slept time.Duration
	for {
		p.mu.Lock()
		until := p.until
		p.mu.Unlock()
		now := pol.now()
		d := until.Sub(now)
		if d <= 0 {
			return slept, nil
		}
		if until.After(deadline) {
			return slept, errHoldExceedsBudget
		}
		if err := pol.sleep(ctx, d); err != nil {
			return slept, err
		}
		slept += d
	}
}

// peekVerdict is what the start of a stream turned out to be.
type peekVerdict string

const (
	peekLimited   peekVerdict = "rate_limited" // exact rate_limit_exceeded before any output: may retry
	peekFailed    peekVerdict = "failed"       // another refusal before output: relay, do not retry
	peekOutput    peekVerdict = "output"       // model output began (or stream ended): relay
	peekAmbiguous peekVerdict = "ambiguous"    // malformed/oversized/conflicting: relay, do not retry
)

// peekStream reads the start of an SSE model stream, in bounded lines and
// bounded total, until it can say whether the upstream refused the turn for
// its rate limit before producing anything. It returns exactly the bytes it
// consumed (to be relayed first, once) and a reader for the rest. alive is
// called on every byte so the stall watch sees reading as activity; whether
// a frame counts as progress stays the watch's own judgement.
func peekStream(src io.Reader, alive func([]byte)) (prefix []byte, rest io.Reader, verdict peekVerdict) {
	br := bufio.NewReaderSize(io.LimitReader(src, modelPeekMax), modelPeekLine)
	// Preserve buffered bytes and continue the original stream after the cap.
	remainder := io.MultiReader(br, src)
	var buf bytes.Buffer
	var frame sseFrame
	for buf.Len() < modelPeekMax {
		line, err := br.ReadSlice('\n')
		buf.Write(line)
		if alive != nil {
			alive(line)
		}
		if buf.Len() >= modelPeekMax || errors.Is(err, bufio.ErrBufferFull) {
			// A line longer than the peek limit: not a refusal we can read.
			return buf.Bytes(), remainder, peekAmbiguous
		}
		if err != nil {
			// Even a complete-looking error frame accompanied by EOF/read failure
			// cannot authorize replay of an uncertain transport outcome.
			return buf.Bytes(), remainder, peekOutput
		}
		done, v := frame.feed(bytes.TrimRight(line, "\r\n"))
		if done {
			switch v {
			case peekLimited, peekFailed, peekOutput, peekAmbiguous:
				return buf.Bytes(), remainder, v
			}
			// "" means: not yet known (created/in_progress/keepalive); go on.
		}
		if err != nil {
			return buf.Bytes(), remainder, peekOutput
		}
	}
	return buf.Bytes(), remainder, peekAmbiguous
}

// sseFrame accumulates one event (until the blank line) and classifies it.
type sseFrame struct {
	event    string
	data     [][]byte
	comments int
	size     int
}

// feed takes one line without its terminator. It returns done=true at a
// frame boundary with the frame's verdict ("" = undecided), and resets.
func (f *sseFrame) feed(line []byte) (done bool, v peekVerdict) {
	if len(line) == 0 {
		if len(f.data) == 0 && f.event == "" {
			f.reset()
			return false, "" // stray blank line / comment-only frame (keepalive): undecided
		}
		v = f.classify()
		f.reset()
		return true, v
	}
	if line[0] == ':' {
		f.comments++
		return false, ""
	}
	key, value, _ := bytes.Cut(line, []byte(":"))
	value = bytes.TrimPrefix(value, []byte(" "))
	switch string(key) {
	case "event":
		if f.event != "" && f.event != string(value) {
			f.event = "\x00conflict"
		} else {
			f.event = string(value)
		}
	case "data":
		f.size += len(value) + 1
		if f.size > modelerror.MaxEnvelope {
			f.event, f.data = "\x00oversize", nil
			return false, ""
		}
		f.data = append(f.data, value)
	}
	return false, ""
}

func (f *sseFrame) reset() { *f = sseFrame{} }

// classify decides one complete frame.
func (f *sseFrame) classify() peekVerdict {
	switch f.event {
	case "\x00conflict", "\x00oversize":
		return peekAmbiguous
	}
	data := bytes.Join(f.data, []byte("\n"))
	if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
		return peekOutput
	}
	typ, keys, ok := sseEventType(data)
	if !ok {
		return peekAmbiguous
	}
	if f.event != "" && typ != "" && f.event != typ {
		return peekAmbiguous
	}
	if typ == "" && f.event != "" && f.event != "error" && f.event != "response.failed" {
		return peekOutput
	}
	// Output wins even when an error or lifecycle event shares the envelope.
	for _, key := range []string{"choices", "delta", "text", "content", "tool_calls", "arguments", "reasoning", "output"} {
		if keys[key] {
			return peekOutput
		}
	}
	var envelope struct {
		Response struct {
			Output json.RawMessage `json:"output"`
		} `json:"response"`
	}
	_ = json.Unmarshal(data, &envelope)
	if out := bytes.TrimSpace(envelope.Response.Output); len(out) != 0 && !bytes.Equal(out, []byte("[]")) && !bytes.Equal(out, []byte("null")) {
		return peekOutput
	}
	isErrorEvent := f.event == "error" || f.event == "response.failed" || typ == "error" || typ == "response.failed" || (typ == "" && keys["error"] && !keys["choices"])
	if isErrorEvent {
		if f.event != "" && f.event != "error" && f.event != "response.failed" && typ != "" && typ != f.event {
			return peekAmbiguous // header and body disagree about what this is
		}
		if !modelerror.IsEvent(data, f.event) && typ != "error" && typ != "response.failed" {
			return peekAmbiguous
		}
		d := modelerror.Parse(data)
		if d.Code == "rate_limit_exceeded" && d.Transient {
			return peekLimited
		}
		return peekFailed
	}
	switch {
	case typ == "" && keys["choices"]:
		return peekOutput // chat/completions chunk: output began
	case typ == "" && len(keys) == 0:
		return peekAmbiguous
	case typ == "response.created" || typ == "response.queued" || typ == "response.in_progress" || streamprogress.KeepAliveEvent(typ):
		return "" // not yet known
	default:
		return peekOutput // any other typed event is output or the end
	}
}

// sseEventType extracts the top-level "type" (if any) and the set of top-level
// keys from one JSON object, without decoding values. ok=false for anything
// that is not a JSON object.
func sseEventType(data []byte) (typ string, keys map[string]bool, ok bool) {
	if !strictRetryJSON(data) {
		return "", nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return "", nil, false
	}
	keys = map[string]bool{}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return "", nil, false
		}
		name, _ := k.(string)
		if keys[name] {
			return "", nil, false // duplicate key: ambiguous
		}
		keys[name] = true
		if name == "type" {
			v, err := dec.Token()
			if err != nil {
				return "", nil, false
			}
			s, isString := v.(string)
			if !isString {
				return "", nil, false
			}
			typ = s
			continue
		}
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return "", nil, false
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return "", nil, false
	}
	return typ, keys, true
}
