// Package gate implements the installation and licence gateway.
package gate

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/redact"
)

const (
	AuditQueueSize    = 1024
	AuditDropInterval = 10 * time.Second
)

// AuditEstablished contains only identity established by authentication and
// outcomes measured by the server. Never populate it from request JSON.
type AuditEstablished struct {
	AccountID    string `json:"account_id,omitempty"`
	Email        string `json:"email,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	SourceIP     string `json:"source_ip,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	HubSessionID string `json:"hub_session_id,omitempty"`
	ModelTokens  int64  `json:"model_tokens,omitempty"`
}

// AuditAsserted is caller-supplied metadata, not proof of identity.
type AuditAsserted struct {
	SessionID      string `json:"session_id,omitempty"`
	Seq            int64  `json:"seq,omitempty"`
	CLIVersion     string `json:"cli_version,omitempty"`
	Tool           string `json:"tool,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	Agent          string `json:"agent,omitempty"`
	AgentSessionID string `json:"agent_session_id,omitempty"`
	SessionName    string `json:"session_name,omitempty"`
}

// AuditEvent deliberately has no prompt, request body, headers, credentials,
// verification link or arbitrary payload field. Values must not contain secrets;
// the writer also redacts recognizable tokens as defense in depth.
type AuditEvent struct {
	EventID     string           `json:"event_id"`
	RequestID   string           `json:"request_id,omitempty"`
	Type        string           `json:"type"`
	At          time.Time        `json:"at"`
	Established AuditEstablished `json:"established"`
	Asserted    AuditAsserted    `json:"asserted"`
	Dropped     uint64           `json:"dropped,omitempty"`
}

var ErrAuditOutput = errors.New("gate: audit output failed")

// Audit serializes JSON lines to a single writer. Write never waits for output;
// a full queue drops the event instead. Close drains accepted events and waits
// for the output writer, which must therefore have bounded blocking behavior.
// The output writer is owned by the caller and is not closed by Audit.
type Audit struct {
	mu      sync.Mutex // protects both channel sends and channel closure
	closed  bool
	queue   chan AuditEvent
	done    chan struct{}
	dropped atomic.Uint64
	err     error // published by closing done
}

func NewAudit(output io.Writer) (*Audit, error) {
	if output == nil {
		return nil, errors.New("gate: audit output required")
	}
	a := &Audit{queue: make(chan AuditEvent, AuditQueueSize), done: make(chan struct{})}
	go a.run(output)
	return a, nil
}

// Write copies an event into the queue. EventID and At are assigned by the
// server, never trusted from a caller. False means full or already closed.
func (a *Audit) Write(event AuditEvent) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false
	}
	event.EventID = ids.New(ids.KindAudit)
	event.At = time.Now().UTC()
	event.Dropped = 0 // only the writer emits loss counters
	select {
	case a.queue <- event:
		return true
	default:
		a.dropped.Add(1)
		return false
	}
}

// Dropped is the cumulative count for /v1/health, including output failures.
// Calls after Close are rejected, not counted as running-service losses.
func (a *Audit) Dropped() uint64 { return a.dropped.Load() }

// Close is concurrent-safe and idempotent. Output errors are deliberately
// generic: arbitrary writer errors might contain credentials or event bodies.
func (a *Audit) Close() error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.queue)
	}
	a.mu.Unlock()
	<-a.done
	return a.err
}

func (a *Audit) run(output io.Writer) {
	ticker := time.NewTicker(AuditDropInterval)
	defer ticker.Stop()
	defer close(a.done)
	var reported uint64
	for {
		select {
		case event, ok := <-a.queue:
			if !ok {
				a.reportDrops(output, &reported)
				return
			}
			if !a.emit(output, event) {
				a.dropped.Add(1)
			}
		case <-ticker.C:
			a.reportDrops(output, &reported)
		}
	}
}

func (a *Audit) reportDrops(output io.Writer, reported *uint64) {
	total := a.Dropped()
	if total == *reported {
		return
	}
	if a.emit(output, AuditEvent{
		EventID: ids.New(ids.KindAudit), Type: "audit_dropped", At: time.Now().UTC(),
		Dropped: total - *reported,
	}) {
		*reported = total
	}
}

func (a *Audit) emit(output io.Writer, event AuditEvent) bool {
	data, err := json.Marshal(event)
	if err == nil {
		data, _, err = redact.JSON(data)
	}
	if err == nil {
		data = append(data, '\n')
		var n int
		n, err = output.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		a.err = ErrAuditOutput
		return false
	}
	return true
}
