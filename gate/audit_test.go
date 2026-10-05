package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

func auditEvents(t *testing.T, data []byte) []AuditEvent {
	t.Helper()
	var events []AuditEvent
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var event AuditEvent
		if err := decoder.Decode(&event); err == io.EOF {
			return events
		} else if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
}

func TestAuditIdentityAndRedaction(t *testing.T) {
	var output bytes.Buffer
	a, err := NewAudit(&output)
	if err != nil {
		t.Fatal(err)
	}
	secret := "ntl_" + strings.Repeat("a", 48)
	before := time.Now()
	if !a.Write(AuditEvent{
		EventID: "caller-controlled", Type: "validate", Dropped: 99,
		Established: AuditEstablished{AccountID: "authenticated-account", SessionID: "login", ModelTokens: 9007199254740993},
		Asserted:    AuditAsserted{SessionID: "claimed-process", UserAgent: secret},
	}) {
		t.Fatal("event rejected")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	events := auditEvents(t, output.Bytes())
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	e := events[0]
	if ids.Check(ids.KindAudit, e.EventID) != nil || e.At.Before(before) || e.At.After(time.Now()) || e.Dropped != 0 {
		t.Fatalf("invalid server metadata: %+v", e)
	}
	if e.Established.AccountID != "authenticated-account" || e.Established.SessionID != "login" || e.Asserted.SessionID != "claimed-process" || e.Established.ModelTokens != 9007199254740993 {
		t.Fatal("identity separation or exact integer lost")
	}
	if strings.Contains(output.String(), secret) || e.Asserted.UserAgent != "[secret:nts_licence]" {
		t.Fatal("recognizable token not redacted")
	}
	if a.Write(AuditEvent{Type: "after_close"}) || a.Dropped() != 0 {
		t.Fatal("closed audit accepted write or changed loss count")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

type blockedAuditWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	output  bytes.Buffer
}

func (w *blockedAuditWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return w.output.Write(p)
}

func TestAuditFullQueueNeverWaitsForOutput(t *testing.T) {
	w := &blockedAuditWriter{started: make(chan struct{}), release: make(chan struct{})}
	a, err := NewAudit(w)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(w.release)
		if err := a.Close(); err != nil {
			t.Error(err)
		}
		events := auditEvents(t, w.output.Bytes())
		if len(events) != AuditQueueSize+2 {
			t.Fatalf("queue not drained with final loss report: %d events", len(events))
		}
		last := events[len(events)-1]
		if last.Type != "audit_dropped" || last.Dropped != 7 {
			t.Fatalf("missing final loss report: %+v", last)
		}
	}()
	a.Write(AuditEvent{Type: "first"})
	select {
	case <-w.started:
	case <-time.After(5 * time.Second):
		t.Fatal("output never started")
	}
	finished := make(chan struct{})
	var accepted int
	go func() {
		defer close(finished)
		for i := 0; i < AuditQueueSize+7; i++ {
			if a.Write(AuditEvent{Type: "queued"}) {
				accepted++
			}
		}
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked on output")
	}
	if accepted != AuditQueueSize || a.Dropped() != 7 {
		t.Fatalf("accepted=%d dropped=%d", accepted, a.Dropped())
	}
}

func TestAuditDropReportsRetryAndDelta(t *testing.T) {
	// Exercise the timer's reporting operation without a real ten-second sleep.
	a := &Audit{}
	var output bytes.Buffer
	var reported uint64
	a.dropped.Store(7)
	a.reportDrops(&output, &reported)
	a.reportDrops(&output, &reported)
	a.dropped.Add(2)
	a.reportDrops(failedAuditWriter{}, &reported)
	if reported != 7 {
		t.Fatal("failed report consumed loss count")
	}
	a.reportDrops(&output, &reported)
	events := auditEvents(t, output.Bytes())
	if len(events) != 2 || events[0].Type != "audit_dropped" || events[0].Dropped != 7 || events[1].Dropped != 2 || a.Dropped() != 9 {
		t.Fatalf("incorrect reports: %+v", events)
	}
}

type failedAuditWriter struct{ short bool }

func (w failedAuditWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("sensitive-output-details")
}

func TestAuditOutputFailure(t *testing.T) {
	if _, err := NewAudit(nil); err == nil {
		t.Fatal("nil output accepted")
	}
	for _, short := range []bool{false, true} {
		a, err := NewAudit(failedAuditWriter{short: short})
		if err != nil {
			t.Fatal(err)
		}
		a.Write(AuditEvent{Type: "lost"})
		if err := a.Close(); err != ErrAuditOutput {
			t.Fatalf("expected generic output error, got %v", err)
		}
		if a.Dropped() != 1 {
			t.Fatalf("output loss not counted: %d", a.Dropped())
		}
	}
}

func TestAuditConcurrentWriteClose(t *testing.T) {
	for round := 0; round < 20; round++ {
		var output bytes.Buffer
		a, err := NewAudit(&output)
		if err != nil {
			t.Fatal(err)
		}
		var writers, closers sync.WaitGroup
		var accepted atomic.Uint64
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			writers.Add(1)
			go func() {
				defer writers.Done()
				<-start
				for j := 0; j < 100; j++ {
					if a.Write(AuditEvent{Type: "concurrent"}) {
						accepted.Add(1)
					}
				}
			}()
		}
		for i := 0; i < 4; i++ {
			closers.Add(1)
			go func() {
				defer closers.Done()
				<-start
				if err := a.Close(); err != nil {
					t.Error(err)
				}
			}()
		}
		close(start)
		writers.Wait()
		closers.Wait()
		var written, losses uint64
		for _, event := range auditEvents(t, output.Bytes()) {
			if event.Type == "audit_dropped" {
				losses += event.Dropped
			} else {
				written++
			}
		}
		if written != accepted.Load() || losses != a.Dropped() {
			t.Fatalf("accepted events not drained: accepted=%d written=%d dropped=%d reported=%d", accepted.Load(), written, a.Dropped(), losses)
		}
	}
}
