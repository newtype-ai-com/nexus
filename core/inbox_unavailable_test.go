package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Production 2026-10-04: the model queue had not reconciled with Nexus yet,
// and a person's typed turn failed with "could not read model inbox". A
// person's turn now goes ahead without mail, says so once, and its tools are
// not interrupted by a queue that has shown it no mail.
func TestPersonTurnProceedsWhileInboxUnreconciled(t *testing.T) {
	q := &interruptInbox{err: fmt.Errorf("queue not reconciled: %w", ErrInboxUnavailable)}
	rounds, ran := 0, 0
	m := modelFunc(func(ctx context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		rounds++
		for _, msg := range r.Messages {
			if msg.inboxID != "" {
				t.Error("mail entered the input of an unreconciled queue")
			}
		}
		if rounds == 1 {
			return ModelResponse{ToolCalls: []ToolCall{call("first", `{}`), call("second", `{}`)}}, nil
		}
		return ModelResponse{Content: "done"}, nil
	})
	work := func(context.Context, ToolContext, json.RawMessage) (string, error) { ran++; return "done", nil }
	e := newTestEngine(t, m, testTools{tool("first", true, work), tool("second", true, work)})
	e.opts.ModelInbox = q
	events := send(t, e, ChatRequest{Message: "이 세션의 이름은 nmcp 이다"})
	assertTerminated(t, events)
	text := eventText(events)
	if strings.Contains(text, "inbox_error") || strings.Contains(text, "could not read model inbox") {
		t.Fatal("the person's turn failed on the inbox")
	}
	if rounds != 2 || ran != 2 {
		t.Fatalf("turn or tools did not run: rounds=%d tools=%d", rounds, ran)
	}
	if strings.Count(text, InboxUnavailableNotice) != 1 {
		t.Fatal("expected exactly one quiet notice")
	}
}

// An automatic inbox turn exists only for mail: an inbox that cannot answer
// is still an error there (and no provider call is paid for).
func TestInboxTurnStillFailsWhileInboxUnavailable(t *testing.T) {
	q := &interruptInbox{err: ErrInboxUnavailable}
	r := ModelRequest{}
	if skipped, err := appendInbox(context.Background(), q, &r, map[string]bool{}, false); err == nil || skipped {
		t.Fatal("inbox turn skipped an unavailable inbox")
	}
	if skipped, err := appendInbox(context.Background(), q, &r, map[string]bool{}, true); err != nil || !skipped || len(r.Messages) != 0 {
		t.Fatal("person turn did not skip an unavailable inbox")
	}
}
