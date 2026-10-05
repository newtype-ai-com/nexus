package core

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestInboxSummaryAndRemovalCannotMarkRead(t *testing.T) {
	ctx := context.Background()
	r := ModelRequest{MaxTokens: 100, Messages: []Message{{Role: "system", Content: "policy"}}}
	i := &testInbox{items: []InboxMessage{{ID: "evt_history", Text: strings.Repeat("old notice ", 5000)}}}
	if _, err := appendInbox(ctx, i, &r, map[string]bool{}, true); err != nil {
		t.Fatal(err)
	}
	r.Messages = append(r.Messages, Message{Role: "assistant", Content: "old answer"}, Message{Role: "user", Content: "current request"})
	calls := 0
	m := modelFunc(func(_ context.Context, request ModelRequest, _ func(string)) (ModelResponse, error) {
		calls++
		if len(consumedInbox(request)) != 0 {
			t.Error("summary input retained receipt provenance")
		}
		return ModelResponse{Content: "summary of old notice"}, nil
	})
	prepared, _ := PrepareMessages(ctx, m, r, 3, 8000)
	if calls != 1 || len(consumedInbox(prepared)) != 0 || len(i.ids) != 0 {
		t.Fatal("summary or removal acknowledged message")
	}
	if len(consumedInbox(r)) != 1 {
		t.Fatal("compaction mutated caller provenance")
	}
}

func TestInboxContextRejectedThenAccepted(t *testing.T) {
	i := &testInbox{items: []InboxMessage{{ID: "evt_retry", Text: "notice"}}}
	calls := 0
	m := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		calls++
		if len(i.ids) != 0 || !reflect.DeepEqual(consumedInbox(r), []string{"evt_retry"}) {
			t.Error("receipt preceded final accepted request")
		}
		if calls == 1 {
			return ModelResponse{}, contextLimitError{}
		}
		return ModelResponse{Content: "accepted"}, nil
	})
	e := newTestEngine(t, m, nil)
	e.opts.Binder = BinderFunc(func(context.Context, BindRequest) (*Binding, error) { return &Binding{Inbox: i}, nil })
	events := send(t, e, ChatRequest{Message: "work"})
	if calls != 2 || len(i.ids) != 1 || i.turns[0] != events[0].TaskID {
		t.Fatalf("retry changed receipt: calls=%d ids=%v turns=%v", calls, i.ids, i.turns)
	}
}
