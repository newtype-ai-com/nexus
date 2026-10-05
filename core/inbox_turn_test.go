package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestInboxTurnOptInAttemptedAndBarrier(t *testing.T) {
	i := &testInbox{items: []InboxMessage{{ID: "a", Text: "notice"}, {ID: "b", Text: "notice"}}}
	var calls atomic.Int32
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls.Add(1)
		return ModelResponse{Content: "refused", FinishReason: "refusal"}, nil
	}), nil)
	e.opts.ModelInbox = i
	if _, err := e.StartInboxTurn(context.Background(), "one"); !errors.Is(err, ErrInboxDisabled) {
		t.Fatal("implicit opt-in", err)
	}
	e.opts.EnableInboxTurns = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.StartInboxTurn(ctx, "one"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel did not win", err)
	}
	if len(e.inboxAttempted) != 0 {
		t.Fatal("cancel consumed retry opportunity")
	}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := e.StartInboxTurn(context.Background(), "one")
			if err != nil && !errors.Is(err, ErrTurnInProgress) {
				t.Error(err)
			}
			if ch != nil {
				for range ch {
				}
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || len(i.ids) != 0 {
		t.Fatal("duplicate call or refusal read", calls.Load(), i.ids)
	}
	for _, items := range [][]InboxMessage{{{ID: "a"}}, {{ID: "a"}, {ID: "b"}}} {
		i.items = items
		ch, err := e.StartInboxTurn(context.Background(), "one")
		if ch != nil || err != nil {
			t.Fatal("set change retried an attempted ID", err)
		}
	}
	i.items = []InboxMessage{{ID: "c", Text: "new notice"}}
	ch, err := e.StartInboxTurn(context.Background(), "one")
	if err != nil || ch == nil {
		t.Fatal("new event suppressed", err)
	}
	collect(t, ch)
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
}

type disappearingInbox struct{ pending atomic.Int32 }

func (i *disappearingInbox) Pending(context.Context) ([]InboxMessage, error) {
	if i.pending.Add(1) == 1 {
		return []InboxMessage{{ID: "a", Text: "notice"}}, nil
	}
	return nil, nil
}
func (*disappearingInbox) Consumed(context.Context, []string, string) error { return nil }

func TestInboxTurnDisappearedSnapshotDoesNotCallModel(t *testing.T) {
	e := newTestEngine(t, modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		t.Error("empty automatic model call")
		return ModelResponse{Content: "done"}, nil
	}), nil)
	e.opts.EnableInboxTurns, e.opts.ModelInbox = true, &disappearingInbox{}
	ch, err := e.StartInboxTurn(context.Background(), "one")
	if err != nil || ch == nil {
		t.Fatal(err)
	}
	collect(t, ch)
}
