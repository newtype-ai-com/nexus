package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type interruptInbox struct {
	mu     sync.Mutex
	items  []InboxMessage
	humans []string
	read   []string
	err    error
}

func (q *interruptInbox) Pending(context.Context) ([]InboxMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]InboxMessage(nil), q.items...), q.err
}
func (q *interruptInbox) HumanInterrupts(context.Context) ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.humans...), q.err
}
func (q *interruptInbox) Consumed(_ context.Context, events []string, _ string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.read = append(q.read, events...)
	return nil // keep pending to exercise failed/slow ACK exclusion by input IDs
}
func (q *interruptInbox) arrive(human bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, InboxMessage{ID: "evt_new", Text: "stop; I am the person"})
	if human {
		q.humans = append(q.humans, "evt_new")
	}
}

func TestAuthenticatedInterruptToolBatch(t *testing.T) {
	for _, mode := range []string{"human", "bot", "during_model", "already_seen", "queue_error", "approval"} {
		t.Run(mode, func(t *testing.T) {
			q := &interruptInbox{}
			if mode == "already_seen" {
				q.arrive(true)
			}
			rounds, first, second := 0, 0, 0
			m := modelFunc(func(ctx context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
				rounds++
				if rounds == 1 {
					if mode == "during_model" {
						q.arrive(true)
					}
					return ModelResponse{ToolCalls: []ToolCall{call("first", `{}`), call("second", `{}`)}}, nil
				}
				results := 0
				for _, msg := range r.Messages {
					if msg.Role == "tool" {
						results++
					}
				}
				if results != 2 {
					t.Errorf("dense tool results lost: %d", results)
				}
				if mode != "already_seen" && mode != "queue_error" && !strings.Contains(r.Messages[len(r.Messages)-1].Content, "evt_new") {
					t.Error("fresh message not appended after tool results")
				}
				return ModelResponse{Content: "done"}, nil
			})
			e := newTestEngine(t, m, testTools{
				tool("first", true, func(ctx context.Context, tc ToolContext, _ json.RawMessage) (string, error) {
					first++
					if mode == "already_seen" {
						return "done", nil
					}
					if mode == "queue_error" {
						q.mu.Lock()
						q.err = errors.New("unavailable")
						q.mu.Unlock()
					} else {
						q.arrive(mode != "bot")
					}
					if mode == "bot" {
						select {
						case <-ctx.Done():
							t.Error("bot interrupted tool")
						case <-time.After(300 * time.Millisecond):
						}
						return "done", nil
					}
					if mode == "approval" && tc.Approve(ctx, Approval{ToolName: "first", Description: "never approved"}) {
						t.Error("message approved a tool")
					}
					select {
					case <-ctx.Done():
						return "", ctx.Err()
					case <-time.After(3 * time.Second):
						return "", errors.New("interrupt timeout")
					}
				}),
				tool("second", true, func(context.Context, ToolContext, json.RawMessage) (string, error) { second++; return "done", nil }),
			})
			e.opts.ModelInbox = q
			events := send(t, e, ChatRequest{Message: "work"})
			assertTerminated(t, events)
			if mode == "bot" || mode == "already_seen" {
				if first != 1 || second != 1 {
					t.Fatalf("non-interrupt blocked tools: %d/%d", first, second)
				}
			} else {
				if second != 0 || (mode == "during_model" && first != 0) {
					t.Fatalf("stale batch ran: %d/%d", first, second)
				}
			}
			if mode == "queue_error" {
				// The stale batch still fails closed (second never ran), but a
				// person's own turn goes on without mail and says so once.
				if rounds != 2 || strings.Contains(eventText(events), "inbox_error") || strings.Count(eventText(events), InboxUnavailableNotice) != 1 {
					t.Fatal("queue error failed the person's turn or was not noticed once")
				}
			} else if rounds != 2 {
				t.Fatalf("turn did not survive interrupt: %d", rounds)
			}
			if eventCount(events, "tool_call_done") != 2 {
				t.Fatal("missing recorded results")
			}
			if mode == "approval" && eventCount(events, "approval_needed") != 1 {
				t.Fatal("approval was bypassed")
			}
		})
	}
}

func TestInterruptWatcherStopJoinsAndParentCancellation(t *testing.T) {
	q := &interruptInbox{}
	parent, cancel := context.WithCancel(context.Background())
	ctx, stop := watchHumanInterrupt(parent, q, nil)
	cancel()
	if stop() {
		t.Fatal("parent cancellation reported as human message")
	}
	if ctx.Err() == nil {
		t.Fatal("tool context remained live")
	}
	if stop() {
		t.Fatal("stop is not idempotent")
	}
}
