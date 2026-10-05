package nexusops

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/nexustransport"
)

// InboxPeek is what a client may learn about the seat's mail without reading
// it: how many messages are unread and their event IDs (oldest first). No
// sender text, no body: a peek never enters a model as a message, so it never
// records a receipt (neither delivered nor read).
type InboxPeek struct {
	Unread int         `json:"unread"`
	Events []ids.Event `json:"event_ids"`
	Note   string      `json:"note"`
}

const peekNote = "읽음 아님 · 읽으려면 nexus_inbox 를 부르세요 / not a read: call nexus_inbox to read"

// Peek lists unread mail without changing any receipt.
func (c *Contract) Peek(ctx context.Context) (InboxPeek, error) {
	items, _, err := c.Seat.Inbox(ctx, 0)
	if err != nil {
		return InboxPeek{}, err
	}
	p := InboxPeek{Events: []ids.Event{}, Note: peekNote}
	for _, m := range items {
		if m.ReadAt == nil {
			p.Events = append(p.Events, m.Event)
		}
	}
	p.Unread = len(p.Events)
	return p, nil
}

// TaskPeek is task_status with no wait and no ledger record (resource reads).
func (c *Contract) TaskPeek(ctx context.Context, task string) (any, error) {
	if ids.Check(ids.KindTask, task) != nil {
		return nil, ErrInvalid
	}
	return c.node(ctx, ids.Task(task))
}

// WatchPoll is the fallback interval when the Nexus stream is unavailable;
// WatchBackoff bounds the wait before reopening a failed stream.
var (
	WatchPoll    = 30 * time.Second
	WatchBackoff = 30 * time.Second
)

// Watch follows the seat's ledger stream (GET /v1/sessions/{id}/stream) and
// calls wake after changes it sees (coalesced: one wake may cover many ledger
// events, and one runs after every reopen). wake decides what changed (Peek,
// TaskPeek); Watch itself reads nothing and marks nothing. When the stream
// route is missing it polls every WatchPoll instead. It returns when ctx ends.
func (c *Contract) Watch(ctx context.Context, wake func(context.Context)) error {
	sig := make(chan struct{}, 1)
	signal := func(context.Context) {
		select {
		case sig <- struct{}{}:
		default:
		}
	}
	done := make(chan struct{})
	defer func() { <-done }()
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				wake(ctx)
			}
		}
	}()
	return c.watch(ctx, signal)
}

func (c *Contract) watch(ctx context.Context, wake func(context.Context)) error {
	var after int64
	backoff := time.Second
	poll := false
	for ctx.Err() == nil {
		wake(ctx)
		if poll {
			if !sleep(ctx, WatchPoll) {
				break
			}
			continue
		}
		next, err := c.follow(ctx, after, wake)
		if next > after {
			after, backoff = next, time.Second
		}
		if err == nil {
			continue // the stream's life ended: reopen from the cursor
		}
		var h *nexustransport.HTTPError
		if errors.As(err, &h) && (h.Code == 404 || h.Code == 405) {
			poll = true // a Nexus without the stream route
			continue
		}
		if !sleep(ctx, backoff) {
			break
		}
		backoff = min(backoff*2, WatchBackoff)
	}
	return ctx.Err()
}

// follow reads one stream until it ends and returns the last ledger sequence.
func (c *Contract) follow(ctx context.Context, after int64, wake func(context.Context)) (int64, error) {
	body, err := c.Seat.session.Stream(ctx, "/v1/sessions/"+url.PathEscape(string(c.Seat.ID))+"/stream", after)
	if err != nil {
		return after, err
	}
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 4096), 1<<20)
	event, id, data := "", "", false
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if event == "ledger" && data {
				if seq, err := strconv.ParseInt(id, 10, 64); err == nil && seq > after {
					after = seq
					wake(ctx)
				}
			}
			event, id, data = "", "", false
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch key {
		case "event":
			event = value
		case "id":
			id = value
		case "data":
			data = true
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		if ctx.Err() != nil {
			return after, ctx.Err()
		}
		return after, errors.New("Nexus stream interrupted")
	}
	return after, nil
}
