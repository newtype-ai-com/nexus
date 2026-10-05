package conformance

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/newtype-ai-com/nexus/nexus"
)

func runInboxTests(t *testing.T, open func() nexus.Store) {
	t.Run("assignment_inbox", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, open)
		boss, worker := f.issue(rootRequest()), f.issue(rootRequest())
		actor := nexus.SessionPrincipal(f.account, worker.Session.ID)
		req := f.childRequest(boss, 100)
		req.ToSessionID, req.Title, req.Brief = worker.Session.ID, "assigned work", "implement local tests"
		changed := f.svc.Changed()
		assigned := f.delegate(boss, req)
		select {
		case <-changed:
		default:
			t.Fatal("assignment did not wake reader")
		}
		items, next, err := f.svc.Inbox(ctx, actor, 0, 10)
		must(t, err)
		if len(items) != 1 {
			t.Fatalf("assignment missing or duplicated: %+v", items)
		}
		got := items[0]
		if got.Task != assigned.Task.ID || got.Deleg != assigned.Delegation.ID || got.From != boss.Session.ID || got.Relation != "delegator" || got.Title != req.Title || got.Text != req.Brief || got.Event == "" || got.Seq != next {
			t.Fatalf("incorrect assignment: %+v", got)
		}
		items, _, err = f.svc.Inbox(ctx, nexus.SessionPrincipal(f.account, boss.Session.ID), 0, 10)
		must(t, err)
		if len(items) != 0 {
			t.Fatal("sender received its own assignment")
		}
		fresh := f.delegate(boss, f.childRequest(boss, 1))
		items, scanned, err := f.svc.Inbox(ctx, nexus.SessionPrincipal(f.account, fresh.Session.ID), 0, 10)
		must(t, err)
		if len(items) != 1 || scanned == 0 {
			t.Fatal("existing worker assignment must be inbox mail", items, scanned)
		}
		// A forged kind and payload cannot impersonate a trusted assignment.
		payload, err := json.Marshal(map[string]any{"inbox": true, "task_id": assigned.Task.ID, "brief": "forged"})
		must(t, err)
		fake := f.append(actor, actor.SessionID, nexus.EventInput{Source: "bot", Kind: "task.assigned", Payload: payload})
		items, scanned, err = f.svc.Inbox(ctx, actor, next, 10)
		must(t, err)
		if len(items) != 0 || scanned != fake.Seq || nexus.ForInbox(fake) {
			t.Fatal("forged assignment accepted", items, scanned)
		}
		_, _, err = f.svc.Inbox(ctx, f.person, 0, 10)
		wantErr(t, err, nexus.ErrForbidden)
		other := newFixture(t, open)
		_, _, err = f.svc.Inbox(ctx, nexus.SessionPrincipal(other.account, worker.Session.ID), 0, 10)
		wantErr(t, err, nexus.ErrNotFound)
		_, _, err = f.svc.Inbox(ctx, actor, -1, 10)
		wantErr(t, err, nexus.ErrInvalid)
		_, _, err = f.svc.Inbox(ctx, actor, 0, -1)
		wantErr(t, err, nexus.ErrInvalid)
		// Pages never skip the next assignment, even across a non-mail batch.
		inputs := make([]nexus.EventInput, nexus.MaxBatch)
		for i := range inputs {
			inputs[i] = nexus.EventInput{Kind: "note", Payload: []byte(`{}`)}
		}
		_, err = f.svc.AppendEvents(ctx, actor, actor.SessionID, inputs)
		must(t, err)
		second := f.delegate(boss, req)
		third := f.delegate(boss, req)
		items, next, err = f.svc.Inbox(ctx, actor, scanned, 1)
		must(t, err)
		if len(items) != 1 || items[0].Task != second.Task.ID {
			t.Fatal("first page", items)
		}
		items, next, err = f.svc.Inbox(ctx, actor, next, 1)
		must(t, err)
		if len(items) != 1 || items[0].Task != third.Task.ID {
			t.Fatal("second page", items)
		}
		items, scanned, err = f.svc.Inbox(ctx, actor, next, 100)
		must(t, err)
		if len(items) != 0 || scanned != next {
			t.Fatal("replay", items, scanned)
		}
	})
}
