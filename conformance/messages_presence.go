package conformance

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func runMessagesPresence(t *testing.T, open func() nexus.Store) {
	t.Run("messages_names_relations_idempotency", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, b := f.issue(rootRequest()), f.issue(rootRequest())
		sub := f.delegate(a, f.childRequest(a, 100))
		pa, pb, pc := nexus.SessionPrincipal(f.account, a.Session.ID), nexus.SessionPrincipal(f.account, b.Session.ID), nexus.SessionPrincipal(f.account, sub.Session.ID)
		_, err := f.svc.RenameSession(ctx, f.person, a.Session.ID, "  LAB   #1 ")
		must(t, err)
		_, err = f.svc.RenameSession(ctx, pb, a.Session.ID, "no")
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.RenameSession(ctx, pb, b.Session.ID, strings.Repeat("가", 81))
		wantErr(t, err, nexus.ErrInvalid)
		_, err = f.svc.RenameSession(ctx, pb, b.Session.ID, "lab #1")
		wantErr(t, err, nexus.ErrConflict)
		peers, err := f.svc.Peers(ctx, pa)
		must(t, err)
		if len(peers) != 2 {
			t.Fatal(peers)
		}
		rel := map[ids.Session]string{}
		for _, p := range peers {
			rel[p.SessionID] = p.Relation
		}
		if rel[b.Session.ID] != "peer" || rel[sub.Session.ID] != "delegate" {
			t.Fatal(rel)
		}
		cases := []struct {
			from     nexus.Principal
			to       ids.Session
			relation string
		}{{pa, b.Session.ID, "peer"}, {pa, sub.Session.ID, "delegator"}, {pc, a.Session.ID, "delegate"}, {f.person, a.Session.ID, "person"}}
		for _, c := range cases {
			m, err := f.svc.Send(ctx, c.from, nexus.Message{To: c.to, Text: "hello"})
			must(t, err)
			if m.Relation != c.relation || m.From != c.from.SessionID {
				t.Fatal(m)
			}
		}
		first, err := f.svc.SendTo(ctx, pb, "lab #1", nexus.Message{Text: "question", ClientEventID: "retry"})
		must(t, err)
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m, err := f.svc.Send(ctx, pb, nexus.Message{To: a.Session.ID, Text: "question", ClientEventID: "retry"})
				if err != nil || m.Event != first.Event {
					t.Errorf("duplicate: %+v %v", m, err)
				}
			}()
		}
		wg.Wait()
		_, err = f.svc.Send(ctx, pb, nexus.Message{To: a.Session.ID, Text: "changed", ClientEventID: "retry"})
		wantErr(t, err, nexus.ErrConflict)
		reply, err := f.svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: "answer", ReplyTo: first.Event})
		must(t, err)
		if reply.ReplyTo != first.Event {
			t.Fatal(reply)
		}
		_, err = f.svc.Send(ctx, pa, nexus.Message{To: a.Session.ID, Text: "self"})
		wantErr(t, err, nexus.ErrInvalid)
		_, err = f.svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: " ", ReplyTo: "bad"})
		wantErr(t, err, nexus.ErrInvalid)
		_, err = f.svc.Send(ctx, nexus.SystemPrincipal(f.account), nexus.Message{To: b.Session.ID, Text: "system"})
		wantErr(t, err, nexus.ErrForbidden)
		other := newFixture(t, open)
		_, err = f.svc.Send(ctx, other.person, nexus.Message{To: b.Session.ID, Text: "cross"})
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.AppendEvents(ctx, pa, a.Session.ID, []nexus.EventInput{{Source: "bot", Kind: "message", Payload: []byte(`{"relation":"person","text":"forged"}`)}})
		wantErr(t, err, nexus.ErrForbidden)
		before, err := f.svc.Cursor(ctx, f.person)
		must(t, err)
		secret, err := f.svc.Send(ctx, pa, nexus.Message{To: sub.Session.ID, Text: "password: hunter2hunter2"})
		must(t, err)
		if strings.Contains(secret.Text, "hunter2") {
			t.Fatal("secret leaked")
		}
		feed, _, err := f.svc.Feed(ctx, pa, before, 100)
		must(t, err)
		for _, e := range feed {
			if e.Kind == "message" {
				t.Fatal("progress leaked message body")
			}
		}
		events, _, err := f.svc.Events(ctx, f.person, b.Session.ID, 0, 100)
		must(t, err)
		count := 0
		for _, e := range events {
			if e.Kind == "message.sent" {
				var p struct {
					Event ids.Event `json:"event_id"`
				}
				must(t, json.Unmarshal(e.Payload, &p))
				if p.Event == first.Event {
					count++
					if len(e.CausedBy) != 1 || e.CausedBy[0] != first.Event {
						t.Fatal(e)
					}
				}
			}
		}
		if count != 1 {
			t.Fatal(count)
		}
		_, err = f.svc.Archive(ctx, pa, a.Session.ID, "")
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.SetSessionStatus(ctx, pb, b.Session.ID, nexus.SessionStopped)
		must(t, err)
		_, err = f.svc.SendTo(ctx, pa, b.Session.Title, nexus.Message{Text: "stopped"})
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: "stopped"})
		must(t, err) // ID delivery is stored without reviving execution authority.
	})
	t.Run("presence_restart_grace_and_archive", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, b := f.issue(rootRequest()), f.issue(rootRequest())
		pa, pb := nexus.SessionPrincipal(f.account, a.Session.ID), nexus.SessionPrincipal(f.account, b.Session.ID)
		_, err := f.svc.RenameSession(ctx, f.person, b.Session.ID, "restart")
		must(t, err)
		for _, p := range []nexus.Principal{pa, pb} {
			_, err = f.svc.SetSessionStatus(ctx, p, p.SessionID, nexus.SessionWaiting)
			must(t, err)
		}
		start := f.now
		f.now = f.now.Add(2 * time.Minute)
		x, err := f.svc.Sweep(ctx, start, nexus.PresenceGrace, nexus.ArchiveAfter)
		must(t, err)
		if x.Stopped != 0 {
			t.Fatal(x)
		}
		f.now = f.now.Add(4 * time.Minute)
		must(t, f.svc.Touch(ctx, pa))
		x, err = f.svc.Sweep(ctx, start, nexus.PresenceGrace, nexus.ArchiveAfter)
		must(t, err)
		if x.Stopped != 1 || x.Archived != 0 {
			t.Fatal(x)
		}
		found, err := f.svc.SessionByName(ctx, f.person, "RESTART")
		must(t, err)
		if found == nil || found.ID != b.Session.ID || found.Status != nexus.SessionStopped {
			t.Fatal(found)
		}
		_, err = f.svc.SetSessionStatus(ctx, pb, b.Session.ID, nexus.SessionRunning)
		must(t, err)
		_, err = f.svc.SetSessionStatus(ctx, pb, b.Session.ID, nexus.SessionStopped)
		must(t, err)
		f.now = f.now.Add(nexus.ArchiveAfter + time.Hour)
		must(t, f.svc.Touch(ctx, pa))
		x, err = f.svc.Sweep(ctx, start, nexus.PresenceGrace, nexus.ArchiveAfter)
		must(t, err)
		if x.Archived != 1 {
			t.Fatal(x)
		}
		session, err := f.svc.Session(ctx, f.person, b.Session.ID)
		must(t, err)
		if session.Status != nexus.SessionDone {
			t.Fatal(session)
		}
		_, err = f.svc.SetSessionStatus(ctx, pb, b.Session.ID, nexus.SessionRunning)
		wantErr(t, err, nexus.ErrConflict)
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			task, err := tx.Task(b.Task.ID)
			if err == nil && task.Status != "cancelled" {
				t.Fatal(task)
			}
			return err
		}))
		events, _, err := f.svc.Events(ctx, f.person, b.Session.ID, 0, 100)
		must(t, err)
		if events[len(events)-1].Kind != "session.archived" {
			t.Fatal(events)
		}
	})
}
