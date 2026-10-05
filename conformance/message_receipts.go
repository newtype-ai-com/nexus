package conformance

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func runMessageReceipts(t *testing.T, open func() nexus.Store) {
	t.Run("message_receipts_exact_identity_and_retry", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, b, c := f.issue(rootRequest()), f.issue(rootRequest()), f.issue(rootRequest())
		pa, pb, pc := nexus.SessionPrincipal(f.account, a.Session.ID), nexus.SessionPrincipal(f.account, b.Session.ID), nexus.SessionPrincipal(f.account, c.Session.ID)
		m, err := f.svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: "mentions " + string(c.Session.ID)})
		must(t, err)
		status := func() nexus.MessageStatus {
			out, err := f.svc.MessageDelivery(ctx, pa, b.Session.ID, m.Event)
			must(t, err)
			return out
		}
		inboxStatus := func(delivered, read bool, turn string) {
			t.Helper()
			items, _, err := f.svc.Inbox(ctx, pb, 0, 100)
			must(t, err)
			if len(items) != 1 {
				t.Fatal(items)
			}
			item := items[0]
			if item.Event != m.Event || item.Kind != "message" || item.SenderKind != nexus.PrincipalSession || (item.DeliveredAt != nil) != delivered || (item.ReadAt != nil) != read || item.ReadTurnID != turn {
				t.Fatal("invalid recipient reconciliation", item)
			}
		}
		inboxStatus(false, false, "")
		if status().Status != "sent" {
			t.Fatal("poll is not delivery/read")
		}
		_, err = f.svc.MessageDelivery(ctx, pc, b.Session.ID, m.Event)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.MessageDelivery(ctx, pb, b.Session.ID, m.Event)
		wantErr(t, err, nexus.ErrForbidden)
		must(t, f.svc.MessageDelivered(ctx, pb, nexus.Receipt{Event: m.Event}))
		if status().Status != "delivered" || status().ReadAt != nil {
			t.Fatal(status())
		}
		inboxStatus(true, false, "")
		wantErr(t, f.svc.MessageDelivered(ctx, pc, nexus.Receipt{Event: m.Event}), nexus.ErrNotFound)
		wantErr(t, f.svc.MessageRead(ctx, f.person, nexus.Receipt{Event: m.Event, TurnID: ids.New(ids.KindTask)}), nexus.ErrForbidden)
		wantErr(t, f.svc.MessageRead(ctx, pb, nexus.Receipt{Event: m.Event, TurnID: "payload secret"}), nexus.ErrInvalid)
		turn := ids.New(ids.KindTask)
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := f.svc.MessageRead(ctx, pb, nexus.Receipt{Event: m.Event, TurnID: turn}); err != nil {
					t.Error(err)
				}
				if err := f.svc.MessageDelivered(ctx, pb, nexus.Receipt{Event: m.Event}); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if s := status(); s.Status != "read" || s.TurnID != turn || s.DeliveredAt == nil || s.ReadAt == nil {
			t.Fatal(s)
		}
		must(t, f.svc.MessageRead(ctx, pb, nexus.Receipt{Event: m.Event, TurnID: ids.New(ids.KindTask)}))
		if status().TurnID != turn {
			t.Fatal("retry changed first consumed turn")
		}
		inboxStatus(true, true, turn)
		// An unrelated sender can mention/reply to the id but cannot claim it.
		_, err = f.svc.Send(ctx, pc, nexus.Message{To: a.Session.ID, Text: "wrong sender", ReplyTo: m.Event})
		must(t, err)
		if status().ReplyID != "" {
			t.Fatal("forged reply link")
		}
		reply, err := f.svc.Send(ctx, pb, nexus.Message{To: a.Session.ID, Text: "answer", ReplyTo: m.Event})
		must(t, err)
		if status().ReplyID != reply.Event {
			t.Fatal(status())
		}
		other := newFixture(t, open)
		_, err = f.svc.MessageDelivery(ctx, other.person, b.Session.ID, m.Event)
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.MessageDelivery(ctx, f.person, b.Session.ID, m.Event)
		must(t, err)
		events, _, err := f.svc.Events(ctx, f.person, b.Session.ID, 0, 100)
		must(t, err)
		counts := map[string]int{}
		for _, e := range events {
			if len(e.CausedBy) == 1 && e.CausedBy[0] == m.Event {
				counts[e.Kind]++
			}
		}
		if counts["message.delivered"] != 1 || counts["message.read"] != 1 || counts["message.reply"] != 1 {
			t.Fatal(counts)
		}
		for _, input := range []nexus.EventInput{
			{Source: "bot", Kind: "message.read", Payload: json.RawMessage(`{}`)},
			{Source: "engine", Kind: "note", ClientEventID: "message.read:" + string(m.Event), Payload: json.RawMessage(`{}`)},
		} {
			_, err := f.svc.AppendEvents(ctx, pb, b.Session.ID, []nexus.EventInput{input})
			wantErr(t, err, nexus.ErrForbidden)
		}
	})
	t.Run("message_read_before_delivery_and_stopped_storage", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, b := f.issue(rootRequest()), f.issue(rootRequest())
		pa, pb := nexus.SessionPrincipal(f.account, a.Session.ID), nexus.SessionPrincipal(f.account, b.Session.ID)
		_, err := f.svc.SetSessionStatus(ctx, pb, b.Session.ID, nexus.SessionStopped)
		must(t, err)
		m, err := f.svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: "stored"})
		must(t, err)
		wantErr(t, f.svc.MessageDelivered(ctx, pb, nexus.Receipt{Event: m.Event}), nexus.ErrRevoked)
		_, err = f.svc.Send(ctx, pb, nexus.Message{To: a.Session.ID, Text: "still stopped"})
		wantErr(t, err, nexus.ErrRevoked)
		_, err = f.svc.SetSessionStatus(ctx, pb, b.Session.ID, nexus.SessionRunning)
		must(t, err)
		must(t, f.svc.MessageRead(ctx, pb, nexus.Receipt{Event: m.Event, TurnID: ids.New(ids.KindTask)}))
		must(t, f.svc.MessageDelivered(ctx, pb, nexus.Receipt{Event: m.Event}))
		out, err := f.svc.MessageDelivery(ctx, pa, b.Session.ID, m.Event)
		must(t, err)
		if out.Status != "read" || out.ReadAt == nil || out.DeliveredAt == nil {
			t.Fatal(out)
		}
		_, err = f.svc.SetSessionStatus(ctx, f.person, b.Session.ID, nexus.SessionDone)
		must(t, err)
		_, err = f.svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: "done"})
		wantErr(t, err, nexus.ErrConflict)
	})
}
