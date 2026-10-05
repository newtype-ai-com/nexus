package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func runBoundaryTests(t *testing.T, open func() nexus.Store) {
	t.Run("redaction_hash_and_input_limits", func(t *testing.T) {
		f := newFixture(t, open)
		s, _ := f.seed(nil, "newtype:run")
		payload := []byte(`{"n":9007199254740993,"text":"password: hunter2hunter2"}`)
		event := f.append(f.person, s.ID, nexus.EventInput{Kind: "note", Payload: payload})
		if event.Redactions != 1 || strings.Contains(string(event.Payload), "hunter2") || !strings.Contains(string(event.Payload), "9007199254740993") {
			t.Fatal("unsafe payload")
		}
		sum := sha256.Sum256(event.Payload)
		if event.PayloadHash != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatal("incorrect hash")
		}
		payload[0] = 'x'
		events, _, err := f.svc.Events(context.Background(), f.person, s.ID, 0, 0)
		must(t, err)
		if events[0].Payload[0] == 'x' {
			t.Fatal("caller payload aliases storage")
		}
		for _, input := range []nexus.EventInput{
			{Kind: ""}, {Kind: strings.Repeat("a", 65)}, {Kind: "note", ClientEventID: strings.Repeat("a", 129)},
			{Kind: "note", Source: "unknown"}, {Kind: "note", CausedBy: []ids.Event{"not-an-event"}},
			{Kind: "note", InvocationID: "not-an-invocation"},
		} {
			_, err := f.svc.AppendEvents(context.Background(), f.person, s.ID, []nexus.EventInput{input})
			wantErr(t, err, nexus.ErrInvalid)
		}
		_, err = f.svc.AppendEvents(context.Background(), f.person, s.ID, make([]nexus.EventInput, 501))
		wantErr(t, err, nexus.ErrInvalid)
		events, next, err := f.svc.Events(context.Background(), f.person, s.ID, 0, 0)
		must(t, err)
		if len(events) != 1 || next != 1 {
			t.Fatal("invalid inputs persisted")
		}
	})
	t.Run("cancelled_update_and_expired_tx", func(t *testing.T) {
		f := newFixture(t, open)
		s, _ := f.seed(nil, "newtype:run")
		ctx, cancel := context.WithCancel(context.Background())
		err := f.store.Update(ctx, func(tx nexus.Tx) error {
			s.Title = "cancelled"
			if err := tx.PutSession(s); err != nil {
				return err
			}
			cancel()
			return nil
		})
		wantErr(t, err, context.Canceled)
		got, err := f.svc.Session(context.Background(), f.person, s.ID)
		must(t, err)
		if got.Title == "cancelled" {
			t.Fatal("cancelled update committed")
		}
		// Memory's lifecycle guard is not required of SQL driver implementations;
		// all Store implementations must nevertheless forbid writes in a View.
		must(t, f.store.View(context.Background(), func(tx nexus.Tx) error {
			_, err := tx.AppendEvent(nexus.Event{})
			wantErr(t, err, nexus.ErrInvalid)
			wantErr(t, tx.PutUsage(ids.Delegation(ids.New(ids.KindDelegation)), nexus.Usage{}), nexus.ErrInvalid)
			return nil
		}))
	})
	t.Run("account_feed_and_cursor", func(t *testing.T) {
		f := newFixture(t, open)
		a, _ := f.seed(nil, "newtype:run")
		b, _ := f.seed(nil, "newtype:run")
		other := newFixture(t, func() nexus.Store { return f.store })
		c, _ := other.seed(nil, "newtype:run")
		f.append(f.person, a.ID, nexus.EventInput{Kind: "one"})
		other.append(other.person, c.ID, nexus.EventInput{Kind: "foreign"})
		f.append(f.person, b.ID, nexus.EventInput{Kind: "two"})
		f.append(f.person, a.ID, nexus.EventInput{Kind: "three"})
		page, next, err := f.svc.Feed(context.Background(), f.person, 0, 2)
		must(t, err)
		if len(page) != 2 || page[0].Kind != "one" || page[1].Kind != "two" {
			t.Fatal("feed order/isolation")
		}
		page, next, err = f.svc.Feed(context.Background(), f.person, next, 2)
		must(t, err)
		if len(page) != 1 || page[0].Kind != "three" {
			t.Fatal("feed continuation")
		}
		cursor, err := f.svc.Cursor(context.Background(), f.person)
		must(t, err)
		if cursor != next {
			t.Fatal("cursor mismatch")
		}
		// Invisible records still advance the cursor, even on an empty page.
		actor := nexus.SessionPrincipal(f.account, a.ID)
		page, next, err = f.svc.Feed(context.Background(), actor, 1, 1)
		must(t, err)
		if len(page) != 0 || next <= 1 {
			t.Fatal("invisible event stalls cursor")
		}
	})
	t.Run("transaction_lifecycle", func(t *testing.T) {
		// Only exercise the extra memory guard; SQL drivers need not implement it.
		store := nexus.NewMemStore()
		var escaped nexus.Tx
		must(t, store.View(context.Background(), func(tx nexus.Tx) error { escaped = tx; return nil }))
		_, err := escaped.Cursor(ids.Account(ids.New(ids.KindAccount)))
		wantErr(t, err, nexus.ErrInvalid)
	})
}
