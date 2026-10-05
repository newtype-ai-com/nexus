package pgstore

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestMessageReceiptsAcrossPoolsAndRestart(t *testing.T) {
	first := testStore(t)
	ctx := context.Background()
	var schema string
	if err := first.Pool().QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema, MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	s1, s2 := nexus.NewService(first, nil), nexus.NewService(second, nil)
	account := ids.Account(ids.New(ids.KindAccount))
	person := nexus.UserPrincipal(account, "fixture@example.com")
	root, err := s1.CreateRoot(ctx, person, nexus.RootRequest{Title: "recipient", Scope: []string{"newtype:run"}})
	if err != nil {
		t.Fatal(err)
	}
	actor := nexus.SessionPrincipal(account, root.Session.ID)
	m, err := s1.Send(ctx, person, nexus.Message{To: actor.SessionID, Text: "multi pool"})
	if err != nil {
		t.Fatal(err)
	}
	turn := ids.New(ids.KindTask)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := s1
			if i%2 == 1 {
				s = s2
			}
			if err := s.MessageRead(ctx, actor, nexus.Receipt{Event: m.Event, TurnID: turn}); err != nil {
				t.Error(err)
			}
			if err := s.MessageDelivered(ctx, actor, nexus.Receipt{Event: m.Event}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	second.Close()
	reopened, err := Open(ctx, Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s3 := nexus.NewService(reopened, nil)
	out, err := s3.MessageDelivery(ctx, person, actor.SessionID, m.Event)
	if err != nil || out.Status != "read" || out.TurnID != turn {
		t.Fatalf("%+v %v", out, err)
	}
	items, _, err := s3.Inbox(ctx, actor, 0, 100)
	if err != nil || len(items) != 1 || items[0].Event != m.Event || items[0].DeliveredAt == nil || items[0].ReadAt == nil || items[0].ReadTurnID != turn || items[0].SenderKind != nexus.PrincipalUser {
		t.Fatalf("recipient reconciliation after restart: %+v %v", items, err)
	}
	events, _, err := s3.Events(ctx, person, actor.SessionID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Kind]++
	}
	if counts["message.delivered"] != 1 || counts["message.read"] != 1 {
		t.Fatal(counts)
	}
}
