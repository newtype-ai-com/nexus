package pgstore

import (
	"context"
	"os"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestLeftAcrossPoolRestart(t *testing.T) {
	first := testStore(t)
	ctx := context.Background()
	var schema string
	if err := first.Pool().QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	service := nexus.NewService(first, nil)
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.com")
	root, err := service.CreateRoot(ctx, person, nexus.RootRequest{Title: "balance", Limits: nexus.Limits{ModelTokens: 100}})
	if err != nil {
		t.Fatal(err)
	}
	actor := nexus.SessionPrincipal(person.AccountID, root.Session.ID)
	if _, err = service.Consume(ctx, actor, root.Delegation.ID, nexus.Limits{ModelTokens: 35}); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	left, err := nexus.NewService(second, nil).Left(ctx, actor, root.Delegation.ID)
	if err != nil || left.ModelTokens != 65 {
		t.Fatalf("%+v %v", left, err)
	}
	if _, err = service.Revoke(ctx, person, root.Delegation.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = nexus.NewService(second, nil).Left(ctx, actor, root.Delegation.ID); err == nil {
		t.Fatal("stale live balance after revoke")
	}
}
