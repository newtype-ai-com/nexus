package nexus_test

import (
	"context"
	"fmt"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// ExampleService_Delegate demonstrates the trusted domain API without a model,
// external credentials or a running server. An HTTP adapter must authenticate
// the principal rather than accepting account/session IDs from the body.
func ExampleService_Delegate() {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.com")
	root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{
		Title: "Build the project", Runner: nexus.Local,
		Scope:  []string{"newtype:run", "session:delegate"},
		Rules:  []nexus.Rule{{Action: "tool:*", Effect: "auto"}, {Action: "tool:remove_file", Effect: "ask"}},
		Limits: nexus.Limits{ModelTokens: 1000, SubSessions: 1},
	})
	if err != nil {
		panic(err)
	}
	// A real local worker bootstraps itself and sends an authenticated request.
	// No runner exists to launch an unspecified target in phase one.
	worker, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "Local worker", Runner: nexus.Local, Scope: []string{"newtype:run"}})
	if err != nil {
		panic(err)
	}
	if err = svc.Touch(ctx, nexus.SessionPrincipal(person.AccountID, worker.Session.ID)); err != nil {
		panic(err)
	}
	child, err := svc.Delegate(ctx, nexus.SessionPrincipal(person.AccountID, root.Session.ID), nexus.DelegateRequest{
		ParentID: root.Delegation.ID, ToSessionID: worker.Session.ID, Title: "Write tests", Runner: nexus.Local,
		Scope: []string{"newtype:run"}, Limits: nexus.Limits{ModelTokens: 300},
	})
	if err != nil {
		panic(err)
	}
	actor := nexus.SessionPrincipal(person.AccountID, child.Session.ID)
	decision, err := svc.Authorize(ctx, actor, child.Delegation.ID, "tool:remove_file")
	if err != nil {
		panic(err)
	}
	fmt.Println(decision.Effect, decision.Approver)
	if _, err = svc.Consume(ctx, actor, child.Delegation.ID, nexus.Limits{ModelTokens: 120}); err != nil {
		panic(err)
	}
	if _, err = svc.SetTaskStatus(ctx, actor, child.Task.ID, "done"); err != nil {
		panic(err)
	}
	details, err := svc.DelegationInfo(ctx, person, root.Delegation.ID)
	if err != nil {
		panic(err)
	}
	fmt.Println("remaining tokens:", details.Remaining.ModelTokens)
	// Output:
	// ask user
	// remaining tokens: 880
}
