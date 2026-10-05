package conformance

import (
	"context"
	"github.com/newtype-ai-com/nexus/nexus"
	"testing"
)

func runTaskManagement(t *testing.T, open func() nexus.Store) {
	t.Run("waiting_person_nonterminal_conservation", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, open)
		root := f.issue(rootRequest())
		child := f.delegate(root, f.childRequest(root, 500))
		actor := nexus.SessionPrincipal(f.account, child.Session.ID)
		before, err := f.svc.DelegationInfo(ctx, f.person, root.Delegation.ID)
		must(t, err)
		steps, err := f.svc.UpsertPlan(ctx, actor, child.Task.ID, []nexus.PlanStep{{Title: "owner approval", Status: "waiting_person"}, {Title: "local work", Status: "in_progress"}})
		must(t, err)
		_, err = f.svc.SetTaskStatus(ctx, actor, child.Task.ID, "waiting_person")
		must(t, err)
		tree, err := f.svc.Tree(ctx, f.person, root.Task.ID)
		must(t, err)
		if tree.Rollup.WaitingPerson != 2 || tree.Rollup.Done != 0 || tree.Rollup.Cancelled != 0 {
			t.Fatal(tree)
		}
		after, err := f.svc.DelegationInfo(ctx, f.person, root.Delegation.ID)
		must(t, err)
		if before.Remaining != after.Remaining {
			t.Fatal("waiting returned reservation", before, after)
		}
		info, err := f.svc.DelegationInfo(ctx, f.person, child.Delegation.ID)
		must(t, err)
		if info.Delegation.EndedAt != nil {
			t.Fatal("waiting ended delegation")
		}
		_, err = f.svc.SetTaskStatus(ctx, nexus.SessionPrincipal(f.account, root.Session.ID), child.Task.ID, "in_progress")
		wantErr(t, err, nexus.ErrForbidden)
		for _, status := range []string{"pending", "in_progress", "waiting_person"} {
			_, err = f.svc.SetTaskStatus(ctx, actor, child.Task.ID, status)
			must(t, err)
		}
		_, err = f.svc.UpsertPlan(ctx, actor, child.Task.ID, []nexus.PlanStep{{ID: steps[0].ID, Title: "owner approval", Status: "in_progress"}, {ID: steps[1].ID, Title: "local work", Status: "done"}})
		must(t, err)
		_, err = f.svc.SetTaskStatus(ctx, actor, child.Task.ID, "done")
		must(t, err)
		info, err = f.svc.DelegationInfo(ctx, f.person, child.Delegation.ID)
		must(t, err)
		if info.Delegation.EndedAt == nil {
			t.Fatal("done no longer settles delegation")
		}
		_, err = f.svc.SetTaskStatus(ctx, f.person, child.Task.ID, "waiting_person")
		wantErr(t, err, nexus.ErrConflict)
	})
	t.Run("plans_visibility_and_terminal", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, open)
		root := f.issue(rootRequest())
		other := f.issue(rootRequest())
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		steps, err := f.svc.UpsertPlan(ctx, actor, root.Task.ID, []nexus.PlanStep{{Title: "first", Status: "in_progress", ActiveForm: "doing"}, {Title: "second"}})
		must(t, err)
		if len(steps) != 2 || steps[0].ActiveForm != "doing" {
			t.Fatal(steps)
		}
		tree, err := f.svc.Tree(ctx, actor, root.Task.ID)
		must(t, err)
		if tree.Rollup.InProgress != 2 || tree.Rollup.Pending != 1 {
			t.Fatal(tree)
		}
		_, err = f.svc.Tree(ctx, nexus.SessionPrincipal(f.account, other.Session.ID), root.Task.ID)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.UpsertPlan(ctx, actor, root.Task.ID, []nexus.PlanStep{{ID: steps[0].ID, Title: "first", Status: "done"}})
		must(t, err)
		tree, err = f.svc.Tree(ctx, actor, root.Task.ID)
		must(t, err)
		if tree.Rollup.Done != 1 || tree.Rollup.Cancelled != 1 {
			t.Fatal(tree)
		}
		_, err = f.svc.UpsertPlan(ctx, actor, root.Task.ID, []nexus.PlanStep{{ID: steps[0].ID, Title: "first", Status: "pending"}})
		wantErr(t, err, nexus.ErrConflict)
		_, err = f.svc.UpsertPlan(ctx, actor, other.Task.ID, nil)
		wantErr(t, err, nexus.ErrForbidden)
	})
	t.Run("reparent_conservation_subtree_and_old_restrictions", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, open)
		r := rootRequest()
		r.Rules = append(r.Rules, nexus.Rule{Action: "tool:danger", Effect: "deny"})
		a := f.issue(r)
		b := f.issue(rootRequest())
		child := f.delegate(a, f.childRequest(a, 500))
		grandReq := f.childRequest(child, 100)
		grandReq.Limits.SubSessions = 0
		grand := f.delegate(child, grandReq)
		actor := nexus.SessionPrincipal(f.account, child.Session.ID)
		_, err := f.svc.Consume(ctx, actor, child.Delegation.ID, nexus.Limits{ModelTokens: 70})
		must(t, err)
		_, err = f.svc.Consume(ctx, nexus.SessionPrincipal(f.account, grand.Session.ID), grand.Delegation.ID, nexus.Limits{ModelTokens: 30})
		must(t, err)
		_, err = f.svc.Reparent(ctx, actor, child.Task.ID, b.Task.ID, true)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.Reparent(ctx, f.person, child.Task.ID, grand.Task.ID, true)
		wantErr(t, err, nexus.ErrInvalid)
		out, err := f.svc.Reparent(ctx, f.person, child.Task.ID, b.Task.ID, true)
		must(t, err)
		if len(out.Reissued) != 2 || out.Task.ParentID != b.Task.ID {
			t.Fatal(out)
		}
		info, err := f.svc.DelegationInfo(ctx, f.person, a.Delegation.ID)
		must(t, err)
		if info.Remaining.ModelTokens != a.Delegation.Limits.ModelTokens-100 {
			t.Fatal(info)
		}
		fresh := out.Reissued[child.Delegation.ID]
		details, err := f.svc.DelegationInfo(ctx, f.person, fresh)
		must(t, err)
		if details.Delegation.Limits.ModelTokens != 400 || details.Remaining.ModelTokens != 330 {
			t.Fatal(details)
		}
		decision, err := f.svc.Authorize(ctx, actor, fresh, "tool:danger")
		must(t, err)
		if decision.Effect != "deny" {
			t.Fatal("old ancestor restriction lost", decision)
		}
		_, err = f.svc.Authorize(ctx, actor, child.Delegation.ID, "tool:read_file")
		wantErr(t, err, nexus.ErrRevoked)
		tree, err := f.svc.Tree(ctx, f.person, child.Task.ID)
		must(t, err)
		if tree.Task.Status == "cancelled" || len(tree.Children) != 1 || tree.Children[0].Task.RootID != b.Task.ID || tree.Children[0].Task.Status == "cancelled" {
			t.Fatal(tree)
		}
		_, err = f.svc.Revoke(ctx, f.person, b.Delegation.ID, "")
		must(t, err)
		_, err = f.svc.Authorize(ctx, actor, fresh, "tool:read_file")
		wantErr(t, err, nexus.ErrRevoked)
	})
	t.Run("reparent_narrowing_rollback", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, open)
		a := f.issue(rootRequest())
		child := f.delegate(a, f.childRequest(a, 500))
		r := rootRequest()
		r.Limits.ModelTokens = 10
		b := f.issue(r)
		before, err := f.svc.Cursor(ctx, f.person)
		must(t, err)
		_, err = f.svc.Reparent(ctx, f.person, child.Task.ID, b.Task.ID, false)
		wantErr(t, err, nexus.ErrConflict)
		after, err := f.svc.Cursor(ctx, f.person)
		must(t, err)
		if before != after {
			t.Fatal("rollback leaked events")
		}
		info, err := f.svc.DelegationInfo(ctx, f.person, child.Delegation.ID)
		must(t, err)
		if info.Delegation.EndedAt != nil {
			t.Fatal("rollback ended mandate")
		}
		out, err := f.svc.Reparent(ctx, f.person, child.Task.ID, b.Task.ID, true)
		must(t, err)
		if len(out.Narrowed) == 0 {
			t.Fatal(out)
		}
		info, err = f.svc.DelegationInfo(ctx, f.person, out.Reissued[child.Delegation.ID])
		must(t, err)
		if info.Remaining.ModelTokens != 10 {
			t.Fatal(info)
		}
	})
}
