package conformance

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// runSecretPlanBindings: NB12-R1/R2/R4/R5/R6 regressions (owner).
func runSecretPlanBindings(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	releaseAll := func(t *testing.T, pf *planFixture, run ids.Run) {
		for _, role := range []string{"approval-admin", "runtime", "db-admin"} {
			out, err := pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run, role)
			must(t, err)
			clear(out.Value)
		}
	}
	t.Run("secret_plan_run_bound_to_original_credential", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.plan("bind-0001")
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		// a renewed credential on the same delegation
		_, token, err := pf.svc.IssueExecutorCredential(ctx, pf.f.person, pf.root.Session.ID, pf.root.Delegation.ID, time.Hour)
		must(t, err)
		renewed, err := pf.svc.AuthenticateExecutor(ctx, token)
		must(t, err)
		// a credential on another delegation of the same session
		d := pf.root.Delegation
		d.ID = ids.Delegation(ids.New(ids.KindDelegation))
		d.RootID = d.ID
		must(t, pf.f.store.Update(ctx, func(tx nexus.Tx) error { return tx.PutDelegation(d) }))
		_, token2, err := pf.svc.IssueExecutorCredential(ctx, pf.f.person, pf.root.Session.ID, d.ID, time.Hour)
		must(t, err)
		other, err := pf.svc.AuthenticateExecutor(ctx, token2)
		must(t, err)
		for _, p := range []nexus.Principal{renewed, other} {
			_, err = pf.svc.ReleaseSecretPlanRole(ctx, p, run.RunID, "approval-admin")
			wantErr(t, err, nexus.ErrForbidden)
			for _, o := range []string{"completed", "failed", "unknown"} {
				_, err = pf.svc.FinishSecretPlan(ctx, p, run.RunID, o)
				wantErr(t, err, nexus.ErrForbidden)
			}
			_, err = pf.svc.SecretPlanRun(ctx, p, run.RunID)
			wantErr(t, err, nexus.ErrForbidden)
		}
		// revoking the original does not let a replacement revive the run
		must(t, pf.svc.RevokeExecutorCredential(ctx, pf.f.person, pf.credID))
		_, err = pf.svc.ReleaseSecretPlanRole(ctx, renewed, run.RunID, "approval-admin")
		wantErr(t, err, nexus.ErrForbidden)
		_, err = pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "approval-admin")
		wantErr(t, err, nexus.ErrForbidden)
		// the original may still finish failed within the grace
		v, err := pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "failed")
		must(t, err)
		if v.Status != "failed" {
			t.Fatal(v.Status)
		}
	})
	t.Run("secret_plan_completed_needs_current_authority", func(t *testing.T) {
		for _, loss := range []string{"revoke", "suspend"} {
			pf := newPlanFixture(t, open, "ask")
			raw := pf.plan("authority-" + loss)
			run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
			must(t, err)
			releaseAll(t, pf, run.RunID)
			switch loss {
			case "revoke":
				_, err = pf.svc.Revoke(ctx, pf.f.person, pf.root.Delegation.ID, "public fixture")
			case "suspend":
				_, err = pf.svc.Suspend(ctx, pf.f.person, pf.root.Session.ID, "public fixture")
			}
			must(t, err)
			_, err = pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "completed")
			if err == nil {
				t.Fatalf("%s: completed without authority", loss)
			}
			v, err := pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "unknown")
			must(t, err)
			if v.Status != "unknown" {
				t.Fatal(v.Status)
			}
		}
	})
	t.Run("secret_plan_approval_read_needs_live_own_executor", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		apr := pf.approve(t, pf.plan("read-0001"))
		_, err := pf.svc.CustodyApproval(ctx, pf.exec, apr)
		must(t, err)
		// another executor credential of another delegation cannot read it
		d := pf.root.Delegation
		d.ID = ids.Delegation(ids.New(ids.KindDelegation))
		d.RootID = d.ID
		must(t, pf.f.store.Update(ctx, func(tx nexus.Tx) error { return tx.PutDelegation(d) }))
		_, token, err := pf.svc.IssueExecutorCredential(ctx, pf.f.person, pf.root.Session.ID, d.ID, time.Hour)
		must(t, err)
		other, err := pf.svc.AuthenticateExecutor(ctx, token)
		must(t, err)
		_, err = pf.svc.CustodyApproval(ctx, other, apr)
		wantErr(t, err, nexus.ErrForbidden)
		// revoked: no approval reads at all
		must(t, pf.svc.RevokeExecutorCredential(ctx, pf.f.person, pf.credID))
		_, err = pf.svc.CustodyApproval(ctx, pf.exec, apr)
		wantErr(t, err, nexus.ErrForbidden)
	})
	t.Run("secret_plan_wrong_issuer_refused_before_approval_use", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := bytes.Replace(pf.plan("issuer-0001"), []byte(`"https://gate.example.test"`), []byte(`"https://nexus.example.test"`), 1)
		apr := pf.approve(t, raw)
		_, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, apr)
		wantErr(t, err, nexus.ErrForbidden)
		v, err := pf.svc.CustodyApproval(ctx, pf.f.person, apr)
		must(t, err)
		if v.Status != "approved" || v.UsedAt != nil {
			t.Fatal("approval touched by a wrong-issuer plan")
		}
	})
	t.Run("secret_plan_after_deadline_only_unknown", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.plan("deadline-0010")
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		pf.f.now = pf.f.now.Add(6 * time.Minute)
		_, err = pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "failed")
		wantErr(t, err, nexus.ErrConflict)
		v, err := pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "unknown")
		must(t, err)
		if v.Status != "unknown" {
			t.Fatal(v.Status)
		}
	})
	t.Run("secret_plan_store_rules_freeze_history", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.plan("store-0001")
		view, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		var started nexus.SecretPlanRun
		must(t, pf.f.store.View(ctx, func(tx nexus.Tx) error {
			var err error
			started, err = tx.SecretPlanRun(view.RunID)
			return err
		}))
		key := "nt-store-alias"
		put := func(x nexus.SecretPlanRun, k string) error {
			return pf.f.store.Update(ctx, func(tx nexus.Tx) error { return tx.PutSecretPlanRun(k, x) })
		}
		clone := func(r nexus.SecretPlanRun) nexus.SecretPlanRun {
			r.Roles = append([]nexus.SecretPlanRole(nil), r.Roles...)
			return r
		}
		until := started.Deadline
		late := started.Deadline.Add(time.Hour)
		// two releases in one write; out of order; nil / late authorisation; alias key
		two := clone(started)
		two.Roles[0].Released, two.Roles[0].AuthorisedUntil = true, &until
		two.Roles[1].Released, two.Roles[1].AuthorisedUntil = true, &until
		second := clone(started)
		second.Roles[1].Released, second.Roles[1].AuthorisedUntil = true, &until
		nilAuth := clone(started)
		nilAuth.Roles[0].Released = true
		lateAuth := clone(started)
		lateAuth.Roles[0].Released, lateAuth.Roles[0].AuthorisedUntil = true, &late
		now := pf.f.now
		unreleasedDone := clone(started)
		unreleasedDone.Status, unreleasedDone.FinishedAt = "completed", &now
		for name, x := range map[string]nexus.SecretPlanRun{"two releases": two, "out of order": second, "nil authorisation": nilAuth,
			"authorisation after deadline": lateAuth, "completed unreleased": unreleasedDone} {
			if err := put(x, nexus.SecretPlanAttemptKey(started)); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
		// a valid single release passes the same rule (positive control)
		one := clone(started)
		one.Roles[0].Released, one.Roles[0].AuthorisedUntil = true, &until
		must(t, put(one, nexus.SecretPlanAttemptKey(started)))
		_, err = pf.svc.FinishSecretPlan(ctx, pf.exec, view.RunID, "failed")
		must(t, err)
		var failed nexus.SecretPlanRun
		must(t, pf.f.store.View(ctx, func(tx nexus.Tx) error {
			var err error
			failed, err = tx.SecretPlanRun(view.RunID)
			return err
		}))
		rewrite := clone(failed) // role 0 was released above; role 1 never was
		rewrite.Roles[1].Released, rewrite.Roles[1].AuthorisedUntil = true, &until
		if err := put(rewrite, nexus.SecretPlanAttemptKey(failed)); err == nil {
			t.Error("terminal run rewritten")
		}
		same := clone(failed)
		if err := put(same, key); err == nil {
			t.Error("existing run stored under an alias key")
		}
		// a new run (fresh id, same plan) under a non-canonical key
		alias := clone(started)
		alias.ID = ids.Run(ids.New(ids.KindRun))
		if err := put(alias, "manager-noncanonical-alias"); err == nil {
			t.Error("new run accepted under a non-canonical attempt key")
		}
		// a new run whose identity disagrees with its plan
		bad := clone(started)
		bad.ID = ids.Run(ids.New(ids.KindRun))
		bad.Attempt = "not-the-plan-attempt"
		if err := put(bad, "nt-new-key"); err == nil {
			t.Error("inconsistent new run accepted")
		}
	})
}
