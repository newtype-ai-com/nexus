package conformance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/secretplan"
)

// public fixture role payloads (valid plan/3 wire values)
const (
	fixtureApproval = `{"adminToken":"PUBLIC_FIXTURE_ADMIN_TOKEN_0123456789","version":1}`
	fixtureDBAdmin  = `{"dbPassword":"PUBLIC-FIXTURE-DBADMIN","version":1}`
)

const planSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type planFixture struct {
	f        *fixture
	svc      *nexus.Service
	root     nexus.Issued
	exec     nexus.Principal
	credID   string
	keychain string
}

func newPlanFixture(t *testing.T, open func() nexus.Store, keychainEffect string) *planFixture {
	f := newFixture(t, open)
	svc := f.sealed(t)
	kc := secretplan.KeychainItemID("/fixture/kc.keychain-db", "org.newtype.fixture", "credentials-v1")
	root, err := svc.CreateRoot(context.Background(), f.person, nexus.RootRequest{Title: "executor", Runner: nexus.Local,
		Scope: []string{"newtype:run", "secrets:fd"}, Rules: []nexus.Rule{
			{Action: "exec:secret-plan", Effect: "ask"}, {Action: "secret:nexus:APPROVAL_ADMIN", Effect: "auto"},
			{Action: "secret:nexus:DB_ADMIN", Effect: "ask"}, {Action: "secret:keychain:" + kc, Effect: keychainEffect}},
		Limits: nexus.Limits{SubSessions: 1, MaxDepth: 1}, TTL: time.Hour})
	must(t, err)
	must(t, svc.Touch(context.Background(), nexus.SessionPrincipal(f.account, root.Session.ID)))
	c, token, err := svc.IssueExecutorCredential(context.Background(), f.person, root.Session.ID, root.Delegation.ID, time.Hour)
	must(t, err)
	p, err := svc.AuthenticateExecutor(context.Background(), token)
	must(t, err)
	_, err = svc.PutSecret(context.Background(), f.person, "APPROVAL_ADMIN", []byte(fixtureApproval))
	must(t, err)
	_, err = svc.PutSecret(context.Background(), f.person, "DB_ADMIN", []byte(fixtureDBAdmin))
	must(t, err)
	return &planFixture{f: f, svc: svc, root: root, exec: p, credID: c.ID, keychain: kc}
}

// plan is the fixture plan: plan/3 a-executor/1 with a closure.
func (pf *planFixture) plan(attempt string) []byte { return pf.planV3(attempt) }

// planV2 is the legacy plan/2 form (refused since plan/3); planV3 derives
// from it and the downgrade tests use it.
func (pf *planFixture) planV2(attempt string) []byte {
	roles := []any{
		map[string]any{"role": "approval-admin", "source": "nexus", "name": "APPROVAL_ADMIN", "generation": int64(1),
			"resource": "secret:nexus:APPROVAL_ADMIN", "fd": int64(35), "max_bytes": int64(4096), "envelope": "a-bridge-envelope/1"},
		map[string]any{"role": "runtime", "source": "keychain-helper",
			"ref":    map[string]any{"keychain": "/fixture/kc.keychain-db", "service": "org.newtype.fixture", "account": "credentials-v1"},
			"helper": map[string]any{"path": "/fixture/helper", "sha256": planSHA, "cdhash": strings.Repeat("c", 40)},
			"argv":   []any{"/fixture/helper", "export-runtime-fd", "33"}, "schema": int64(1), "custody_evidence_sha256": planSHA,
			"resource": "secret:keychain:" + pf.keychain, "fd": int64(33), "max_bytes": int64(4096), "envelope": "a-bridge-envelope/1"},
		map[string]any{"role": "db-admin", "source": "nexus", "name": "DB_ADMIN", "generation": int64(1),
			"resource": "secret:nexus:DB_ADMIN", "fd": int64(34), "max_bytes": int64(4096), "envelope": "a-bridge-envelope/1"},
	}
	m := map[string]any{
		"schema": secretplan.Schema, "issuer": "https://gate.example.test", "account": string(pf.f.account),
		"session": string(pf.root.Session.ID), "delegation": string(pf.root.Delegation.ID), "attempt": attempt,
		"program":   map[string]any{"interpreter": "/usr/bin/python3", "script": "/fixture/caller.py", "args": []any{}},
		"bootstrap": map[string]any{"shim": "/fixture/shim", "executor": "/fixture/newtype"},
		"pins": map[string]any{"/usr/bin/python3": planSHA, "/fixture/caller.py": planSHA, "/fixture/shim": planSHA,
			"/fixture/newtype": planSHA, "/fixture/helper": planSHA},
		"cwd": "/fixture", "env": map[string]any{}, "stdin": "devnull", "roles": roles, "control_fd": int64(36),
		"output":          map[string]any{"mode": "enum-json", "schema_id": "a-result/1", "keys": map[string]any{"status": []any{"ok", "unknown"}}},
		"timeout_seconds": int64(300), "cleanup_seconds": int64(10), "expires_at": pf.f.now.Add(30 * time.Minute).Unix(),
	}
	return secretplan.Encode(m)
}

// approve runs the Part A approval for the plan hash (executor requests, person decides).
func (pf *planFixture) approve(t *testing.T, raw []byte) ids.Approval {
	t.Helper()
	ctx := context.Background()
	x, err := pf.svc.RequestCustodyApproval(ctx, pf.exec, pf.root.Delegation.ID, "exec:secret-plan", secretplan.Hash(raw), 20*time.Minute)
	must(t, err)
	_, err = pf.svc.DecideCustodyApproval(ctx, pf.f.person, x.ID, secretplan.Hash(raw), true)
	must(t, err)
	return x.ID
}

func runSecretPlans(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	t.Run("secret_plan_happy_path_in_order", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.plan("attempt-0001")
		apr := pf.approve(t, raw)
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, apr)
		must(t, err)
		if run.Status != "started" || len(run.Roles) != 3 || run.Version != nexus.SecretPlanRunVersion {
			t.Fatalf("%+v", run)
		}
		// the approval is consumed
		got, err := pf.svc.CustodyApproval(ctx, pf.f.person, apr)
		must(t, err)
		if got.Status != "used" {
			t.Fatal("approval not consumed by start")
		}
		// out of order
		_, err = pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "runtime")
		wantErr(t, err, nexus.ErrConflict)
		r1, err := pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "approval-admin")
		must(t, err)
		if string(r1.Value) != fixtureApproval || r1.AuthorisedUntil == "" {
			t.Fatal("nexus release")
		}
		_, err = pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "approval-admin")
		wantErr(t, err, nexus.ErrConflict) // once
		r2, err := pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "runtime")
		must(t, err)
		if r2.Value != nil {
			t.Fatal("keychain source returned a value from Nexus")
		}
		// completed refused while a role is unreleased
		_, err = pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "completed")
		wantErr(t, err, nexus.ErrConflict)
		_, err = pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "db-admin")
		must(t, err)
		done, err := pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "completed")
		must(t, err)
		if done.Status != "completed" || done.FinishedAt == nil {
			t.Fatalf("%+v", done)
		}
		_, err = pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "unknown")
		wantErr(t, err, nexus.ErrConflict) // monotonic
		// no value bytes in the ledger
		must(t, pf.f.store.View(ctx, func(tx nexus.Tx) error {
			evs, err := tx.Events(pf.root.Session.ID, 0, 0)
			for _, e := range evs {
				if strings.Contains(string(e.Payload), "PUBLIC-FIXTURE") {
					t.Fatal("secret value in the ledger")
				}
			}
			return err
		}))
	})
	t.Run("secret_plan_attempt_unique_and_lookup", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.plan("attempt-0002")
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		// a new approval never reopens the attempt
		_, err = pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, pf.plan("attempt-0002")))
		if err == nil {
			t.Fatal("attempt reopened")
		}
		got, err := pf.svc.SecretPlanRunByAttempt(ctx, pf.exec, "attempt-0002")
		must(t, err)
		if got.RunID != run.RunID {
			t.Fatal("lookup by attempt")
		}
		_, err = pf.svc.SecretPlanRunByAttempt(ctx, pf.exec, "attempt-9999")
		wantErr(t, err, nexus.ErrNotFound)
		// a wrong plan hash / unapproved plan never starts
		other := pf.plan("attempt-0003")
		_, err = pf.svc.StartSecretPlan(ctx, pf.exec, other, pf.approve(t, pf.plan("attempt-0004")))
		wantErr(t, err, nexus.ErrConflict)
	})
	t.Run("secret_plan_authority_rechecked_on_release", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.plan("attempt-0005")
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		must(t, pf.svc.RevokeExecutorCredential(ctx, pf.f.person, pf.credID))
		_, err = pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "approval-admin")
		wantErr(t, err, nexus.ErrForbidden)
		// within the grace the revoked credential may read and finish failed/unknown, never completed
		_, err = pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "completed")
		wantErr(t, err, nexus.ErrForbidden)
		v, err := pf.svc.SecretPlanRun(ctx, pf.exec, run.RunID)
		must(t, err)
		if v.Status != "started" {
			t.Fatal(v.Status)
		}
		done, err := pf.svc.FinishSecretPlan(ctx, pf.exec, run.RunID, "unknown")
		must(t, err)
		if done.Status != "unknown" {
			t.Fatal(done.Status)
		}
		// after the grace: nothing
		pf.f.now = pf.f.now.Add(time.Hour + nexus.FinishGrace)
		_, err = pf.svc.SecretPlanRun(ctx, pf.exec, run.RunID)
		wantErr(t, err, nexus.ErrForbidden)
	})
	t.Run("secret_plan_delegation_revoked_and_generation_moved", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.plan("attempt-0006")
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		_, err = pf.svc.PutSecret(ctx, pf.f.person, "APPROVAL_ADMIN", []byte("PUBLIC-FIXTURE-NEWER"))
		must(t, err)
		_, err = pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "approval-admin")
		wantErr(t, err, nexus.ErrConflict) // the planned generation is no longer current
		pf2 := newPlanFixture(t, open, "ask")
		raw2 := pf2.plan("attempt-0007")
		run2, err := pf2.svc.StartSecretPlan(ctx, pf2.exec, raw2, pf2.approve(t, raw2))
		must(t, err)
		_, err = pf2.svc.Revoke(ctx, pf2.f.person, pf2.root.Delegation.ID, "test")
		must(t, err)
		_, err = pf2.svc.ReleaseSecretPlanRole(ctx, pf2.exec, run2.RunID, "approval-admin")
		if err == nil {
			t.Fatal("released after delegation revocation")
		}
	})
	t.Run("secret_plan_deadline_and_deny", func(t *testing.T) {
		pf := newPlanFixture(t, open, "deny")
		raw := pf.plan("attempt-0008")
		_, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		wantErr(t, err, nexus.ErrForbidden) // a denied resource never starts
		pf2 := newPlanFixture(t, open, "ask")
		raw2 := pf2.plan("attempt-0009")
		run, err := pf2.svc.StartSecretPlan(ctx, pf2.exec, raw2, pf2.approve(t, raw2))
		must(t, err)
		pf2.f.now = pf2.f.now.Add(6 * time.Minute) // past start + timeout (300s)
		_, err = pf2.svc.ReleaseSecretPlanRole(ctx, pf2.exec, run.RunID, "approval-admin")
		wantErr(t, err, nexus.ErrConflict)
		v, err := pf2.svc.SecretPlanRun(ctx, pf2.exec, run.RunID)
		must(t, err)
		if v.Status != "unknown" {
			t.Fatal("expired started run not terminal on read")
		}
	})
	t.Run("secret_plan_only_executor_credentials", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.plan("attempt-0010")
		apr := pf.approve(t, raw)
		plainSession := nexus.SessionPrincipal(pf.f.account, pf.root.Session.ID)
		_, err := pf.svc.StartSecretPlan(ctx, plainSession, raw, apr)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = pf.svc.StartSecretPlan(ctx, pf.f.person, raw, apr)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = pf.svc.AuthenticateExecutor(ctx, "nte_"+strings.Repeat("0", 64))
		wantErr(t, err, nexus.ErrForbidden)
		_, _, err = pf.svc.IssueExecutorCredential(ctx, plainSession, pf.root.Session.ID, pf.root.Delegation.ID, time.Hour)
		wantErr(t, err, nexus.ErrForbidden)
		_, _, err = pf.svc.IssueExecutorCredential(ctx, pf.f.person, pf.root.Session.ID, pf.root.Delegation.ID, 8*24*time.Hour)
		wantErr(t, err, nexus.ErrInvalid)
	})
}
