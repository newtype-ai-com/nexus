package conformance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/secretplan"
	"github.com/newtype-ai-com/nexus/seal"
)

// runReceipts: signed bootstrap/dispatch receipts (schema ruling §4).
func runReceipts(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	challenge := strings.Repeat("ab", 32)
	start := func(t *testing.T, pf *planFixture, attempt string) nexus.SecretPlanRunView {
		_, err := pf.svc.PutSecret(ctx, pf.f.person, "APPROVAL_ADMIN", []byte(`{"adminToken":"PUBLIC_FIXTURE_ADMIN_TOKEN_0123456789","version":1}`))
		must(t, err)
		_, err = pf.svc.PutSecret(ctx, pf.f.person, "DB_ADMIN", []byte(`{"dbPassword":"PUBLIC-FIXTURE-PW-16","version":1}`))
		must(t, err)
		raw := bytes.Replace(pf.planV3(attempt), []byte(`"generation":1`), []byte(`"generation":2`), -1)
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		return run
	}
	verify := func(t *testing.T, pf *planFixture, jws string) map[string]any {
		payload, err := seal.VerifyType(jws, pf.svc.ReceiptKeysPublic(), seal.ReceiptJWSType)
		must(t, err)
		if _, err := seal.Verify(jws, pf.svc.ReceiptKeysPublic()); err == nil {
			t.Fatal("a receipt verified as a delegation certificate")
		}
		if _, err := secretplan.Parse(payload); err != nil {
			t.Fatal("receipt payload not canonical")
		}
		var m map[string]any
		must(t, json.Unmarshal(payload, &m))
		if len(m) != len(nexus.ReceiptKeys) {
			t.Fatalf("receipt keys %v", m)
		}
		return m
	}
	t.Run("receipt_bootstrap_then_dispatch", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		run := start(t, pf, "receipt-0001")
		_, err := pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "dispatch", challenge)
		wantErr(t, err, nexus.ErrConflict) // nothing released yet
		jws, err := pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "bootstrap", challenge)
		must(t, err)
		m := verify(t, pf, jws)
		if m["op"] != "bootstrap" || m["challenge"] != challenge || m["run_id"] != string(run.RunID) ||
			m["consumer_profile"] != secretplan.ProfileAExecutor || m["credential_id"] != pf.credID {
			t.Fatalf("%v", m)
		}
		if m["expires_at"].(float64)-m["issued_at"].(float64) > 10 {
			t.Fatal("receipt lifetime over 10 s")
		}
		for _, role := range []string{"approval-admin", "runtime", "db-admin"} {
			out, err := pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, role)
			must(t, err)
			clear(out.Value)
			if role == "approval-admin" {
				_, err = pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "bootstrap", challenge)
				wantErr(t, err, nexus.ErrConflict) // bootstrap only before any release
			}
		}
		jws, err = pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "dispatch", challenge)
		must(t, err)
		if verify(t, pf, jws)["op"] != "dispatch" {
			t.Fatal("dispatch receipt")
		}
	})
	t.Run("receipt_role_descriptors_from_plan", func(t *testing.T) {
		// run-receipt/2: every role entry is the stored plan's role object
		// (secretplan.RoleDescriptor) plus released, in plan order; the
		// generation is the plan's pinned one (2 here), the Keychain role
		// carries its item/helper/argv/custody point and no generation.
		pf := newPlanFixture(t, open, "ask")
		run := start(t, pf, "receipt-0004")
		raw := bytes.Replace(pf.planV3("receipt-0004"), []byte(`"generation":1`), []byte(`"generation":2`), -1)
		plan, err := secretplan.Parse(raw)
		must(t, err)
		planRoles := plan.(map[string]any)["roles"].([]any)
		check := func(m map[string]any, released bool) {
			t.Helper()
			if m["version"] != nexus.ReceiptVersion || nexus.ReceiptVersion != "newtype.run-receipt/2" {
				t.Fatalf("version %v", m["version"])
			}
			got := m["roles"].([]any)
			if len(got) != len(planRoles) {
				t.Fatalf("roles %v", got)
			}
			for i, x := range got {
				d := x.(map[string]any)
				if d["released"] != released {
					t.Fatalf("released %v", d)
				}
				delete(d, "released")
				want, err := secretplan.Parse(secretplan.Encode(planRoles[i]))
				must(t, err)
				gotC, err := json.Marshal(d)
				must(t, err)
				back, err := secretplan.Parse(gotC)
				must(t, err)
				if !bytes.Equal(secretplan.Encode(back), secretplan.Encode(want)) {
					t.Fatalf("role %d descriptor %s != plan role %s", i, secretplan.Encode(back), secretplan.Encode(want))
				}
			}
			kc := got[1].(map[string]any)
			if _, ok := kc["generation"]; ok || kc["source"] != "keychain-helper" {
				t.Fatalf("keychain descriptor %v", kc)
			}
			h := kc["helper"].(map[string]any)
			if h["path"] != "/fixture/helper" || h["cdhash"] != strings.Repeat("c", 40) || kc["custody_evidence_sha256"] != planSHA ||
				len(kc["argv"].([]any)) != 3 || kc["ref"].(map[string]any)["account"] != "credentials-v1" {
				t.Fatalf("keychain descriptor %v", kc)
			}
			for _, i := range []int{0, 2} {
				n := got[i].(map[string]any)
				if n["generation"] != float64(2) || n["source"] != "nexus" {
					t.Fatalf("nexus descriptor %v", n)
				}
			}
		}
		jws, err := pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "bootstrap", challenge)
		must(t, err)
		check(verify(t, pf, jws), false)
		// the projection is signed: any change to a descriptor fails verification
		parts := strings.Split(jws, ".")
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		must(t, err)
		for _, swap := range [][2]string{{`"generation":2`, `"generation":3`}, {`"name":"DB_ADMIN"`, `"name":"DB_OTHER"`},
			{`"cdhash":"` + strings.Repeat("c", 40), `"cdhash":"` + strings.Repeat("d", 40)},
			{`"export-runtime-fd"`, `"export-other-fd"`}, {`"account":"credentials-v1"`, `"account":"credentials-v2"`}} {
			altered := bytes.Replace(payload, []byte(swap[0]), []byte(swap[1]), 1)
			if bytes.Equal(altered, payload) {
				t.Fatalf("fixture lacks %s", swap[0])
			}
			forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(altered) + "." + parts[2]
			if _, err := seal.VerifyType(forged, pf.svc.ReceiptKeysPublic(), seal.ReceiptJWSType); err == nil {
				t.Fatalf("altered projection %s verified", swap[1])
			}
		}
		for _, role := range []string{"approval-admin", "runtime", "db-admin"} {
			out, err := pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, role)
			must(t, err)
			clear(out.Value)
		}
		jws, err = pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "dispatch", challenge)
		must(t, err)
		check(verify(t, pf, jws), true)
	})
	t.Run("receipt_projection_follows_the_plan", func(t *testing.T) {
		// a plan with another helper SHA/CDHash/argv or Keychain item yields
		// those exact values in the signed projection (what A compares)
		pf := newPlanFixture(t, open, "ask")
		_, err := pf.svc.PutSecret(ctx, pf.f.person, "APPROVAL_ADMIN", []byte(fixtureApproval))
		must(t, err)
		raw := pf.planV3("receipt-0005")
		raw = bytes.Replace(raw, []byte(`"cdhash":"`+strings.Repeat("c", 40)), []byte(`"cdhash":"`+strings.Repeat("b", 40)), 1)
		raw = bytes.Replace(raw, []byte(`"export-runtime-fd","33"`), []byte(`"export-runtime-fd","33","--strict"`), 1)
		raw = bytes.Replace(raw, []byte(`"generation":1,"max_bytes":4096,"name":"APPROVAL_ADMIN"`), []byte(`"generation":2,"max_bytes":4096,"name":"APPROVAL_ADMIN"`), 1)
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		jws, err := pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "bootstrap", challenge)
		must(t, err)
		roles := verify(t, pf, jws)["roles"].([]any)
		kc := roles[1].(map[string]any)
		if kc["helper"].(map[string]any)["cdhash"] != strings.Repeat("b", 40) || len(kc["argv"].([]any)) != 4 ||
			roles[0].(map[string]any)["generation"] != float64(2) || roles[2].(map[string]any)["generation"] != float64(1) {
			t.Fatalf("projection %v", roles)
		}
	})
	t.Run("receipt_refusals", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		run := start(t, pf, "receipt-0002")
		for _, c := range []struct{ op, ch string }{{"use", challenge}, {"bootstrap", "AB"}, {"bootstrap", strings.Repeat("A", 64)}} {
			_, err := pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, c.op, c.ch)
			wantErr(t, err, nexus.ErrInvalid)
		}
		// a renewed credential never gets a receipt for the original run
		_, token, err := pf.svc.IssueExecutorCredential(ctx, pf.f.person, pf.root.Session.ID, pf.root.Delegation.ID, 3600e9)
		must(t, err)
		other, err := pf.svc.AuthenticateExecutor(ctx, token)
		must(t, err)
		_, err = pf.svc.SecretPlanReceipt(ctx, other, run.RunID, "bootstrap", challenge)
		wantErr(t, err, nexus.ErrForbidden)
		// lost authority: no receipt
		_, err = pf.svc.Revoke(ctx, pf.f.person, pf.root.Delegation.ID, "public fixture")
		must(t, err)
		if _, err = pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "bootstrap", challenge); err == nil {
			t.Fatal("receipt after delegation revocation")
		}
	})
	t.Run("receipt_plan2_refused", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		raw := pf.planV2("receipt-0003")
		_, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		wantErr(t, err, nexus.ErrInvalid) // plan/2 is refused outright now
	})
}
