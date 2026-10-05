package conformance

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/secretplan"
)

// planV3 is the fixture plan in the plan/3 a-executor/1 form.
func (pf *planFixture) planV3(attempt string) []byte {
	m, err := secretplan.Parse(pf.planV2(attempt))
	if err != nil {
		panic(err)
	}
	top := m.(map[string]any)
	top["schema"] = secretplan.SchemaV3
	top["consumer_profile"] = secretplan.ProfileAExecutor
	for i, s := range []string{secretplan.PayloadApprovalAdmin, secretplan.PayloadRuntime, secretplan.PayloadDBAdmin} {
		r := top["roles"].([]any)[i].(map[string]any)
		delete(r, "envelope")
		r["payload_schema"], r["delivery"] = s, secretplan.DeliveryTyped
		if s == secretplan.PayloadRuntime {
			r["helper_output_schema"], r["expected_environment"] = secretplan.PayloadRuntime, "site-production"
		}
	}
	// §2 closure: direct interpreter, manifest-covered roots, typed cwd
	pins := top["pins"].(map[string]any)
	prog := top["program"].(map[string]any)
	pins["/opt/fxpy/bin/python3.12"] = pins[prog["interpreter"].(string)]
	delete(pins, prog["interpreter"].(string))
	prog["interpreter"] = "/opt/fxpy/bin/python3.12"
	sha := strings.Repeat("e", 64)
	top["directory_manifests"] = []any{
		map[string]any{"root": "/fixture", "manifest_path": "/manifests/fixture.json", "manifest_sha256": sha},
		map[string]any{"root": "/opt/fxpy/lib", "manifest_path": "/manifests/stdlib.json", "manifest_sha256": strings.Repeat("f", 64)},
	}
	top["import_policy"] = map[string]any{"version": secretplan.ImportPolicyVersion, "implementation": secretplan.ImplementationCPython,
		"interpreter": "/opt/fxpy/bin/python3.12", "bootstrap": "/fixture/bootstrap.py", "stdlib_root": "/opt/fxpy/lib", "module_roots": []any{"/fixture"}}
	top["cwd"] = map[string]any{"path": "/fixture", "directory_manifest_sha256": sha}
	return secretplan.Encode(top)
}

// runSecretPlanV3: Nexus releases a plan/3 value only if it matches the
// role's payload schema.
func runSecretPlanV3(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	t.Run("secret_plan_v3_payload_checked_before_release", func(t *testing.T) {
		pf := newPlanFixture(t, open, "ask")
		// valid approval-admin wire, invalid db-admin wire (generation 2 of each)
		_, err := pf.svc.PutSecret(ctx, pf.f.person, "APPROVAL_ADMIN", []byte(`{"adminToken":"PUBLIC_FIXTURE_ADMIN_TOKEN_0123456789","version":1}`))
		must(t, err)
		_, err = pf.svc.PutSecret(ctx, pf.f.person, "DB_ADMIN", []byte(`{"dbPassword":"short","version":1}`))
		must(t, err)
		raw := bytes.Replace(pf.planV3("v3-payload-0001"), []byte(`"generation":1`), []byte(`"generation":2`), -1)
		run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
		must(t, err)
		out, err := pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "approval-admin")
		must(t, err)
		clear(out.Value)
		out, err = pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "runtime")
		must(t, err)
		_, err = pf.svc.ReleaseSecretPlanRole(ctx, pf.exec, run.RunID, "db-admin")
		wantErr(t, err, nexus.ErrConflict) // schema mismatch: nothing released
	})
}
