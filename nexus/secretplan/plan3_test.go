package secretplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vectorPathV3 = "../../docs/evidence/secret-plan-v3/vectors.json"

// goodPlanV3 is goodPlan in the plan/3 a-executor/1 form.
func goodPlanV3() map[string]any {
	m := goodPlan()
	m["schema"] = SchemaV3
	m["consumer_profile"] = ProfileAExecutor
	schemas := []string{PayloadApprovalAdmin, PayloadRuntime, PayloadDBAdmin}
	for i, s := range schemas {
		r := roleAt(m, i)
		delete(r, "envelope")
		r["payload_schema"] = s
		r["delivery"] = DeliveryTyped
		if s == PayloadRuntime {
			r["helper_output_schema"] = PayloadRuntime
			r["expected_environment"] = "site-production"
		}
	}
	addClosure(m)
	return m
}

const (
	fxPython   = "/opt/fixture/python/bin/python3.12"
	fxStdlib   = "/opt/fixture/python/lib/python3.12"
	fxManifest = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	fxStdSHA   = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// addClosure turns a plan/2-shaped map into the plan/3 closure form: the
// direct interpreter, manifest-covered roots, typed cwd.
func addClosure(m map[string]any) {
	pins := m["pins"].(map[string]any)
	old := m["program"].(map[string]any)["interpreter"].(string)
	pins[fxPython] = pins[old]
	delete(pins, old)
	m["program"].(map[string]any)["interpreter"] = fxPython
	m["directory_manifests"] = []any{
		map[string]any{"root": "/fixture/a", "manifest_path": "/fixture/manifests/a.json", "manifest_sha256": fxManifest},
		map[string]any{"root": fxStdlib, "manifest_path": "/fixture/manifests/stdlib.json", "manifest_sha256": fxStdSHA},
	}
	m["import_policy"] = map[string]any{"version": ImportPolicyVersion, "implementation": ImplementationCPython,
		"interpreter": fxPython, "bootstrap": "/fixture/a/bootstrap.py", "stdlib_root": fxStdlib, "module_roots": []any{"/fixture/a"}}
	m["cwd"] = map[string]any{"path": "/fixture/a", "directory_manifest_sha256": fxManifest}
}

// genericV3: one opaque Nexus role, inherited output allowed.
func genericV3() map[string]any {
	m := goodPlanV3()
	m["consumer_profile"] = ProfileGeneric
	r := clone(roleAt(m, 0)).(map[string]any)
	r["role"], r["payload_schema"], r["max_bytes"] = "token", PayloadOpaque, int64(16384)
	m["roles"] = []any{r}
	m["output"] = map[string]any{"mode": "inherit", "schema_id": "generic-result/1", "keys": map[string]any{}}
	return m
}

func casesV3() []vector {
	good := Encode(goodPlanV3())
	gen := Encode(genericV3())
	out := []vector{{Name: "a-executor good", Input: string(good), Accept: true, Hash: Hash(good)},
		{Name: "generic opaque good", Input: string(gen), Accept: true, Hash: Hash(gen)}}
	mut := func(name, reason string, base func() map[string]any, f func(map[string]any)) {
		m := base()
		f(m)
		out = append(out, vector{Name: name, Input: string(Encode(m)), Reason: reason})
	}
	a := goodPlanV3
	mut("v3 with legacy envelope key", "role_keys", a, func(m map[string]any) { roleAt(m, 0)["envelope"] = "a-bridge-envelope/1" })
	mut("v2 envelope plan labelled v3 without profile", "keys", a, func(m map[string]any) { delete(m, "consumer_profile") })
	mut("unknown profile", "profile", a, func(m map[string]any) { m["consumer_profile"] = "a-executor/2" })
	mut("envelope delivery", "role_delivery", a, func(m map[string]any) { roleAt(m, 0)["delivery"] = "a-bridge-envelope/1" })
	mut("unknown payload schema", "role_payload", a, func(m map[string]any) { roleAt(m, 0)["payload_schema"] = "json/1" })
	mut("keychain opaque payload", "role_payload", a, func(m map[string]any) { roleAt(m, 1)["payload_schema"] = PayloadOpaque })
	mut("helper output schema differs", "role_payload", a, func(m map[string]any) { roleAt(m, 1)["helper_output_schema"] = PayloadOpaque })
	mut("keychain missing environment", "role_keys", a, func(m map[string]any) { delete(roleAt(m, 1), "expected_environment") })
	mut("keychain bad environment", "role_environment", a, func(m map[string]any) { roleAt(m, 1)["expected_environment"] = "SITE" })
	mut("nexus with helper output schema", "role_keys", a, func(m map[string]any) { roleAt(m, 0)["helper_output_schema"] = PayloadRuntime })
	mut("typed payload over 4096", "role_fd_or_size", a, func(m map[string]any) { roleAt(m, 0)["max_bytes"] = int64(4097) })
	mut("a profile swapped schemas", "profile_a", a, func(m map[string]any) {
		roleAt(m, 0)["payload_schema"], roleAt(m, 2)["payload_schema"] = PayloadDBAdmin, PayloadApprovalAdmin
	})
	mut("a profile opaque role", "profile_a", a, func(m map[string]any) { roleAt(m, 0)["payload_schema"] = PayloadOpaque })
	mut("a profile wrong order", "profile_a", a, func(m map[string]any) {
		r := m["roles"].([]any)
		r[0], r[2] = r[2], r[0]
	})
	mut("a profile two roles", "profile_a", a, func(m map[string]any) { m["roles"] = m["roles"].([]any)[:2] })
	mut("a profile inherit output", "output_profile", a, func(m map[string]any) {
		m["output"] = map[string]any{"mode": "inherit", "schema_id": "a-result/1", "keys": map[string]any{}}
	})
	// §2 closure
	dm := func(m map[string]any, i int) map[string]any {
		return m["directory_manifests"].([]any)[i].(map[string]any)
	}
	ip := func(m map[string]any) map[string]any { return m["import_policy"].(map[string]any) }
	mut("no directory manifests", "directory_manifests", a, func(m map[string]any) { m["directory_manifests"] = []any{} })
	mut("overlapping roots", "directory_overlap", a, func(m map[string]any) { dm(m, 1)["root"] = "/fixture/a/sub" })
	mut("manifest inside its root", "directory_manifests", a, func(m map[string]any) { dm(m, 0)["manifest_path"] = "/fixture/a/m.json" })
	mut("manifest sha not hex", "directory_manifests", a, func(m map[string]any) { dm(m, 0)["manifest_sha256"] = "x" })
	mut("import policy version", "import_policy", a, func(m map[string]any) { ip(m)["version"] = "newtype.import-policy/2" })
	mut("implementation pypy", "import_policy", a, func(m map[string]any) { ip(m)["implementation"] = "pypy" })
	mut("stdlib not covered", "import_closure", a, func(m map[string]any) { ip(m)["stdlib_root"] = "/usr/lib/python3" })
	mut("module root not covered", "import_closure", a, func(m map[string]any) { ip(m)["module_roots"] = []any{"/fixture/b"} })
	mut("duplicate module root", "import_closure", a, func(m map[string]any) { ip(m)["module_roots"] = []any{"/fixture/a", "/fixture/a"} })
	mut("bootstrap outside roots", "import_closure", a, func(m map[string]any) { ip(m)["bootstrap"] = "/tmp/bootstrap.py" })
	mut("launcher stub interpreter", "import_interpreter", a, func(m map[string]any) { ip(m)["interpreter"] = "/usr/bin/python3" })
	mut("cwd string", "cwd", a, func(m map[string]any) { m["cwd"] = "/fixture/a" })
	mut("cwd other manifest sha", "cwd", a, func(m map[string]any) { m["cwd"].(map[string]any)["directory_manifest_sha256"] = fxStdSHA })
	mut("cwd not a manifest root", "cwd", a, func(m map[string]any) { m["cwd"].(map[string]any)["path"] = "/fixture" })
	mut("generic with A db-admin schema", "profile_generic", genericV3, func(m map[string]any) {
		roleAt(m, 0)["payload_schema"] = PayloadDBAdmin
		roleAt(m, 0)["max_bytes"] = int64(4096)
	})
	mut("generic with A approval schema", "profile_generic", genericV3, func(m map[string]any) {
		roleAt(m, 0)["payload_schema"] = PayloadApprovalAdmin
		roleAt(m, 0)["max_bytes"] = int64(4096)
	})
	return out
}

func TestVectorsV3(t *testing.T) {
	got := casesV3()
	if *update {
		raw, err := json.MarshalIndent(map[string]any{"schema": SchemaV3, "note": "shared Go/Python plan/3 vectors; accept => plan_hash, reject => reason", "vectors": got}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Dir(vectorPathV3), 0o755)
		if err := os.WriteFile(vectorPathV3, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.ReadFile(vectorPathV3)
	if err != nil {
		t.Fatal("v3 vectors missing; run with -update-vectors")
	}
	var stored struct {
		Vectors []vector `json:"vectors"`
	}
	if json.Unmarshal(file, &stored) != nil || len(stored.Vectors) != len(got) {
		t.Fatalf("v3 vector file out of date (%d stored, %d in code)", len(stored.Vectors), len(got))
	}
	for i, v := range stored.Vectors {
		if v != got[i] {
			t.Fatalf("v3 vector %d (%s) differs", i, v.Name)
		}
		p, err := Validate([]byte(v.Input))
		if v.Accept {
			if err != nil || p.Hash != v.Hash || p.Version != 3 {
				t.Fatalf("%s: %v", v.Name, err)
			}
		} else if err == nil || err.Error() != "secret plan: "+v.Reason {
			t.Fatalf("%s: want %s got %v", v.Name, v.Reason, err)
		}
	}
}

func TestPayloadSchemas(t *testing.T) {
	p, err := Validate(Encode(goodPlanV3()))
	if err != nil {
		t.Fatal(err)
	}
	admin, runtime, db := p.Roles[0], p.Roles[1], p.Roles[2]
	pw := strings.Repeat("A", 43) // 32 bytes of base64url without padding
	ok := map[*Role]string{
		&admin:   `{"adminToken":"` + strings.Repeat("t", 32) + `","version":1}`,
		&runtime: `{"environment":"site-production","runtimePassword":"` + pw + `","version":1}`,
		&db:      `{"dbPassword":"PUBLIC-FIXTURE-PW-16","version":1}`,
	}
	for r, b := range ok {
		if err := ValidatePayload(*r, []byte(b)); err != nil {
			t.Fatalf("%s: %v", r.Role, err)
		}
	}
	bad := []struct {
		r Role
		b string
	}{
		{admin, `{"adminToken":"short","version":1}`},
		{admin, `{"adminToken":"` + strings.Repeat("t", 32) + `","version":true}`},
		{admin, `{"adminToken":"` + strings.Repeat("t", 32) + `","version":1.0}`},
		{admin, `{"adminToken":"` + strings.Repeat("t", 32) + `","version":1,"x":1}`},
		{admin, `{"adminToken":"` + strings.Repeat("t", 32) + `","adminToken":"` + strings.Repeat("u", 32) + `","version":1}`},
		{admin, `{"adminToken":"` + strings.Repeat("t", 32) + `","version":1}` + "\n"},
		{runtime, `{"environment":"site-staging","runtimePassword":"` + pw + `","version":1}`},
		{runtime, `{"environment":"site-production","runtimePassword":"` + pw + `=","version":1}`},
		{runtime, `{"environment":"site-production","runtimePassword":"` + pw[:42] + `","version":1}`},
		{db, `{"dbPassword":"short","version":1}`},
		{db, `{"dbPassword":"PUBLIC-FIXTURE-PW\u0001-16","version":1}`},
		{db, `{"dbPassword":["x"],"version":1}`},
		{db, `{"adminToken":"` + strings.Repeat("t", 32) + `","version":1}`}, // cross-role substitution
		{db, ``},
		{db, `{"dbPassword":"` + strings.Repeat("p", 4090) + `","version":1}`}, // over the 4096 delivered budget
	}
	for i, c := range bad {
		if err := ValidatePayload(c.r, []byte(c.b)); err == nil {
			t.Errorf("bad payload %d (%s) accepted", i, c.r.Role)
		} else if strings.Contains(err.Error(), "PUBLIC") || strings.Contains(err.Error(), "tttt") {
			t.Fatal("error carries payload text")
		}
	}
}
