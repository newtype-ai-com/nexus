package secretplan

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
)

var update = flag.Bool("update-vectors", false, "rewrite docs/evidence/secret-plan-v2/vectors.json")

// vectorPath: the general plan rules, ported to plan/3. The historical
// plan/2 file stays as a downgrade fixture: every entry must now be refused.
const vectorPath = "../../docs/evidence/secret-plan-v3/vectors-rules.json"
const legacyVectorPath = "../../docs/evidence/secret-plan-v2/vectors.json"

// Public fixture identifiers (fixed so vectors are stable).
const (
	fxAccount    = "nt_01M40AAAAAAAAAAAAAAAAAAAAA"
	fxSession    = "slv_01M40BBBBBBBBBBBBBBBBBBBBB"
	fxDelegation = "mnd_01M40CCCCCCCCCCCCCCCCCCCCC"
	fxSHA        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fxHelperSHA  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fxCDHash     = "cccccccccccccccccccccccccccccccccccccccc"
	fxEvidence   = "dddddddddddddddddddddddddddddddddddddddd" + "dddddddddddddddddddddddd"
)

func goodPlan() map[string]any {
	kc := KeychainItemID("/Users/fixture/Library/Keychains/login.keychain-db", "org.newtype.fixture", "credentials-v1")
	return map[string]any{
		"schema": Schema, "issuer": "https://nexus.example.test",
		"account": fxAccount, "session": fxSession, "delegation": fxDelegation, "attempt": "a-fixture-0001",
		"program":   map[string]any{"interpreter": "/usr/bin/python3", "script": "/fixture/a/caller.py", "args": []any{"--plan", "/fixture/a/manifest.json"}},
		"bootstrap": map[string]any{"shim": "/fixture/bin/newtype-fd-shim", "executor": "/fixture/bin/newtype"},
		"pins": map[string]any{
			"/usr/bin/python3": fxSHA, "/fixture/a/caller.py": fxSHA, "/fixture/a/manifest.json": fxSHA,
			"/fixture/bin/newtype-fd-shim": fxSHA, "/fixture/bin/newtype": fxSHA, "/fixture/helper/keychain-helper-v1": fxHelperSHA,
		},
		"cwd": "/fixture/a", "env": map[string]any{}, "stdin": "devnull",
		"roles": []any{
			map[string]any{"role": "approval-admin", "source": "nexus", "name": "APPROVAL_ADMIN", "generation": int64(3),
				"resource": "secret:nexus:APPROVAL_ADMIN", "fd": int64(35), "max_bytes": int64(4096), "envelope": "a-bridge-envelope/1"},
			map[string]any{"role": "runtime", "source": "keychain-helper",
				"ref":    map[string]any{"keychain": "/Users/fixture/Library/Keychains/login.keychain-db", "service": "org.newtype.fixture", "account": "credentials-v1"},
				"helper": map[string]any{"path": "/fixture/helper/keychain-helper-v1", "sha256": fxHelperSHA, "cdhash": fxCDHash},
				"argv":   []any{"/fixture/helper/keychain-helper-v1", "export-runtime-fd", "33"},
				"schema": int64(1), "custody_evidence_sha256": fxEvidence,
				"resource": "secret:keychain:" + kc, "fd": int64(33), "max_bytes": int64(4096), "envelope": "a-bridge-envelope/1"},
			map[string]any{"role": "db-admin", "source": "nexus", "name": "DB_ADMIN", "generation": int64(7),
				"resource": "secret:nexus:DB_ADMIN", "fd": int64(34), "max_bytes": int64(4096), "envelope": "a-bridge-envelope/1"},
		},
		"control_fd":      int64(36),
		"output":          map[string]any{"mode": "enum-json", "schema_id": "a-result/1", "keys": map[string]any{"status": []any{"blocked", "dispatched", "unknown"}}},
		"timeout_seconds": int64(300), "cleanup_seconds": int64(15), "expires_at": int64(1791077400),
	}
}

// clone deep-copies a fixture map so mutations stay local.
func clone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = clone(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = clone(e)
		}
		return out
	}
	return v
}

func roleAt(m map[string]any, i int) map[string]any { return m["roles"].([]any)[i].(map[string]any) }

type vector struct {
	Name   string `json:"name"`
	Input  string `json:"input"`
	Accept bool   `json:"accept"`
	Reason string `json:"reason,omitempty"`
	Hash   string `json:"plan_hash,omitempty"`
}

// cases returns the shared vector set: name -> raw bytes, expected reason ("" = accept).
func cases() []vector {
	good := Encode(goodPlanV3())
	out := []vector{{Name: "good", Input: string(good), Accept: true, Hash: Hash(good)}}
	add := func(name, reason string, raw []byte) {
		out = append(out, vector{Name: name, Input: string(raw), Reason: reason})
	}
	mut := func(name, reason string, f func(map[string]any)) {
		m := clone(goodPlanV3()).(map[string]any)
		f(m)
		add(name, reason, Encode(m))
	}
	gs := string(good)
	add("not canonical: space", "not_canonical", []byte(strings.Replace(gs, `":`, `": `, 1)))
	add("not canonical: key order", "not_canonical", []byte(strings.Replace(gs, `{"account":`, `{"zz":1,"account":`, 1)))
	add("duplicate key nested", "duplicate_key", []byte(strings.Replace(gs, `"args":[`, `"args":["x"],"args":[`, 1)))
	add("float", "integer", []byte(strings.Replace(gs, `"control_fd":36`, `"control_fd":36.0`, 1)))
	add("exponent", "integer", []byte(strings.Replace(gs, `"control_fd":36`, `"control_fd":3.6e1`, 1)))
	add("non-ascii byte", "non_ascii", []byte(strings.Replace(gs, `a-fixture-0001`, "a-fixtur\xc3\xa9-0001", 1)))
	add("unicode escape", "string", []byte(strings.Replace(gs, `a-fixture-0001`, `a-fixtur\u00e9-0001`, 1)))
	add("control escape", "string", []byte(strings.Replace(gs, `a-fixture-0001`, `a-fixture\n0001`, 1)))
	add("trailing", "trailing", append(append([]byte{}, good...), []byte(" {}")...))
	mut("schema v1", "schema", func(m map[string]any) { m["schema"] = "newtype.secret-plan/1" })
	mut("extra key", "keys", func(m map[string]any) { m["extra"] = true })
	mut("missing pins", "keys", func(m map[string]any) { delete(m, "pins") })
	mut("foreign agent session", "actor", func(m map[string]any) { m["session"] = "ags_01M408V9XW0E13A5J7BVKMGC8A" })
	mut("http issuer", "actor", func(m map[string]any) { m["issuer"] = "http://nexus.example.test" })
	mut("relative script", "program", func(m map[string]any) { m["program"].(map[string]any)["script"] = "caller.py" })
	mut("env not empty", "stdio", func(m map[string]any) { m["env"] = map[string]any{"A": "1"} })
	mut("no roles", "roles", func(m map[string]any) { m["roles"] = []any{} })
	mut("unknown source", "role_source", func(m map[string]any) { roleAt(m, 0)["source"] = "env" })
	mut("nexus generation string", "role_nexus", func(m map[string]any) { roleAt(m, 0)["generation"] = "3" })
	mut("nexus generation bool", "role_nexus", func(m map[string]any) { roleAt(m, 0)["generation"] = true })
	mut("nexus generation zero", "role_nexus", func(m map[string]any) { roleAt(m, 0)["generation"] = int64(0) })
	mut("keychain with generation", "role_keys", func(m map[string]any) { roleAt(m, 1)["generation"] = int64(1) })
	mut("keychain generation null", "role_keys", func(m map[string]any) { roleAt(m, 1)["generation"] = nil })
	mut("nexus with schema", "role_keys", func(m map[string]any) { roleAt(m, 0)["schema"] = int64(1) })
	mut("keychain schema 2", "role_keychain", func(m map[string]any) { roleAt(m, 1)["schema"] = int64(2) })
	mut("resource mismatch nexus", "resource", func(m map[string]any) { roleAt(m, 0)["resource"] = "secret:nexus:OTHER" })
	mut("resource cross source", "resource", func(m map[string]any) { roleAt(m, 1)["resource"] = "secret:nexus:credentials-v1" })
	mut("role fd 0", "role_fd_or_size", func(m map[string]any) { roleAt(m, 0)["fd"] = int64(0) })
	mut("role fd 36", "role_fd_or_size", func(m map[string]any) { roleAt(m, 0)["fd"] = int64(36) })
	mut("duplicate fd", "role_duplicate", func(m map[string]any) { roleAt(m, 2)["fd"] = int64(35) })
	mut("control collides", "control_fd", func(m map[string]any) { m["control_fd"] = int64(33) })
	mut("control 37", "control_fd", func(m map[string]any) { m["control_fd"] = int64(37) })
	mut("typed payload over 4096", "role_fd_or_size", func(m map[string]any) { roleAt(m, 0)["max_bytes"] = int64(4097) })
	mut("opaque over 16384", "role_fd_or_size", func(m map[string]any) {
		roleAt(m, 0)["payload_schema"] = PayloadOpaque
		roleAt(m, 0)["max_bytes"] = int64(16385)
	})
	mut("helper argv0 differs", "role_helper", func(m map[string]any) { roleAt(m, 1)["argv"].([]any)[0] = "/other" })
	mut("helper unpinned", "helper_pin", func(m map[string]any) { delete(m["pins"].(map[string]any), "/fixture/helper/keychain-helper-v1") })
	mut("helper pin differs", "helper_pin", func(m map[string]any) { m["pins"].(map[string]any)["/fixture/helper/keychain-helper-v1"] = fxSHA })
	mut("shim unpinned", "pins_required", func(m map[string]any) { delete(m["pins"].(map[string]any), "/fixture/bin/newtype-fd-shim") })
	mut("output inherit with keys", "output", func(m map[string]any) { m["output"].(map[string]any)["mode"] = "inherit" })
	mut("output free text", "output", func(m map[string]any) {
		m["output"].(map[string]any)["keys"] = map[string]any{"status": []any{"Any Text"}}
	})
	mut("timeout 601", "times", func(m map[string]any) { m["timeout_seconds"] = int64(601) })
	mut("cleanup 0", "times", func(m map[string]any) { m["cleanup_seconds"] = int64(0) })
	// NB12-R7: canonical path spelling, generation domain, A profile output
	mut("script dot component", "program", func(m map[string]any) { m["program"].(map[string]any)["script"] = "/fixture/./caller.py" })
	mut("script dotdot component", "program", func(m map[string]any) {
		m["program"].(map[string]any)["script"] = "/fixture/x/../caller.py"
	})
	mut("cwd trailing slash", "cwd", func(m map[string]any) { m["cwd"] = "/fixture/" })
	mut("interpreter double slash", "program", func(m map[string]any) { m["program"].(map[string]any)["interpreter"] = "/usr//bin/python3" })
	mut("keychain dot alias", "role_keychain", func(m map[string]any) {
		roleAt(m, 1)["ref"].(map[string]any)["keychain"] = "/fixture/./kc.keychain-db"
	})
	mut("nexus generation 2^53", "role_nexus", func(m map[string]any) { roleAt(m, 0)["generation"] = MaxInt })
	mut("inherit output with A profile", "output_profile", func(m map[string]any) {
		m["output"].(map[string]any)["mode"] = "inherit"
		m["output"].(map[string]any)["keys"] = map[string]any{}
	})
	mut("five roles", "roles", func(m map[string]any) {
		r := m["roles"].([]any)
		m["roles"] = append(r, clone(r[0]), clone(r[2]))
	})
	return out
}

func TestVectors(t *testing.T) {
	got := cases()
	if *update {
		raw, err := json.MarshalIndent(map[string]any{"schema": SchemaV3, "note": "general plan rules on plan/3; accept => plan_hash, reject => reason", "vectors": got}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal("vectors missing; run go test ./nexus/secretplan -run TestVectors -update-vectors")
	}
	var stored struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(file, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Vectors) != len(got) {
		t.Fatalf("vector file has %d cases, code has %d", len(stored.Vectors), len(got))
	}
	for i, v := range stored.Vectors {
		if v != got[i] {
			t.Fatalf("vector %q drifted from the code", v.Name)
		}
		p, err := Validate([]byte(v.Input))
		switch {
		case v.Accept && err != nil:
			t.Errorf("%s: refused: %v", v.Name, err)
		case v.Accept && p.Hash != v.Hash:
			t.Errorf("%s: hash", v.Name)
		case !v.Accept && err == nil:
			t.Errorf("%s: accepted", v.Name)
		case !v.Accept && err.(Error) != Error(v.Reason):
			t.Errorf("%s: reason %q want %q", v.Name, err, v.Reason)
		}
	}
}

func TestGoodPlanFields(t *testing.T) {
	p, err := Validate(Encode(goodPlanV3()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roles) != 3 || p.Roles[1].Source != "keychain-helper" || p.Roles[1].FD != 33 || p.Roles[0].Generation != 3 || p.ControlFD != 36 {
		t.Fatalf("%+v", p)
	}
	order := []string{}
	for _, r := range p.Roles {
		order = append(order, r.Role)
	}
	if strings.Join(order, ",") != "approval-admin,runtime,db-admin" {
		t.Fatal("role order not preserved")
	}
	if ids.Check(ids.KindSession, p.Session) != nil || !strings.HasPrefix(p.Hash, "sha256:") {
		t.Fatal("actor/hash")
	}
}

func TestBoundsAndErrorsCarryNoInput(t *testing.T) {
	deep := strings.Repeat(`{"a":`, MaxDepth+1) + "1" + strings.Repeat("}", MaxDepth+1)
	if _, err := Parse([]byte(deep)); err != Error("too_deep") {
		t.Fatalf("depth: %v", err)
	}
	many := make([]string, MaxCollection+1)
	for i := range many {
		many[i] = "1"
	}
	if _, err := Parse([]byte("[" + strings.Join(many, ",") + "]")); err != Error("too_many") {
		t.Fatalf("collection: %v", err)
	}
	if _, err := Parse([]byte(`"` + strings.Repeat("x", MaxString+1) + `"`)); err != Error("string") {
		t.Fatalf("string: %v", err)
	}
	if _, err := Parse([]byte(`9007199254740993`)); err != Error("integer") {
		t.Fatalf("int range: %v", err)
	}
	_, err := Validate([]byte(`{"PUBLIC_SENTINEL":1}`))
	if err == nil || strings.Contains(err.Error(), "PUBLIC_SENTINEL") {
		t.Fatal("input reflected")
	}
	keys := []string{}
	for k := range goodPlan() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) != 18 {
		t.Fatal("fixture key count")
	}
}

// TestLegacyPlan2Refused: plan/2 (envelope-labelled) plans are refused under
// the plan/3 contract, never reinterpreted (schema ruling §1).
func TestLegacyPlan2Refused(t *testing.T) {
	file, err := os.ReadFile(legacyVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(file, &stored); err != nil || len(stored.Vectors) == 0 {
		t.Fatal("legacy vectors")
	}
	for _, v := range stored.Vectors {
		if _, err := Validate([]byte(v.Input)); err == nil {
			t.Errorf("legacy %s accepted", v.Name)
		}
	}
	if _, err := Validate(Encode(goodPlan())); err != Error("schema") {
		t.Fatalf("plan/2 good plan: %v", err)
	}
}
