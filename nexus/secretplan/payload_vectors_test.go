package secretplan

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const payloadVectorPath = "../../docs/evidence/secret-plan-v3/payload_vectors.json"

type payloadVector struct {
	Name        string `json:"name"`
	Schema      string `json:"schema"`
	Environment string `json:"expected_environment"`
	MaxBytes    int64  `json:"max_bytes"`
	RawB64      string `json:"raw_b64"`
	Accept      bool   `json:"accept"`
	Reason      string `json:"reason,omitempty"`
}

func payloadCases() []payloadVector {
	pw := strings.Repeat("A", 43)
	tok := strings.Repeat("t", 32)
	db := "PUBLIC-FIXTURE-PW-16"
	rt := func(env, p string) string {
		return `{"environment":"` + env + `","runtimePassword":"` + p + `","version":1}`
	}
	out := []payloadVector{}
	add := func(name, schema, raw string, accept bool, reason string) {
		out = append(out, payloadVector{Name: name, Schema: schema, Environment: "site-production", MaxBytes: TypedMax,
			RawB64: base64.StdEncoding.EncodeToString([]byte(raw)), Accept: accept, Reason: reason})
	}
	// approval-admin
	add("admin ok", PayloadApprovalAdmin, `{"adminToken":"`+tok+`","version":1}`, true, "")
	add("admin ok spaced", PayloadApprovalAdmin, `{"adminToken": "`+tok+`", "version": 1}`, true, "")
	add("admin short", PayloadApprovalAdmin, `{"adminToken":"short","version":1}`, false, "payload_approval_admin")
	add("admin version true", PayloadApprovalAdmin, `{"adminToken":"`+tok+`","version":true}`, false, "payload_approval_admin")
	add("admin version 1.0", PayloadApprovalAdmin, `{"adminToken":"`+tok+`","version":1.0}`, false, "payload_approval_admin")
	add("admin version string", PayloadApprovalAdmin, `{"adminToken":"`+tok+`","version":"1"}`, false, "payload_approval_admin")
	add("admin extra key", PayloadApprovalAdmin, `{"adminToken":"`+tok+`","version":1,"x":1}`, false, "payload_shape")
	add("admin duplicate key", PayloadApprovalAdmin, `{"adminToken":"`+tok+`","adminToken":"`+tok+`","version":1}`, false, "payload_shape")
	add("admin trailing newline", PayloadApprovalAdmin, `{"adminToken":"`+tok+`","version":1}`+"\n", false, "payload_shape")
	add("admin leading space", PayloadApprovalAdmin, ` {"adminToken":"`+tok+`","version":1}`, false, "payload_shape")
	add("db payload as admin", PayloadApprovalAdmin, `{"dbPassword":"`+db+`","version":1}`, false, "payload_shape")
	// runtime
	add("runtime ok", PayloadRuntime, rt("site-production", pw), true, "")
	add("runtime other env", PayloadRuntime, rt("site-staging", pw), false, "payload_environment")
	add("runtime bad env grammar", PayloadRuntime, rt("SITE", pw), false, "payload_runtime")
	add("runtime padded", PayloadRuntime, rt("site-production", pw+"="), false, "payload_runtime")
	add("runtime 42 chars", PayloadRuntime, rt("site-production", pw[:42]), false, "payload_runtime")
	add("runtime noncanonical bits", PayloadRuntime, rt("site-production", pw[:42]+"B"), false, "payload_runtime")
	add("runtime standard alphabet", PayloadRuntime, rt("site-production", pw[:42]+"+"), false, "payload_runtime")
	add("runtime nested", PayloadRuntime, `{"environment":["site-production"],"runtimePassword":"`+pw+`","version":1}`, false, "payload_shape")
	// db-admin: UTF-8 / scalar boundaries
	add("db ok", PayloadDBAdmin, `{"dbPassword":"`+db+`","version":1}`, true, "")
	add("db 16 bytes", PayloadDBAdmin, `{"dbPassword":"`+strings.Repeat("p", 16)+`","version":1}`, true, "")
	add("db 15 bytes", PayloadDBAdmin, `{"dbPassword":"`+strings.Repeat("p", 15)+`","version":1}`, false, "payload_db_admin")
	add("db 512 bytes", PayloadDBAdmin, `{"dbPassword":"`+strings.Repeat("p", 512)+`","version":1}`, true, "")
	add("db 513 bytes", PayloadDBAdmin, `{"dbPassword":"`+strings.Repeat("p", 513)+`","version":1}`, false, "payload_db_admin")
	add("db multibyte counts bytes", PayloadDBAdmin, `{"dbPassword":"`+strings.Repeat("é", 8)+`","version":1}`, true, "")
	add("db valid surrogate pair", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-😀","version":1}`, true, "")
	add("db literal U+FFFD", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-�","version":1}`, true, "")
	add("db lone high surrogate", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\ud800x","version":1}`, false, "payload_encoding")
	add("db lone low surrogate", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\udc00x","version":1}`, false, "payload_encoding")
	add("db invalid utf-8", PayloadDBAdmin, "{\"dbPassword\":\"PUBLIC-FIXTURE-\xff-\",\"version\":1}", false, "payload_encoding")
	add("db C0 control", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\u0001-","version":1}`, false, "payload_db_admin")
	add("db DEL", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\u007f-","version":1}`, false, "payload_db_admin")
	add("db C1 control", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\u0085-","version":1}`, false, "payload_db_admin")
	add("db empty", PayloadDBAdmin, ``, false, "payload_size")
	big := `{"dbPassword":"` + strings.Repeat("p", 4096-len(`{"dbPassword":"","version":1}`)) + `","version":1}`
	add("db exactly 4096 delivered bytes", PayloadDBAdmin, big, false, "payload_db_admin") // size ok, password > 512
	add("db 4097 delivered bytes", PayloadDBAdmin, big[:1]+" "+big[1:], false, "payload_size")
	// P3-2-R1: precedence and exact four-hex escapes
	add("runtime wrong env and bad password", PayloadRuntime, rt("site-staging", "short!"), false, "payload_environment")
	add("db escape with space", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\u 085-","version":1}`, false, "payload_encoding")
	add("db escape with sign", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\u+085-","version":1}`, false, "payload_encoding")
	add("db escape non-hex", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\u00g1-","version":1}`, false, "payload_encoding")
	add("db high surrogate then bad low", PayloadDBAdmin, `{"dbPassword":"PUBLIC-FIXTURE-\ud83d\u 00-","version":1}`, false, "payload_encoding")
	add("admin payload as db", PayloadDBAdmin, `{"adminToken":"`+tok+`","version":1}`, false, "payload_shape")
	return out
}

func TestPayloadVectors(t *testing.T) {
	got := payloadCases()
	if *update {
		raw, _ := json.MarshalIndent(map[string]any{"schema": "newtype.plan3-payload/1", "note": "shared Go/Python typed-payload vectors (raw delivered bytes)", "vectors": got}, "", "  ")
		if err := os.WriteFile(payloadVectorPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.ReadFile(payloadVectorPath)
	if err != nil {
		t.Fatal("payload vectors missing; run with -update-vectors")
	}
	var stored struct {
		Vectors []payloadVector `json:"vectors"`
	}
	if json.Unmarshal(file, &stored) != nil || len(stored.Vectors) != len(got) {
		t.Fatal("payload vectors out of date")
	}
	for i, v := range stored.Vectors {
		if v != got[i] {
			t.Fatalf("vector %d (%s) differs", i, v.Name)
		}
		raw, _ := base64.StdEncoding.DecodeString(v.RawB64)
		r := Role{PayloadSchema: v.Schema, MaxBytes: v.MaxBytes, ExpectedEnvironment: v.Environment}
		err := ValidatePayload(r, raw)
		if v.Accept != (err == nil) || (!v.Accept && err.Error() != "secret plan: "+v.Reason) {
			t.Errorf("%s: accept=%v got %v", v.Name, v.Accept, err)
		}
	}
}
