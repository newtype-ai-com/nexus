package conformance

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/seal"
)

const receiptVectorPath = "../docs/evidence/run-receipt/vectors.json"

// TestReceiptVectors writes Go-signed public-fixture receipts for the Python
// verifier (NT_UPDATE_RECEIPT_VECTORS=1) and always checks the stored file
// still verifies with the Go verifier.
func TestReceiptVectors(t *testing.T) {
	if os.Getenv("NT_UPDATE_RECEIPT_VECTORS") == "1" {
		writeReceiptVectors(t)
	}
	raw, err := os.ReadFile(receiptVectorPath)
	if err != nil {
		t.Fatal("receipt vectors missing; run with NT_UPDATE_RECEIPT_VECTORS=1")
	}
	var file struct {
		Anchors []seal.PublicKey `json:"anchors"`
		Good    string           `json:"good_receipt"`
	}
	must(t, json.Unmarshal(raw, &file))
	if _, err := seal.VerifyType(file.Good, file.Anchors, seal.ReceiptJWSType); err != nil {
		t.Fatal("stored good receipt no longer verifies in Go")
	}
}

func writeReceiptVectors(t *testing.T) {
	ctx := context.Background()
	pf := newPlanFixture(t, func() nexus.Store { return nexus.NewMemStore() }, "ask")
	challenge := strings.Repeat("cd", 32)
	_, err := pf.svc.PutSecret(ctx, pf.f.person, "APPROVAL_ADMIN", []byte(`{"adminToken":"PUBLIC_FIXTURE_ADMIN_TOKEN_0123456789","version":1}`))
	must(t, err)
	raw := []byte(strings.Replace(string(pf.planV3("receipt-vector-01")), `"generation":1`, `"generation":2`, 1))
	run, err := pf.svc.StartSecretPlan(ctx, pf.exec, raw, pf.approve(t, raw))
	must(t, err)
	good, err := pf.svc.SecretPlanReceipt(ctx, pf.exec, run.RunID, "bootstrap", challenge)
	must(t, err)
	payload, err := seal.VerifyType(good, pf.svc.ReceiptKeysPublic(), seal.ReceiptJWSType)
	must(t, err)
	var p map[string]any
	must(t, json.Unmarshal(payload, &p))
	// the same fixture key signs a delegation-typed JWS over the same payload
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	signer, _ := seal.NewEd25519Signer(ed25519.NewKeyFromSeed(seed), "fixture-v1")
	wrongTyp, _ := signer.SignJWS(seal.JWSType, payload)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), challenge, strings.Repeat("ce", 32), 1))) + "." + parts[2]
	other, _ := seal.NewEd25519Signer(ed25519.NewKeyFromSeed(make([]byte, 32)), "fixture-v1")
	foreign, _ := other.SignJWS(seal.ReceiptJWSType, payload)
	expected := map[string]any{}
	for _, k := range []string{"issuer", "account", "session", "delegation", "credential_id", "run_id", "attempt", "plan_hash", "consumer_profile", "roles", "program", "import_policy", "cwd"} {
		expected[k] = p[k]
	}
	issued := p["issued_at"].(float64)
	// signed variants with the public fixture key: raw header/payload bytes
	key := ed25519.NewKeyFromSeed(seed)
	b64 := base64.RawURLEncoding.EncodeToString
	sign := func(header, payload string) string {
		in := b64([]byte(header)) + "." + b64([]byte(payload))
		return in + "." + b64(ed25519.Sign(key, []byte(in)))
	}
	goodHeader := `{"alg":"EdDSA","kid":"fixture-v1","typ":"newtype-run-receipt+jws"}`
	ps := string(payload)
	fdFloat := strings.Replace(ps, `"fd":35,`, `"fd":35.0,`, 1)
	relInt := strings.Replace(ps, `"released":false`, `"released":0`, 1)
	dupKey := strings.Replace(ps, `{"account":`, `{"account":"nt_00000000000000000000000000","account":`, 1)
	phase := strings.Replace(ps, `"released":false`, `"released":true`, 1)
	// run-receipt/2 descriptors (AV2-R2): correctly signed but not what the
	// consumer expects (binding), or malformed descriptors (payload)
	swap := func(old, new string) string {
		out := strings.Replace(ps, old, new, 1)
		if out == ps {
			t.Fatalf("vector fixture lacks %s", old)
		}
		return out
	}
	genOther := swap(`"generation":2`, `"generation":3`)
	genFloat := swap(`"generation":2`, `"generation":2.0`)
	cdOther := swap(`"cdhash":"`+strings.Repeat("c", 40), `"cdhash":"`+strings.Repeat("d", 40))
	argvOther := swap(`"export-runtime-fd","33"`, `"export-runtime-fd","34"`)
	itemOther := swap(`"service":"org.newtype.fixture"`, `"service":"org.newtype.other"`)
	nameOther := swap(`"name":"APPROVAL_ADMIN"`, `"name":"APPROVAL_OTHER"`)
	v1 := swap(`"version":"newtype.run-receipt/2"`, `"version":"newtype.run-receipt/1"`)
	out := map[string]any{
		"schema":       "newtype.run-receipt.vectors/2",
		"note":         "public fixture key (seed 0..31, kid fixture-v1); never a production trust anchor",
		"anchors":      pf.svc.ReceiptKeysPublic(),
		"good_receipt": good,
		"expected":     expected,
		"challenge":    challenge,
		"op":           "bootstrap",
		"now":          int64(issued),
		"cases": []map[string]any{
			{"name": "good", "jws": good, "now": int64(issued), "accept": true},
			{"name": "wrong typ (delegation certificate)", "jws": wrongTyp, "now": int64(issued), "reason": "receipt_header"},
			{"name": "tampered payload", "jws": tampered, "now": int64(issued), "reason": "receipt_signature"},
			{"name": "foreign key same kid", "jws": foreign, "now": int64(issued), "reason": "receipt_signature"},
			{"name": "expired", "jws": good, "now": int64(p["expires_at"].(float64)), "reason": "receipt_expired"},
			{"name": "not yet valid", "jws": good, "now": int64(issued) - 5, "reason": "receipt_expired"},
			{"name": "two parts", "jws": parts[0] + "." + parts[1], "now": int64(issued), "reason": "receipt_shape"},
			{"name": "header keys reordered", "jws": sign(`{"kid":"fixture-v1","alg":"EdDSA","typ":"newtype-run-receipt+jws"}`, ps), "now": int64(issued), "reason": "receipt_header"},
			{"name": "header duplicate key", "jws": sign(`{"alg":"EdDSA","alg":"EdDSA","kid":"fixture-v1","typ":"newtype-run-receipt+jws"}`, ps), "now": int64(issued), "reason": "receipt_header"},
			{"name": "role fd float", "jws": sign(goodHeader, fdFloat), "now": int64(issued), "reason": "receipt_payload"},
			{"name": "role released int", "jws": sign(goodHeader, relInt), "now": int64(issued), "reason": "receipt_payload"},
			{"name": "payload duplicate key", "jws": sign(goodHeader, dupKey), "now": int64(issued), "reason": "receipt_payload"},
			{"name": "bootstrap with a released role", "jws": sign(goodHeader, phase), "now": int64(issued), "reason": "receipt_phase"},
			{"name": "one-char segment", "jws": "a." + parts[1] + "." + parts[2], "now": int64(issued), "reason": "receipt_encoding"},
			{"name": "descriptor other generation (signed)", "jws": sign(goodHeader, genOther), "now": int64(issued), "reason": "receipt_binding"},
			{"name": "descriptor helper cdhash (signed)", "jws": sign(goodHeader, cdOther), "now": int64(issued), "reason": "receipt_binding"},
			{"name": "descriptor helper argv (signed)", "jws": sign(goodHeader, argvOther), "now": int64(issued), "reason": "receipt_binding"},
			{"name": "descriptor keychain item without resource (signed)", "jws": sign(goodHeader, itemOther), "now": int64(issued), "reason": "receipt_payload"},
			{"name": "descriptor nexus name without resource (signed)", "jws": sign(goodHeader, nameOther), "now": int64(issued), "reason": "receipt_payload"},
			{"name": "descriptor generation float", "jws": sign(goodHeader, genFloat), "now": int64(issued), "reason": "receipt_payload"},
			{"name": "descriptor altered (unsigned)", "jws": parts[0] + "." + b64([]byte(genOther)) + "." + parts[2], "now": int64(issued), "reason": "receipt_signature"},
			{"name": "version 1 receipt", "jws": sign(goodHeader, v1), "now": int64(issued), "reason": "receipt_payload"},
		},
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	must(t, os.MkdirAll("../docs/evidence/run-receipt", 0o755))
	must(t, os.WriteFile(receiptVectorPath, append(b, '\n'), 0o644))
}
