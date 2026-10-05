package nexusserver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/seal"
)

func TestPublicDelegationKeys(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	signer, _ := seal.NewEd25519Signer(ed25519.NewKeyFromSeed(seed), "fixture-v1")
	deriver, _ := seal.NewMasterDeriver(seed)
	s, err := nexus.NewServiceWithSealing(nexus.NewMemStore(), nil, &seal.Sealer{Signer: signer, Deriver: deriver}, "https://gate.example.test")
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(s, gate.NewMemoryCredentials(), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/delegation/keys", nil))
	var out struct {
		Keys []seal.PublicKey `json:"keys"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Keys) != 1 || out.Keys[0] != signer.Keys()[0] {
		t.Fatal("public signing keys unavailable")
	}
	if strings.Contains(w.Body.String(), base64.StdEncoding.EncodeToString(seed)) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("key disclosure or unsafe caching")
	}
}

func TestConfig(t *testing.T) {
	for _, tc := range []struct {
		dsn, schema, dev string
		ok               bool
	}{
		{"postgres://user:fixture@db.example:5432/db?sslmode=verify-full", "newtype_preview", "", true},
		{"postgres://user:fixture@db.example:6543/db?sslmode=verify-full", "newtype_preview", "", false},
		{"postgres://user:fixture@db.example/db?sslmode=require", "newtype_preview", "", false},
		{"postgres://user:fixture@db.example/db?sslmode=disable", "newtype_preview", "1", false},
		{"postgres://user:fixture@127.0.0.1:5432/db?sslmode=disable", "newtype_test", "1", true},
		{"postgres://user:fixture@127.0.0.1:5432/db?sslmode=disable", "newtype_test", "", false},
		{"postgres://user:fixture@db.example/db?sslmode=verify-full", "public", "", false},
		{"postgres://user:fixture@db.example/db?sslmode=verify-full", "bad;schema", "", false},
		{"postgres://user:fixture@127.0.0.1/db?sslmode=disable&host=db.example", "newtype_test", "1", false},
		{"postgres://user:fixture@db.example/db?sslmode=verify-full&sslmode=disable", "newtype_test", "", false},
		{"not a dsn fixture", "newtype_test", "", false},
	} {
		env := map[string]string{"DATABASE_URL": tc.dsn, "NEXUS_DB_SCHEMA": tc.schema, "NEXUS_ALLOW_LOCAL_DB": tc.dev}
		_, err := ConfigFromEnv(func(k string) string { return env[k] })
		if (err == nil) != tc.ok {
			t.Errorf("unexpected validation result for schema %s: %v", tc.schema, err)
		}
		if err != nil && strings.Contains(err.Error(), "fixture") {
			t.Fatal("credential leaked")
		}
	}
}

func TestHealthAndFailClosed(t *testing.T) {
	var dbErr error
	h, err := NewHandler(nexus.NewService(nexus.NewMemStore(), nil), gate.NewMemoryCredentials(), func(context.Context) error { return dbErr })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path   string
		status int
	}{{"/v1/health", 200}, {"/llm.txt", 200}, {"/v1/sessions", 401}, {"/v1/executions/invalid", 401}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
	dbErr = errors.New("secret SQL error")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/health", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("unhealthy readiness not sanitized")
	}
	s := HTTPServer("8080", h)
	if s.WriteTimeout != 0 || s.ReadHeaderTimeout <= 0 || s.MaxHeaderBytes > 16384 {
		t.Fatal("unsafe HTTP server timeouts/limits")
	}
}
