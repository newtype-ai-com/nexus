package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/seal"
)

func TestSecretsHTTPNeverEchoValues(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	signer, _ := seal.NewEd25519Signer(ed25519.NewKeyFromSeed(seed), "fixture-v1")
	deriver, _ := seal.NewMasterDeriver(append(seed, seed...))
	svc, err := nexus.NewServiceWithSealing(nexus.NewMemStore(), nil, &seal.Sealer{Signer: signer, Deriver: deriver}, "https://gate.example.test")
	if err != nil {
		t.Fatal(err)
	}
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	actor := user
	api, err := New(Config{Service: svc, Authenticate: func(*http.Request) (nexus.Principal, error) { return actor, nil },
		Run: func(context.Context, string, json.RawMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	const value = "PUBLIC-FIXTURE-SECRET-ECHO-CHECK"
	call := func(method, path, ctype, body string, want int) string {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), value) {
			t.Fatal("value echoed")
		}
		return w.Body.String()
	}
	call("PUT", "/v1/secrets/DB_ADMIN", "application/json", value, 403)
	if out := call("PUT", "/v1/secrets/DB_ADMIN", "application/octet-stream", value, 200); !strings.Contains(out, `"version":1`) {
		t.Fatal(out)
	}
	call("PUT", "/v1/secrets/DB_ADMIN", "application/octet-stream", "", 400)
	call("PUT", "/v1/secrets/1BAD", "application/octet-stream", value, 400)
	call("PUT", "/v1/secrets/BIG", "application/octet-stream", strings.Repeat("x", nexus.SecretValueLimit+1), 400)
	if out := call("GET", "/v1/secrets", "", "", 200); !strings.Contains(out, `"name":"DB_ADMIN"`) || !strings.Contains(out, `"version":1`) {
		t.Fatal(out)
	}
	call("DELETE", "/v1/secrets/DB_ADMIN", "", "", 200)
	call("DELETE", "/v1/secrets/DB_ADMIN", "", "", 404)
	if out := call("PUT", "/v1/secrets/DB_ADMIN", "application/octet-stream", value, 200); !strings.Contains(out, `"version":2`) {
		t.Fatal("generation reset over HTTP: " + out)
	}
	root, err := svc.CreateRoot(context.Background(), user, nexus.RootRequest{Title: "bot"})
	if err != nil {
		t.Fatal(err)
	}
	actor = nexus.SessionPrincipal(user.AccountID, root.Session.ID)
	call("PUT", "/v1/secrets/DB_ADMIN", "application/octet-stream", value, 403)
	call("GET", "/v1/secrets", "", "", 403)
	call("DELETE", "/v1/secrets/DB_ADMIN", "", "", 403)
}
