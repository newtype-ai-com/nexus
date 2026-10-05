package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

func TestServerLifecyclePostgres(t *testing.T) {
	dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL database on literal loopback")
	}
	// The server's local-dev exception (NEXUS_ALLOW_LOCAL_DB=1) only covers a
	// literal loopback address; a "localhost" DSN (as in CI) names the same
	// disposable server, so pin it to 127.0.0.1 rather than relax the check.
	if u, err := url.Parse(dsn); err == nil && u.Hostname() == "localhost" {
		u.Host = net.JoinHostPort("127.0.0.1", u.Port())
		if u.Port() == "" {
			u.Host = "127.0.0.1"
		}
		dsn = u.String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	name := "server_test_" + strings.ToLower(string(ids.New(ids.KindEvent)))
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("NEXUS_DB_SCHEMA", name)
	t.Setenv("NEXUS_ALLOW_LOCAL_DB", "1")
	base, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	defer func() {
		_, err := base.Pool().Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{name}.Sanitize()+" CASCADE")
		if err != nil {
			t.Error(err)
		}
	}()
	for range 2 {
		if err = run(ctx, []string{"migrate"}, strings.NewReader("")); err != nil {
			t.Fatal(err)
		}
	}
	account := ids.Account(ids.New(ids.KindAccount))
	licence := "fixture-licence-token-never-use-in-production"
	login := "fixture-login-token-never-use-in-production"
	for _, kind := range []string{"licence", "login"} {
		token := licence
		if kind == "login" {
			token = login
		}
		c := gate.Credential{Verifier: gate.Verifier(token), Kind: kind, Account: account, Email: "user@example.test", Expires: time.Now().Add(time.Hour)}
		raw, _ := json.Marshal(c)
		if err = run(ctx, []string{"provision"}, strings.NewReader(string(raw))); err != nil {
			t.Fatal(err)
		}
	}
	var grant httpapi.GrantSummary
	// Run the actual server twice, verifying durable credentials survive restart.
	for iteration := range 2 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		t.Setenv("PORT", strconv.Itoa(port))
		runCtx, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- run(runCtx, nil, strings.NewReader("")) }()
		client := &http.Client{Timeout: time.Second}
		baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
		ready := false
		for range 100 {
			resp, err := client.Get(baseURL + "/v1/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					ready = true
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ready {
			stop()
			t.Fatal("server not ready")
		}
		for _, auth := range []bool{false, true} {
			req, _ := http.NewRequest("GET", baseURL+"/v1/sessions", nil)
			want := 401
			if auth {
				req.Header.Set("Authorization", "Bearer "+licence)
				req.Header.Set("X-Newtype-Login", login)
				want = 200
			}
			resp, err := client.Do(req)
			if err != nil {
				stop()
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != want {
				stop()
				t.Fatalf("status %d, want %d", resp.StatusCode, want)
			}
		}
		if iteration == 0 {
			req, _ := http.NewRequest("POST", baseURL+"/v1/requests", strings.NewReader(`{"title":"persistent root","scope":["observe:progress"],"ttl_seconds":3600}`))
			req.Header.Set("Authorization", "Bearer "+licence)
			req.Header.Set("X-Newtype-Login", login)
			resp, err := client.Do(req)
			if err != nil {
				stop()
				t.Fatal(err)
			}
			decodeErr := json.NewDecoder(resp.Body).Decode(&grant)
			resp.Body.Close()
			if resp.StatusCode != 201 || decodeErr != nil || grant.Task == nil {
				stop()
				t.Fatal("root creation failed")
			}
		} else {
			req, _ := http.NewRequest("GET", baseURL+"/v1/delegations/"+string(grant.Delegation), nil)
			req.Header.Set("Authorization", "Bearer "+licence)
			req.Header.Set("X-Newtype-Login", login)
			resp, err := client.Do(req)
			if err != nil {
				stop()
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				stop()
				t.Fatal("root did not survive restart")
			}
		}
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("shutdown did not complete")
		}
	}
}
