package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
	"github.com/newtype-ai-com/nexus/seal"
)

// Extra Section 1 lifecycle regression: acquiring the admin socket must succeed
// before the public surface can accept any approval request.
func TestIndependentBottleneckStartupSummaryAndErrorStages(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, protocol := range []string{"chat/completions", "responses"} {
			cfg := nexusserver.Config{DSN: "SYNTHETIC-DSN-SECRET", ResendAPIKey: "SYNTHETIC-MAIL-SECRET", MailFrom: "SYNTHETIC-SENDER", Schema: "SYNTHETIC-SCHEMA"}
			if enabled {
				cfg.OwnerOnly = true
				cfg.OwnerEmail = "SYNTHETIC-OWNER"
				cfg.EnrolmentConfig = &gate.EnrolmentConfig{AdminToken: "SYNTHETIC-ADMIN-SECRET"}
				cfg.ModelConfig = &gate.ModelConfig{Key: "SYNTHETIC-MODEL-SECRET", Models: []string{"SYNTHETIC-MODEL-NAME"}, Upstream: "https://SYNTHETIC-ENDPOINT/" + protocol}
				cfg.Sealer = &seal.Sealer{}
			}
			out := startupSummary(cfg)
			if strings.Contains(out, "SYNTHETIC") {
				t.Fatal("startup summary echoes configured value")
			}
			for _, key := range []string{"enrolment", "model", "sealing", "owner_configured", "owner_only"} {
				if !strings.Contains(out, fmt.Sprintf("%s=%t", key, enabled)) {
					t.Fatal("startup summary presence incorrect")
				}
			}
			want := "disabled"
			if enabled {
				want = "chat_completions"
				if protocol == "responses" {
					want = "responses"
				}
			}
			if !strings.Contains(out, "model_protocol="+want) {
				t.Fatal("startup fixed protocol label incorrect")
			}
		}
	}
	// Synthetic error classification only, not actual PostgreSQL/TLS execution.
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("SYNTHETIC-DSN-SECRET"), "connect"},
		{fmt.Errorf("SYNTHETIC-SECRET: %w", context.DeadlineExceeded), "timeout"},
		{fmt.Errorf("SYNTHETIC-SECRET: %w", &pgconn.PgError{Code: "28P01", Message: "SYNTHETIC-PASSWORD"}), "authentication"},
		{fmt.Errorf("SYNTHETIC-SECRET: %w", &pgconn.PgError{Code: "28000", Message: "SYNTHETIC-PASSWORD"}), "authentication"},
		{fmt.Errorf("SYNTHETIC-SECRET: %w", x509.UnknownAuthorityError{}), "tls_verification"},
	} {
		if pgstore.ConnectionStage(tc.err) != tc.want {
			t.Fatal("safe connection stage incorrect")
		}
	}
}

func TestIndependentBottleneckApprovalsRunWithoutDatabase(t *testing.T) {
	// A trap counts any attempted DB connection; no PostgreSQL fixture is used.
	trap, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("DB trap setup failed")
	}
	defer trap.Close()
	var dbCalls atomic.Int32
	trapDone := make(chan struct{})
	go func() {
		defer close(trapDone)
		for {
			c, err := trap.Accept()
			if err != nil {
				return
			}
			dbCalls.Add(1)
			c.Close()
		}
	}()
	reserve := func() string {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("address reservation failed")
		}
		addr := l.Addr().String()
		l.Close()
		return addr
	}
	public, admin := reserve(), reserve()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private directory failed")
	}
	for key, value := range map[string]string{
		"DATABASE_URL":    "postgres://synthetic:unused@" + trap.Addr().String() + "/unused?sslmode=disable",
		"NEXUS_DB_SCHEMA": "", "BASE_URL": "https://approval.example.test",
		"NEXUS_OWNER_EMAIL": gate.UserAdministrator, "RESEND_API_KEY": "synthetic-mail-key",
		"MAIL_FROM": "fixture@example.test", "ADMIN_TOKEN": strings.Repeat("synthetic-admin-", 4),
		"APPROVALS_STORE":       filepath.Join(dir, "changes.jsonl"),
		"APPROVALS_PUBLIC_ADDR": public, "APPROVALS_ADMIN_ADDR": admin, "APPROVALS_MAX_REQUESTS": "5",
	} {
		t.Setenv(key, value)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"approvals"}, strings.NewReader("")) }()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 100 * time.Millisecond}
	ready := false
	for i := 0; i < 100; i++ {
		res, err := client.Get("http://" + public + "/v1/changes")
		if err == nil {
			res.Body.Close()
			ready = res.StatusCode == 404
			break
		}
		select {
		case <-done:
			t.Fatal("approvals run stopped before serving")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("approvals lifecycle failed")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("approvals shutdown timed out")
	}
	trap.Close()
	<-trapDone
	if !ready || dbCalls.Load() != 0 {
		t.Fatal("approvals not ready or attempted database connection")
	}
}

func TestIndependentBottleneckAdminBindFailureClosesPublic(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicAddr := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var calls atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	err = serveApprovalSurfaces(context.Background(), publicAddr, admin.Addr().String(), h, h)
	if err == nil || !strings.Contains(err.Error(), "admin listen") {
		t.Fatal("missing safe admin bind stage")
	}
	if calls.Load() != 0 {
		t.Fatal("request served before both listeners were acquired")
	}
	probe, err := net.Listen("tcp", publicAddr)
	if err != nil {
		t.Fatal("public listener not released after admin failure")
	}
	probe.Close()
}

// Public proxy headers must not make an administrative path routable. This
// tests listener separation only; the real change handler is tested separately.
func TestIndependentBottleneckApprovalSurfacesAndCancellation(t *testing.T) {
	p, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	a, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	public, admin := http.NewServeMux(), http.NewServeMux()
	public.HandleFunc("/change/approve", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	admin.HandleFunc("/v1/changes", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveApprovalListeners(ctx, p, a, public, admin) }()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE"} {
		for _, path := range []string{"/v1/changes", "/v1/changes/car_fixture", "/v1/changes/car_fixture/consume", "/v1/changes/car_fixture/result"} {
			req, _ := http.NewRequest(method, "http://"+p.Addr().String()+path, strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer synthetic-admin-token-not-used")
			req.Header.Set("Forwarded", "for=127.0.0.1;proto=https")
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
			res, err := client.Do(req)
			if err != nil {
				t.Fatal("loopback request failed")
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != 404 {
				t.Fatalf("public %s %s = %d, want 404", method, path, res.StatusCode)
			}
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("approval shutdown failed")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("approval shutdown exceeded bounded timeout")
	}
	for _, addr := range []string{p.Addr().String(), a.Addr().String()} {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Fatal("approval socket still accepts after shutdown")
		}
	}
}
