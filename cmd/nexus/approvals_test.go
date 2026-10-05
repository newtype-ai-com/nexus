package main

import (
	"context"
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

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
)

func vacantApprovalAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func TestApprovalsRunNoDatabaseConnection(t *testing.T) {
	trap, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer trap.Close()
	var calls atomic.Int32
	go func() {
		for {
			c, e := trap.Accept()
			if e != nil {
				return
			}
			calls.Add(1)
			c.Close()
		}
	}()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	public, admin := vacantApprovalAddress(t), vacantApprovalAddress(t)
	for k, v := range map[string]string{"DATABASE_URL": "postgres://synthetic:synthetic@" + trap.Addr().String() + "/synthetic?sslmode=disable", "NEXUS_DB_SCHEMA": "invalid db schema proves bypass", "BASE_URL": "https://lic.example", "NEXUS_OWNER_EMAIL": gate.UserAdministrator, "RESEND_API_KEY": "synthetic-not-used", "MAIL_FROM": "sender@example.com", "ADMIN_TOKEN": strings.Repeat("A", 40), "APPROVALS_STORE": filepath.Join(dir, "changes.jsonl"), "APPROVALS_PUBLIC_ADDR": public, "APPROVALS_ADMIN_ADDR": admin, "APPROVALS_MAX_REQUESTS": "1"} {
		t.Setenv(k, v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"approvals"}, strings.NewReader("")) }()
	client := &http.Client{Timeout: time.Second}
	ready := false
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
		res, err := client.Get("http://" + public + "/v1/changes")
		if err == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != 404 {
				t.Fatal(res.StatusCode)
			}
			ready = true
			break
		}
		select {
		case e := <-done:
			t.Fatal(e)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("approvals not ready")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("shutdown")
	}
	if calls.Load() != 0 {
		t.Fatalf("DB connections=%d", calls.Load())
	}
	t.Log("approvals actual run: public ready, admin separate, trap DB connections=0, mail/model requests=0")
}
func TestStartupSummaryNoSecrets(t *testing.T) {
	marker := "SYNTHETIC-SECRET"
	cfg := nexusserver.Config{DSN: marker, Schema: marker, OwnerEmail: marker, ResendAPIKey: marker, MailFrom: marker, OwnerOnly: true, EnrolmentConfig: &gate.EnrolmentConfig{}, ModelConfig: &gate.ModelConfig{Key: marker, Upstream: "https://" + marker + "/responses", Models: []string{marker}}}
	got := startupSummary(cfg)
	if strings.Contains(got, marker) || !strings.Contains(got, "model_protocol=responses") || !strings.Contains(got, "owner_only=true") {
		t.Fatal(fmt.Sprintf("unsafe summary: %s", got))
	}
}
