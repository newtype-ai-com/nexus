//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
)

func TestCallBudgetStatusOffline(t *testing.T) {
	t.Setenv("DATABASE_URL", "INVALID-SECRET-NEVER-READ")
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "calls.jsonl")
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := gate.InitializeModelCallBudget(path, gate.ModelCallBudgetHeader{Version: 1, Rollout: "fixture", MaxCalls: 1, ExpiresAt: expiry}); err != nil {
		t.Fatal(err)
	}
	args := []string{"--file", path, "--rollout", "fixture", "--max-calls", "1", "--expires-at", expiry.Format(time.RFC3339)}
	before, _ := os.ReadFile(path)
	var out bytes.Buffer
	if err := runModelCallBudgetStatus(append(args, "--require-ready"), &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		gate.ModelCallBudgetStatus
		ExecutionAuthorized bool `json:"execution_authorized"`
		ServerVerified      bool `json:"server_verified"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Used != 0 || result.Remaining != 1 || result.ExecutionAuthorized || result.ServerVerified {
		t.Fatal(out.String())
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("status changed ledger")
	}
	if err := run(context.Background(), append([]string{"call-budget-status"}, args...), strings.NewReader("")); err != nil {
		t.Fatal("dispatch touched DB", err)
	}
	for _, bad := range [][]string{nil, {"--file", path}, append(append([]string{}, args...), "--max-calls", "2"), append(append([]string{}, args...), "--rollout", "different"), append(append([]string{}, args...), "--expires-at", "2000-01-01T00:00:00Z"), append(append([]string{}, args...), "--unknown")} {
		out.Reset()
		if runModelCallBudgetStatus(bad, &out) == nil || out.Len() != 0 {
			t.Fatal("invalid/mismatch accepted")
		}
	}
	if err := os.WriteFile(path, append(before, []byte("1\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if runModelCallBudgetStatus(append(args, "--require-ready"), &out) == nil || out.Len() != 0 {
		t.Fatal("exhausted ready")
	}
	if err := runModelCallBudgetStatus(args, &out); err != nil {
		t.Fatal("exhausted not inspectable", err)
	}
}
