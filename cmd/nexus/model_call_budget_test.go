//go:build darwin || linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCallBudgetInitOffline(t *testing.T) {
	t.Setenv("DATABASE_URL", "INVALID-SECRET-NEVER-READ")
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "calls.jsonl")
	args := []string{"call-budget-init", "--file", path, "--rollout", "fixture", "--max-calls", "1", "--expires-at", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if run(context.Background(), args, strings.NewReader("")) == nil {
		t.Fatal("missing confirmation accepted")
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("unconfirmed created ledger")
	}
	args = append(args, "--confirm")
	if err = run(context.Background(), args, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = run(context.Background(), args, strings.NewReader("")); err == nil {
		t.Fatal("reset accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing ledger changed")
	}
}
