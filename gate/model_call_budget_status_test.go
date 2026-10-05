//go:build darwin || linux

package gate

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestModelCallBudgetInspectReadOnly(t *testing.T) {
	path := budgetFixture(t, 1)
	before, _ := os.ReadFile(path)
	status, err := InspectModelCallBudget(path)
	if err != nil || status.Used != 0 || status.Remaining != 1 || status.Expired || status.Header.Rollout != "fixture" {
		t.Fatal(status, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("inspection changed ledger")
	}
	if err := checkModelCallBudget(path, true); err != nil {
		t.Fatal(err)
	}
	status, err = InspectModelCallBudget(path)
	if err != nil || status.Used != 1 || status.Remaining != 0 {
		t.Fatal(status, err)
	}
	status.Header.ExpiresAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	raw, _ := json.Marshal(status.Header)
	raw = append(raw, []byte("\n1\n")...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	status, err = InspectModelCallBudget(path)
	if err != nil || !status.Expired || status.Remaining != 0 {
		t.Fatal(status, err)
	}
	if checkModelCallBudget(path, false) == nil {
		t.Fatal("expired accepted by startup")
	}
	after, _ = os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("expired inspection changed ledger")
	}
}

func TestModelCallBudgetInspectCorruptionAndLock(t *testing.T) {
	path := budgetFixture(t, 1)
	f, unlock, err := openLockedModelCallBudget(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectModelCallBudget(path); err == nil {
		t.Fatal("exclusive lock bypassed")
	}
	unlock()
	f.Close()
	if _, err := InspectModelCallBudget(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectModelCallBudget(path); err == nil {
		t.Fatal("corrupt accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectModelCallBudget(path); err == nil {
		t.Fatal("missing accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("inspection created file")
	}
}

func TestModelCallBudgetInspectSharedReadLock(t *testing.T) {
	path := budgetFixture(t, 1)
	f, unlock, err := openReadOnlyModelCallBudget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer unlock()
	if _, err := f.Write([]byte("1\n")); err == nil {
		t.Fatal("read handle writable")
	}
	if _, err := InspectModelCallBudget(path); err != nil {
		t.Fatal("shared inspection", err)
	}
	if checkModelCallBudget(path, true) == nil {
		t.Fatal("writer bypassed reader")
	}
}
