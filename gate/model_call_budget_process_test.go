//go:build darwin || linux

package gate

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Only the test process's explicit synthetic ledger is passed to the child.
func TestModelCallBudgetProcessHelper(t *testing.T) {
	if os.Getenv("NEWTYPE_BUDGET_TEST_CHILD") != "1" {
		t.Skip("child helper")
	}
	path := os.Getenv("NEWTYPE_BUDGET_TEST_PATH")
	if os.Getenv("NEWTYPE_BUDGET_TEST_LOCK") == "1" {
		f, unlock, err := openLockedModelCallBudget(path)
		if err != nil {
			os.Exit(2)
		}
		defer f.Close()
		defer unlock()
		fmt.Println("locked")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(0)
	}
	for i := 0; i < 20; i++ {
		_ = checkModelCallBudget(path, true)
	}
	os.Exit(0)
}

func budgetChild(ctx context.Context, path string, lock bool) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestModelCallBudgetProcessHelper$")
	cmd.Env = []string{"NEWTYPE_BUDGET_TEST_CHILD=1", "NEWTYPE_BUDGET_TEST_PATH=" + path}
	if lock {
		cmd.Env = append(cmd.Env, "NEWTYPE_BUDGET_TEST_LOCK=1")
	}
	return cmd
}

func TestModelCallBudgetAcrossProcesses(t *testing.T) {
	path := budgetFixture(t, 7)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := budgetChild(ctx, path, false).Run(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	for checkModelCallBudget(path, true) == nil {
	}
	status, err := InspectModelCallBudget(path)
	if err != nil || status.Used != 7 || status.Remaining != 0 {
		t.Fatal(status, err)
	}
	if err := budgetChild(ctx, path, false).Run(); err != nil {
		t.Fatal(err)
	}
	status, err = InspectModelCallBudget(path)
	if err != nil || status.Used != 7 {
		t.Fatal("restart changed total", status, err)
	}
}

func TestModelCallBudgetKilledLockHolder(t *testing.T) {
	path := budgetFixture(t, 2)
	if err := checkModelCallBudget(path, true); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := budgetChild(ctx, path, true)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatal("child lock handshake failed", err)
	}
	if checkModelCallBudget(path, true) == nil {
		t.Fatal("child lock bypassed")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	status, err := InspectModelCallBudget(path)
	if err != nil || status.Used != 1 {
		t.Fatal("kill damaged ledger", status, err)
	}
	if err := checkModelCallBudget(path, true); err != nil {
		t.Fatal("lock not released", err)
	}
	if checkModelCallBudget(path, true) == nil {
		t.Fatal("kill reset cap")
	}
}
