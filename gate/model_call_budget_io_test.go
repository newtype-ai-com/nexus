//go:build darwin || linux

package gate

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// Faults affect only this file instance; tests never alter a global hook.
type budgetFaultFile struct {
	*os.File
	fault         string
	writes, syncs int
}

var errBudgetFixtureIO = errors.New("fixture I/O failure")

func (f *budgetFaultFile) Read(p []byte) (int, error) {
	if f.fault == "read" {
		return 0, errBudgetFixtureIO
	}
	return f.File.Read(p)
}

func (f *budgetFaultFile) Seek(offset int64, whence int) (int64, error) {
	if f.fault == "seek" {
		return 0, errBudgetFixtureIO
	}
	return f.File.Seek(offset, whence)
}

func (f *budgetFaultFile) Write(p []byte) (int, error) {
	f.writes++
	switch f.fault {
	case "write":
		return 0, errBudgetFixtureIO
	case "short", "partial":
		n, err := f.File.Write(p[:1])
		if err != nil {
			return n, err
		}
		if f.fault == "partial" {
			return n, errBudgetFixtureIO
		}
		return n, nil
	}
	return f.File.Write(p)
}

func (f *budgetFaultFile) Sync() error {
	f.syncs++
	if f.fault == "sync" {
		return errBudgetFixtureIO
	}
	return f.File.Sync()
}

func TestModelCallBudgetIOFailures(t *testing.T) {
	for _, fault := range []string{"read", "seek", "write", "short", "partial", "sync"} {
		t.Run(fault, func(t *testing.T) {
			path := budgetFixture(t, 1)
			file, unlock, err := openLockedModelCallBudget(path)
			if err != nil {
				t.Fatal(err)
			}
			f := &budgetFaultFile{File: file, fault: fault}
			err = consumeModelCallBudget(f, true, time.Now())
			unlock()
			file.Close()
			if err == nil {
				t.Fatal("I/O failure allowed dispatch")
			}
			if fault != "sync" && f.syncs != 0 {
				t.Fatal("synced after failed read/seek/write")
			}
			if (fault == "read" || fault == "seek") && f.writes != 0 {
				t.Fatal("wrote after read/seek failure")
			}
			status, inspectErr := InspectModelCallBudget(path)
			switch fault {
			case "short", "partial":
				if inspectErr == nil || checkModelCallBudget(path, true) == nil {
					t.Fatal("torn record did not fail closed on reopen")
				}
			case "sync":
				// A fully written record is never removed on sync failure. This
				// observes page-cache bytes, not power-loss durability.
				if inspectErr != nil || status.Used != 1 || checkModelCallBudget(path, true) == nil {
					t.Fatal("sync failure refunded the visible record")
				}
			default:
				if inspectErr != nil || status.Used != 0 {
					t.Fatal("failure before write changed ledger")
				}
			}
		})
	}
}

func TestModelCallBudgetConsumptionSyncsBeforeSuccess(t *testing.T) {
	path := budgetFixture(t, 1)
	file, unlock, err := openLockedModelCallBudget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	defer unlock()
	f := &budgetFaultFile{File: file}
	if err := consumeModelCallBudget(f, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f.writes != 1 || f.syncs != 1 {
		t.Fatal("successful consumption missing one durable append")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if consumeModelCallBudget(f, true, time.Now()) == nil || f.writes != 1 || f.syncs != 1 {
		t.Fatal("exhausted ledger was written again")
	}
}
