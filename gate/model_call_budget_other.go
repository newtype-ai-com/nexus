//go:build !darwin && !linux

package gate

import "os"

// A configured call ledger is deliberately unsupported without audited locking.
func createModelCallBudgetFile(string) (*os.File, error)         { return nil, errModelCallBudget }
func openLockedModelCallBudget(string) (*os.File, func(), error) { return nil, nil, errModelCallBudget }
func openReadOnlyModelCallBudget(string) (*os.File, func(), error) {
	return nil, nil, errModelCallBudget
}
