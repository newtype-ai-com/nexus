//go:build !darwin && !linux

package gate

import "os"

// The approval service is deployed only on Linux; fail closed elsewhere until
// an equivalent no-follow, durable append and process lock is implemented.
func openChangeJournal(string) (*os.File, error) { return nil, ErrChangeStorage }
func lockChangeJournal(*os.File) error           { return ErrChangeStorage }
