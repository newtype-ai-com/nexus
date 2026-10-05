//go:build windows

package core

import "os"

// The caller checks the pinned root and descriptor identity before reading.
func openPlanFile(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
