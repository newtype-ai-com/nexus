//go:build !darwin && !linux

package core

import "os"

// A no-follow, hardlink-aware bounded opener has not been validated here.
// Do not silently weaken secret-file protection on unsupported platforms.
func openEvidenceFile(*os.Root, string) (*os.File, error) { return nil, ErrEvidenceUnresolved }
