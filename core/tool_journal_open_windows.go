//go:build windows

package core

import "os"

// Root confines resolution; the caller checks leaf type and descriptor identity.
// Native Windows filesystem race behaviour is not verified by cross compilation.
func openJournalFile(root *os.Root, name string, flags int) (*os.File, error) {
	return root.OpenFile(name, flags, 0600)
}

// syncDir is a no-op on Windows: Sync on a directory opened by os.Open is
// FlushFileBuffers without write access and always fails (ERROR_ACCESS_DENIED),
// which refused every tool start. NTFS journals the directory entry; the
// journal file's own Sync (FlushFileBuffers) is still required and checked.
func syncDir(string) error { return nil }

// journalModePrivate: Windows has no POSIX mode bits (Go reports 0666 for any
// writable file), so they carry no privacy signal. The boundary is the
// host-owned session directory's ACL, as for the session records beside it.
func journalModePrivate(os.FileInfo) bool { return true }
