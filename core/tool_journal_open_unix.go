//go:build !windows

package core

import (
	"os"

	"golang.org/x/sys/unix"
)

func openJournalFile(root *os.Root, name string, flags int) (*os.File, error) {
	return root.OpenFile(name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// journalModePrivate refuses a journal readable or writable by group/other.
func journalModePrivate(fi os.FileInfo) bool { return fi.Mode().Perm()&0077 == 0 }
