//go:build darwin || linux

package core

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Refuse symlinks at EVERY component (including within the workspace), hardlink
// aliases and special files, before reading. Nonblocking protects FIFO races.
func openEvidenceFile(root *os.Root, path string) (*os.File, error) {
	base, err := root.Open(".")
	if err != nil {
		return nil, ErrEvidenceUnresolved
	}
	if path == "." {
		return base, nil
	}
	parts := strings.Split(path, "/")
	current := base
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, e := unix.Openat(int(current.Fd()), part, flags, 0)
		current.Close()
		if e != nil {
			return nil, ErrEvidenceUnresolved
		}
		current = os.NewFile(uintptr(fd), "evidence")
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			current.Close()
			return nil, ErrEvidenceUnresolved
		}
		kind := st.Mode & unix.S_IFMT
		if kind != unix.S_IFREG && kind != unix.S_IFDIR || kind == unix.S_IFREG && st.Nlink != 1 {
			current.Close()
			return nil, ErrEvidenceUnresolved
		}
	}
	return current, nil
}
