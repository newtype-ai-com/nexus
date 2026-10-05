//go:build darwin || linux

package gate

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func modelCallBudgetDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	var st unix.Stat_t
	if unix.Lstat(dir, &st) != nil || st.Uid != uint32(os.Geteuid()) {
		return false
	}
	// Resolve trusted ancestors as well; a symlink cannot redirect the ledger.
	resolved, err := filepath.EvalSymlinks(dir)
	return err == nil && resolved == dir
}

func createModelCallBudgetFile(path string) (*os.File, error) {
	if !modelCallBudgetDirectory(path) {
		return nil, errModelCallBudget
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errModelCallBudget
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openLockedModelCallBudget(path string) (*os.File, func(), error) {
	return openModelCallBudget(path, false)
}

func openReadOnlyModelCallBudget(path string) (*os.File, func(), error) {
	return openModelCallBudget(path, true)
}

func openModelCallBudget(path string, readOnly bool) (*os.File, func(), error) {
	if !modelCallBudgetDirectory(path) {
		return nil, nil, errModelCallBudget
	}
	mode, lock := unix.O_RDWR, unix.LOCK_EX
	if readOnly {
		mode, lock = unix.O_RDONLY, unix.LOCK_SH
	}
	fd, err := unix.Open(path, mode|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errModelCallBudget
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func() (*os.File, func(), error) { f.Close(); return nil, nil, errModelCallBudget }
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		return fail()
	}
	// Contention fails closed rather than blocking an HTTP request indefinitely.
	if unix.Flock(fd, lock|unix.LOCK_NB) != nil {
		return fail()
	}
	return f, func() { _ = unix.Flock(fd, unix.LOCK_UN) }, nil
}
