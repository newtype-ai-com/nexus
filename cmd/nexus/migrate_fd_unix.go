//go:build linux || darwin

package main

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"golang.org/x/sys/unix"
)

var linuxPipeLink = regexp.MustCompile(`^pipe:\[[0-9]+\]$`)

// readDSNFD reads the DSN from an inherited anonymous pipe: read-only end,
// no name (Linux /proc link pipe:[…], Darwin nlink 0), at most dsnFDLimit
// bytes, EOF within dsnFDTimeout. The FD is closed on every path.
func readDSNFD(fd int) (raw []byte, err error) {
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return nil, errDSNFD
	}
	// Darwin anonymous pipes have nlink 0; Linux pipefs inodes have nlink 1, so on
	// Linux the anonymity proof is the /proc link alone (a named FIFO links to its path).
	if !isLinux && st.Nlink != 0 {
		return nil, errDSNFD
	}
	if isLinux {
		link, lerr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if lerr != nil || !linuxPipeLink.MatchString(link) {
			return nil, errDSNFD
		}
	}
	flags, ferr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if ferr != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, errDSNFD
	}
	buf := make([]byte, dsnFDLimit+1)
	defer clear(buf)
	n := 0
	deadline := time.Now().Add(dsnFDTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errDSNFD
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, perr := unix.Poll(fds, int(remaining/time.Millisecond)+1)
		if perr == unix.EINTR {
			continue
		}
		if perr != nil {
			return nil, errDSNFD
		}
		if ready == 0 {
			continue
		}
		m, rerr := unix.Read(fd, buf[n:])
		if rerr == unix.EINTR || rerr == unix.EAGAIN {
			continue
		}
		if rerr != nil {
			return nil, errDSNFD
		}
		if m == 0 {
			out := make([]byte, n)
			copy(out, buf[:n])
			return out, nil
		}
		n += m
		if n > dsnFDLimit {
			return nil, errDSNFD
		}
	}
}
