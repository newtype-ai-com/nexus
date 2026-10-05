//go:build !windows

package core

import (
	"golang.org/x/sys/unix"
	"os"
)

// NOFOLLOW blocks leaf aliases; NONBLOCK prevents a raced-in FIFO hanging pin.
func openPlanFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
}
