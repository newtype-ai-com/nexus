//go:build !linux && !darwin

package main

// readDSNFD is unavailable off Linux/Darwin: the mode refuses.
func readDSNFD(fd int) ([]byte, error) { return nil, errDSNFD }
