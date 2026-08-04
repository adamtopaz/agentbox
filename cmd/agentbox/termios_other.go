//go:build !linux

package main

import (
	"errors"
	"syscall"
)

// agentbox targets Linux (incus, systemd credentials, flock). These stubs
// exist only so the package still cross-compiles; anything that needs echo
// control fails cleanly rather than reading a secret in the clear.
const (
	tcGets = 0
	tcSets = 0
)

func ioctlTermios(int, uintptr, *syscall.Termios) error {
	return errors.New("terminal echo control is only implemented on Linux")
}
