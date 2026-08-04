//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

// Terminal echo control, stdlib only (golang.org/x/term is not a dependency
// worth taking for one prompt).
const (
	tcGets = syscall.TCGETS
	tcSets = syscall.TCSETS
)

func ioctlTermios(fd int, req uintptr, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), req,
		uintptr(unsafe.Pointer(t)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
