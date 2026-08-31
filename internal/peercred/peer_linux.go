//go:build linux

package peercred

import (
	"fmt"
	"net"
	"syscall"
)

type Credentials struct {
	UID, GID uint32
	PID      int32
}

func FromConn(conn net.Conn) (Credentials, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return Credentials{}, fmt.Errorf("connection has no syscall handle")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return Credentials{}, err
	}
	var peer Credentials
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		peer = Credentials{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}
	}); err != nil {
		return Credentials{}, err
	}
	return peer, socketErr
}
