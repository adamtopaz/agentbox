//go:build linux

package control

import (
	"fmt"
	"net"
	"syscall"
)

func peerCredentials(conn net.Conn) (Peer, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return Peer{}, fmt.Errorf("connection has no syscall handle")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var peer Peer
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		peer = Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}
	}); err != nil {
		return Peer{}, err
	}
	return peer, socketErr
}
