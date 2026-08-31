//go:build !linux

package peercred

import (
	"fmt"
	"net"
)

type Credentials struct {
	UID, GID uint32
	PID      int32
}

func FromConn(net.Conn) (Credentials, error) {
	return Credentials{}, fmt.Errorf("peer credentials are only supported on Linux")
}
