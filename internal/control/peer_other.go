//go:build !linux

package control

import (
	"fmt"
	"net"
)

func peerCredentials(net.Conn) (Peer, error) {
	return Peer{}, fmt.Errorf("peer credentials are only supported on Linux")
}
