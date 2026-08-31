//go:build linux

package control

import (
	"net"

	"agentbox/internal/peercred"
)

func peerCredentials(conn net.Conn) (Peer, error) {
	peer, err := peercred.FromConn(conn)
	return Peer{UID: peer.UID, GID: peer.GID, PID: peer.PID}, err
}
