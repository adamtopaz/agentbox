// Package sdnotify implements the small subset of systemd's notification
// protocol that agentboxd needs. It is deliberately stdlib-only.
package sdnotify

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Send delivers one state update when NOTIFY_SOCKET is present. Running the
// daemon outside a notifying service is supported and becomes a no-op.
func Send(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if state == "" || strings.IndexByte(state, 0) >= 0 {
		return fmt.Errorf("invalid empty or NUL-containing notification state")
	}
	// systemd represents an abstract Unix socket by replacing its leading NUL
	// with '@' in the environment.
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + strings.TrimPrefix(socket, "@")
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(state)); err != nil {
		return err
	}
	return nil
}

func Ready() error {
	return Send("READY=1\nSTATUS=Serving control and container proxy sockets")
}

func Stopping() error { return Send("STOPPING=1\nSTATUS=Shutting down") }
