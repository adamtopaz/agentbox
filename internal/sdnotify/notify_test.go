package sdnotify

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadyNotifiesConfiguredSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := Ready(); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 256)
	n, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	message := string(buffer[:n])
	if !strings.Contains(message, "READY=1") || !strings.Contains(message, "STATUS=") {
		t.Fatalf("notification=%q", message)
	}
}

func TestSendWithoutSocketIsNoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Ready(); err != nil {
		t.Fatal(err)
	}
}
