package caddyctl

import (
	"net"
	"strings"
	"testing"

	"agentbox/internal/fakebin"
)

func TestValidateAndReload(t *testing.T) {
	f := fakebin.New(t, "caddy")
	c := Client{Bin: f.Bin()}

	if err := c.Validate("/tmp/x"); err != nil {
		t.Fatal(err)
	}
	f.RespondStderr("reload", 1, "", "Error: adapting config: line 7\n")
	err := c.Reload("/tmp/x")
	if err == nil || !strings.Contains(err.Error(), "line 7") {
		t.Fatalf("reload error must include caddy's output, got: %v", err)
	}

	calls := f.Calls()
	if len(calls) != 2 {
		t.Fatalf("calls: %v", calls)
	}
	wantValidate := []string{"validate", "--config", "/tmp/x", "--adapter", "caddyfile"}
	for i, a := range wantValidate {
		if calls[0][i] != a {
			t.Fatalf("validate argv = %v", calls[0])
		}
	}
}

func TestVersion(t *testing.T) {
	f := fakebin.New(t, "caddy")
	f.Respond("version", 0, "v2.8.4 h1:abc123\n")
	c := Client{Bin: f.Bin()}
	v, err := c.Version()
	if err != nil || v != "v2.8.4" {
		t.Fatalf("v=%q err=%v", v, err)
	}
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"v2.8.4", true}, {"2.8.0", true}, {"v2.10.1", true}, {"v3.0.0", true},
		{"2.6.2", false}, {"v2.7.9", false}, {"garbage", false}, {"", false},
	}
	for _, c := range cases {
		if got := VersionAtLeast(c.v, 2, 8); got != c.want {
			t.Errorf("VersionAtLeast(%q) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestAdminReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !(Client{AdminAddr: ln.Addr().String()}).AdminReachable() {
		t.Fatal("listener should be reachable")
	}
	if (Client{AdminAddr: "127.0.0.1:1"}).AdminReachable() {
		t.Fatal("closed port should not be reachable")
	}
}
