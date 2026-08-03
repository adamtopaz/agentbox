// Package caddyctl shells out to the caddy binary for validate/reload —
// mirroring how lifecycle shells out to incus, and avoiding Caddy's huge Go
// module graph. Errors always include caddy's own output (it names the
// offending config line).
package caddyctl

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

type Client struct {
	Bin       string // caddy binary; default "caddy"
	AdminAddr string // admin endpoint; default "localhost:2019"
}

func (c Client) bin() string {
	if c.Bin == "" {
		return "caddy"
	}
	return c.Bin
}

func (c Client) admin() string {
	if c.AdminAddr == "" {
		return DefaultAdminAddr
	}
	return c.AdminAddr
}

// DefaultAdminAddr is a unix socket rather than Caddy's default
// localhost:2019: the admin API is unauthenticated and can load a config that
// reads any credential Caddy holds, so it must not be reachable by every
// local user. Mode 0660 in a setgid agentbox directory limits it to root and
// the agentbox group.
const DefaultAdminAddr = "unix//run/agentbox/admin.sock|0660"

func (c Client) run(args ...string) error {
	out, err := exec.Command(c.bin(), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", c.bin(), strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Validate checks a Caddyfile without touching the running instance.
func (c Client) Validate(path string) error {
	return c.run("validate", "--config", path, "--adapter", "caddyfile")
}

// Reload applies a Caddyfile to the running instance via its admin API (the
// address is taken from the config file itself by caddy).
func (c Client) Reload(path string) error {
	return c.run("reload", "--config", path, "--adapter", "caddyfile")
}

// AdminReachable reports whether something is listening on the admin
// endpoint, i.e. whether caddy is running.
func (c Client) AdminReachable() bool {
	network, addr := "tcp", c.admin()
	if path, ok := strings.CutPrefix(addr, "unix/"); ok {
		network = "unix"
		addr, _, _ = strings.Cut(path, "|") // drop the socket mode suffix
	}
	conn, err := net.DialTimeout(network, addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Version returns caddy's version string (e.g. "v2.8.4" or "2.6.2").
func (c Client) Version() (string, error) {
	out, err := exec.Command(c.bin(), "version").Output()
	if err != nil {
		return "", fmt.Errorf("%s version: %w", c.bin(), err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("%s version: empty output", c.bin())
	}
	return fields[0], nil
}

// VersionAtLeast parses a caddy version string like "v2.8.4" and compares the
// major.minor pair against the given minimum.
func VersionAtLeast(version string, major, minor int) bool {
	v := strings.TrimPrefix(version, "v")
	var maj, min int
	if _, err := fmt.Sscanf(v, "%d.%d", &maj, &min); err != nil {
		return false
	}
	if maj != major {
		return maj > major
	}
	return min >= minor
}
