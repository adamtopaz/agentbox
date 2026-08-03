package lifecycle

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/fakebin"
	"agentbox/internal/state"
)

type env struct {
	m         *Manager
	incus     *fakebin.Fake
	recon     *int
	out       *bytes.Buffer
	listeners map[string]net.Listener
}

func newEnv(t *testing.T) *env {
	t.Helper()
	states, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	incus := fakebin.New(t, "incus")
	sockets := t.TempDir()
	recon := 0
	out := &bytes.Buffer{}
	m := &Manager{
		Incus:      Incus{Bin: incus.Bin()},
		States:     states,
		SocketDir:  sockets,
		SocketWait: 200 * time.Millisecond,
		Out:        out,
	}
	// The reconcile stub plays Caddy's part: after a successful cycle every
	// state entry has a socket that actually accepts connections (a bare file
	// is exactly the stale-inode case create must reject).
	listeners := map[string]net.Listener{}
	t.Cleanup(func() {
		for _, ln := range listeners {
			ln.Close()
		}
	})
	m.Reconcile = func() error {
		recon++
		list, err := states.List()
		if err != nil {
			return err
		}
		want := map[string]bool{}
		for _, c := range list {
			want[c.Name] = true
			if _, ok := listeners[c.Name]; ok {
				continue
			}
			ln, err := net.Listen("unix", filepath.Join(sockets, c.Name+".sock"))
			if err != nil {
				return err
			}
			listeners[c.Name] = ln
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					conn.Close()
				}
			}()
		}
		for name, ln := range listeners {
			if !want[name] {
				ln.Close()
				delete(listeners, name)
				os.Remove(filepath.Join(sockets, name+".sock"))
			}
		}
		return nil
	}
	return &env{m: m, incus: incus, recon: &recon, out: out, listeners: listeners}
}

func TestCreateHappyPath(t *testing.T) {
	e := newEnv(t)
	e.incus.Respond("list --format json", 0, "[]")

	if err := e.m.Create("dev"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := e.m.States.Get("dev"); !found {
		t.Fatal("state file missing")
	}
	if *e.recon != 1 {
		t.Fatalf("reconcile called %d times, want 1", *e.recon)
	}

	calls := e.incus.Calls()
	var launches, deviceAdds [][]string
	for _, c := range calls {
		if c[0] == "launch" {
			launches = append(launches, c)
		}
		if len(c) > 2 && c[0] == "config" && c[2] == "add" {
			deviceAdds = append(deviceAdds, c)
		}
	}
	if len(launches) != 1 {
		t.Fatalf("launch calls: %v", calls)
	}
	wantLaunch := []string{"launch", Image, "dev", "-c", "user.agentbox=true", "-c", "boot.autostart=true"}
	if strings.Join(launches[0], " ") != strings.Join(wantLaunch, " ") {
		t.Fatalf("launch argv = %v", launches[0])
	}
	if len(deviceAdds) != 2 {
		t.Fatalf("want both proxy devices (tcp + unix socket), got: %v", calls)
	}
	sock := "connect=unix:" + filepath.Join(e.m.SocketDir, "dev.sock")
	tcpDev := strings.Join(deviceAdds[0], " ")
	for _, part := range []string{DeviceName, "proxy", "listen=" + ListenAddr, "bind=instance", sock} {
		if !strings.Contains(tcpDev, part) {
			t.Fatalf("tcp device add %q missing %q", tcpDev, part)
		}
	}
	// The unix device is what `gh` dials; both devices reach the same host
	// socket, so the host routes and the prefix routes share one Caddy site.
	unixDev := strings.Join(deviceAdds[1], " ")
	for _, part := range []string{SocketDeviceName, "proxy", "listen=unix:" + SocketListenPath,
		"bind=instance", "mode=0666", sock} {
		if !strings.Contains(unixDev, part) {
			t.Fatalf("unix device add %q missing %q", unixDev, part)
		}
	}
}

func TestCreateRejectsBadAndExistingNames(t *testing.T) {
	e := newEnv(t)
	if err := e.m.Create("Bad Name"); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := e.m.Create(state.ReservedName); err == nil {
		t.Fatal("reserved name accepted")
	}

	e.incus.Respond("list --format json", 0, "[]")
	if err := e.m.Create("dev"); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Create("dev"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate create: %v", err)
	}
}

func TestCreateRefusesForeignInstance(t *testing.T) {
	e := newEnv(t)
	e.incus.Respond("list --format json", 0, `[{"name":"dev","status":"Running","config":{}}]`)
	err := e.m.Create("dev")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected foreign-instance refusal, got %v", err)
	}
	if _, found, _ := e.m.States.Get("dev"); found {
		t.Fatal("state file should not exist after refusal")
	}
}

func TestCreateRollsBackOnDeviceAddFailure(t *testing.T) {
	e := newEnv(t)
	e.incus.Respond("list --format json", 0, "[]")
	e.incus.RespondStderr("config device add", 1, "", "Error: proxy devices unavailable\n")

	err := e.m.Create("dev")
	if err == nil || !strings.Contains(err.Error(), "proxy devices unavailable") {
		t.Fatalf("expected device-add failure, got %v", err)
	}
	if _, found, _ := e.m.States.Get("dev"); found {
		t.Fatal("state file not rolled back")
	}
	var deleted bool
	for _, c := range e.incus.Calls() {
		if c[0] == "delete" && strings.Contains(strings.Join(c, " "), "dev") {
			deleted = true
		}
	}
	if !deleted {
		t.Fatal("launched instance not deleted during rollback")
	}
	if *e.recon != 2 { // initial + rollback
		t.Fatalf("reconcile called %d times, want 2", *e.recon)
	}
}

func TestCreateFailsWhenSocketNeverAppears(t *testing.T) {
	e := newEnv(t)
	e.incus.Respond("list --format json", 0, "[]")
	e.m.Reconcile = func() error { return nil } // caddy "down": no socket appears
	err := e.m.Create("dev")
	if err == nil || !strings.Contains(err.Error(), "caddy") {
		t.Fatalf("expected socket-wait failure, got %v", err)
	}
	if _, found, _ := e.m.States.Get("dev"); found {
		t.Fatal("state file not rolled back")
	}
}

func TestDestroyToleratesMissingInstance(t *testing.T) {
	e := newEnv(t)
	if err := e.m.States.Put(state.Container{Name: "ghost", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	e.incus.RespondStderr("delete --force ghost", 1, "", "Error: Instance not found\n")

	if err := e.m.Destroy("ghost"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := e.m.States.Get("ghost"); found {
		t.Fatal("state file survived destroy")
	}
	if !strings.Contains(e.out.String(), "not found") {
		t.Fatal("missing-instance warning not printed")
	}
}

// TestDestroyRefusesUnmanagedInstance guards against a name typo wiping out
// an unrelated container: `incus delete --force` cannot be undone.
func TestDestroyRefusesUnmanagedInstance(t *testing.T) {
	e := newEnv(t)
	e.incus.Respond("list --format json", 0,
		`[{"name":"production-db","status":"Running","config":{}}]`)

	err := e.m.Destroy("production-db")
	if err == nil || !strings.Contains(err.Error(), "not agentbox-managed") {
		t.Fatalf("expected refusal, got %v", err)
	}
	for _, c := range e.incus.Calls() {
		if c[0] == "delete" {
			t.Fatalf("destroy issued a delete for an unmanaged instance: %v", c)
		}
	}

	if err := e.m.Destroy("never-existed"); err == nil || !strings.Contains(err.Error(), "unknown container") {
		t.Fatalf("expected unknown-container error, got %v", err)
	}
}

// TestDestroyAcceptsTaggedInstanceWithoutStateFile covers the drift case the
// runbook points operators at: the instance is ours, the state file is gone.
func TestDestroyAcceptsTaggedInstanceWithoutStateFile(t *testing.T) {
	e := newEnv(t)
	e.incus.Respond("list --format json", 0,
		`[{"name":"orphan","status":"Running","config":{"user.agentbox":"true"}}]`)

	if err := e.m.Destroy("orphan"); err != nil {
		t.Fatal(err)
	}
	var deleted bool
	for _, c := range e.incus.Calls() {
		if c[0] == "delete" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatal("tagged orphan instance should be deletable")
	}
}

func TestBlockUnblock(t *testing.T) {
	e := newEnv(t)
	if err := e.m.States.Put(state.Container{Name: "dev", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}

	if err := e.m.Block("dev", false); err != nil {
		t.Fatal(err)
	}
	c, _, _ := e.m.States.Get("dev")
	if !c.Blocked {
		t.Fatal("not blocked")
	}
	if !strings.Contains(e.out.String(), "--hard") {
		t.Fatal("soft block must mention the drain caveat and --hard")
	}

	if err := e.m.Block("dev", true); err != nil {
		t.Fatal(err)
	}
	var removed bool
	for _, call := range e.incus.Calls() {
		if strings.HasPrefix(strings.Join(call, " "), "config device remove dev "+DeviceName) {
			removed = true
		}
	}
	if !removed {
		t.Fatal("hard block did not remove the proxy device")
	}

	// Device list is empty -> unblock must re-add it.
	if err := e.m.Unblock("dev"); err != nil {
		t.Fatal(err)
	}
	c, _, _ = e.m.States.Get("dev")
	if c.Blocked {
		t.Fatal("still blocked")
	}
	var readded bool
	for _, call := range e.incus.Calls() {
		if strings.HasPrefix(strings.Join(call, " "), "config device add dev "+DeviceName) {
			readded = true
		}
	}
	if !readded {
		t.Fatal("unblock did not re-add the missing proxy device")
	}

	if err := e.m.Block("nosuch", false); err == nil {
		t.Fatal("blocking unknown container must fail")
	}
}

func TestListShowsDrift(t *testing.T) {
	e := newEnv(t)
	if err := e.m.States.Put(state.Container{Name: "tracked", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.States.Put(state.Container{Name: "gone", Created: time.Now(), Blocked: true}); err != nil {
		t.Fatal(err)
	}
	// tracked: running with a live socket; gone: no instance; stray: incus-only.
	e.incus.Respond("list --format json", 0, `[
		{"name":"tracked","status":"Running","config":{"user.agentbox":"true"}},
		{"name":"stray","status":"Running","config":{"user.agentbox":"true"}},
		{"name":"unrelated","status":"Running","config":{}}
	]`)
	if err := e.m.Reconcile(); err != nil {
		t.Fatal(err)
	}
	// Kill the listener behind "gone" but leave its socket file: a stale
	// inode from a crashed Caddy must read as absent, not present.
	ln := e.listeners["gone"].(*net.UnixListener)
	ln.SetUnlinkOnClose(false)
	ln.Close()
	delete(e.listeners, "gone")
	if _, err := os.Stat(filepath.Join(e.m.SocketDir, "gone.sock")); err != nil {
		t.Fatalf("stale socket file should still exist: %v", err)
	}

	rows, err := e.m.List()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Row{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	if r := byName["tracked"]; r.Incus != "Running" || !r.Socket || r.Blocked {
		t.Fatalf("tracked row = %+v", r)
	}
	if r := byName["gone"]; r.Incus != "MISSING!" || r.Socket || !r.Blocked {
		t.Fatalf("gone row = %+v (a dead socket file must not count as present)", r)
	}
	if r := byName["stray"]; !strings.Contains(r.Incus, "untracked") {
		t.Fatalf("stray row = %+v", r)
	}
	if _, ok := byName["unrelated"]; ok {
		t.Fatal("untagged instance must not be listed")
	}
}
