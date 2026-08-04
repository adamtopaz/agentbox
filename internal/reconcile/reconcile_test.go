package reconcile

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/caddyctl"
	"agentbox/internal/fakebin"
	"agentbox/internal/state"
)

const routesJSON = `{"routes":[{"name":"echo","gateway":"*","prefix":"/echo","upstream":"http://127.0.0.1:9999","inject":[{"header":"x-test","value":"Bearer {secret:tok}"}]}]}`

func testParams(t *testing.T, caddyBin string) Params {
	t.Helper()
	base := t.TempDir()
	routes := filepath.Join(base, "routes.json")
	if err := os.WriteFile(routes, []byte(routesJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return Params{
		RoutesPath:     routes,
		StateBase:      base,
		CaddyfilePath:  filepath.Join(base, "Caddyfile"),
		SocketDir:      "/run/agentbox/containers",
		CredentialsDir: "/nonexistent/credentials", // proof we never open it
		Caddy:          caddyctl.Client{Bin: caddyBin, AdminAddr: "127.0.0.1:1"},
	}
}

func TestFirstCycleWritesAndSkipsReloadWhenCaddyDown(t *testing.T) {
	caddy := fakebin.New(t, "caddy")
	p := testParams(t, caddy.Bin())

	res, err := Run(p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Reloaded {
		t.Fatalf("res = %+v; want Changed, not Reloaded (admin port closed)", res)
	}
	data, err := os.ReadFile(p.CaddyfilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "handle_path /echo/*") {
		t.Fatal("caddyfile content wrong")
	}
	calls := caddy.Calls()
	if len(calls) != 1 || calls[0][0] != "validate" {
		t.Fatalf("want exactly one validate call, got %v", calls)
	}
}

func TestIdenticalCycleDoesNothing(t *testing.T) {
	caddy := fakebin.New(t, "caddy")
	p := testParams(t, caddy.Bin())
	if _, err := Run(p); err != nil {
		t.Fatal(err)
	}
	caddy.Reset()

	res, err := Run(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("second identical cycle must not change anything")
	}
	if calls := caddy.Calls(); calls != nil {
		t.Fatalf("second identical cycle must not invoke caddy at all, got %v", calls)
	}
}

func TestContainerChangeTriggersRerender(t *testing.T) {
	caddy := fakebin.New(t, "caddy")
	p := testParams(t, caddy.Bin())
	if _, err := Run(p); err != nil {
		t.Fatal(err)
	}

	dir, err := state.Open(p.StateBase)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.Put(state.Container{Name: "newbie", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	res, err := Run(p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Containers != 1 {
		t.Fatalf("res = %+v", res)
	}
	data, _ := os.ReadFile(p.CaddyfilePath)
	if !strings.Contains(string(data), "newbie.sock") {
		t.Fatal("new container missing from rendered config")
	}
}

func TestValidateFailureKeepsPreviousConfig(t *testing.T) {
	caddy := fakebin.New(t, "caddy")
	p := testParams(t, caddy.Bin())
	if _, err := Run(p); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p.CaddyfilePath)

	dir, _ := state.Open(p.StateBase)
	if err := dir.Put(state.Container{Name: "newbie", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	caddy.RespondStderr("validate", 1, "", "Error: bad config\n")

	_, err := Run(p)
	if err == nil || !strings.Contains(err.Error(), "validation") {
		t.Fatalf("expected validation error, got %v", err)
	}
	after, _ := os.ReadFile(p.CaddyfilePath)
	if string(after) != string(before) {
		t.Fatal("previous config was clobbered on validation failure")
	}
	rejected, err := os.ReadFile(p.CaddyfilePath + ".rejected")
	if err != nil {
		t.Fatal("no .rejected file kept for debugging")
	}
	if !strings.Contains(string(rejected), "newbie.sock") {
		t.Fatal(".rejected does not contain the candidate config")
	}
}

func TestReloadFailureRestoresPreviousConfig(t *testing.T) {
	// A real listener makes AdminReachable true; the fake caddy then fails
	// the reload.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	caddy := fakebin.New(t, "caddy")
	p := testParams(t, caddy.Bin())
	p.Caddy.AdminAddr = ln.Addr().String()
	if _, err := Run(p); err != nil { // first run: reload succeeds (fake default)
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p.CaddyfilePath)

	dir, _ := state.Open(p.StateBase)
	if err := dir.Put(state.Container{Name: "newbie", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	caddy.RespondStderr("reload", 1, "", "Error: loading config\n")

	_, err = Run(p)
	if err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("expected reload error, got %v", err)
	}
	after, _ := os.ReadFile(p.CaddyfilePath)
	if string(after) != string(before) {
		t.Fatal("previous config not restored after reload failure")
	}
}

// TestConcurrentCyclesSerialize proves the flock does its job: without it, a
// slow cycle finishing last installs its stale snapshot and silently reverts
// whatever a concurrent command just did (e.g. un-blocking a container).
func TestConcurrentCyclesSerialize(t *testing.T) {
	caddy := fakebin.New(t, "caddy")
	// Make validate slow enough that the two cycles would overlap if unlocked.
	caddy.Respond("validate", 0, "")
	p := testParams(t, caddy.Bin())

	dir, err := state.Open(p.StateBase)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.Put(state.Container{Name: "dev", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(p); err != nil {
		t.Fatal(err)
	}

	// Cycle A holds the lock; while it does, flip the container to blocked and
	// run cycle B. B must wait, then render the blocked config — and the final
	// on-disk config must reflect the newest state, not A's snapshot.
	unlock, err := Lock(p.StateBase)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		c, _, _ := dir.Get("dev")
		c.Blocked = true
		if err := dir.Put(c); err != nil {
			done <- err
			return
		}
		_, err := Run(p)
		done <- err
	}()

	select {
	case err := <-done:
		unlock()
		t.Fatalf("second cycle ran while the lock was held (err=%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()

	if err := <-done; err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p.CaddyfilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "container blocked") {
		t.Fatal("final config does not reflect the newest state")
	}
}

func TestMissingSecretRoutesFailClosed(t *testing.T) {
	caddy := fakebin.New(t, "caddy")
	p := testParams(t, caddy.Bin())
	p.SecretsManifest = filepath.Join(p.StateBase, "secrets.installed")
	if err := os.WriteFile(p.SecretsManifest, []byte("# names only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(p); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.CaddyfilePath)
	if strings.Contains(string(data), "reverse_proxy") {
		t.Fatal("route referencing an uninstalled secret must render as 503, not proxy")
	}

	// Once installed, the route proxies normally.
	if err := os.WriteFile(p.SecretsManifest, []byte("tok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(p); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(p.CaddyfilePath)
	if !strings.Contains(string(data), "reverse_proxy") {
		t.Fatal("expected a reverse_proxy for the credentialed route")
	}
}

func TestMalformedRoutesFailsCleanly(t *testing.T) {
	caddy := fakebin.New(t, "caddy")
	p := testParams(t, caddy.Bin())
	if err := os.WriteFile(p.RoutesPath, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(p); err == nil {
		t.Fatal("expected error on malformed routes.json")
	}
	if calls := caddy.Calls(); calls != nil {
		t.Fatalf("caddy must not be touched when config is malformed, got %v", calls)
	}
}

// TestDropinCrossCheck pins the half of the fail-closed check that had no
// coverage: what the drop-in says caddy will actually load. A mismatch here
// once silently pinned every credentialed route at 503, and the inverse
// mistake would let an unloaded credential render as live.
func TestDropinCrossCheck(t *testing.T) {
	cases := []struct {
		name    string
		dropin  string
		wantHit bool
	}{
		{"encrypted spelling", "[Service]\nLoadCredentialEncrypted=tok:/etc/agentbox/secrets/tok.cred\n", true},
		{"legacy spelling", "[Service]\nLoadCredential=tok:/etc/agentbox/secrets/tok\n", true},
		{"indented", "[Service]\n  LoadCredentialEncrypted=tok:/x\n", true},
		{"names another credential", "[Service]\nLoadCredentialEncrypted=other:/x\n", false},
		{"no credential lines", "[Service]\nExecStart=/usr/bin/caddy run\n", false},
		{"commented out", "[Service]\n#LoadCredentialEncrypted=tok:/x\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			caddy := fakebin.New(t, "caddy")
			p := testParams(t, caddy.Bin())
			p.SecretsManifest = filepath.Join(p.StateBase, "secrets.installed")
			p.CaddyDropin = filepath.Join(p.StateBase, "dropin.conf")
			if err := os.WriteFile(p.SecretsManifest, []byte("tok\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.CaddyDropin, []byte(c.dropin), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Run(p); err != nil {
				t.Fatal(err)
			}
			// The runtime guard emits the 503 text on every credentialed
			// route, so presence of a reverse_proxy is the discriminator:
			// a control-plane-disabled route renders the respond alone.
			data, _ := os.ReadFile(p.CaddyfilePath)
			proxying := strings.Contains(string(data), "reverse_proxy")
			if proxying != c.wantHit {
				t.Fatalf("credential visible in drop-in = %v but route proxying = %v", c.wantHit, proxying)
			}
		})
	}
}

// TestMissingDropinFailsClosed: no drop-in at all means caddy holds nothing.
func TestMissingDropinFailsClosed(t *testing.T) {
	caddy := fakebin.New(t, "caddy")
	p := testParams(t, caddy.Bin())
	p.SecretsManifest = filepath.Join(p.StateBase, "secrets.installed")
	p.CaddyDropin = filepath.Join(p.StateBase, "does-not-exist.conf")
	if err := os.WriteFile(p.SecretsManifest, []byte("tok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(p); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p.CaddyfilePath)
	if strings.Contains(string(data), "reverse_proxy") {
		t.Fatal("a missing drop-in must mean nothing is installed, not check-disabled")
	}
}
