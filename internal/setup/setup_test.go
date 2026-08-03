package setup

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run executes setup in prefix mode. PATH is emptied so LookPath("docker")
// fails deterministically and no system binary can be touched.
func run(t *testing.T, prefix string, opts Options) string {
	t.Helper()
	t.Setenv("PATH", "")
	opts.Prefix = prefix
	var out bytes.Buffer
	opts.Out = &out
	if err := Run(opts); err != nil {
		t.Fatalf("setup: %v\noutput:\n%s", err, out.String())
	}
	return out.String()
}

func TestFreshRunCreatesEverything(t *testing.T) {
	prefix := t.TempDir()
	out := run(t, prefix, Options{AccountID: "acct123", GatewayID: "gw123"})

	checks := map[string]string{
		"etc/agentbox/agentbox.json":                       `"account_id": "acct123"`,
		"etc/agentbox/routes.json":                         `"prefix": "/anthropic"`,
		"etc/tmpfiles.d/agentbox.conf":                     "d /run/agentbox/containers 2775 caddy agentbox",
		"etc/systemd/system/caddy.service.d/agentbox.conf": "--config /var/lib/agentbox/Caddyfile",
		"usr/local/bin/agentbox":                           "",
	}
	for rel, substr := range checks {
		data, err := os.ReadFile(filepath.Join(prefix, rel))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		if substr != "" && !strings.Contains(string(data), substr) {
			t.Errorf("%s missing %q", rel, substr)
		}
	}
	for _, rel := range []string{"etc/agentbox/secrets", "var/lib/agentbox/containers.d"} {
		if fi, err := os.Stat(filepath.Join(prefix, rel)); err != nil || !fi.IsDir() {
			t.Errorf("dir %s: %v", rel, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(prefix, "etc/agentbox/secrets")); fi.Mode().Perm() != 0o700 {
		t.Errorf("secrets dir mode = %v, want 0700", fi.Mode().Perm())
	}
	// The state dirs must be setgid, or files root creates there land in
	// group root and every non-root CLI command fails on the lock file.
	// os.Chmod silently drops a raw 0o2000, so this needs os.ModeSetgid.
	for _, rel := range []string{"var/lib/agentbox", "var/lib/agentbox/containers.d"} {
		fi, err := os.Stat(filepath.Join(prefix, rel))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSetgid == 0 {
			t.Errorf("%s is not setgid (mode %v)", rel, fi.Mode())
		}
		if fi.Mode().Perm() != 0o775 {
			t.Errorf("%s mode = %v, want 0775", rel, fi.Mode().Perm())
		}
	}
	// The systemd drop-in must tolerate a missing runtime dir, or a
	// tmpfiles.d hiccup takes caddy down at boot.
	dropinPath := filepath.Join(prefix, "etc/systemd/system/caddy.service.d/agentbox.conf")
	if d, _ := os.ReadFile(dropinPath); !strings.Contains(string(d), "ReadWritePaths=-/run/agentbox") {
		t.Errorf("drop-in ReadWritePaths must be prefixed with '-'\n%s", d)
	}
	// tmpfiles must not name a user that setup never creates (only the group
	// exists) — systemd-tmpfiles fails the whole line otherwise.
	tf, _ := os.ReadFile(filepath.Join(prefix, "etc/tmpfiles.d/agentbox.conf"))
	for _, line := range strings.Split(string(tf), "\n") {
		if strings.HasPrefix(line, "d ") && strings.Fields(line)[3] == "agentbox" {
			t.Errorf("tmpfiles.d names a nonexistent 'agentbox' user: %q", line)
		}
	}
	// No secrets installed yet: the drop-in must carry no LoadCredential
	// lines, and the operator must be told.
	dropin, _ := os.ReadFile(filepath.Join(prefix, "etc/systemd/system/caddy.service.d/agentbox.conf"))
	if strings.Contains(string(dropin), "LoadCredential") {
		t.Error("LoadCredential rendered for missing secrets")
	}
	if !strings.Contains(out, "not installed") {
		t.Error("missing-secret warning absent")
	}
}

func TestIdempotentSecondRun(t *testing.T) {
	prefix := t.TempDir()
	run(t, prefix, Options{AccountID: "acct123", GatewayID: "gw123"})
	// Second run: no flags — must reuse agentbox.json instead of prompting.
	out := run(t, prefix, Options{})
	if !strings.Contains(out, "nothing to change") {
		t.Fatalf("second run not idempotent:\n%s", out)
	}
}

func TestSecretsWireUpCredentialsAndCompanions(t *testing.T) {
	prefix := t.TempDir()
	run(t, prefix, Options{AccountID: "acct123", GatewayID: "gw123"})

	secrets := filepath.Join(prefix, "etc/agentbox/secrets")
	// Dummy test material only — never real tokens in tests.
	if err := os.WriteFile(filepath.Join(secrets, "cf-aig-token"), []byte("dummy-aig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "gh-pat"), []byte("dummy-pat\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run(t, prefix, Options{})

	companion, err := os.ReadFile(filepath.Join(secrets, "gh-pat.basic"))
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("x-access-token:dummy-pat"))
	if string(companion) != want {
		t.Fatalf("companion = %q, want %q (exactly one trailing newline trimmed)", companion, want)
	}

	dropin, err := os.ReadFile(filepath.Join(prefix, "etc/systemd/system/caddy.service.d/agentbox.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"LoadCredential=cf-aig-token:/etc/agentbox/secrets/cf-aig-token",
		"LoadCredential=gh-pat:/etc/agentbox/secrets/gh-pat",
		"LoadCredential=gh-pat.basic:/etc/agentbox/secrets/gh-pat.basic",
	} {
		if !strings.Contains(string(dropin), line) {
			t.Errorf("drop-in missing %q\n%s", line, dropin)
		}
	}
	// The drop-in must reference secrets by path only — never contain values.
	for _, leak := range []string{"dummy-aig", "dummy-pat", want} {
		if strings.Contains(string(dropin), leak) {
			t.Errorf("drop-in leaks secret material %q", leak)
		}
	}

	// The manifest lets the non-root CLI tell which routes have credentials,
	// and must itself carry names only.
	manifest, err := os.ReadFile(filepath.Join(prefix, "etc/agentbox/secrets.installed"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cf-aig-token", "gh-pat", "gh-pat.basic"} {
		if !strings.Contains(string(manifest), name+"\n") {
			t.Errorf("manifest missing %q\n%s", name, manifest)
		}
	}
	for _, leak := range []string{"dummy-aig", "dummy-pat", want} {
		if strings.Contains(string(manifest), leak) {
			t.Errorf("manifest leaks secret material %q", leak)
		}
	}
	if fi, _ := os.Stat(filepath.Join(prefix, "etc/agentbox/secrets.installed")); fi.Mode().Perm() != 0o644 {
		t.Errorf("manifest mode = %v, want 0644 (the non-root CLI must read it)", fi.Mode().Perm())
	}

	// Third run with everything in place must still be a no-op — map
	// iteration order must not churn the generated files.
	for range 3 {
		if out := run(t, prefix, Options{}); !strings.Contains(out, "nothing to change") {
			t.Fatalf("re-run not idempotent with secrets installed:\n%s", out)
		}
	}
}

func TestNeverClobbersEditedRoutes(t *testing.T) {
	prefix := t.TempDir()
	run(t, prefix, Options{AccountID: "acct123", GatewayID: "gw123"})

	routesPath := filepath.Join(prefix, "etc/agentbox/routes.json")
	edited := `{"routes":[{"name":"custom","prefix":"/custom","upstream":"https://example.com"}]}` + "\n"
	if err := os.WriteFile(routesPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	out := run(t, prefix, Options{})
	got, _ := os.ReadFile(routesPath)
	if string(got) != edited {
		t.Fatal("operator-edited routes.json was clobbered")
	}
	if _, err := os.Stat(routesPath + ".new"); err != nil {
		t.Fatal("routes.json.new not written")
	}
	if !strings.Contains(out, "routes.json.new") {
		t.Error("operator not told about routes.json.new")
	}
}
