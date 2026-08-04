package setup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/config"
	"agentbox/internal/credstore"
	"agentbox/internal/fakebin"
	"agentbox/internal/reconcile"
)

// run executes setup in prefix mode. PATH is emptied so LookPath("docker")
// fails deterministically and no system binary can be touched.
func run(t *testing.T, prefix string, opts Options) string {
	t.Helper()
	t.Setenv("PATH", "")
	opts.Prefix = prefix
	if opts.CredsBin == "" {
		opts.CredsBin = fakebin.SystemdCreds(t)
	}
	var out bytes.Buffer
	opts.Out = &out
	if err := Run(opts); err != nil {
		t.Fatalf("setup: %v\noutput:\n%s", err, out.String())
	}
	return out.String()
}

func TestFreshRunCreatesEverything(t *testing.T) {
	prefix := t.TempDir()
	out := run(t, prefix, Options{AccountID: "acct123", Gateways: []string{"prod"}})

	checks := map[string]string{
		"etc/agentbox/agentbox.json":                       `"account_id": "acct123"`,
		"etc/agentbox/routes.json":                         `"prefix": "/cloudflare/prod"`,
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
	run(t, prefix, Options{AccountID: "acct123", Gateways: []string{"prod"}})
	// Second run: no flags — must reuse agentbox.json instead of prompting.
	out := run(t, prefix, Options{})
	if !strings.Contains(out, "nothing to change") {
		t.Fatalf("second run not idempotent:\n%s", out)
	}
}

func TestSecretsWireUpCredentialsAndCompanions(t *testing.T) {
	prefix := t.TempDir()
	credsBin := fakebin.SystemdCreds(t)
	run(t, prefix, Options{AccountID: "acct123", Gateways: []string{"prod"}, CredsBin: credsBin})

	secrets := filepath.Join(prefix, "etc/agentbox/secrets")
	store := credstore.Store{Dir: secrets, Bin: credsBin}
	// Dummy test material only — never real tokens in tests.
	if err := store.Put("cf-aig-token-prod", []byte("dummy-aig")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put("gh-pat", []byte("dummy-pat")); err != nil {
		t.Fatal(err)
	}

	run(t, prefix, Options{CredsBin: credsBin})

	// The HTTP Basic companion is derived from the stored secret without the
	// operator re-entering it, and is itself stored encrypted.
	companion, err := store.Get("gh-pat.basic")
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("x-access-token:dummy-pat"))
	if string(companion) != want {
		t.Fatalf("companion = %q, want %q", companion, want)
	}

	dropin, err := os.ReadFile(filepath.Join(prefix, "etc/systemd/system/caddy.service.d/agentbox.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"LoadCredentialEncrypted=cf-aig-token-prod:/etc/agentbox/secrets/cf-aig-token-prod.cred",
		"LoadCredentialEncrypted=gh-pat:/etc/agentbox/secrets/gh-pat.cred",
		"LoadCredentialEncrypted=gh-pat.basic:/etc/agentbox/secrets/gh-pat.basic.cred",
	} {
		if !strings.Contains(string(dropin), line) {
			t.Errorf("drop-in missing %q\n%s", line, dropin)
		}
	}
	if strings.Contains(string(dropin), "LoadCredential=") {
		t.Error("drop-in still uses unencrypted LoadCredential=")
	}
	for _, leak := range []string{"dummy-aig", "dummy-pat", want} {
		if strings.Contains(string(dropin), leak) {
			t.Errorf("drop-in leaks secret material %q", leak)
		}
	}

	// Manifest carries names only, and names the ciphertext-backed secrets.
	manifest, err := os.ReadFile(filepath.Join(prefix, "etc/agentbox/secrets.installed"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cf-aig-token-prod", "gh-pat", "gh-pat.basic"} {
		if !strings.Contains(string(manifest), name+"\n") {
			t.Errorf("manifest missing %q\n%s", name, manifest)
		}
	}
	for _, leak := range []string{"dummy-aig", "dummy-pat", want} {
		if strings.Contains(string(manifest), leak) {
			t.Errorf("manifest leaks secret material %q", leak)
		}
	}

	// The drop-in setup writes must be parseable by the reconcile cross-check
	// that gates fail-closed rendering. If these two drift, every credentialed
	// route renders 503 forever with no error anywhere — so assert the
	// contract directly rather than testing each side against its own fixture.
	seen, err := reconcile.CredentialNamesInDropin(
		filepath.Join(prefix, "etc/systemd/system/caddy.service.d/agentbox.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cf-aig-token-prod", "gh-pat", "gh-pat.basic"} {
		if !seen[name] {
			t.Errorf("reconcile cannot see credential %q in the drop-in setup wrote", name)
		}
	}

	// Nothing in the secrets dir may be a plaintext file.
	entries, err := os.ReadDir(secrets)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), credstore.Ext) {
			t.Errorf("non-ciphertext file left in the secrets dir: %q", e.Name())
		}
	}

	for range 3 {
		if out := run(t, prefix, Options{CredsBin: credsBin}); !strings.Contains(out, "nothing to change") {
			t.Fatalf("re-run not idempotent with secrets installed:\n%s", out)
		}
	}
}

// TestPlaintextSecretsAreMigrated covers upgrading a host that installed
// secrets the old way: enabling encryption must not leave the cleartext copy
// sitting there readable.
func TestPlaintextSecretsAreMigrated(t *testing.T) {
	prefix := t.TempDir()
	credsBin := fakebin.SystemdCreds(t)
	run(t, prefix, Options{AccountID: "acct123", Gateways: []string{"prod"}, CredsBin: credsBin})

	secrets := filepath.Join(prefix, "etc/agentbox/secrets")
	// A hand-installed plaintext secret, with the trailing newline a paste
	// would leave behind.
	if err := os.WriteFile(filepath.Join(secrets, "cf-aig-token-prod"), []byte("dummy-aig\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := run(t, prefix, Options{CredsBin: credsBin})
	if !strings.Contains(out, "removed the plaintext copy") {
		t.Errorf("migration not reported:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(secrets, "cf-aig-token-prod")); !os.IsNotExist(err) {
		t.Fatal("plaintext secret survived migration")
	}
	store := credstore.Store{Dir: secrets, Bin: credsBin}
	got, err := store.Get("cf-aig-token-prod")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "dummy-aig" {
		t.Fatalf("migrated value = %q (trailing newline should be trimmed)", got)
	}
}

// TestReconcilesGatewayRoutesKeepingOperatorEdits: the generated gateway
// routes must track agentbox.json, because they are what enforces which
// gateway a container may reach. Refusing to touch the file (the old
// behaviour) left that boundary describing a set of gateways the operator no
// longer had — silently open in one direction, silently dead in the other.
func TestReconcilesGatewayRoutesKeepingOperatorEdits(t *testing.T) {
	prefix := t.TempDir()
	run(t, prefix, Options{AccountID: "acct123", Gateways: []string{"prod"}})
	routesPath := filepath.Join(prefix, "etc/agentbox/routes.json")

	// An operator-added route, alongside the generated ones.
	cfg, err := config.Load(routesPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Routes = append(cfg.Routes, config.Route{
		Name: "mine", Prefix: "/mine", Gateway: config.AnyGateway,
		Upstream: "https://example.com",
	})
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(routesPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	// Add one gateway and remove the original.
	metaPath := filepath.Join(prefix, "etc/agentbox/agentbox.json")
	if err := os.WriteFile(metaPath,
		[]byte(`{"account_id":"acct123","gateways":["experiments"]}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, prefix, Options{})

	got, err := config.Load(routesPath)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]config.Route{}
	for _, r := range got.Routes {
		byName[r.Name] = r
	}
	if _, ok := byName["cloudflare-experiments"]; !ok {
		t.Error("route for the newly configured gateway was not added")
	}
	if _, ok := byName["cloudflare-prod"]; ok {
		t.Error("route for a removed gateway was left behind — that container could still reach it")
	}
	if r, ok := byName["mine"]; !ok || r.Upstream != "https://example.com" {
		t.Error("operator-added route was not preserved")
	}
	// No route may omit the gateway field: that is what makes the boundary
	// established by construction rather than by remembering.
	for _, r := range got.Routes {
		if r.Gateway == "" {
			t.Errorf("route %q has no gateway", r.Name)
		}
	}
}

// TestLegacyRoutesAreRefusedLoudly: the pre-pinning format had no gateway
// field. Loading it must fail with migration guidance rather than being
// treated as a table of universal routes.
func TestLegacyRoutesAreRefusedLoudly(t *testing.T) {
	prefix := t.TempDir()
	run(t, prefix, Options{AccountID: "acct123", Gateways: []string{"prod"}})
	routesPath := filepath.Join(prefix, "etc/agentbox/routes.json")
	legacy := `{"routes":[{"name":"cloudflare","prefix":"/cloudflare",` +
		`"upstream":"https://gateway.ai.cloudflare.com/v1/acct123",` +
		`"inject":[{"header":"cf-aig-authorization","value":"Bearer {secret:cf-aig-token}"}]}]}` + "\n"
	if err := os.WriteFile(routesPath, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", "")
	var out bytes.Buffer
	err := Run(Options{Prefix: prefix, Out: &out, CredsBin: fakebin.SystemdCreds(t)})
	if err == nil {
		t.Fatal("a routes.json in the pre-pinning format must not be accepted")
	}
	if !strings.Contains(err.Error(), "gateway") {
		t.Fatalf("error should explain the missing gateway field: %v", err)
	}
}

// TestLegacyMetaIsMigrated: an agentbox.json from before multi-gateway keeps
// its account id and becomes a one-gateway list.
func TestLegacyMetaIsMigrated(t *testing.T) {
	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "etc/agentbox"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "etc/agentbox/agentbox.json"),
		[]byte(`{"account_id":"acct123","gateway_id":"ff"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := run(t, prefix, Options{})
	if !strings.Contains(out, "migrated") {
		t.Errorf("migration not reported:\n%s", out)
	}
	m, err := config.LoadMeta(filepath.Join(prefix, "etc/agentbox/agentbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	if m.AccountID != "acct123" {
		t.Errorf("account id lost in migration: %+v", m)
	}
	if len(m.Gateways) != 1 || m.Gateways[0] != "ff" {
		t.Errorf("gateways = %v, want [ff]", m.Gateways)
	}
}
