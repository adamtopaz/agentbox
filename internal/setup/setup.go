// Package setup implements `agentbox setup`: one idempotent, root-run command
// that prepares the host — Caddy ≥2.8, the agentbox group, directories,
// tmpfiles.d, the caddy.service drop-in (config path + LoadCredential lines),
// routes.json, {basic:...} companion secrets, Docker/incus firewall
// coexistence, and the initial Caddyfile render.
//
// Every filesystem step honors a --prefix root so tests exercise the real
// code paths without touching the host; system-mutating steps (apt, useradd,
// systemctl, iptables) are skipped in prefix mode.
package setup

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"agentbox/internal/caddyctl"
	"agentbox/internal/config"
	"agentbox/internal/credstore"
	"agentbox/internal/paths"
	"agentbox/internal/reconcile"
)

type Options struct {
	Prefix    string // test root; "" = the real host
	AccountID string
	Gateways  []string
	AdminUser string // user added to the agentbox group; default $SUDO_USER
	NoStart   bool
	CaddyBin  string // default "caddy"
	CredsBin  string // systemd-creds binary; default "systemd-creds"
	In        io.Reader
	Out       io.Writer
}

type runner struct {
	o Options
	// unusable holds credentials that are stored but do not decrypt. They are
	// kept out of both the drop-in and the manifest: listing one would make
	// systemd fail to activate caddy at all (decryption failure is fatal to
	// unit activation), turning a degraded proxy into a dead one.
	unusable map[string]bool
	out      io.Writer
	in       *bufio.Reader
	warnings []string
	changes  []string
}

// Run executes all setup steps in order.
func Run(o Options) error {
	r := &runner{o: o, out: o.Out, in: bufio.NewReader(orStdin(o.In))}
	if r.out == nil {
		r.out = os.Stdout
	}

	steps := []struct {
		name string
		fn   func() error
	}{
		{"root privileges", r.requireRoot},
		{"caddy >= 2.8", r.ensureCaddy},
		{"agentbox group", r.ensureGroup},
		{"directories", r.ensureDirs},
		{"gateway coordinates (agentbox.json)", r.ensureMeta},
		{"routes.json", r.ensureRoutes},
		{"encrypt any plaintext secrets", r.migratePlaintextSecrets},
		{"{basic:...} companion secrets", r.ensureBasicCompanions},
		{"verify stored credentials", r.verifyStoredCredentials},
		{"secrets manifest", r.ensureSecretsManifest},
		{"tmpfiles.d", r.ensureTmpfiles},
		{"caddy.service drop-in", r.ensureCaddyDropin},
		{"firewall unit (Docker coexistence)", r.ensureFirewallUnit},
		{"install binary", r.installBinary},
		{"render initial Caddyfile", r.initialReconcile},
		{"system services", r.startServices},
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			return fmt.Errorf("setup: %s: %w", s.name, err)
		}
	}
	r.summary()
	return nil
}

func orStdin(in io.Reader) io.Reader {
	if in == nil {
		return os.Stdin
	}
	return in
}

func (r *runner) prefixed(p string) string { return filepath.Join(r.o.Prefix, p) }
func (r *runner) prefixMode() bool         { return r.o.Prefix != "" }

func (r *runner) logf(format string, args ...any) {
	fmt.Fprintf(r.out, "  "+format+"\n", args...)
}

func (r *runner) change(format string, args ...any) {
	r.changes = append(r.changes, fmt.Sprintf(format, args...))
	r.logf(format, args...)
}

func (r *runner) warn(format string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
	r.logf("WARNING: "+format, args...)
}

func (r *runner) requireRoot() error {
	if r.prefixMode() {
		r.logf("skipped (prefix mode)")
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root (sudo agentbox setup)")
	}
	return nil
}

func (r *runner) caddyBin() string {
	if r.o.CaddyBin == "" {
		return "caddy"
	}
	return r.o.CaddyBin
}

// caddyBinPath resolves the absolute caddy path for the systemd drop-in,
// which cannot use PATH lookup. Falls back to the packaged location when
// resolution fails (prefix mode has an empty PATH).
func (r *runner) caddyBinPath() string {
	if p, err := exec.LookPath(r.caddyBin()); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
	}
	return "/usr/bin/caddy"
}

func (r *runner) ensureCaddy() error {
	if r.prefixMode() {
		r.logf("skipped (prefix mode)")
		return nil
	}
	client := caddyctl.Client{Bin: r.caddyBin()}
	v, err := client.Version()
	if err == nil && caddyctl.VersionAtLeast(v, 2, 8) {
		r.logf("caddy %s ok", v)
		return nil
	}
	if err == nil {
		r.logf("caddy %s is too old (Debian's package lacks the {file.*} placeholder); installing from Caddy's official apt repo", v)
	} else {
		r.logf("caddy not found; installing from Caddy's official apt repo")
	}
	cmds := [][]string{
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "debian-keyring", "debian-archive-keyring", "apt-transport-https", "curl", "gnupg"},
		{"bash", "-c", "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg"},
		{"bash", "-c", "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' -o /etc/apt/sources.list.d/caddy-stable.list"},
		{"apt-get", "update"},
		{"apt-get", "install", "-y", "caddy"},
	}
	for _, c := range cmds {
		if err := r.system(c[0], c[1:]...); err != nil {
			return err
		}
	}
	v, err = client.Version()
	if err != nil {
		return fmt.Errorf("caddy still not runnable after install: %w", err)
	}
	if !caddyctl.VersionAtLeast(v, 2, 8) {
		return fmt.Errorf("caddy %s installed but >= 2.8 required", v)
	}
	r.change("installed caddy %s", v)
	return nil
}

func (r *runner) ensureGroup() error {
	if r.prefixMode() {
		r.logf("skipped (prefix mode)")
		return nil
	}
	if _, err := user.LookupGroup("agentbox"); err != nil {
		if err := r.system("groupadd", "--system", "agentbox"); err != nil {
			return err
		}
		r.change("created group agentbox")
	} else {
		r.logf("group agentbox exists")
	}
	admin := r.o.AdminUser
	if admin == "" {
		admin = os.Getenv("SUDO_USER")
	}
	if admin == "" || admin == "root" {
		r.warn("no admin user to add to the agentbox group (pass --admin-user); CLI commands will need root")
		return nil
	}
	if _, err := user.Lookup(admin); err != nil {
		return fmt.Errorf("admin user %q: %w", admin, err)
	}
	// Both groups are checked on every run: a user may already be in one and
	// not the other, and each is separately required.
	inGroup, err := userInGroup(admin, "agentbox")
	if err != nil {
		return err
	}
	if inGroup {
		r.logf("user %s already in group agentbox", admin)
	} else {
		if err := r.system("usermod", "-aG", "agentbox", admin); err != nil {
			return err
		}
		r.change("added %s to group agentbox (re-login required to take effect)", admin)
	}
	r.ensureIncusGroup(admin)
	return nil
}

// userInGroup reports whether the named user is a member of the named group.
// A group that does not exist means "not a member", not an error.
func userInGroup(username, group string) (bool, error) {
	g, err := user.LookupGroup(group)
	if err != nil {
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return false, nil
		}
		return false, err
	}
	u, err := user.Lookup(username)
	if err != nil {
		return false, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	for _, gid := range gids {
		if gid == g.Gid {
			return true, nil
		}
	}
	return false, nil
}

// ensureIncusGroup adds the operator to incus-admin, without which
// /var/lib/incus/unix.socket is unreadable and every create/destroy/list
// fails with a permission error that names nothing useful. Note this group is
// root-equivalent on most hosts (it can launch privileged containers), so the
// change is reported explicitly rather than done quietly.
func (r *runner) ensureIncusGroup(admin string) {
	if _, err := user.LookupGroup("incus-admin"); err != nil {
		return // incus not installed with that group; nothing to advise
	}
	inGroup, err := userInGroup(admin, "incus-admin")
	if err != nil || inGroup {
		return
	}
	if err := r.system("usermod", "-aG", "incus-admin", admin); err != nil {
		r.warn("could not add %s to group incus-admin (%v); container commands will fail until you do", admin, err)
		return
	}
	r.change("added %s to group incus-admin — note this group can manage all incus instances and is effectively root on this host (re-login required)", admin)
}

func (r *runner) ensureDirs() error {
	// os.FileMode is not a Unix mode word: os.Chmod only translates the named
	// bits, so a raw 0o2000 would be silently dropped and the directory would
	// not be setgid — meaning files created there by root would land in
	// group root and lock the agentbox group out of its own state dir.
	const groupDir = 0o775 | os.ModeSetgid
	dirs := []struct {
		path  string
		mode  os.FileMode
		group bool // root:agentbox + setgid
	}{
		{paths.Etc, 0o755, false},
		{paths.Secrets, 0o700, false},
		{paths.StateBase, groupDir, true},
		{filepath.Join(paths.StateBase, "containers.d"), groupDir, true},
	}
	for _, d := range dirs {
		p := r.prefixed(d.path)
		if err := os.MkdirAll(p, d.mode.Perm()); err != nil {
			return err
		}
		if err := os.Chmod(p, d.mode); err != nil {
			return err
		}
		if d.group && !r.prefixMode() {
			g, err := user.LookupGroup("agentbox")
			if err != nil {
				return fmt.Errorf("lookup group agentbox: %w", err)
			}
			gid, err := strconv.Atoi(g.Gid)
			if err != nil {
				return fmt.Errorf("group agentbox has non-numeric gid %q", g.Gid)
			}
			if err := os.Chown(p, 0, gid); err != nil {
				return fmt.Errorf("chown %s to root:agentbox: %w", p, err)
			}
			// Chown clears setgid on some filesystems; re-apply after it.
			if err := os.Chmod(p, d.mode); err != nil {
				return err
			}
		}
	}
	r.logf("directories ok")
	return nil
}

func (r *runner) ensureMeta() error {
	metaPath := r.prefixed(paths.Meta)
	existing, err := config.LoadMeta(metaPath)
	haveExisting := err == nil
	if !haveExisting {
		// A file in the pre-multi-gateway shape validates as invalid, which
		// would otherwise throw away the account id sitting right there and
		// re-prompt for everything.
		if legacy, ok := readLegacyMeta(metaPath); ok {
			// haveExisting stays false on purpose: the values are carried
			// forward, but the file itself must be rewritten in the new shape.
			existing = legacy
			r.change("migrated %s from the single-gateway format (gateway %q)", metaPath, legacy.Gateways[0])
			r.warn("the old shared credential %q is no longer referenced; each gateway now uses cf-aig-token-<gateway>. Add the per-gateway token, then revoke the old one in Cloudflare and delete its ciphertext", "cf-aig-token")
		}
	}

	m := config.Meta{AccountID: r.o.AccountID, Gateways: r.o.Gateways}
	if m.AccountID == "" {
		m.AccountID = existing.AccountID
	}
	if len(m.Gateways) == 0 {
		m.Gateways = existing.Gateways
	}
	if m.AccountID == "" {
		m.AccountID = r.prompt("Cloudflare account ID")
	}
	if len(m.Gateways) == 0 {
		for _, g := range strings.Split(r.prompt("AI Gateway names (comma-separated)"), ",") {
			if g = strings.TrimSpace(g); g != "" {
				m.Gateways = append(m.Gateways, g)
			}
		}
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if haveExisting && slices.Equal(existing.Gateways, m.Gateways) && existing.AccountID == m.AccountID {
		r.logf("agentbox.json ok")
		return nil
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(metaPath, append(data, '\n'), 0o644); err != nil {
		return err
	}
	r.change("wrote %s", metaPath)
	return nil
}

// readLegacyMeta recognises the pre-multi-gateway {account_id, gateway_id}
// shape so an upgrade keeps what it can instead of starting over.
func readLegacyMeta(path string) (config.Meta, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config.Meta{}, false
	}
	var legacy struct {
		AccountID string `json:"account_id"`
		GatewayID string `json:"gateway_id"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return config.Meta{}, false
	}
	if legacy.GatewayID == "" {
		return config.Meta{}, false
	}
	m := config.Meta{AccountID: legacy.AccountID, Gateways: []string{legacy.GatewayID}}
	if m.Validate() != nil {
		return config.Meta{}, false
	}
	return m, true
}

func (r *runner) prompt(label string) string {
	fmt.Fprintf(r.out, "  %s: ", label)
	line, err := r.in.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

func (r *runner) ensureRoutes() error {
	m, err := config.LoadMeta(r.prefixed(paths.Meta))
	if err != nil {
		return err
	}
	generated := config.DefaultRoutes(m)
	routesPath := r.prefixed(paths.Routes)

	_, readErr := os.Stat(routesPath)
	if errors.Is(readErr, fs.ErrNotExist) {
		return r.writeRoutes(routesPath, config.Config{Routes: generated}, "wrote %s")
	}
	if readErr != nil {
		return readErr
	}

	// Merge rather than replace-or-refuse. The gateway routes are generated
	// and must track agentbox.json — leaving them stale is how the pinning
	// boundary silently stops matching what the operator declared, in both
	// directions: a removed gateway keeps its route, and an added one never
	// gets one. Everything the operator added is preserved untouched.
	cur, err := config.Load(routesPath)
	if err != nil {
		return fmt.Errorf("%w\n(the previous format is not compatible: every route now needs a \"gateway\" field, %q for routes any container may use. Move the file aside and re-run to regenerate)",
			err, config.AnyGateway)
	}
	isGenerated := func(name string) bool { return strings.HasPrefix(name, "cloudflare-") }
	merged := make([]config.Route, 0, len(cur.Routes)+len(generated))
	for _, rt := range cur.Routes {
		if !isGenerated(rt.Name) {
			merged = append(merged, rt)
		}
	}
	merged = append(generated[:len(m.Gateways):len(m.Gateways)], merged...)

	want := config.Config{Routes: merged}
	if err := want.Validate(); err != nil {
		return fmt.Errorf("merging generated gateway routes with %s: %w", routesPath, err)
	}
	same, err := sameRoutes(routesPath, want)
	if err != nil {
		return err
	}
	if same {
		r.logf("routes.json ok")
		return nil
	}
	return r.writeRoutes(routesPath, want, "updated %s (gateway routes reconciled with agentbox.json)")
}

func (r *runner) writeRoutes(path string, c config.Config, msg string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return err
	}
	r.change(msg, path)
	return nil
}

// sameRoutes reports whether the file already encodes exactly this table.
func sameRoutes(path string, c config.Config) (bool, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return false, err
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return string(cur) == string(append(data, '\n')), nil
}

// ensureBasicCompanions writes base64(USER:secret) companion files for every
// {basic:USER:NAME} template. Caddy cannot base64-encode file contents, so
// this — run by root, inside setup only — is the sole place agentbox code
// reads a secret value. Rotating NAME means re-running `agentbox setup`.
func (r *runner) ensureBasicCompanions() error {
	cfg, err := config.Load(r.prefixed(paths.Routes))
	if err != nil {
		return err
	}
	store := r.credStore()
	for name, usr := range cfg.BasicSecrets() {
		if !store.Has(name) {
			r.warn("secret %q not installed yet; add it with: sudo agentbox add-secret %s", name, name)
			continue
		}
		// Caddy cannot base64-encode a file's contents, so the pre-encoded
		// companion is derived here. This is the only place agentbox code
		// handles a secret value, as root, in memory — never on disk.
		val, err := store.Get(name)
		if err != nil {
			// Do not abort: setup is the documented recovery command, and the
			// remaining steps still produce a coherent config in which this
			// secret's routes fail closed with 503.
			r.warn("secret %q is stored but cannot be decrypted (%v); its routes will serve 503. Re-add it with: sudo agentbox add-secret %s", name, err, name)
			continue
		}
		token := strings.TrimSpace(string(val))
		if token == "" {
			r.warn("secret %q is empty; its routes will proxy without a usable credential", name)
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(usr + ":" + token))
		companion := name + ".basic"
		if cur, err := store.Get(companion); err == nil && string(cur) == encoded {
			r.logf("%s ok", companion)
			continue
		}
		if err := store.Put(companion, []byte(encoded)); err != nil {
			return err
		}
		r.change("wrote encrypted companion %s", store.Path(companion))
	}
	return nil
}

// migratePlaintextSecrets encrypts any secret left on disk in plaintext by an
// older agentbox (or installed by hand) and removes the cleartext copy, so
// enabling encryption does not silently leave the original readable.
func (r *runner) migratePlaintextSecrets() error {
	dir := r.prefixed(paths.Secrets)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	store := r.credStore()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || strings.HasSuffix(name, credstore.Ext) {
			continue
		}
		if !credstore.ValidName(name) {
			r.warn("ignoring unexpected file in the secrets dir: %q", name)
			continue
		}
		val, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		// Trimming and charset validation live in credstore.Put, the single
		// choke point both this and add-secret go through.
		if len(bytes.TrimSpace(val)) == 0 {
			r.warn("plaintext secret %q is empty; leaving it alone", name)
			continue
		}
		if err := store.Put(name, val); err != nil {
			return fmt.Errorf("migrating %q (plaintext left in place): %w", name, err)
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}
		r.change("encrypted %s and removed the plaintext copy", name)
	}
	return nil
}

func (r *runner) credStore() credstore.Store {
	return credstore.Store{Dir: r.prefixed(paths.Secrets), Bin: r.o.CredsBin}
}

// verifyStoredCredentials decrypt-probes every stored credential once, so a
// corrupt or unsealable one is excluded from the config rather than taking
// caddy down on the next restart. Values are discarded immediately.
func (r *runner) verifyStoredCredentials() error {
	r.unusable = map[string]bool{}
	store := r.credStore()
	names, err := store.List()
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, err := store.Get(name); err != nil {
			r.unusable[name] = true
			r.warn("credential %q is stored but does not decrypt (%v); excluding it so caddy can still start. Its routes serve 503 — re-add it with: sudo agentbox add-secret %s",
				name, err, strings.TrimSuffix(name, ".basic"))
		}
	}
	return nil
}

// usable reports whether a stored credential decrypted during this run.
func (r *runner) usable(name string) bool {
	return r.credStore().Has(name) && !r.unusable[name]
}

// ensureSecretsManifest records which secret names are installed, so the
// non-root CLI (which cannot read /etc/agentbox/secrets, mode 0700 root) can
// still render routes with missing credentials as 503 instead of proxying
// unauthenticated. Names only — never values.
func (r *runner) ensureSecretsManifest() error {
	all, err := r.credStore().List()
	if err != nil {
		return err
	}
	var names []string
	for _, n := range all {
		if !r.unusable[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	content := "# Managed by agentbox setup — names of installed secrets, never values.\n"
	for _, n := range names {
		content += n + "\n"
	}
	return writeIfChanged(r.prefixed(paths.SecretsManifest), content, 0o644, r)
}

func (r *runner) ensureTmpfiles() error {
	p := r.prefixed("/etc/tmpfiles.d/agentbox.conf")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := writeIfChanged(p, tmpfilesConf, 0o644, r); err != nil {
		return err
	}
	if !r.prefixMode() {
		if err := r.system("systemd-tmpfiles", "--create", p); err != nil {
			return err
		}
	}
	return nil
}

func (r *runner) ensureCaddyDropin() error {
	cfg, err := config.Load(r.prefixed(paths.Routes))
	if err != nil {
		return err
	}
	need := cfg.SecretNames()
	for name := range cfg.BasicSecrets() {
		need = append(need, name+".basic")
	}
	sort.Strings(need) // map iteration order must not churn the unit file

	store := r.credStore()
	var creds []string
	for _, name := range need {
		if !store.Has(name) {
			r.warn("secret %q referenced by routes.json is not installed; its routes serve 503 until you run: sudo agentbox add-secret %s", name, name)
			continue
		}
		if r.unusable[name] {
			continue // already reported by verifyStoredCredentials
		}
		// Unprefixed path: this line goes into a real unit file. The Has()
		// check above is what the test prefix root applies to.
		creds = append(creds, fmt.Sprintf("LoadCredentialEncrypted=%s:%s",
			name, filepath.Join(paths.Secrets, name+credstore.Ext)))
	}
	dropin := renderCaddyDropin(r.caddyBinPath(), creds)
	target := r.prefixed(paths.CaddyDropin)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return writeIfChanged(target, dropin, 0o644, r)
}

func (r *runner) ensureFirewallUnit() error {
	if _, err := exec.LookPath("docker"); err != nil {
		r.logf("docker not present; skipping firewall coexistence unit")
		return nil
	}
	dir := r.prefixed("/etc/systemd/system")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(dir, "agentbox-firewall.service"), firewallUnit, 0o644, r); err != nil {
		return err
	}
	if r.prefixMode() {
		return nil
	}
	// Apply immediately too — the unit only covers future boots.
	return ApplyFirewallRules(r.out)
}

func (r *runner) installBinary() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	target := r.prefixed(paths.InstalledBin)
	if same, _ := sameFile(self, target); same {
		r.logf("binary ok (%s)", target)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	tmp := target + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	r.change("installed %s", target)
	return nil
}

func (r *runner) initialReconcile() error {
	if r.prefixMode() {
		r.logf("skipped (prefix mode)")
		return nil
	}
	// RenderOnly: at this point caddy may still be running the stock config
	// without our LoadCredential drop-in. Reloading it here would take over
	// whatever it was serving and proxy without credentials; startServices
	// restarts it cleanly a moment later.
	res, err := reconcile.Run(reconcile.Params{
		RoutesPath:      paths.Routes,
		StateBase:       paths.StateBase,
		CaddyfilePath:   paths.Caddyfile,
		SocketDir:       paths.SocketDir,
		CredentialsDir:  paths.CredentialsDir,
		SecretsManifest: paths.SecretsManifest,
		CaddyDropin:     paths.CaddyDropin,
		RenderOnly:      true,
		Caddy:           caddyctl.Client{Bin: r.caddyBin()},
	})
	if err != nil {
		return err
	}
	r.logf("Caddyfile rendered (%d routes, %d containers)", res.Routes, res.Containers)
	return nil
}

func (r *runner) startServices() error {
	if r.prefixMode() {
		r.logf("skipped (prefix mode)")
		return nil
	}
	if r.o.NoStart {
		r.logf("--no-start: remember to run: systemctl daemon-reload && systemctl restart caddy")
		return nil
	}
	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "caddy"},
		{"systemctl", "restart", "caddy"},
	}
	if _, err := os.Stat("/etc/systemd/system/agentbox-firewall.service"); err == nil {
		cmds = append(cmds, []string{"systemctl", "enable", "--now", "agentbox-firewall.service"})
	}
	for _, c := range cmds {
		if err := r.system(c[0], c[1:]...); err != nil {
			return err
		}
	}
	r.change("caddy restarted with agentbox config")
	return nil
}

func (r *runner) summary() {
	fmt.Fprintln(r.out)
	if len(r.changes) == 0 {
		fmt.Fprintln(r.out, "setup: nothing to change — host already configured")
	} else {
		fmt.Fprintln(r.out, "setup: changes applied:")
		for _, c := range r.changes {
			fmt.Fprintln(r.out, "  - "+c)
		}
	}
	for _, w := range r.warnings {
		fmt.Fprintln(r.out, "  ! "+w)
	}
	if len(r.warnings) == 0 {
		fmt.Fprintln(r.out, "next: agentbox build-image && agentbox create <name>")
	}
}

func (r *runner) system(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = r.out
	cmd.Stderr = r.out
	cmd.Stdin = nil
	// sudo does not forward DEBIAN_FRONTEND, and an apt conffile prompt would
	// hang setup forever.
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// ApplyFirewallRules inserts idempotent ACCEPT rules for incusbr0 into
// Docker's DOCKER-USER chain — Docker flips the kernel's global FORWARD
// policy to DROP, which silently kills incus containers' egress. Also used by
// the boot-time oneshot unit (`agentbox setup-firewall`).
func ApplyFirewallRules(out io.Writer) error {
	for _, dir := range []string{"-i", "-o"} {
		check := exec.Command("iptables", "-C", "DOCKER-USER", dir, "incusbr0", "-j", "ACCEPT")
		if check.Run() == nil {
			continue
		}
		ins := exec.Command("iptables", "-I", "DOCKER-USER", dir, "incusbr0", "-j", "ACCEPT")
		if o, err := ins.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables -I DOCKER-USER %s incusbr0: %w: %s", dir, err, strings.TrimSpace(string(o)))
		}
		fmt.Fprintf(out, "  added DOCKER-USER ACCEPT rule (%s incusbr0)\n", dir)
	}
	return nil
}

func writeIfChanged(path, content string, mode os.FileMode, r *runner) error {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		r.logf("%s ok", path)
		return nil
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return err
	}
	r.change("wrote %s", path)
	return nil
}

func sameFile(a, b string) (bool, error) {
	ha, err := fileHash(a)
	if err != nil {
		return false, err
	}
	hb, err := fileHash(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

func fileHash(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
