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
	"sort"
	"strconv"
	"strings"

	"agentbox/internal/caddyctl"
	"agentbox/internal/config"
	"agentbox/internal/paths"
	"agentbox/internal/reconcile"
)

type Options struct {
	Prefix    string // test root; "" = the real host
	AccountID string
	GatewayID string
	AdminUser string // user added to the agentbox group; default $SUDO_USER
	NoStart   bool
	CaddyBin  string // default "caddy"
	In        io.Reader
	Out       io.Writer
}

type runner struct {
	o        Options
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
		{"{basic:...} companion secrets", r.ensureBasicCompanions},
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

	m := config.Meta{AccountID: r.o.AccountID, GatewayID: r.o.GatewayID}
	if m.AccountID == "" && haveExisting {
		m.AccountID = existing.AccountID
	}
	if m.GatewayID == "" && haveExisting {
		m.GatewayID = existing.GatewayID
	}
	if m.AccountID == "" {
		m.AccountID = r.prompt("Cloudflare account ID")
	}
	if m.GatewayID == "" {
		m.GatewayID = r.prompt("AI Gateway ID")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if haveExisting && existing == m {
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
	cfg := config.Config{Routes: config.DefaultRoutes(m)}
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	routesPath := r.prefixed(paths.Routes)
	existing, readErr := os.ReadFile(routesPath)
	switch {
	case errors.Is(readErr, fs.ErrNotExist):
		if err := os.WriteFile(routesPath, data, 0o644); err != nil {
			return err
		}
		r.change("wrote %s", routesPath)
	case readErr != nil:
		return readErr
	case string(existing) == string(data):
		r.logf("routes.json ok")
	default:
		// Never clobber operator edits: leave the fresh render next door.
		if err := os.WriteFile(routesPath+".new", data, 0o644); err != nil {
			return err
		}
		r.warn("%s differs from the generated default; wrote %s.new instead (existing file kept)", routesPath, routesPath)
	}
	return nil
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
	for name, usr := range cfg.BasicSecrets() {
		src := filepath.Join(r.prefixed(paths.Secrets), name)
		val, err := os.ReadFile(src)
		if errors.Is(err, fs.ErrNotExist) {
			r.warn("secret %q not installed yet (%s); re-run setup after: install -m 600 /dev/stdin %s", name, src, src)
			continue
		}
		if err != nil {
			return err
		}
		token := strings.TrimRight(string(val), "\r\n")
		if token == "" {
			r.warn("secret %q is empty; its routes will proxy without a usable credential", name)
		}
		if strings.TrimSpace(token) != token {
			r.warn("secret %q has leading/trailing whitespace, which will be sent verbatim", name)
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(usr + ":" + token))
		dst := src + ".basic"
		if cur, err := os.ReadFile(dst); err == nil && string(cur) == encoded {
			r.logf("%s ok", dst)
			continue
		}
		if err := os.WriteFile(dst, []byte(encoded), 0o600); err != nil {
			return err
		}
		r.change("wrote %s", dst)
	}
	return nil
}

// ensureSecretsManifest records which secret names are installed, so the
// non-root CLI (which cannot read /etc/agentbox/secrets, mode 0700 root) can
// still render routes with missing credentials as 503 instead of proxying
// unauthenticated. Names only — never values.
func (r *runner) ensureSecretsManifest() error {
	entries, err := os.ReadDir(r.prefixed(paths.Secrets))
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
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
	var creds []string
	cfg, err := config.Load(r.prefixed(paths.Routes))
	if err != nil {
		return err
	}
	need := cfg.SecretNames()
	for name := range cfg.BasicSecrets() {
		need = append(need, name+".basic")
	}
	sort.Strings(need) // map iteration order must not churn the unit file
	for _, name := range need {
		src := filepath.Join(r.prefixed(paths.Secrets), name)
		if _, err := os.Stat(src); err != nil {
			r.warn("secret %q referenced by routes.json is not installed (%s); Caddy will not receive it until you install it and re-run setup", name, src)
			continue
		}
		// The unprefixed path goes into the unit; the stat above is what the
		// prefix root is for.
		creds = append(creds, fmt.Sprintf("LoadCredential=%s:%s", name, filepath.Join(paths.Secrets, name)))
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
