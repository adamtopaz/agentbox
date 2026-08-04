// Package reconcile implements the single control-plane cycle: load routes
// and container state, render the Caddyfile, and — only if it changed —
// validate, atomically install, and reload Caddy. There is no daemon; every
// mutating CLI command calls Run.
package reconcile

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"agentbox/internal/caddyctl"
	"agentbox/internal/caddyfile"
	"agentbox/internal/config"
	"agentbox/internal/state"
)

type Params struct {
	RoutesPath      string // /etc/agentbox/routes.json
	StateBase       string // /var/lib/agentbox
	CaddyfilePath   string // /var/lib/agentbox/Caddyfile (persistent, survives reboot)
	SocketDir       string // /run/agentbox/containers
	CredentialsDir  string // /run/credentials/caddy.service
	SecretsManifest string // /etc/agentbox/secrets.installed; empty disables the check
	CaddyDropin     string // caddy.service.d drop-in, cross-checked for LoadCredential lines
	GracePeriod     string // default 10s
	// RenderOnly writes and validates the config without reloading Caddy.
	// `agentbox setup` uses it so the initial render cannot disturb a caddy
	// instance that has not yet been pointed at agentbox's config.
	RenderOnly bool
	Caddy      caddyctl.Client
}

type Result struct {
	Changed    bool // rendered config differed from the installed one
	Reloaded   bool // caddy accepted a reload (false also when caddy is not running)
	Containers int
	Routes     int
}

// Run executes one reconcile cycle under an exclusive lock, so two concurrent
// CLI invocations cannot race and install a stale config (which would, for
// instance, silently un-block a blocked container).
func Run(p Params) (Result, error) {
	unlock, err := Lock(p.StateBase)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	return RunLocked(p)
}

// RunLocked is Run for callers that already hold the lock via Lock. Commands
// that mutate state first (create, destroy, block) take the lock around the
// whole command so their read-modify-write cannot interleave with another
// invocation's.
func RunLocked(p Params) (Result, error) { return runLocked(p) }

// Lock takes the exclusive flock on <StateBase>/.reconcile.lock. It is not
// reentrant: a caller holding it must use RunLocked, not Run.
func Lock(stateBase string) (func(), error) {
	if err := os.MkdirAll(stateBase, 0o775); err != nil {
		return nil, err
	}
	path := filepath.Join(stateBase, ".reconcile.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o664)
	if err != nil {
		return nil, fmt.Errorf("open reconcile lock: %w", err)
	}
	// Taking the lock needs write access, and root's umask would otherwise
	// leave the file 0644 — locking every non-root member of group agentbox
	// out of the CLI once setup has run once.
	if fi, statErr := f.Stat(); statErr == nil && fi.Mode().Perm() != 0o664 {
		if chErr := f.Chmod(0o664); chErr != nil {
			slog.Debug("could not widen reconcile lock mode", "err", chErr)
		}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("acquire reconcile lock: %w", err)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func runLocked(p Params) (Result, error) {
	var res Result

	cfg, err := config.Load(p.RoutesPath)
	if err != nil {
		return res, err
	}
	dir, err := state.Open(p.StateBase)
	if err != nil {
		return res, err
	}
	containers, err := dir.List()
	if err != nil {
		return res, err
	}
	installed, err := readSecretsManifest(p.SecretsManifest, p.CaddyDropin)
	if err != nil {
		return res, err
	}
	res.Routes = len(cfg.Routes)
	res.Containers = len(containers)

	grace := p.GracePeriod
	if grace == "" {
		grace = "10s"
	}
	admin := p.Caddy.AdminAddr
	if admin == "" {
		admin = caddyctl.DefaultAdminAddr
	}
	text, err := caddyfile.Render(caddyfile.Options{
		Routes:           cfg.Routes,
		Containers:       containers,
		SocketDir:        p.SocketDir,
		CredentialsDir:   p.CredentialsDir,
		AdminAddr:        admin,
		GracePeriod:      grace,
		InstalledSecrets: installed,
	})
	if err != nil {
		return res, err
	}

	prev, prevErr := os.ReadFile(p.CaddyfilePath)
	if prevErr == nil && string(prev) == text {
		return res, nil // nothing to do — no reload churn
	}

	if err := os.MkdirAll(filepath.Dir(p.CaddyfilePath), 0o775); err != nil {
		return res, err
	}
	tmpName, err := writeTemp(p.CaddyfilePath, text)
	if err != nil {
		return res, err
	}
	defer os.Remove(tmpName) // no-op once renamed

	if err := p.Caddy.Validate(tmpName); err != nil {
		rejected := p.CaddyfilePath + ".rejected"
		if mvErr := os.Rename(tmpName, rejected); mvErr != nil {
			rejected = tmpName
		}
		return res, fmt.Errorf("rendered Caddyfile failed validation; previous config kept, candidate at %s: %w", rejected, err)
	}

	if err := os.Rename(tmpName, p.CaddyfilePath); err != nil {
		return res, err
	}
	res.Changed = true
	// A previous failure's artifact must not linger and read like a live one.
	if err := os.Remove(p.CaddyfilePath + ".rejected"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("could not remove stale rejected config", "err", err)
	}

	if p.RenderOnly {
		return res, nil
	}
	if !p.Caddy.AdminReachable() {
		slog.Warn("caddy is not running; config written and will apply when caddy starts",
			"caddyfile", p.CaddyfilePath)
		return res, nil
	}
	if err := p.Caddy.Reload(p.CaddyfilePath); err != nil {
		// Never leave a config on disk that the running instance rejected: a
		// later caddy restart would pick up something worse than what is live.
		if prevErr == nil {
			if restored, wErr := writeTemp(p.CaddyfilePath, string(prev)); wErr == nil {
				if rErr := os.Rename(restored, p.CaddyfilePath); rErr == nil {
					_ = p.Caddy.Reload(p.CaddyfilePath) // best effort back to known-good
				} else {
					os.Remove(restored)
				}
			}
			return res, fmt.Errorf("caddy reload failed; previous config restored: %w", err)
		}
		// No previous config to restore. Leave this one in place: it passed
		// `caddy validate`, and deleting it would leave caddy.service unable
		// to start at all.
		return res, fmt.Errorf("caddy reload failed; %s was written but the running instance rejected it: %w", p.CaddyfilePath, err)
	}
	res.Reloaded = true
	return res, nil
}

// writeTemp writes content to a temp file beside target and returns its path.
func writeTemp(target, content string) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".caddyfile-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Chmod(0o664); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// readSecretsManifest reports which secrets Caddy will actually be able to
// read, by name. Setting the path to "" disables the check entirely (tests
// and pure rendering); otherwise a missing or unreadable manifest means
// "nothing is installed" — fail closed, because Caddy expands {file.*} of an
// absent credential to the empty string and would forward the request
// unauthenticated.
//
// The manifest alone is not enough: it records what `setup` found in
// /etc/agentbox/secrets, whereas Caddy only receives credentials listed in
// its LoadCredential drop-in, and only as of its last *start*. A secret
// counts as installed only if it appears in both.
func readSecretsManifest(path, dropinPath string) (map[string]bool, error) {
	if path == "" {
		slog.Warn("secrets manifest path is empty; the fail-closed credential check is DISABLED")
		return nil, nil
	}
	installed, err := readNameList(path)
	if errors.Is(err, fs.ErrNotExist) {
		slog.Warn("secrets manifest missing; treating all credentials as uninstalled (routes will serve 503)",
			"path", path, "hint", "run: sudo agentbox setup")
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	if dropinPath == "" {
		slog.Warn("caddy drop-in path is empty; credentials are not cross-checked against what caddy will load")
		return installed, nil
	}
	loaded, err := readLoadCredentialNames(dropinPath)
	if errors.Is(err, fs.ErrNotExist) {
		slog.Warn("caddy credentials drop-in missing; treating all credentials as uninstalled",
			"path", dropinPath, "hint", "run: sudo agentbox setup")
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	for name := range installed {
		if !loaded[name] {
			slog.Warn("secret is installed but not loaded into caddy; its routes will serve 503",
				"secret", name, "hint", "run: sudo agentbox setup")
			delete(installed, name)
		}
	}
	return installed, nil
}

func readNameList(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if name := strings.TrimSpace(sc.Text()); name != "" && !strings.HasPrefix(name, "#") {
			out[name] = true
		}
	}
	return out, sc.Err()
}

// credentialDirectives are the systemd settings that actually hand a
// credential to the service. Both spellings are accepted so the check keeps
// working across the plaintext-to-encrypted transition — and, more to the
// point, so it cannot silently match nothing if the drop-in changes form.
var credentialDirectives = []string{"LoadCredentialEncrypted=", "LoadCredential="}

// CredentialNamesInDropin extracts the credential IDs a systemd drop-in makes
// available to its service, e.g. `LoadCredentialEncrypted=<name>:<path>`.
// Exported so the setup package can assert that what it writes is what this
// package reads — these two must never drift apart, because a mismatch means
// every credentialed route silently renders 503 forever.
func CredentialNamesInDropin(path string) (map[string]bool, error) {
	return readLoadCredentialNames(path)
}

func readLoadCredentialNames(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		for _, directive := range credentialDirectives {
			spec, ok := strings.CutPrefix(line, directive)
			if !ok {
				continue
			}
			if name, _, ok := strings.Cut(spec, ":"); ok && name != "" {
				out[name] = true
			}
			break
		}
	}
	return out, sc.Err()
}
