// Command agentbox manages credential-isolating Incus sandboxes for coding
// agents. Caddy is the data plane (one unix-socket site per container,
// header stripping + credential injection); this CLI renders Caddy's config
// and orchestrates incus. There is no daemon: every mutating command runs one
// reconcile cycle.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"agentbox/internal/caddyctl"
	"agentbox/internal/lifecycle"
	"agentbox/internal/paths"
	"agentbox/internal/reconcile"
	"agentbox/internal/state"
)

const usage = `agentbox — credential-isolating sandboxes for coding agents

usage: agentbox <command> [flags] [args]

host:
  setup                  one-time host setup (root); re-run after adding secrets
  build-image            (re)build the agentbox-base container image

containers:
  create <name>          new wired container (proxy at 127.0.0.1:8787 inside)
  shell <name>           login shell as user 'agent' inside the container
  list                   containers with incus/socket/blocked status
  destroy <name>         delete container + its proxy config

proxy:
  proxy status           same view as list, plus creation times
  proxy routes           route table (names, prefixes, upstreams)
  proxy reload           force one reconcile cycle (render -> validate -> reload)
  proxy block [--hard] <name>
                         403 the container's site; --hard also severs existing
                         connections by removing its incus proxy device
  proxy unblock <name>   restore routes (and the proxy device if missing)

Proxy access logs: journalctl -u caddy (metadata only by construction).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "setup":
		code = cmdSetup(os.Args[2:])
	case "setup-firewall": // hidden: used by agentbox-firewall.service
		code = cmdSetupFirewall(os.Args[2:])
	case "build-image":
		code = cmdBuildImage(os.Args[2:])
	case "create":
		code = cmdCreate(os.Args[2:])
	case "shell":
		code = cmdShell(os.Args[2:])
	case "list":
		code = cmdList(os.Args[2:])
	case "destroy":
		code = cmdDestroy(os.Args[2:])
	case "proxy":
		code = cmdProxy(os.Args[2:])
	case "debug-echo": // hidden: e2e test upstream
		code = cmdDebugEcho(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		code = 2
	}
	os.Exit(code)
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}

// commonFlags are shared by every command that touches the proxy config.
type commonFlags struct {
	routes    string
	stateBase string
	runDir    string
	caddyfile string
	credsDir  string
	manifest  string
	dropin    string
	caddyBin  string
	admin     string
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.routes, "routes", paths.Routes, "routes.json path")
	fs.StringVar(&c.stateBase, "state-dir", paths.StateBase, "state base directory")
	fs.StringVar(&c.runDir, "run-dir", paths.RunDir, "runtime dir (sockets under <run-dir>/containers)")
	fs.StringVar(&c.caddyfile, "caddyfile", "", "rendered Caddyfile path (default <state-dir>/Caddyfile)")
	fs.StringVar(&c.credsDir, "credentials-dir", paths.CredentialsDir, "credentials dir rendered into {file.*} placeholders")
	fs.StringVar(&c.manifest, "secrets-manifest", paths.SecretsManifest, "list of installed secret names (routes missing one render as 503)")
	fs.StringVar(&c.dropin, "caddy-dropin", paths.CaddyDropin, "caddy.service drop-in, cross-checked for LoadCredential lines")
	fs.StringVar(&c.caddyBin, "caddy-bin", "caddy", "caddy binary")
	fs.StringVar(&c.admin, "caddy-admin", caddyctl.DefaultAdminAddr, "caddy admin endpoint")
}

func (c *commonFlags) caddyfilePath() string {
	if c.caddyfile != "" {
		return c.caddyfile
	}
	return filepath.Join(c.stateBase, "Caddyfile")
}

func (c *commonFlags) socketDir() string {
	return filepath.Join(c.runDir, "containers")
}

func (c *commonFlags) params() reconcile.Params {
	return reconcile.Params{
		RoutesPath:      c.routes,
		StateBase:       c.stateBase,
		CaddyfilePath:   c.caddyfilePath(),
		SocketDir:       c.socketDir(),
		CredentialsDir:  c.credsDir,
		SecretsManifest: c.manifest,
		CaddyDropin:     c.dropin,
		Caddy:           caddyctl.Client{Bin: c.caddyBin, AdminAddr: c.admin},
	}
}

func (c *commonFlags) reconcileOnce() error {
	_, err := reconcile.Run(c.params())
	return err
}

func (c *commonFlags) manager() (*lifecycle.Manager, error) {
	states, err := state.Open(c.stateBase)
	if err != nil {
		return nil, err
	}
	// The manager holds the lock across each whole command, so its reconcile
	// hook must be the variant that does not take it again.
	return &lifecycle.Manager{
		Incus:     lifecycle.Incus{},
		States:    states,
		SocketDir: c.socketDir(),
		Lock:      func() (func(), error) { return reconcile.Lock(c.stateBase) },
		Reconcile: func() error {
			_, err := reconcile.RunLocked(c.params())
			return err
		},
	}, nil
}

// parseArgs runs the FlagSet and returns the positional args, exiting with
// usage code 2 on error (flag package already printed the message).
func parseArgs(fs *flag.FlagSet, args []string) ([]string, bool) {
	if err := fs.Parse(args); err != nil {
		return nil, false
	}
	return fs.Args(), true
}
