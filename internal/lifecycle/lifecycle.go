// Package lifecycle orchestrates incus for create/destroy/list/shell/block.
// All incus interaction goes through the Incus wrapper (shelling out to the
// CLI — zero dependencies, identical to manual operation), so tests can point
// it at a fake binary.
package lifecycle

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"agentbox/internal/state"
)

const (
	// DeviceName is the incus proxy device mapping 127.0.0.1:8787 inside the
	// container to its host-side unix socket.
	DeviceName = "agentbox-proxy"
	// ListenAddr is the container-side address agents talk to.
	ListenAddr = "tcp:127.0.0.1:8787"

	// SocketDeviceName carries the same host socket into the container as a
	// unix socket, for clients that cannot take a base URL but can dial a
	// socket — `gh` via its http_unix_socket setting. Requests arrive with
	// their real Host header and are matched by the host routes.
	SocketDeviceName = "agentbox-socket"
	// SocketListenPath is where that socket appears inside the container.
	SocketListenPath = "/run/agentbox.sock"

	// Image is the container image alias created by `agentbox build-image`.
	Image = "agentbox-base"
)

// Manager wires together incus, the state dir, and the reconcile hook.
type Manager struct {
	Incus  Incus
	States *state.Dir
	// Lock is held for the whole of each mutating command, so a command's
	// read-modify-write of the state dir cannot interleave with another
	// invocation's. Reconcile must therefore be the already-locked variant.
	Lock       func() (func(), error)
	SocketDir  string       // /run/agentbox/containers
	Reconcile  func() error // one reconcile cycle (render → validate → reload)
	SocketWait time.Duration
	Out        io.Writer
}

// locked runs fn holding the command lock (a no-op when no Lock is set, as in
// tests that drive the manager directly).
func (m *Manager) locked(fn func() error) error {
	if m.Lock == nil {
		return fn()
	}
	unlock, err := m.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func (m *Manager) out() io.Writer {
	if m.Out == nil {
		return os.Stdout
	}
	return m.Out
}

func (m *Manager) socketPath(name string) string {
	return filepath.Join(m.SocketDir, name+".sock")
}

func (m *Manager) socketWait() time.Duration {
	if m.SocketWait == 0 {
		return 3 * time.Second
	}
	return m.SocketWait
}

// Create brings up a fully wired container: state file → reconcile → socket
// bound by Caddy → incus launch → proxy device. Any failure past the state
// file rolls everything back.
func (m *Manager) Create(name, gateway string) error {
	return m.locked(func() error {
		if !state.ValidName(name) {
			return fmt.Errorf("invalid container name %q (lowercase slug, max 63 chars; %q is reserved)", name, state.ReservedName)
		}
		// Before anything is written or launched: the gateway ends up in the
		// state file and the rendered config, so it is checked here rather
		// than at the point of use.
		if !configValidGateway(gateway) {
			return fmt.Errorf("invalid gateway %q (lowercase letters, digits and dashes)", gateway)
		}
		if _, found, err := m.States.Get(name); err != nil {
			return err
		} else if found {
			return fmt.Errorf("container %q already exists (state file present)", name)
		}
		if exists, err := m.instanceExists(name); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("incus instance %q already exists but is not agentbox-managed here", name)
		}

		if err := m.States.Put(state.Container{Name: name, Created: time.Now().UTC(), Gateway: gateway}); err != nil {
			return err
		}
		launched := false
		rollback := func(cause error) error {
			if launched {
				if err := m.Incus.Run("delete", "--force", name); err != nil {
					fmt.Fprintf(m.out(), "warning: rollback could not delete instance %s: %v\n", name, err)
				}
			}
			if err := m.States.Remove(name); err != nil {
				fmt.Fprintf(m.out(), "warning: rollback could not remove state file for %s: %v\n", name, err)
			}
			if err := m.Reconcile(); err != nil {
				fmt.Fprintf(m.out(), "warning: rollback reconcile failed: %v\n", err)
			}
			return cause
		}

		if err := m.Reconcile(); err != nil {
			return rollback(fmt.Errorf("reconcile failed: %w", err))
		}
		if err := m.waitForSocket(name); err != nil {
			return rollback(err)
		}
		if err := m.Incus.Run("launch", Image, name,
			"-c", "user.agentbox=true", "-c", "boot.autostart=true"); err != nil {
			if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "Image") {
				err = fmt.Errorf("%w\n(hint: build the base image first with `agentbox build-image`)", err)
			}
			return rollback(err)
		}
		launched = true
		for _, args := range m.deviceArgs(name) {
			if err := m.Incus.Run(args...); err != nil {
				return rollback(err)
			}
		}

		// Wire the agents to this container's gateway. Deliberately done here
		// rather than baked into the image: there is no default gateway, and
		// an image that hard-coded one would strand every container built
		// from it when the choice changed.
		if err := m.wireGateway(name, gateway); err != nil {
			return rollback(err)
		}

		fmt.Fprintf(m.out(), "container %q ready on gateway %q — proxy at http://127.0.0.1:8787 (and %s) inside; enter it with: agentbox shell %s\n",
			name, gateway, SocketListenPath, name)
		return nil
	})
}

// wireGateway writes the gateway-dependent agent configuration inside the
// container. Everything it writes is a URL: no credential crosses this line.
//
// This happens at create time rather than image build because there is no
// default gateway — an image with one baked in would strand every container
// built from it the moment the choice changed.
func (m *Manager) wireGateway(name, gateway string) error {
	script, err := gatewayScript(gateway)
	if err != nil {
		return err
	}
	return m.Incus.RunInput(script, "exec", name, "--", "sh", "-s")
}

// gatewayScript builds the in-container wiring script. Split out from
// wireGateway so what gets written is assertable without an incus.
func gatewayScript(gateway string) (string, error) {
	if !configValidGateway(gateway) {
		return "", fmt.Errorf("invalid gateway name %q", gateway)
	}
	base := "http://127.0.0.1:8787/cloudflare/" + gateway
	// The gateway name is validated above, so it cannot break out of these
	// here-docs; nothing else is interpolated.
	return `set -eu
GW=` + base + `
cat > /etc/profile.d/agentbox-gateway.sh <<EOF
# agentbox: this container's AI Gateway. Written by agentbox create.
export AGENTBOX_GATEWAY=` + gateway + `
export ANTHROPIC_BASE_URL=$GW/anthropic
export OPENAI_BASE_URL=$GW/openai
export CLOUDFLARE_GATEWAY_ID=` + gateway + `
EOF
chmod 0644 /etc/profile.d/agentbox-gateway.sh

# /etc/environment is not shell: KEY=value lines only, managed marker block.
touch /etc/environment
awk '/^# BEGIN agentbox-gateway$/{skip=1} /^# END agentbox-gateway$/{skip=0; next} !skip{print}' \
    /etc/environment > /etc/environment.tmp
{
  cat /etc/environment.tmp
  echo "# BEGIN agentbox-gateway"
  echo "AGENTBOX_GATEWAY=` + gateway + `"
  echo "ANTHROPIC_BASE_URL=$GW/anthropic"
  echo "OPENAI_BASE_URL=$GW/openai"
  echo "CLOUDFLARE_GATEWAY_ID=` + gateway + `"
  echo "# END agentbox-gateway"
} > /etc/environment
rm -f /etc/environment.tmp

# Codex takes a base URL from its config file, not the environment, so the
# whole stanza is regenerated rather than patched in place.
if id agent >/dev/null 2>&1; then
  install -d -o agent -g agent -m 0755 /home/agent/.codex
  cat > /home/agent/.codex/config.toml <<EOF
# agentbox: route Codex through the host-side proxy (dummy key; real auth is
# injected by the proxy). Codex speaks the Responses API -> OpenAI models.
model_provider = "agentbox"

[model_providers.agentbox]
name = "agentbox proxy"
base_url = "$GW/openai"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
EOF
  chown agent:agent /home/agent/.codex/config.toml
  chmod 0644 /home/agent/.codex/config.toml
fi

# pi resolves a provider's endpoint as extension > models.json > built-in, and
# honours no *_BASE_URL environment variable (docs/models.md, "Overriding
# Built-in Providers"; docs/environment-variables.md lists none). So its
# providers have to be redirected declaratively here, or pi talks to Anthropic
# and OpenAI directly — failing closed against the dummy keys, but bypassing
# the proxy entirely.
#
# cloudflare-ai-gateway gets the bare gateway base. A provider-level override
# replaces each model's catalog baseUrl wholesale, losing the provider segment
# that URL ended in — so the gateway route carries a path_map that puts the
# segment back, keyed on the suffix pi appends per API shape:
#   /v1/messages      (anthropic-messages) -> /anthropic/v1/messages
#   /responses        (openai-responses)   -> /openai/responses
#   /chat/completions (openai-completions) -> /compat/chat/completions
# The suffixes are disjoint, so one base URL covers all three families. Without
# it a single override can only ever satisfy one of them (Cloudflare reads the
# leftover "v1" as a provider name and answers 400 Invalid provider).
if id agent >/dev/null 2>&1; then
  install -d -o agent -g agent -m 0755 /home/agent/.pi /home/agent/.pi/agent
  cat > /home/agent/.pi/agent/models.json <<EOF
{
  "providers": {
    "anthropic": { "baseUrl": "$GW/anthropic" },
    "openai": { "baseUrl": "$GW/openai" },
    "cloudflare-ai-gateway": { "baseUrl": "$GW" }
  }
}
EOF
  chown -R agent:agent /home/agent/.pi
  chmod 0644 /home/agent/.pi/agent/models.json
fi
`, nil
}

// deviceArgs returns the incus invocations that wire both proxy devices for a
// container: the TCP one agents point their base URL at, and the unix socket
// for host-addressed clients.
func (m *Manager) deviceArgs(name string) [][]string {
	return [][]string{
		{"config", "device", "add", name, DeviceName, "proxy",
			"listen=" + ListenAddr,
			"connect=unix:" + m.socketPath(name),
			"bind=instance"},
		{"config", "device", "add", name, SocketDeviceName, "proxy",
			"listen=unix:" + SocketListenPath,
			"connect=unix:" + m.socketPath(name),
			"bind=instance",
			// The agent user must be able to dial it; the socket carries no
			// authority of its own (the host side decides everything).
			"mode=0666"},
	}
}

// waitForSocket waits until the container's socket actually accepts a
// connection. A stat would not do: unix socket files outlive the process that
// bound them, so a stale inode from a crashed Caddy would make `create`
// report success while the container talks to nothing.
func (m *Manager) waitForSocket(name string) error {
	deadline := time.Now().Add(m.socketWait())
	for {
		if conn, err := net.DialTimeout("unix", m.socketPath(name), 500*time.Millisecond); err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("caddy did not serve %s within %s — is caddy.service running?", m.socketPath(name), m.socketWait())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// socketLive reports whether the container's socket currently accepts
// connections (used by list/status, where a stale file is drift worth seeing).
func (m *Manager) socketLive(name string) bool {
	conn, err := net.DialTimeout("unix", m.socketPath(name), 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Destroy deletes the container (removing its proxy device with it — the
// instant, kernel-level sever), then the state file, then reconciles.
//
// It refuses to touch an instance that is neither in agentbox's state dir nor
// tagged user.agentbox=true: `incus delete --force` is unrecoverable, and a
// name typo must not be able to take out an unrelated container.
func (m *Manager) Destroy(name string) error {
	return m.locked(func() error {
		if !state.ValidName(name) {
			return fmt.Errorf("invalid container name %q", name)
		}
		_, tracked, err := m.States.Get(name)
		if err != nil {
			return err
		}
		if !tracked {
			managed, exists, err := m.instanceManaged(name)
			if err != nil {
				return err
			}
			if exists && !managed {
				return fmt.Errorf("incus instance %q is not agentbox-managed (no state file, no user.agentbox tag); refusing to delete it", name)
			}
			if !exists {
				return fmt.Errorf("unknown container %q: no state file and no such incus instance", name)
			}
		}
		if err := m.Incus.Run("delete", "--force", name); err != nil {
			if isNotFound(err) {
				fmt.Fprintf(m.out(), "warning: incus instance %q not found (already deleted?); cleaning up state\n", name)
			} else {
				return err
			}
		}
		if err := m.States.Remove(name); err != nil {
			return err
		}
		return m.Reconcile()
	})
}

// Block 403s the container's Caddy site. With hard=true it also removes the
// incus proxy device, severing existing connections at the kernel instead of
// letting them drain through Caddy's reload grace period.
func (m *Manager) Block(name string, hard bool) error {
	return m.locked(func() error {
		c, found, err := m.States.Get(name)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("unknown container %q", name)
		}
		c.Blocked = true
		if err := m.States.Put(c); err != nil {
			return err
		}
		if err := m.Reconcile(); err != nil {
			return err
		}
		if hard {
			// Try every device even if one fails: leaving the other attached
			// would mean "connections severed" was a lie.
			var errs []error
			for _, dev := range []string{DeviceName, SocketDeviceName} {
				if err := m.Incus.Run("config", "device", "remove", name, dev); err != nil {
					if isNotFound(err) {
						fmt.Fprintf(m.out(), "note: device %s already absent on %q\n", dev, name)
					} else {
						errs = append(errs, err)
					}
				}
			}
			if len(errs) > 0 {
				return fmt.Errorf("container is 403ed but some devices remain attached: %w", errors.Join(errs...))
			}
			fmt.Fprintf(m.out(), "blocked %q (hard): proxy devices removed, connections severed\n", name)
			return nil
		}
		fmt.Fprintf(m.out(), "blocked %q: new requests get 403; in-flight requests drain for up to the reload grace period.\nUse --hard (or agentbox destroy) to sever instantly.\n", name)
		return nil
	})
}

// Unblock restores the container's routes and re-adds the proxy device if a
// hard block removed it.
func (m *Manager) Unblock(name string) error {
	return m.locked(func() error {
		c, found, err := m.States.Get(name)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("unknown container %q", name)
		}
		c.Blocked = false
		if err := m.States.Put(c); err != nil {
			return err
		}
		if err := m.Reconcile(); err != nil {
			return err
		}
		devices, err := m.Incus.Output("config", "device", "list", name)
		if err != nil {
			return err
		}
		readded := false
		for _, args := range m.deviceArgs(name) {
			dev := args[4]
			if containsLine(string(devices), dev) {
				continue
			}
			if err := m.Incus.Run(args...); err != nil {
				return err
			}
			readded = true
		}
		if readded {
			fmt.Fprintf(m.out(), "unblocked %q and re-added its proxy devices\n", name)
			return nil
		}
		fmt.Fprintf(m.out(), "unblocked %q\n", name)
		return nil
	})
}

// Row is one line of `agentbox list` / `agentbox proxy status` output. Drift
// (state file without instance, tagged instance without state file, missing
// socket) must be visible, never papered over.
type Row struct {
	Name    string
	Gateway string
	Incus   string // instance status, or "MISSING!" / "untracked"
	Blocked bool
	Socket  bool
	Created time.Time
}

type incusInstance struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Config map[string]string `json:"config"`
}

// List joins the three sources of truth.
func (m *Manager) List() ([]Row, error) {
	states, err := m.States.List()
	if err != nil {
		return nil, err
	}
	var instances []incusInstance
	if err := m.Incus.JSON(&instances, "list", "--format", "json"); err != nil {
		return nil, err
	}
	byName := make(map[string]incusInstance)
	for _, inst := range instances {
		if inst.Config["user.agentbox"] == "true" {
			byName[inst.Name] = inst
		}
	}
	var rows []Row
	seen := make(map[string]bool)
	for _, c := range states {
		row := Row{Name: c.Name, Gateway: c.Gateway, Blocked: c.Blocked, Created: c.Created, Incus: "MISSING!"}
		if inst, ok := byName[c.Name]; ok {
			row.Incus = inst.Status
		}
		row.Socket = m.socketLive(c.Name)
		rows = append(rows, row)
		seen[c.Name] = true
	}
	for name, inst := range byName {
		if seen[name] {
			continue
		}
		rows = append(rows, Row{Name: name, Incus: inst.Status + " (untracked!)"})
	}
	return rows, nil
}

func (m *Manager) instanceExists(name string) (bool, error) {
	_, exists, err := m.instanceManaged(name)
	return exists, err
}

// instanceManaged reports whether the named incus instance carries agentbox's
// tag, and whether it exists at all.
func (m *Manager) instanceManaged(name string) (managed, exists bool, err error) {
	var instances []incusInstance
	if err := m.Incus.JSON(&instances, "list", "--format", "json"); err != nil {
		return false, false, err
	}
	for _, inst := range instances {
		if inst.Name == name {
			return inst.Config["user.agentbox"] == "true", true, nil
		}
	}
	return false, false, nil
}

func isNotFound(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "not found") || strings.Contains(s, "doesn't exist") || strings.Contains(s, "does not exist")
}

func containsLine(s, line string) bool {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}

// configValidGateway mirrors config.ValidGatewayName. Duplicated rather than
// imported to keep lifecycle free of the config package; the renderer and
// setup validate against the canonical rule before anything reaches here.
var gatewayNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}$`)

func configValidGateway(s string) bool { return gatewayNameRE.MatchString(s) }
