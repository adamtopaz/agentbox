package setup

import (
	"fmt"
	"strings"

	"agentbox/internal/paths"
)

// tmpfilesConf recreates the runtime dir tree on every boot. Both dirs are
// owned by the caddy user — it creates the admin socket in the first and the
// per-container sockets in the second — and setgid to the agentbox group so
// those sockets are reachable by the CLI. There is deliberately no `agentbox`
// *user*: only the group exists, so naming one here would make
// systemd-tmpfiles fail and abort setup.
const tmpfilesConf = `# Managed by agentbox setup — regenerated on every run.
d /run/agentbox 2775 caddy agentbox -
d /run/agentbox/containers 2775 caddy agentbox -
`

// firewallUnit re-applies the DOCKER-USER ACCEPT rules for incusbr0 at boot,
// after docker.service has (re)created the chain and flipped FORWARD to DROP.
const firewallUnit = `# Managed by agentbox setup — regenerated on every run.
[Unit]
Description=agentbox: allow incus bridge traffic despite Docker's FORWARD drop policy
After=docker.service network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + paths.InstalledBin + ` setup-firewall

[Install]
WantedBy=multi-user.target
`

// renderCaddyDropin produces /etc/systemd/system/caddy.service.d/agentbox.conf:
// point Caddy at the agentbox-rendered Caddyfile and load the referenced
// secrets as systemd credentials (which Caddy reads back via {file.*}).
// loadCredentials must already be sorted so re-runs are byte-identical.
func renderCaddyDropin(caddyBin string, loadCredentials []string) string {
	var b strings.Builder
	b.WriteString("# Managed by agentbox setup — regenerated on every run.\n")
	b.WriteString("# Re-run `agentbox setup` after installing or rotating secrets.\n")
	b.WriteString("[Service]\n")
	// Empty assignments reset the packaged unit's list before ours is added.
	fmt.Fprintf(&b, "ExecStart=\nExecStart=%s run --environ --config %s --adapter caddyfile\n", caddyBin, paths.Caddyfile)
	fmt.Fprintf(&b, "ExecReload=\nExecReload=%s reload --config %s --adapter caddyfile --force\n", caddyBin, paths.Caddyfile)
	// The leading '-' matters: without it a missing path makes the unit fail
	// to start, so a tmpfiles.d hiccup would take the proxy down at boot with
	// an opaque namespacing error. (/run is already writable under the stock
	// unit's ProtectSystem=full; this is belt-and-braces.)
	fmt.Fprintf(&b, "ReadWritePaths=-%s\n", paths.RunDir)
	for _, line := range loadCredentials {
		b.WriteString(line + "\n")
	}
	return b.String()
}
