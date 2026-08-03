// Package paths holds the canonical host locations agentbox uses. Everything
// is overridable by CLI flags (and rooted under a prefix in setup tests);
// these are just the defaults.
package paths

const (
	Etc     = "/etc/agentbox"
	Routes  = "/etc/agentbox/routes.json"
	Secrets = "/etc/agentbox/secrets"
	Meta    = "/etc/agentbox/agentbox.json"
	// SecretsManifest lists the names (never values) of installed secrets, so
	// the non-root CLI can render routes with missing credentials as 503
	// without being able to read /etc/agentbox/secrets itself.
	SecretsManifest = "/etc/agentbox/secrets.installed"
	StateBase       = "/var/lib/agentbox"
	// Caddyfile is persistent (not tmpfs) and secret-free, so caddy.service
	// boots on its own after a reboot with no agentbox involvement.
	Caddyfile      = "/var/lib/agentbox/Caddyfile"
	LockFile       = "/var/lib/agentbox/.reconcile.lock"
	RunDir         = "/run/agentbox"
	SocketDir      = "/run/agentbox/containers"
	CredentialsDir = "/run/credentials/caddy.service"
	// CaddyDropin is the generated caddy.service drop-in; its LoadCredential
	// lines are what Caddy will actually receive, so reconcile cross-checks
	// the manifest against them.
	CaddyDropin  = "/etc/systemd/system/caddy.service.d/agentbox.conf"
	InstalledBin = "/usr/local/bin/agentbox"
)
