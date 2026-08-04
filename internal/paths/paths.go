// Package paths contains deployment defaults. Components accept overrides in
// tests and development; these constants define the production layout.
package paths

const (
	EtcDir              = "/etc/agentbox"
	MasterCredential    = "/etc/agentbox/master-key.cred"
	StateDir            = "/var/lib/agentbox"
	StateFile           = "/var/lib/agentbox/state.json"
	SecretsDir          = "/var/lib/agentbox/secrets"
	RuntimeDir          = "/run/agentbox"
	ControlSocket       = "/run/agentbox/control.sock"
	ContainerSocketsDir = "/run/agentbox/containers"
	InstalledCLI        = "/usr/local/bin/agentbox"
	InstalledDaemon     = "/usr/local/bin/agentboxd"
	UnitFile            = "/etc/systemd/system/agentboxd.service"
	MasterKeyName       = "master-key"
)
