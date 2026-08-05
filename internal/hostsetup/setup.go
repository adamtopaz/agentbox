// Package hostsetup performs the small amount of privileged installation
// agentbox requires: a service user/group, two binaries, one encrypted master
// key, and one hardened systemd unit. Runtime configuration is managed through
// the daemon API, not by rewriting unit files.
package hostsetup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"agentbox/internal/atomicfile"
	"agentbox/internal/paths"
)

type Options struct {
	Prefix, AdminUser, CLIBinary, DaemonBinary, CredsBinary string
	NoStart                                                 bool
	Out                                                     io.Writer
}

func Run(options Options) error {
	r := &runner{options: options, out: options.Out}
	if r.out == nil {
		r.out = os.Stdout
	}
	if options.Prefix == "" && os.Geteuid() != 0 {
		return errors.New("setup requires root (sudo agentbox setup)")
	}
	if options.Prefix == "" {
		if err := r.ensureAccounts(); err != nil {
			return fmt.Errorf("accounts: %w", err)
		}
	}
	if err := r.ensureDirectories(); err != nil {
		return fmt.Errorf("directories: %w", err)
	}
	if err := r.installBinaries(); err != nil {
		return fmt.Errorf("binaries: %w", err)
	}
	if err := r.ensureMasterCredential(); err != nil {
		return fmt.Errorf("master credential: %w", err)
	}
	if err := r.installUnit(); err != nil {
		return fmt.Errorf("unit: %w", err)
	}
	if options.Prefix == "" {
		r.addAdminGroups()
		if !options.NoStart {
			for _, command := range [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "enable", "agentboxd.service"}, {"systemctl", "restart", "agentboxd.service"}} {
				if err := r.command(command[0], command[1:]...); err != nil {
					return err
				}
			}
		}
	}
	fmt.Fprintln(r.out, "setup complete")
	if options.NoStart {
		fmt.Fprintln(r.out, "next: systemctl daemon-reload && systemctl enable --now agentboxd")
	} else {
		fmt.Fprintln(r.out, "next: agentbox profile create <name>")
	}
	return nil
}

type runner struct {
	options Options
	out     io.Writer
}

func (r *runner) path(path string) string { return filepath.Join(r.options.Prefix, path) }

func (r *runner) ensureAccounts() error {
	if _, err := user.LookupGroup("agentbox"); err != nil {
		if err := r.command("groupadd", "--system", "agentbox"); err != nil {
			return err
		}
	}
	if _, err := user.Lookup("agentboxd"); err != nil {
		if err := r.command("useradd", "--system", "--gid", "agentbox", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "agentboxd"); err != nil {
			return err
		}
	}
	return nil
}

func (r *runner) ensureDirectories() error {
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{paths.EtcDir, 0o700}, {paths.StateDir, 0o700}, {paths.SecretsDir, 0o700}} {
		path := r.path(item.path)
		if err := os.MkdirAll(path, item.mode); err != nil {
			return err
		}
		if err := os.Chmod(path, item.mode); err != nil {
			return err
		}
	}
	if r.options.Prefix != "" {
		return nil
	}
	u, err := user.Lookup("agentboxd")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	g, err := user.LookupGroup("agentbox")
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	for _, path := range []string{paths.StateDir, paths.SecretsDir} {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func (r *runner) installBinaries() error {
	cli := r.options.CLIBinary
	if cli == "" {
		var err error
		cli, err = os.Executable()
		if err != nil {
			return err
		}
	}
	daemon := r.options.DaemonBinary
	if daemon == "" {
		daemon = filepath.Join(filepath.Dir(cli), "agentboxd")
	}
	for _, item := range []struct{ source, target string }{{cli, r.path(paths.InstalledCLI)}, {daemon, r.path(paths.InstalledDaemon)}} {
		data, err := os.ReadFile(item.source)
		if err != nil {
			return fmt.Errorf("read %s: %w (build both binaries with `make bin`)", item.source, err)
		}
		if err := atomicfile.Write(item.target, data, 0o755); err != nil {
			return err
		}
		fmt.Fprintf(r.out, "installed %s\n", item.target)
	}
	return nil
}

func (r *runner) ensureMasterCredential() error {
	target := r.path(paths.MasterCredential)
	if info, err := os.Stat(target); err == nil {
		if info.Mode().Perm() != 0o600 {
			return os.Chmod(target, 0o600)
		}
		fmt.Fprintln(r.out, "master credential already exists")
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if r.options.Prefix != "" {
		// Prefix mode is a filesystem-layout test mode and must never exercise
		// or depend on the host's TPM/credential key.
		return atomicfile.Write(target, []byte("prefix-mode-placeholder\n"), 0o600)
	}
	bin := r.options.CredsBinary
	if bin == "" {
		bin = "systemd-creds"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("systemd-creds is required: %w", err)
	}
	if err := r.command(bin, "setup"); err != nil {
		return err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	defer clear(key)
	tmp, err := os.CreateTemp(filepath.Dir(target), ".master-key-*.cred")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	enc := exec.Command(bin, "encrypt", "--name="+paths.MasterKeyName, "--with-key=auto", "--newline=no", "-", tmpPath)
	enc.Stdin = bytes.NewReader(key)
	var stderr bytes.Buffer
	enc.Stderr = &stderr
	if err := enc.Run(); err != nil {
		return fmt.Errorf("systemd-creds encrypt: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	dec := exec.Command(bin, "decrypt", "--name="+paths.MasterKeyName, "--newline=no", tmpPath, "-")
	var plaintext, decErr bytes.Buffer
	dec.Stdout = &plaintext
	dec.Stderr = &decErr
	if err := dec.Run(); err != nil {
		return fmt.Errorf("verify systemd credential: %w: %s", err, strings.TrimSpace(decErr.String()))
	}
	decrypted := plaintext.Bytes()
	defer clear(decrypted)
	if !bytes.Equal(decrypted, key) {
		return errors.New("systemd credential did not round-trip; refusing to install it")
	}
	ciphertext, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(target, ciphertext, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(r.out, "created TPM/host-bound master credential %s\n", target)
	return nil
}

func (r *runner) installUnit() error {
	unit := `# Managed by agentbox setup.
[Unit]
Description=Agentbox credential-isolating reverse proxy
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
NotifyAccess=main
User=agentboxd
Group=agentbox
UMask=0007
ExecStart=` + paths.InstalledDaemon + `
Restart=on-failure
RestartSec=2s
TimeoutStartSec=30s
TimeoutStopSec=15s
RuntimeDirectory=agentbox
RuntimeDirectoryMode=0750
StateDirectory=agentbox
StateDirectoryMode=0700
LoadCredentialEncrypted=` + paths.MasterKeyName + `:` + paths.MasterCredential + `

NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
ProtectProc=invisible
ProcSubset=pid
RemoveIPC=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitCORE=0
LimitNOFILE=8192
TasksMax=512
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
`
	if err := atomicfile.Write(r.path(paths.UnitFile), []byte(unit), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(r.out, "installed %s\n", r.path(paths.UnitFile))
	return nil
}

func (r *runner) addAdminGroups() {
	admin := r.options.AdminUser
	if admin == "" {
		admin = os.Getenv("SUDO_USER")
	}
	if admin == "" || admin == "root" {
		return
	}
	for _, group := range []string{"agentbox", "incus-admin"} {
		if _, err := user.LookupGroup(group); err != nil {
			continue
		}
		if err := r.command("usermod", "-aG", group, admin); err != nil {
			fmt.Fprintf(r.out, "warning: add %s to %s: %v\n", admin, group, err)
		}
	}
	fmt.Fprintf(r.out, "group membership changed for %s; log out and back in\n", admin)
}

func (r *runner) command(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = r.out
	cmd.Stderr = r.out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
