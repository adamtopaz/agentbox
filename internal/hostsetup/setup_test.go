package hostsetup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/paths"
)

func TestPrefixInstallLayout(t *testing.T) {
	dir := t.TempDir()
	cli := filepath.Join(dir, "source-agentbox")
	daemon := filepath.Join(dir, "source-agentboxd")
	if err := os.WriteFile(cli, []byte("cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(daemon, []byte("daemon"), 0o755); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(dir, "root")
	var output bytes.Buffer
	if err := Run(Options{Prefix: prefix, CLIBinary: cli, DaemonBinary: daemon, NoStart: true, Out: &output}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{paths.InstalledCLI, paths.InstalledDaemon, paths.MasterCredential, paths.UnitFile} {
		if _, err := os.Stat(filepath.Join(prefix, path)); err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
	}
	credential := filepath.Join(prefix, paths.MasterCredential)
	info, err := os.Stat(credential)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %o", info.Mode().Perm())
	}
	unit, err := os.ReadFile(filepath.Join(prefix, paths.UnitFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Type=notify", "NotifyAccess=main", "User=agentboxd", "RuntimeDirectoryMode=0750",
		"LoadCredentialEncrypted=master-key:", "ProtectProc=invisible", "ProcSubset=pid",
		"SystemCallArchitectures=native", "LimitCORE=0", "LimitNOFILE=8192", "TasksMax=512",
		"CapabilityBoundingSet=",
	} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("unit missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(string(unit)), "caddy") {
		t.Fatal("unit retains a Caddy reference")
	}
}
