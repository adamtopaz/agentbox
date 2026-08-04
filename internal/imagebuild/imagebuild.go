// Package imagebuild creates the reusable agent image through Incus itself.
// A disposable cloud image consumes the embedded cloud-init specification,
// is verified and scrubbed, then is published. Privilege stays behind the
// Incus daemon boundary; the operator-facing command does not require sudo.
package imagebuild

import (
	"errors"
	"fmt"
	"io"
	"os"

	imageasset "agentbox/image"
	"agentbox/internal/incus"
)

const (
	BuilderName = "agentbox-build"
	BuilderTag  = "user.agentbox-build"
	DefaultBase = "images:debian/13/cloud"
)

type Options struct {
	Alias, Source string
	Incus         Incus
	Definition    []byte
	Out           io.Writer
	Keep          bool
}

// Incus is the minimal daemon-backed capability required to construct and
// publish an image. Image building never receives host filesystem privilege.
type Incus interface {
	Run(...string) error
	RunInput(string, ...string) error
	RunStreaming(...string) error
	JSON(any, ...string) error
}

type instance struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Config map[string]string `json:"config"`
}

func Run(options Options) (returnErr error) {
	if options.Incus == nil {
		return errors.New("Incus client is required")
	}
	if options.Alias == "" {
		options.Alias = incus.DefaultImage
	}
	if options.Source == "" {
		options.Source = DefaultBase
	}
	definition := options.Definition
	if len(definition) == 0 {
		definition = imageasset.Definition
	}
	if len(definition) == 0 {
		return errors.New("embedded Incus builder definition is empty")
	}

	exists, owned, err := builderState(options.Incus)
	if err != nil {
		return err
	}
	if exists && !owned {
		return fmt.Errorf("Incus instance %q exists but is not an agentbox image builder; refusing to replace it", BuilderName)
	}
	if exists {
		fmt.Fprintf(output(options.Out), "deleting stale managed builder %s\n", BuilderName)
		if err := options.Incus.Run("delete", "--force", BuilderName); err != nil {
			return err
		}
	}

	// Arm cleanup before init: an Incus operation can fail after it created the
	// instance. The deferred ownership check handles that ambiguous result.
	defer func() {
		if options.Keep {
			if exists, owned, _ := builderState(options.Incus); exists && owned {
				fmt.Fprintf(output(options.Out), "builder %s kept; delete it with: incus delete --force %s\n", BuilderName, BuilderName)
			}
			return
		}
		cleanupErr := deleteOwnedBuilder(options.Incus)
		if cleanupErr == nil {
			return
		}
		if returnErr == nil {
			returnErr = cleanupErr
			return
		}
		fmt.Fprintf(output(options.Out), "warning: builder cleanup failed: %v\n", cleanupErr)
	}()

	fmt.Fprintf(output(options.Out), "creating %s from %s\n", BuilderName, options.Source)
	if err := options.Incus.RunInput(string(definition), "init", options.Source, BuilderName); err != nil {
		return fmt.Errorf("create builder: %w", err)
	}
	if err := options.Incus.RunStreaming("start", BuilderName); err != nil {
		return fmt.Errorf("start builder: %w", err)
	}

	fmt.Fprintln(output(options.Out), "waiting for cloud-init provisioning")
	if err := options.Incus.RunStreaming("exec", BuilderName, "--", "cloud-init", "status", "--wait", "--long"); err != nil {
		return fmt.Errorf("cloud-init provisioning failed (rerun with --keep-builder to inspect its status and logs): %w", err)
	}
	if err := options.Incus.RunStreaming("exec", BuilderName, "--", "sh", "-ceu", verifyScript); err != nil {
		return fmt.Errorf("verify provisioned image: %w", err)
	}

	// The specification belongs to the disposable builder, not instances made
	// from the published image. Disable cloud-init after cleaning it so child
	// containers start from the baked state without provisioning a second time.
	if err := options.Incus.Run("config", "unset", BuilderName, "cloud-init.user-data"); err != nil {
		return fmt.Errorf("remove builder cloud-init configuration: %w", err)
	}
	if err := options.Incus.RunStreaming("exec", BuilderName, "--", "sh", "-ceu", cleanupScript); err != nil {
		return fmt.Errorf("clean builder: %w", err)
	}
	if err := options.Incus.RunStreaming("stop", BuilderName); err != nil {
		return fmt.Errorf("stop builder: %w", err)
	}

	fmt.Fprintf(output(options.Out), "publishing image %q\n", options.Alias)
	if err := options.Incus.RunStreaming("publish", BuilderName, "--alias", options.Alias, "--reuse",
		"description=Agentbox Debian 13 coding-agent container"); err != nil {
		return fmt.Errorf("publish image: %w", err)
	}
	fmt.Fprintf(output(options.Out), "image %q published from declarative Incus/cloud-init configuration\n", options.Alias)
	return nil
}

func builderState(client Incus) (exists, owned bool, err error) {
	var instances []instance
	if err := client.JSON(&instances, "list", "--format", "json"); err != nil {
		return false, false, err
	}
	for _, item := range instances {
		if item.Name == BuilderName {
			return true, item.Config[BuilderTag] == "true", nil
		}
	}
	return false, false, nil
}

func deleteOwnedBuilder(client Incus) error {
	exists, owned, err := builderState(client)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if !owned {
		return fmt.Errorf("refusing to delete non-agentbox instance %q during cleanup", BuilderName)
	}
	return client.Run("delete", "--force", BuilderName)
}

func output(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stdout
}

const verifyScript = `
for command in claude codex fd pi gh git node npm; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing expected command: $command" >&2
    exit 1
  }
done
test "$(node --version)" = 'v24.19.0'
test "$(npm --version)" = '11.17.0'
test "$(readlink "$(command -v fd)")" = '/usr/bin/fdfind'
dpkg-query --show fd-find >/dev/null
fd --version
npm list --global --depth=0 | grep -F '@anthropic-ai/claude-code@2.1.220'
npm list --global --depth=0 | grep -F '@openai/codex@0.145.0'
npm list --global --depth=0 | grep -F '@earendil-works/pi-coding-agent@0.82.1'
claude --version | grep -F '2.1.220'
codex --version | grep -F '0.145.0'
pi --version | grep -F '0.82.1'
test -f /home/agent/.config/gh/config.yml
test -f /home/agent/.claude.json
test -f /etc/agentbox-image
grep -F 'http_unix_socket: /run/agentbox.sock' /home/agent/.config/gh/config.yml
if git config --system --get-regexp '^url\..*\.insteadof$'; then
  echo 'system URL rewrites must not change canonical repository metadata' >&2
  exit 1
fi
grep -F 'export GIT_EXEC_PATH=/usr/local/lib/agentbox/git-core' /etc/profile.d/agentbox.sh
grep -F 'GIT_EXEC_PATH=/usr/local/lib/agentbox/git-core' /etc/environment
grep -F 'github-git-transport=helper-v1' /etc/agentbox-image
test -x /usr/local/lib/agentbox/git-core/git-remote-https
test -x /usr/local/lib/agentbox/git-remote-http-original
test "$(GIT_EXEC_PATH=/usr/local/lib/agentbox/git-core git --exec-path)" = \
  /usr/local/lib/agentbox/git-core
visudo -c
`

const cleanupScript = `
cloud-init clean --logs --machine-id --seed
touch /etc/cloud/cloud-init.disabled
rm -f /etc/ssh/ssh_host_* /var/lib/dbus/machine-id
apt-get clean
npm cache clean --force
find /var/lib/apt/lists -mindepth 1 -delete
sync
`
