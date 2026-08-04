// Package buildimage implements `agentbox build-image`: launch a stock
// Debian container, run image/provision.sh inside it, and publish the result
// as the agentbox-base image alias.
package buildimage

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"agentbox/internal/config"
	"agentbox/internal/lifecycle"
	"agentbox/internal/paths"
	"agentbox/internal/state"
)

const (
	buildContainer = state.ReservedName // agentbox-build
	buildTag       = "user.agentbox-build"
	sourceImage    = "images:debian/13"
)

type Options struct {
	Incus         lifecycle.Incus
	Alias         string // default agentbox-base
	ProvisionPath string // override the embedded provision.sh
	Provision     []byte // embedded default (set by cmd)
	MetaPath      string // default /etc/agentbox/agentbox.json
	KeepBuild     bool
	Out           io.Writer
}

func Run(o Options) error {
	if o.Alias == "" {
		o.Alias = lifecycle.Image
	}
	if o.MetaPath == "" {
		o.MetaPath = paths.Meta
	}
	out := o.Out
	if out == nil {
		out = os.Stdout
	}
	inc := o.Incus

	script := o.Provision
	if o.ProvisionPath != "" {
		var err error
		script, err = os.ReadFile(o.ProvisionPath)
		if err != nil {
			return err
		}
	}
	if len(script) == 0 {
		return errors.New("no provision script")
	}

	accountID, gatewayID := "", ""
	if m, err := config.LoadMeta(o.MetaPath); err == nil {
		accountID, gatewayID = m.AccountID, m.GatewayID
	} else if errors.Is(err, fs.ErrNotExist) {
		// The gateway name is baked into the image's base URLs, so an empty
		// one produces containers that fail against Cloudflare with a 404
		// that looks like an API fault.
		return fmt.Errorf("%s not found: run `agentbox setup` first so the image can be wired to a gateway", o.MetaPath)
	} else {
		return err
	}

	// Never delete a stale name-squatter that we did not create.
	var instances []struct {
		Name   string            `json:"name"`
		Config map[string]string `json:"config"`
	}
	if err := inc.JSON(&instances, "list", "--format", "json"); err != nil {
		return err
	}
	for _, inst := range instances {
		if inst.Name != buildContainer {
			continue
		}
		if inst.Config[buildTag] != "true" {
			return fmt.Errorf("an incus instance named %q exists but was not created by agentbox build-image; refusing to delete it", buildContainer)
		}
		fmt.Fprintf(out, "deleting stale build container %s\n", buildContainer)
		if err := inc.Run("delete", "--force", buildContainer); err != nil {
			return err
		}
	}

	fmt.Fprintf(out, "launching %s as %s\n", sourceImage, buildContainer)
	if err := inc.RunStreaming("launch", sourceImage, buildContainer, "-c", buildTag+"=true"); err != nil {
		return err
	}
	keepForDebug := false
	defer func() {
		if o.KeepBuild || keepForDebug {
			fmt.Fprintf(out, "build container %s kept (delete with: incus delete --force %s)\n", buildContainer, buildContainer)
			return
		}
		if err := inc.Run("delete", "--force", buildContainer); err != nil {
			fmt.Fprintf(out, "warning: could not delete build container: %v\n", err)
		}
	}()

	if err := waitReady(inc, out); err != nil {
		keepForDebug = true
		return err
	}

	tmp, err := os.CreateTemp("", "agentbox-provision-*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(script); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := inc.Run("file", "push", tmp.Name(), buildContainer+"/root/provision.sh"); err != nil {
		return err
	}

	fmt.Fprintln(out, "running provision.sh (streaming)")
	if err := inc.RunStreaming("exec", buildContainer,
		"--env", "AGENTBOX_ACCOUNT_ID="+accountID,
		"--env", "AGENTBOX_GATEWAY_ID="+gatewayID,
		"--env", "AGENTBOX_BUILD_DATE="+time.Now().UTC().Format("2006-01-02"),
		"--", "bash", "-euo", "pipefail", "/root/provision.sh"); err != nil {
		keepForDebug = true
		return fmt.Errorf("provisioning failed (build container kept for debugging): %w", err)
	}

	if err := inc.Run("stop", buildContainer); err != nil {
		return err
	}
	// Republish: drop the alias (incus keeps the underlying image
	// unreferenced), then publish under it again.
	var aliases []struct {
		Name string `json:"name"`
	}
	if err := inc.JSON(&aliases, "image", "alias", "list", "--format", "json"); err == nil {
		for _, a := range aliases {
			if a.Name == o.Alias {
				if err := inc.Run("image", "alias", "delete", o.Alias); err != nil {
					return err
				}
			}
		}
	}
	fmt.Fprintf(out, "publishing %s (this can take a minute)\n", o.Alias)
	if err := inc.RunStreaming("publish", buildContainer, "--alias", o.Alias); err != nil {
		keepForDebug = true
		return err
	}
	fmt.Fprintf(out, "image %s ready — create containers with: agentbox create <name>\n", o.Alias)
	return nil
}

// waitReady waits for systemd (fresh containers are routinely "degraded" —
// that still counts as up) and for DNS egress, the thing Docker's FORWARD
// policy most often breaks.
func waitReady(inc lifecycle.Incus, out io.Writer) error {
	deadline := time.Now().Add(60 * time.Second)
	sawSystemd := false
	for time.Now().Before(deadline) {
		if !sawSystemd {
			o, _ := inc.Output("exec", buildContainer, "--", "systemctl", "is-system-running")
			s := strings.TrimSpace(string(o))
			if s == "running" || s == "degraded" {
				sawSystemd = true
			} else {
				time.Sleep(2 * time.Second)
				continue
			}
		}
		if err := inc.Run("exec", buildContainer, "--", "getent", "hosts", "deb.debian.org"); err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	if !sawSystemd {
		return errors.New("build container never reached running/degraded state")
	}
	return errors.New("build container has no DNS/egress after 60s — if Docker runs on this host, its FORWARD drop policy is the usual cause; run `sudo agentbox setup-firewall` (or `agentbox setup`) and retry")
}
