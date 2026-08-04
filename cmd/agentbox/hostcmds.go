package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"agentbox/image"
	"agentbox/internal/buildimage"
	"agentbox/internal/lifecycle"
	"agentbox/internal/setup"
)

func cmdSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	account := fs.String("account-id", "", "Cloudflare account ID (prompted if absent)")
	gateways := fs.String("gateways", "", "comma-separated AI Gateway names (prompted if absent)")
	adminUser := fs.String("admin-user", "", "user to add to the agentbox group (default $SUDO_USER)")
	noStart := fs.Bool("no-start", false, "prepare everything but do not (re)start services")
	prefix := fs.String("prefix", "", "root all paths here and skip system mutations (testing)")
	caddyBin := fs.String("caddy-bin", "", "caddy binary (default caddy)")
	if _, ok := parseArgs(fs, args); !ok {
		return 2
	}
	err := setup.Run(setup.Options{
		Prefix:    *prefix,
		AccountID: *account,
		Gateways:  splitList(*gateways),
		AdminUser: *adminUser,
		NoStart:   *noStart,
		CaddyBin:  *caddyBin,
		Out:       os.Stdout,
	})
	if err != nil {
		return fail(err)
	}
	return 0
}

// splitList parses a comma-separated flag into a trimmed, non-empty list.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdSetupFirewall(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: agentbox setup-firewall")
		return 2
	}
	if err := setup.ApplyFirewallRules(os.Stdout); err != nil {
		return fail(err)
	}
	return 0
}

func cmdBuildImage(args []string) int {
	fs := flag.NewFlagSet("build-image", flag.ContinueOnError)
	provision := fs.String("provision", "", "provision script overriding the embedded image/provision.sh")
	keep := fs.Bool("keep-build", false, "keep the build container after publishing")
	alias := fs.String("alias", lifecycle.Image, "image alias to publish")
	if _, ok := parseArgs(fs, args); !ok {
		return 2
	}
	err := buildimage.Run(buildimage.Options{
		Incus:         lifecycle.Incus{},
		Alias:         *alias,
		ProvisionPath: *provision,
		Provision:     image.Provision,
		KeepBuild:     *keep,
		Out:           os.Stdout,
	})
	if err != nil {
		return fail(err)
	}
	return 0
}
