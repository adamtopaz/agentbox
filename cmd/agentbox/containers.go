package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"text/tabwriter"

	"agentbox/internal/config"
	"agentbox/internal/paths"
	"agentbox/internal/state"
)

func cmdCreate(args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	gateway := fs.String("gateway", "", "AI Gateway this container may use (required; see agentbox.json)")
	meta := fs.String("meta", paths.Meta, "gateway coordinates file")
	rest, ok := parseArgs(fs, args)
	if !ok {
		return 2
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentbox create --gateway <gateway> <name>")
		return 2
	}
	// There is deliberately no default gateway: the container's site will
	// carry only this gateway's route, so the choice has to be explicit.
	if *gateway == "" {
		fmt.Fprintln(os.Stderr, "usage: agentbox create --gateway <gateway> <name>")
		fmt.Fprintln(os.Stderr, "  --gateway is required; there is no default. Configured gateways:")
		if md, err := config.LoadMeta(*meta); err == nil {
			for _, g := range md.Gateways {
				fmt.Fprintf(os.Stderr, "    %s\n", g)
			}
		}
		return 2
	}
	// Fail closed on an unreadable or unparseable file: a container must not
	// be created against a gateway nobody could verify.
	md, err := config.LoadMeta(*meta)
	if err != nil {
		return fail(fmt.Errorf("cannot verify gateway %q against %s: %w", *gateway, *meta, err))
	}
	if !md.HasGateway(*gateway) {
		return fail(fmt.Errorf("gateway %q is not configured in %s (have: %s)",
			*gateway, *meta, strings.Join(md.Gateways, ", ")))
	}
	m, mErr := cf.manager()
	if mErr != nil {
		return fail(mErr)
	}
	if err := m.Create(rest[0], *gateway); err != nil {
		return fail(err)
	}
	return 0
}

func cmdDestroy(args []string) int {
	fs := flag.NewFlagSet("destroy", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	rest, ok := parseArgs(fs, args)
	if !ok {
		return 2
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentbox destroy <name>")
		return 2
	}
	m, err := cf.manager()
	if err != nil {
		return fail(err)
	}
	if err := m.Destroy(rest[0]); err != nil {
		return fail(err)
	}
	fmt.Printf("destroyed %q\n", rest[0])
	return 0
}

func cmdShell(args []string) int {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	rest, ok := parseArgs(fs, args)
	if !ok {
		return 2
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentbox shell <name>")
		return 2
	}
	if !state.ValidName(rest[0]) {
		return fail(fmt.Errorf("invalid container name %q", rest[0]))
	}
	incusPath, err := exec.LookPath("incus")
	if err != nil {
		return fail(err)
	}
	// Login shell so /etc/profile.d/agentbox.sh (the proxy wiring) applies.
	argv := []string{"incus", "exec", rest[0], "--", "su", "-", "agent"}
	if err := syscall.Exec(incusPath, argv, os.Environ()); err != nil {
		return fail(fmt.Errorf("exec incus: %w", err))
	}
	return 0 // unreachable
}

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	if _, ok := parseArgs(fs, args); !ok {
		return 2
	}
	m, err := cf.manager()
	if err != nil {
		return fail(err)
	}
	rows, err := m.List()
	if err != nil {
		return fail(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 8, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tGATEWAY\tINCUS\tBLOCKED\tSOCKET")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n", r.Name, orDash(r.Gateway), r.Incus, r.Blocked, presence(r.Socket))
	}
	w.Flush()
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func presence(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}
