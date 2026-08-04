package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"agentbox/internal/config"
)

func cmdProxy(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentbox proxy status|routes|reload|block [--hard] <name>|unblock <name>")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		return cmdProxyStatus(rest)
	case "routes":
		return cmdProxyRoutes(rest)
	case "reload":
		return cmdProxyReload(rest)
	case "block":
		return cmdProxyBlock(rest)
	case "unblock":
		return cmdProxyUnblock(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown proxy subcommand %q\n", sub)
		return 2
	}
}

func cmdProxyStatus(args []string) int {
	fs := flag.NewFlagSet("proxy status", flag.ContinueOnError)
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
	fmt.Fprintln(w, "NAME\tGATEWAY\tINCUS\tBLOCKED\tSOCKET\tCREATED")
	for _, r := range rows {
		created := ""
		if !r.Created.IsZero() {
			created = r.Created.Local().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\t%s\n", r.Name, orDash(r.Gateway), r.Incus, r.Blocked, presence(r.Socket), created)
	}
	w.Flush()
	fmt.Println("\nproxy traffic logs: journalctl -u caddy")
	return 0
}

// cmdProxyRoutes prints the route table. It never resolves secrets — only
// config.Load, which handles names.
func cmdProxyRoutes(args []string) int {
	fs := flag.NewFlagSet("proxy routes", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	if _, ok := parseArgs(fs, args); !ok {
		return 2
	}
	cfg, err := config.Load(cf.routes)
	if err != nil {
		return fail(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 8, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tMATCH\tSELECTOR\tUPSTREAM\tINJECTS")
	for _, r := range cfg.Routes {
		match := "path"
		if r.IsHostRoute() {
			match = "host"
		}
		// Header names only — a value could hold a secret template, and this
		// table is the operator's audit surface for "what gets credentials".
		var injected []string
		for _, h := range r.Inject {
			injected = append(injected, h.Header)
		}
		names := strings.Join(injected, ",")
		if names == "" {
			names = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Name, match, r.Selector(), r.Upstream, names)
	}
	w.Flush()
	return 0
}

func cmdProxyReload(args []string) int {
	fs := flag.NewFlagSet("proxy reload", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	if _, ok := parseArgs(fs, args); !ok {
		return 2
	}
	if err := cf.reconcileOnce(); err != nil {
		return fail(err)
	}
	fmt.Println("reconciled")
	return 0
}

func cmdProxyBlock(args []string) int {
	fs := flag.NewFlagSet("proxy block", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	hard := fs.Bool("hard", false, "also remove the incus proxy device (severs existing connections instantly)")
	rest, ok := parseArgs(fs, args)
	if !ok {
		return 2
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentbox proxy block [--hard] <name>")
		return 2
	}
	m, err := cf.manager()
	if err != nil {
		return fail(err)
	}
	if err := m.Block(rest[0], *hard); err != nil {
		return fail(err)
	}
	return 0
}

func cmdProxyUnblock(args []string) int {
	fs := flag.NewFlagSet("proxy unblock", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	rest, ok := parseArgs(fs, args)
	if !ok {
		return 2
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentbox proxy unblock <name>")
		return 2
	}
	m, err := cf.manager()
	if err != nil {
		return fail(err)
	}
	if err := m.Unblock(rest[0]); err != nil {
		return fail(err)
	}
	return 0
}
