package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"text/tabwriter"

	"agentbox/internal/state"
)

func cmdCreate(args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	var cf commonFlags
	cf.register(fs)
	rest, ok := parseArgs(fs, args)
	if !ok {
		return 2
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentbox create <name>")
		return 2
	}
	m, err := cf.manager()
	if err != nil {
		return fail(err)
	}
	if err := m.Create(rest[0]); err != nil {
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
	fmt.Fprintln(w, "NAME\tINCUS\tBLOCKED\tSOCKET")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%v\t%s\n", r.Name, r.Incus, r.Blocked, presence(r.Socket))
	}
	w.Flush()
	return 0
}

func presence(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}
