package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"text/tabwriter"

	"agentbox/internal/control"
	"agentbox/internal/domain"
	"agentbox/internal/incus"
	"agentbox/internal/paths"
	"agentbox/internal/profile"
)

func cmdContainer(ctx context.Context, client *control.Client, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentbox container create|list|shell|destroy|block|unblock")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("container create", flag.ContinueOnError)
		scope := fs.String("scope", "", "route scope")
		configure := fs.String("configure", "cloudflare", "container configuration profile: cloudflare or none")
		image := fs.String("image", incus.DefaultImage, "Incus image alias")
		cpus := fs.Uint("cpus", incus.DefaultCPUs, "maximum CPUs")
		memory := fs.String("memory", incus.DefaultMemory, "maximum memory")
		processes := fs.Uint("processes", incus.DefaultProcesses, "maximum processes")
		disk := fs.String("disk", incus.DefaultDisk, "maximum root disk size")
		incusBin := fs.String("incus-bin", "incus", "Incus CLI")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 || *scope == "" {
			return errors.New("usage: agentbox container create --scope SCOPE [--configure cloudflare|none] [resource flags] <name>")
		}
		var script string
		switch *configure {
		case "none":
		case "cloudflare":
			var err error
			script, err = profile.CloudflareContainerScript(*scope)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown configure profile %q", *configure)
		}
		manager := containerManager(client, *incusBin)
		manager.Image = *image
		return manager.Create(ctx, incus.CreateOptions{
			Name: fs.Arg(0), Scope: *scope, ConfigureScript: script,
			CPUs: *cpus, Memory: *memory, Processes: *processes, Disk: *disk,
		})
	case "list":
		fs := flag.NewFlagSet("container list", flag.ContinueOnError)
		incusBin := fs.String("incus-bin", "incus", "Incus CLI")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("usage: agentbox container list")
		}
		rows, err := containerManager(client, *incusBin).List(ctx)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSCOPE\tINCUS\tBLOCKED\tSOCKET")
		for _, row := range rows {
			socket := "absent"
			if row.Socket {
				socket = "present"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n", row.Name, orDash(row.Scope), row.Incus, row.Blocked, socket)
		}
		return w.Flush()
	case "shell":
		if len(args) != 2 {
			return errors.New("usage: agentbox container shell <name>")
		}
		if !domain.ValidName(args[1]) {
			return fmt.Errorf("invalid container name %q", args[1])
		}
		path, err := exec.LookPath("incus")
		if err != nil {
			return err
		}
		return syscall.Exec(path, []string{"incus", "exec", args[1], "--", "su", "-", "agent"}, os.Environ())
	case "destroy":
		if len(args) != 2 {
			return errors.New("usage: agentbox container destroy <name>")
		}
		return containerManager(client, "incus").Destroy(ctx, args[1])
	case "block":
		fs := flag.NewFlagSet("container block", flag.ContinueOnError)
		hard := fs.Bool("hard", false, "remove proxy devices to sever connections")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: agentbox container block [--hard] <name>")
		}
		return containerManager(client, "incus").Block(ctx, fs.Arg(0), *hard)
	case "unblock":
		if len(args) != 2 {
			return errors.New("usage: agentbox container unblock <name>")
		}
		return containerManager(client, "incus").Unblock(ctx, args[1])
	default:
		return fmt.Errorf("unknown container command %q", args[0])
	}
}

func containerManager(client *control.Client, bin string) *incus.Manager {
	return &incus.Manager{Incus: incus.Client{Bin: bin}, Control: client, SocketDir: paths.ContainerSocketsDir, Out: os.Stdout}
}
func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
