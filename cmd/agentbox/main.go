// Command agentbox is the operator-facing client for agentboxd and the Incus
// lifecycle adapter. All live route and key changes go through the daemon's
// typed control service.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"agentbox/internal/control"
	"agentbox/internal/paths"
)

const usage = `agentbox — credential-isolating coding-agent containers

usage: agentbox [--socket PATH] <command> ...

host:
  setup                         install agentboxd and its systemd unit
  image build                   provision and publish the declarative Incus image
  status                        show daemon health

generic control plane:
  route list [--json] <profile>
  route put <profile> <route.json>
  route replace <profile> <routes.json>
  route delete <profile> <name>
  key list
  key set <name>                read value hidden or from stdin
  key delete <name>
  credential source list
  credential source put <source.json>
  credential source github-app <name> [flags]
  credential source delete <name>

profiles:
  profile list|show|create|put|delete
  profile set cloudflare <profile> --account-id ID --gateway NAME --private-key KEY
  profile unset cloudflare <profile>
  profile set github <profile> --source SOURCE
  profile unset github <profile>

containers:
  container create --profile PROFILE [resource flags] <name>
  container list
  container shell <name>
  container destroy <name>
  container block [--hard] <name>
  container unblock <name>
`

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	global := flag.NewFlagSet("agentbox", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	socket := global.String("socket", envOr("AGENTBOX_SOCKET", paths.ControlSocket), "agentboxd control socket")
	showVersion := global.Bool("version", false, "print version")
	global.Usage = func() { fmt.Fprint(global.Output(), usage) }
	if err := global.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("agentbox", version)
		return nil
	}
	args := global.Args()
	if len(args) == 0 || args[0] == "help" {
		global.Usage()
		if len(args) == 0 {
			return flag.ErrHelp
		}
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := control.NewClient(*socket)
	switch args[0] {
	case "status":
		return cmdStatus(ctx, client, args[1:])
	case "route":
		return cmdRoute(ctx, client, args[1:])
	case "key":
		return cmdKey(ctx, client, args[1:])
	case "credential":
		return cmdCredential(ctx, client, args[1:])
	case "profile":
		return cmdProfile(ctx, client, args[1:])
	case "container":
		return cmdContainer(ctx, client, args[1:])
	case "setup":
		return cmdSetup(args[1:])
	case "image":
		return cmdImage(args[1:])
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
