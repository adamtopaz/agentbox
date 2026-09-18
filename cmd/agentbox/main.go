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
	"agentbox/internal/hostrun"
	"agentbox/internal/paths"
)

const usage = `agentbox — credential-isolating coding-agent containers

usage: agentbox [--admin-socket PATH] [--user-socket PATH] <command> ...

regular user:
  host profiles                 list profiles assigned to this Unix user
  host claude --profile PROFILE run Claude Code on the host through Agentbox
  host codex --profile PROFILE  run Codex on the host through Agentbox
  host pi --profile PROFILE     run Pi on the host through Agentbox
  host run --profile PROFILE [--] COMMAND [ARGS...]
                                run any program on the host through Agentbox

administrator (run with sudo):
  setup                         install agentboxd and its systemd unit
  image build                   provision and publish the declarative Incus image
  status                        show daemon health

administrator control plane:
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

user grants (admin):
  user list [USERNAME]
  user grant USERNAME PROFILE
  user revoke USERNAME PROFILE

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
		if exit, ok := err.(*hostrun.ExitError); ok {
			os.Exit(exit.Code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	global := flag.NewFlagSet("agentbox", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	legacySocket := global.String("socket", "", "deprecated alias for --admin-socket")
	adminSocket := global.String("admin-socket", envOr("AGENTBOX_ADMIN_SOCKET", paths.ControlSocket), "root-only agentboxd administrator socket")
	userSocket := global.String("user-socket", envOr("AGENTBOX_SOCKET", paths.UserControlSocket), "agentboxd user socket")
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
	if *legacySocket != "" {
		*adminSocket = *legacySocket
	}
	adminClient := control.NewClient(*adminSocket)
	userClient := control.NewClient(*userSocket)
	switch args[0] {
	case "status":
		return cmdStatus(ctx, adminClient, args[1:])
	case "route":
		return cmdRoute(ctx, adminClient, args[1:])
	case "key":
		return cmdKey(ctx, adminClient, args[1:])
	case "credential":
		return cmdCredential(ctx, adminClient, args[1:])
	case "profile":
		return cmdProfile(ctx, adminClient, args[1:])
	case "user":
		return cmdUser(ctx, adminClient, args[1:])
	case "container":
		if os.Geteuid() != 0 {
			return fmt.Errorf("container commands require administrator elevation (run with sudo)")
		}
		return cmdContainer(ctx, adminClient, args[1:])
	case "setup":
		return cmdSetup(args[1:])
	case "image":
		if os.Geteuid() != 0 {
			return fmt.Errorf("image commands require administrator elevation (run with sudo)")
		}
		return cmdImage(args[1:])
	case "host":
		return cmdHost(ctx, userClient, *userSocket, args[1:])
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
