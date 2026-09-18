package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"agentbox/internal/control"
	"agentbox/internal/domain"
	"agentbox/internal/hostrun"
	"agentbox/internal/hostsetup"
	"agentbox/internal/imagebuild"
	"agentbox/internal/incus"
	"agentbox/internal/paths"
)

const hostUsage = "usage: agentbox host profiles | <claude|codex|pi> --profile PROFILE [agent options] | run --profile PROFILE [--] COMMAND [ARGS...]"

// hostInvocation is the parsed form of `agentbox host <claude|codex|pi|run>`.
type hostInvocation struct {
	agent   hostrun.Agent
	profile string
	program string
	args    []string
	gitBin  string
}

func parseHostArgs(args []string) (hostInvocation, error) {
	agent := hostrun.Agent(args[0])
	if !agent.Valid() {
		return hostInvocation{}, fmt.Errorf("unknown host agent %q (want claude, codex, pi, or run)", args[0])
	}
	command := "host " + string(agent)
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	profileName := fs.String("profile", "", "Agentbox profile")
	gitBin := fs.String("git-bin", "git", "Git executable")
	var usage string
	var agentBin *string
	if agent == hostrun.AgentRun {
		// The program is positional. Flag parsing stops at the first non-flag
		// argument, so the program's own options need no `--` separator; only a
		// program whose name itself begins with `-` must follow one.
		usage = "usage: agentbox host run --profile PROFILE [--git-bin PATH] [--] COMMAND [ARGS...]"
	} else {
		usage = "usage: agentbox " + command + " --profile PROFILE [--" + string(agent) + "-bin PATH] [--git-bin PATH] [--] [" + strings.ToUpper(string(agent)) + "_ARGS...]"
		agentBin = fs.String(string(agent)+"-bin", string(agent), agent.DisplayName()+" executable")
	}
	fs.Usage = func() { fmt.Fprintln(fs.Output(), usage) }
	if err := fs.Parse(args[1:]); err != nil {
		if agent == hostrun.AgentRun && !errors.Is(err, flag.ErrHelp) {
			return hostInvocation{}, fmt.Errorf("%w (a program whose name begins with '-' must follow '--')", err)
		}
		return hostInvocation{}, err
	}
	if *profileName == "" {
		return hostInvocation{}, errors.New(usage)
	}
	invocation := hostInvocation{agent: agent, profile: *profileName, args: fs.Args(), gitBin: *gitBin}
	if agentBin != nil {
		invocation.program = *agentBin
		return invocation, nil
	}
	if len(invocation.args) == 0 || invocation.args[0] == "" {
		return hostInvocation{}, errors.New(usage)
	}
	invocation.program, invocation.args = invocation.args[0], invocation.args[1:]
	return invocation, nil
}

func cmdHost(ctx context.Context, client *control.Client, controlSocket string, args []string) error {
	if len(args) == 0 {
		return errors.New(hostUsage)
	}
	if args[0] == "profiles" {
		if len(args) != 1 {
			return errors.New("usage: agentbox host profiles")
		}
		profiles, err := client.UserProfiles(ctx)
		if err != nil {
			return err
		}
		for _, profile := range profiles {
			fmt.Println(profile.Name)
		}
		return nil
	}
	invocation, err := parseHostArgs(args)
	if err != nil {
		return err
	}
	profiles, err := client.UserProfiles(ctx)
	if err != nil {
		return err
	}
	var current *domain.UserProfile
	for i := range profiles {
		if profiles[i].Name == invocation.profile {
			current = &profiles[i]
			break
		}
	}
	if current == nil {
		return fmt.Errorf("profile %q is not assigned to this user", invocation.profile)
	}
	return hostrun.Run(ctx, client, hostrun.Options{
		Profile: *current, Agent: invocation.agent, AgentBin: invocation.program, AgentArgs: invocation.args, GitBin: invocation.gitBin,
		ControlSocket: controlSocket, SocketDir: paths.HostSocketsDir,
		Environment: os.Environ(), Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	admin := fs.String("admin-user", "", "initial user to add to the agentbox host-access group (default $SUDO_USER)")
	daemon := fs.String("daemon-binary", "", "agentboxd binary (default: sibling of agentbox)")
	noStart := fs.Bool("no-start", false, "install without restarting agentboxd")
	prefix := fs.String("prefix", "", "root filesystem writes under this test directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: agentbox setup [--admin-user USER] [--daemon-binary PATH] [--no-start]")
	}
	return hostsetup.Run(hostsetup.Options{AdminUser: *admin, DaemonBinary: *daemon, NoStart: *noStart, Prefix: *prefix, Out: os.Stdout})
}

func cmdImage(args []string) error {
	if len(args) == 0 || args[0] != "build" {
		return errors.New("usage: agentbox image build [--alias NAME] [--source IMAGE] [--keep-builder]")
	}
	fs := flag.NewFlagSet("image build", flag.ContinueOnError)
	alias := fs.String("alias", incus.DefaultImage, "Incus image alias")
	source := fs.String("source", imagebuild.DefaultBase, "cloud-init-enabled Incus base image")
	incusBin := fs.String("incus-bin", "incus", "Incus CLI")
	keep := fs.Bool("keep-builder", false, "keep the disposable builder instance")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: agentbox image build [--alias NAME] [--source IMAGE] [--keep-builder]")
	}
	return imagebuild.Run(imagebuild.Options{
		Alias: *alias, Source: *source, Keep: *keep,
		Incus: incus.Client{Bin: *incusBin, Out: os.Stdout, Err: os.Stderr}, Out: os.Stdout,
	})
}
