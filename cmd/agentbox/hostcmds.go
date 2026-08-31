package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"agentbox/internal/control"
	"agentbox/internal/hostrun"
	"agentbox/internal/hostsetup"
	"agentbox/internal/imagebuild"
	"agentbox/internal/incus"
	"agentbox/internal/paths"
)

func cmdHost(ctx context.Context, client *control.Client, controlSocket string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentbox host <claude|codex|pi> --profile PROFILE [agent options]")
	}
	agent := hostrun.Agent(args[0])
	if !agent.Valid() {
		return fmt.Errorf("unknown host agent %q (want claude, codex, or pi)", args[0])
	}
	command := "host " + string(agent)
	usage := "usage: agentbox " + command + " --profile PROFILE [--" + string(agent) + "-bin PATH] [--git-bin PATH] [--] [" + strings.ToUpper(string(agent)) + "_ARGS...]"
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	profileName := fs.String("profile", "", "Agentbox profile")
	agentBin := fs.String(string(agent)+"-bin", string(agent), agent.DisplayName()+" executable")
	gitBin := fs.String("git-bin", "git", "Git executable")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *profileName == "" {
		return errors.New(usage)
	}
	current, err := findProfile(ctx, client, *profileName)
	if err != nil {
		return err
	}
	return hostrun.Run(ctx, client, hostrun.Options{
		Profile: current, Agent: agent, AgentBin: *agentBin, AgentArgs: fs.Args(), GitBin: *gitBin,
		ControlSocket: controlSocket, SocketDir: paths.ContainerSocketsDir,
		Environment: os.Environ(), Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	admin := fs.String("admin-user", "", "user to add to agentbox and incus-admin groups (default $SUDO_USER)")
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
