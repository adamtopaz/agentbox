package main

import (
	"errors"
	"flag"
	"os"

	"agentbox/internal/hostsetup"
	"agentbox/internal/imagebuild"
	"agentbox/internal/incus"
)

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
