// Command agentboxd runs the unprivileged agentbox control and data planes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"agentbox/internal/app"
	"agentbox/internal/control"
	"agentbox/internal/paths"
	"agentbox/internal/proxy"
	"agentbox/internal/sdnotify"
	"agentbox/internal/secret"
	"agentbox/internal/state"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agentboxd:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("agentboxd", flag.ContinueOnError)
	statePath := fs.String("state", paths.StateFile, "persistent non-secret state file")
	secretsDir := fs.String("secrets", paths.SecretsDir, "encrypted key directory")
	controlSocket := fs.String("control-socket", paths.ControlSocket, "control API Unix socket")
	userControlSocket := fs.String("user-control-socket", paths.UserControlSocket, "restricted user API Unix socket")
	containerSockets := fs.String("container-sockets", paths.ContainerSocketsDir, "per-container proxy socket directory")
	hostSockets := fs.String("host-sockets", paths.HostSocketsDir, "per-user host-session proxy socket directory")
	userGroup := fs.String("user-group", "", "group allowed to use host sessions (production unit: agentbox)")
	adminUID := fs.Uint("admin-uid", 0, "UID allowed to use the administrator API")
	masterKeyFile := fs.String("master-key-file", "", "master key file (default: systemd credential master-key)")
	logFormat := fs.String("log-format", "json", "log format: json or text")
	showVersion := fs.Bool("version", false, "print version")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if uint64(*adminUID) > uint64(^uint32(0)) {
		return fmt.Errorf("--admin-uid exceeds 32-bit Unix UID range")
	}
	if *showVersion {
		fmt.Println("agentboxd", version)
		return nil
	}

	var handler slog.Handler
	switch *logFormat {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, nil)
	case "text":
		handler = slog.NewTextHandler(os.Stderr, nil)
	default:
		return fmt.Errorf("invalid --log-format %q", *logFormat)
	}
	log := slog.New(handler)
	slog.SetDefault(log)
	syscall.Umask(0o007)
	userGID, err := lookupGroupGID(*userGroup)
	if err != nil {
		return err
	}

	key, err := readMasterKey(*masterKeyFile)
	if err != nil {
		return err
	}
	keys, err := secret.Open(*secretsDir, key)
	clear(key)
	if err != nil {
		return fmt.Errorf("open encrypted key store: %w", err)
	}
	service, err := app.Open(state.Store{Path: *statePath}, keys)
	if err != nil {
		return fmt.Errorf("open state: %w", err)
	}
	defer service.Close()

	dataPlane := &proxy.Server{Snapshots: service, Materials: service, Log: log}
	listeners := &proxy.ListenerManager{Dir: *containerSockets, HostDir: *hostSockets, HostGID: userGID, Proxy: dataPlane, Log: log}
	if err := service.AttachListeners(listeners); err != nil {
		return fmt.Errorf("start container listeners: %w", err)
	}

	api := control.API{Service: service, Log: log, AdminUID: uint32(*adminUID)}
	controlServer := &control.Server{Socket: *controlSocket, SocketMode: 0o600, Handler: api.Handler(), Log: log}
	if err := controlServer.Start(); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = listeners.Close(ctx)
		return fmt.Errorf("start control server: %w", err)
	}
	userServer := &control.Server{Socket: *userControlSocket, SocketMode: 0o660, SocketGID: userGID, Handler: api.UserHandler(), Log: log}
	if err := userServer.Start(); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = controlServer.Close(ctx)
		_ = listeners.Close(ctx)
		return fmt.Errorf("start user control server: %w", err)
	}
	health := service.Health(context.Background())
	if err := sdnotify.Ready(); err != nil {
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = userServer.Close(shutdown)
		_ = controlServer.Close(shutdown)
		_ = listeners.Close(shutdown)
		return fmt.Errorf("notify systemd that agentboxd is ready: %w", err)
	}
	log.Info("agentboxd ready", "version", version, "control_socket", *controlSocket,
		"profiles", health.Profiles, "routes", health.Routes, "keys", health.Keys, "containers", health.Containers,
		"credential_sources", health.CredentialSources, "credential_bindings", health.CredentialBindings)

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-sigCtx.Done()
	_ = sdnotify.Stopping()
	log.Info("agentboxd stopping")
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := controlServer.Close(shutdown); err != nil {
		log.Warn("control shutdown failed", "err", err)
	}
	if err := userServer.Close(shutdown); err != nil {
		log.Warn("user control shutdown failed", "err", err)
	}
	if err := listeners.Close(shutdown); err != nil {
		return err
	}
	return nil
}

func lookupGroupGID(name string) (*int, error) {
	if name == "" {
		return nil, nil
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return nil, fmt.Errorf("look up user group %q: %w", name, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return nil, fmt.Errorf("group %q has invalid gid %q", name, group.Gid)
	}
	return &gid, nil
}

func readMasterKey(override string) ([]byte, error) {
	path := override
	if path == "" {
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return nil, fmt.Errorf("CREDENTIALS_DIRECTORY is unset; run under agentboxd.service or pass --master-key-file")
		}
		path = filepath.Join(dir, paths.MasterKeyName)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read master key %s: %w", path, err)
	}
	if len(value) != 32 {
		clear(value)
		return nil, fmt.Errorf("master key %s is %d bytes, want 32", path, len(value))
	}
	return value, nil
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
