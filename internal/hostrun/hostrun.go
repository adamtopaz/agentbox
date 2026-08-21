// Package hostrun launches a host-side Codex process whose model and GitHub
// traffic use an ephemeral Agentbox data-plane identity.
package hostrun

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"agentbox/internal/domain"
)

type Control interface {
	AddHostSession(context.Context, domain.Container) (domain.Container, error)
	DeleteHostSession(context.Context, string) error
}

type Options struct {
	Profile       domain.Profile
	CodexBin      string
	CodexArgs     []string
	GitBin        string
	ControlSocket string
	SocketDir     string
	Environment   []string
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	TempDir       string
	SocketWait    time.Duration
}

// ExitError reports the launched Codex process's exit status without asking
// the CLI entry point to print a second, misleading Agentbox error.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("Codex exited with status %d", e.Code) }

func Run(ctx context.Context, control Control, options Options) (retErr error) {
	if control == nil {
		return errors.New("control client is required")
	}
	if err := domain.ValidateProfile(options.Profile); err != nil {
		return err
	}
	if options.CodexBin == "" {
		options.CodexBin = "codex"
	}
	codexPath, err := exec.LookPath(options.CodexBin)
	if err != nil {
		return fmt.Errorf("find Codex executable %q: %w", options.CodexBin, err)
	}
	if options.GitBin == "" {
		options.GitBin = "git"
	}
	if options.SocketDir == "" {
		return errors.New("host-session socket directory is required")
	}

	name, err := randomSessionName()
	if err != nil {
		return err
	}
	created, err := control.AddHostSession(ctx, domain.Container{Name: name, Profile: options.Profile.Name})
	if err != nil {
		return err
	}
	name = created.Name
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := control.DeleteHostSession(cleanupCtx, name); err != nil && retErr == nil {
			retErr = fmt.Errorf("remove host session %q: %w", name, err)
		}
	}()

	socket := filepath.Join(options.SocketDir, name+".sock")
	if err := waitForSocket(ctx, socket, options.SocketWait); err != nil {
		return err
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	bridge, err := startBridge(socket, token)
	if err != nil {
		return err
	}
	defer bridge.Close()

	temp, err := os.MkdirTemp(options.TempDir, "agentbox-host-")
	if err != nil {
		return fmt.Errorf("create host-session directory: %w", err)
	}
	defer os.RemoveAll(temp)
	gitExec, err := prepareGitExec(options.GitBin, filepath.Join(temp, "git-core"), bridge.URL(), token)
	if err != nil {
		return err
	}
	ghConfig := filepath.Join(temp, "gh")
	if err := prepareGHConfig(ghConfig, socket); err != nil {
		return err
	}

	env := hostEnvironment(options.Environment, options.Profile.Environment, bridge.URL(), token, map[string]string{
		"AGENTBOX_HOST_SESSION": name,
		"AGENTBOX_SOCKET":       options.ControlSocket,
		"GH_CONFIG_DIR":         ghConfig,
		"GIT_EXEC_PATH":         gitExec,
		"GIT_TERMINAL_PROMPT":   "0",
	})
	openAIBase := envValue(env, "OPENAI_BASE_URL")
	if openAIBase == "" {
		return errors.New("profile does not define OPENAI_BASE_URL")
	}
	args := codexArgs(openAIBase, options.CodexArgs)
	// Keep the child in the terminal's foreground process group. Interactive
	// Codex uses SIGINT to cancel a turn, so the launcher's signal-derived
	// context must not turn every Ctrl-C into an unconditional child kill. The
	// terminal delivers the signal to Codex directly; Agentbox waits so it can
	// still remove the host identity when Codex eventually exits.
	command := exec.Command(codexPath, args...)
	command.Env = env
	command.Stdin = options.Stdin
	command.Stdout = options.Stdout
	command.Stderr = options.Stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &ExitError{Code: exit.ExitCode()}
		}
		return fmt.Errorf("run Codex: %w", err)
	}
	return nil
}

func codexArgs(openAIBase string, user []string) []string {
	overrides := []string{
		"-c", `model_provider="agentbox"`,
		"-c", `model_providers.agentbox.name="Agentbox proxy"`,
		"-c", "model_providers.agentbox.base_url=" + strconv.Quote(openAIBase),
		"-c", `model_providers.agentbox.wire_api="responses"`,
		"-c", `model_providers.agentbox.env_key="OPENAI_API_KEY"`,
	}
	return append(overrides, user...)
}

func hostEnvironment(base []string, profile map[string]string, proxyURL, token string, extra map[string]string) []string {
	values := make(map[string]string, len(base)+len(profile)+len(extra)+3)
	order := make([]string, 0, len(values))
	set := func(name, value string) {
		if _, exists := values[name]; !exists {
			order = append(order, name)
		}
		values[name] = value
	}
	for _, entry := range base {
		if name, value, ok := strings.Cut(entry, "="); ok {
			set(name, value)
		}
	}
	for name, value := range profile {
		set(name, rewriteLoopbackURL(value, proxyURL))
	}
	// The random values are short-lived capabilities for the authenticated
	// host loopback listener, not reusable upstream credentials.
	set("OPENAI_API_KEY", token)
	set("ANTHROPIC_API_KEY", token)
	set("GH_TOKEN", token)
	for name, value := range extra {
		if value != "" {
			set(name, value)
		}
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		out = append(out, name+"="+values[name])
	}
	return out
}

func rewriteLoopbackURL(value, proxyURL string) string {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.Host != "127.0.0.1:8787" {
		return value
	}
	proxy, _ := url.Parse(proxyURL)
	u.Scheme, u.Host = proxy.Scheme, proxy.Host
	return u.String()
}

func envValue(env []string, name string) string {
	prefix := name + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func randomSessionName() (string, error) {
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate host session name: %w", err)
	}
	return fmt.Sprintf("host-%d-%d-%s", os.Getuid(), os.Getpid(), hex.EncodeToString(random[:])), nil
}

func randomToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate host session token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

func waitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("daemon did not serve %s within %s", path, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

type bridge struct {
	listener net.Listener
	server   *http.Server
	url      string
}

func startBridge(socket, token string) (*bridge, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for host proxy: %w", err)
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.URL.Scheme = "http"
			request.Out.URL.Host = "agentbox"
			request.Out.URL.User = nil
			request.Out.Host = request.In.Host
			request.Out.Header.Del("Authorization")
			request.Out.Header.Del("Proxy-Authorization")
			request.Out.Header.Del("X-Api-Key")
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Agentbox host proxy unavailable", http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, token) {
			http.Error(w, "Agentbox host proxy authentication required", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10}
	b := &bridge{listener: listener, server: server, url: "http://" + listener.Addr().String()}
	go func() { _ = server.Serve(listener) }()
	return b, nil
}

func (b *bridge) URL() string { return b.url }
func (b *bridge) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = b.server.Shutdown(ctx)
	_ = b.listener.Close()
}

func authorized(r *http.Request, token string) bool {
	provided := r.Header.Get("X-Api-Key")
	if provided == "" {
		authorization := r.Header.Get("Authorization")
		if scheme, value, ok := strings.Cut(authorization, " "); ok &&
			(strings.EqualFold(scheme, "bearer") || strings.EqualFold(scheme, "token")) {
			provided = value
		} else if strings.EqualFold(scheme, "basic") {
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err == nil {
				_, provided, _ = strings.Cut(string(decoded), ":")
			}
		}
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

func prepareGHConfig(dir, socket string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create GitHub CLI config directory: %w", err)
	}
	config := fmt.Sprintf("http_unix_socket: %s\ngit_protocol: https\nprompt: enabled\n", strconv.Quote(socket))
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte(config), 0o600); err != nil {
		return fmt.Errorf("write GitHub CLI config: %w", err)
	}
	return nil
}

func prepareGitExec(gitBin, target, proxyURL, token string) (string, error) {
	command := exec.Command(gitBin, "--exec-path")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("find Git executable directory: %w", err)
	}
	original := strings.TrimSpace(string(output))
	if !filepath.IsAbs(original) {
		return "", fmt.Errorf("Git executable directory must be absolute, got %q", original)
	}
	entries, err := os.ReadDir(original)
	if err != nil {
		return "", fmt.Errorf("read Git executable directory: %w", err)
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.Name() == "git-remote-https" {
			continue
		}
		if err := os.Symlink(filepath.Join(original, entry.Name()), filepath.Join(target, entry.Name())); err != nil {
			return "", fmt.Errorf("link Git helper %q: %w", entry.Name(), err)
		}
	}
	originalHTTP := filepath.Join(original, "git-remote-http")
	if info, err := os.Stat(originalHTTP); err != nil || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("Git HTTP helper %s is not executable", originalHTTP)
	}
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}
	gitURL := "http://x-access-token:" + token + "@" + proxy.Host + "/github-git/"
	script := "#!/bin/sh\nset -eu\noriginal=" + shellQuote(originalHTTP) + "\n" +
		"if [ \"$#\" -eq 2 ]; then\n" +
		"  remote=$1\n  url=$2\n  case \"$url\" in\n" +
		"    https://github.com/*)\n" +
		"      path=${url#https://github.com/}\n" +
		"      exec \"$original\" \"$remote\" " + shellQuote(gitURL) + "\"$path\"\n" +
		"      ;;\n  esac\nfi\nexec \"$original\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(target, "git-remote-https"), []byte(script), 0o700); err != nil {
		return "", fmt.Errorf("write GitHub HTTPS transport helper: %w", err)
	}
	return target, nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
