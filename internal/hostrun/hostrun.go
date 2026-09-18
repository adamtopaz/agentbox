// Package hostrun launches host-side coding agents whose model and GitHub
// traffic use an ephemeral Agentbox data-plane identity.
package hostrun

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	AddHostSession(context.Context, string) (domain.HostSession, error)
	DeleteHostSession(context.Context, string) error
}

type Agent string

const (
	AgentClaude Agent = "claude"
	AgentCodex  Agent = "codex"
	AgentPi     Agent = "pi"
)

func (a Agent) Valid() bool {
	return a == AgentClaude || a == AgentCodex || a == AgentPi
}

func (a Agent) DisplayName() string {
	switch a {
	case AgentClaude:
		return "Claude Code"
	case AgentCodex:
		return "Codex"
	case AgentPi:
		return "Pi"
	default:
		return string(a)
	}
}

type Options struct {
	Profile       domain.UserProfile
	Agent         Agent
	AgentBin      string
	AgentArgs     []string
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

// ExitError reports the launched agent process's exit status without asking
// the CLI entry point to print a second, misleading Agentbox error.
type ExitError struct {
	Agent Agent
	Code  int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("%s exited with status %d", e.Agent.DisplayName(), e.Code)
}

func Run(ctx context.Context, control Control, options Options) (retErr error) {
	if control == nil {
		return errors.New("control client is required")
	}
	if err := domain.ValidateProfile(domain.Profile{Name: options.Profile.Name, Routes: []domain.Route{}, Credentials: map[string]string{}, Environment: options.Profile.Environment}); err != nil {
		return err
	}
	if options.Agent == "" {
		options.Agent = AgentCodex
	}
	if !options.Agent.Valid() {
		return fmt.Errorf("unsupported host agent %q", options.Agent)
	}
	if options.AgentBin == "" {
		options.AgentBin = string(options.Agent)
	}
	agentPath, err := exec.LookPath(options.AgentBin)
	if err != nil {
		return fmt.Errorf("find %s executable %q: %w", options.Agent.DisplayName(), options.AgentBin, err)
	}
	if options.GitBin == "" {
		options.GitBin = "git"
	}
	if options.SocketDir == "" {
		return errors.New("host-session socket directory is required")
	}

	created, err := control.AddHostSession(ctx, options.Profile.Name)
	if err != nil {
		return err
	}
	name := created.Name
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
	args := options.AgentArgs
	switch options.Agent {
	case AgentCodex:
		openAIBase := envValue(env, "OPENAI_BASE_URL")
		if openAIBase == "" {
			return errors.New("profile does not define OPENAI_BASE_URL")
		}
		args = codexArgs(openAIBase, args)
	case AgentClaude:
		if envValue(env, "ANTHROPIC_BASE_URL") == "" {
			return errors.New("profile does not define ANTHROPIC_BASE_URL")
		}
		// Claude Code treats ANTHROPIC_AUTH_TOKEN as a gateway credential and
		// sends it as a bearer token. This avoids its persistent API-key approval
		// flow while keeping the random capability out of user configuration.
		env = withoutEnv(env, "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR")
		env = withEnv(env, map[string]string{
			"ANTHROPIC_AUTH_TOKEN":                     token,
			"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
			"DISABLE_AUTOUPDATER":                      "1",
		})
	case AgentPi:
		openAIBase := envValue(env, "OPENAI_BASE_URL")
		anthropicBase := envValue(env, "ANTHROPIC_BASE_URL")
		if openAIBase == "" && anthropicBase == "" {
			return errors.New("profile does not define OPENAI_BASE_URL or ANTHROPIC_BASE_URL")
		}
		piDir := filepath.Join(temp, "pi-agent")
		if err := preparePiAgentDir(piSourceDir(options.Environment), piDir, openAIBase, anthropicBase); err != nil {
			return err
		}
		env = withEnv(env, map[string]string{
			"PI_CODING_AGENT_DIR": piDir,
			"PI_OFFLINE":          "1",
		})
	}
	// Keep the child in the terminal's foreground process group. Interactive
	// agents use SIGINT to cancel a turn, so the launcher's signal-derived
	// context must not turn every Ctrl-C into an unconditional child kill. The
	// terminal delivers the signal to the agent directly; Agentbox waits so it
	// can still remove the host identity when the agent eventually exits.
	command := exec.Command(agentPath, args...)
	command.Env = env
	command.Stdin = options.Stdin
	command.Stdout = options.Stdout
	command.Stderr = options.Stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &ExitError{Agent: options.Agent, Code: exit.ExitCode()}
		}
		return fmt.Errorf("run %s: %w", options.Agent.DisplayName(), err)
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

func withEnv(base []string, values map[string]string) []string {
	out := append([]string(nil), base...)
	for name, value := range values {
		prefix := name + "="
		replaced := false
		for i, entry := range out {
			if strings.HasPrefix(entry, prefix) {
				out[i] = prefix + value
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, prefix+value)
		}
	}
	return out
}

func withoutEnv(base []string, names ...string) []string {
	removed := make(map[string]bool, len(names))
	for _, name := range names {
		removed[name] = true
	}
	out := make([]string, 0, len(base))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		if !removed[name] {
			out = append(out, entry)
		}
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

func piSourceDir(environment []string) string {
	if configured := envValue(environment, "PI_CODING_AGENT_DIR"); configured != "" {
		if configured == "~" {
			if home := envValue(environment, "HOME"); home != "" {
				return home
			}
		}
		if strings.HasPrefix(configured, "~/") {
			if home := envValue(environment, "HOME"); home != "" {
				return filepath.Join(home, strings.TrimPrefix(configured, "~/"))
			}
		}
		return configured
	}
	home := envValue(environment, "HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".pi", "agent")
}

func preparePiAgentDir(source, target, openAIBase, anthropicBase string) error {
	if err := os.MkdirAll(target, 0o700); err != nil {
		return fmt.Errorf("create temporary Pi configuration: %w", err)
	}
	if source != "" {
		entries, err := os.ReadDir(source)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read Pi configuration directory: %w", err)
		}
		for _, entry := range entries {
			if entry.Name() == "auth.json" || entry.Name() == "models.json" {
				continue
			}
			from, err := filepath.Abs(filepath.Join(source, entry.Name()))
			if err != nil {
				return err
			}
			if err := os.Symlink(from, filepath.Join(target, entry.Name())); err != nil {
				return fmt.Errorf("link Pi configuration %q: %w", entry.Name(), err)
			}
		}
	}

	var modelsPath, authPath string
	if source != "" {
		modelsPath = filepath.Join(source, "models.json")
		authPath = filepath.Join(source, "auth.json")
	}
	models, err := readJSONObject(modelsPath, true)
	if err != nil {
		return fmt.Errorf("read Pi models: %w", err)
	}
	providers, err := rawObject(models["providers"])
	if err != nil {
		return fmt.Errorf("read Pi model providers: %w", err)
	}
	for name, baseURL := range map[string]string{"anthropic": anthropicBase, "openai": openAIBase} {
		if baseURL == "" {
			continue
		}
		provider, err := rawObject(providers[name])
		if err != nil {
			return fmt.Errorf("read Pi %s provider: %w", name, err)
		}
		provider["baseUrl"] = mustJSON(baseURL)
		providers[name] = mustJSON(provider)
	}
	models["providers"] = mustJSON(providers)
	if err := writeJSON(filepath.Join(target, "models.json"), models); err != nil {
		return fmt.Errorf("write temporary Pi models: %w", err)
	}

	auth, err := readJSONObject(authPath, false)
	if err != nil {
		return fmt.Errorf("read Pi authentication: %w", err)
	}
	if anthropicBase != "" {
		auth["anthropic"] = mustJSON(map[string]string{"type": "api_key", "key": "$ANTHROPIC_API_KEY"})
	}
	if openAIBase != "" {
		auth["openai"] = mustJSON(map[string]string{"type": "api_key", "key": "$OPENAI_API_KEY"})
	}
	if err := writeJSON(filepath.Join(target, "auth.json"), auth); err != nil {
		return fmt.Errorf("write temporary Pi authentication: %w", err)
	}
	return nil
}

func readJSONObject(path string, allowComments bool) (map[string]json.RawMessage, error) {
	if path == "" {
		return map[string]json.RawMessage{}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	if allowComments {
		data = cleanJSONC(data)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("expected a JSON object")
	}
	return value, nil
}

func rawObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(raw) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("expected a JSON object")
	}
	return value, nil
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o600)
}

// cleanJSONC removes comments and trailing commas outside JSON strings. Pi
// accepts both in models.json, so the temporary overlay must accept them too.
func cleanJSONC(data []byte) []byte {
	withoutComments := make([]byte, 0, len(data))
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		current := data[i]
		if inString {
			withoutComments = append(withoutComments, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			withoutComments = append(withoutComments, current)
			continue
		}
		if current == '/' && i+1 < len(data) && data[i+1] == '/' {
			i += 2
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				withoutComments = append(withoutComments, '\n')
			}
			continue
		}
		if current == '/' && i+1 < len(data) && data[i+1] == '*' {
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				if data[i] == '\n' {
					withoutComments = append(withoutComments, '\n')
				}
				i++
			}
			i++
			continue
		}
		withoutComments = append(withoutComments, current)
	}

	out := make([]byte, 0, len(withoutComments))
	inString, escaped = false, false
	for i, current := range withoutComments {
		if inString {
			out = append(out, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			out = append(out, current)
			continue
		}
		if current == ',' {
			next := i + 1
			for next < len(withoutComments) && strings.ContainsRune(" \t\r\n", rune(withoutComments[next])) {
				next++
			}
			if next < len(withoutComments) && (withoutComments[next] == '}' || withoutComments[next] == ']') {
				continue
			}
		}
		out = append(out, current)
	}
	return out
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
		ForceAttemptHTTP2: false,
		IdleConnTimeout:   90 * time.Second,
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
		// Claude Code probes the origin before its authenticated Messages API
		// request. Answer this fixed health check locally: forwarding it would be
		// useless, while requiring the session token would make Claude reject an
		// otherwise valid custom base URL.
		if r.Method == http.MethodHead && r.URL.Path == "/api/hello" {
			w.WriteHeader(http.StatusOK)
			return
		}
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
