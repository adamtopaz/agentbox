package hostrun

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/domain"
)

func TestHostEnvironmentRewritesOnlyAgentboxLoopback(t *testing.T) {
	env := hostEnvironment(
		[]string{"PATH=/bin", "OPENAI_API_KEY=real-key", "KEEP=old"},
		map[string]string{
			"OPENAI_BASE_URL":    "http://127.0.0.1:8787/cloudflare/prod/openai",
			"ANTHROPIC_BASE_URL": "http://example.test/v1",
			"KEEP":               "profile",
		},
		"http://127.0.0.1:43210", "session-token", map[string]string{"GH_CONFIG_DIR": "/tmp/gh"},
	)
	for name, want := range map[string]string{
		"OPENAI_BASE_URL":    "http://127.0.0.1:43210/cloudflare/prod/openai",
		"ANTHROPIC_BASE_URL": "http://example.test/v1",
		"OPENAI_API_KEY":     "session-token",
		"ANTHROPIC_API_KEY":  "session-token",
		"GH_TOKEN":           "session-token",
		"KEEP":               "profile",
		"GH_CONFIG_DIR":      "/tmp/gh",
	} {
		if got := envValue(env, name); got != want {
			t.Errorf("%s=%q, want %q", name, got, want)
		}
	}
}

func TestAuthorizedAcceptsSupportedClientHeaders(t *testing.T) {
	const token = "temporary-capability"
	requests := []*http.Request{
		{Header: http.Header{"Authorization": {"Bearer " + token}}},
		{Header: http.Header{"Authorization": {"token " + token}}},
		{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))}}},
		{Header: http.Header{"X-Api-Key": {token}}},
	}
	for i, request := range requests {
		if !authorized(request, token) {
			t.Errorf("request %d was rejected", i)
		}
	}
	if authorized(&http.Request{Header: http.Header{"Authorization": {"Bearer wrong"}}}, token) {
		t.Fatal("wrong token was accepted")
	}
}

func TestBridgeAnswersClaudeHealthCheckLocally(t *testing.T) {
	bridge, err := startBridge(filepath.Join(t.TempDir(), "unused.sock"), "temporary-capability")
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	request, err := http.NewRequest(http.MethodHead, bridge.URL()+"/api/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}

	response, err = http.Get(bridge.URL() + "/api/hello")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET status=%d", response.StatusCode)
	}
}

func TestCodexArgsUseEphemeralProviderOverride(t *testing.T) {
	args := codexArgs("http://127.0.0.1:43210/cloudflare/prod/openai", []string{"exec", "hello"})
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		`model_provider="agentbox"`,
		`model_providers.agentbox.base_url="http://127.0.0.1:43210/cloudflare/prod/openai"`,
		`model_providers.agentbox.wire_api="responses"`,
		`model_providers.agentbox.env_key="OPENAI_API_KEY"`,
		"exec\nhello",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args do not contain %q: %v", want, args)
		}
	}
}

func TestPreparePiAgentDirOverlaysProvidersAndCredentials(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "models.json"), []byte(`{
  // Pi supports comments and trailing commas here.
  "providers": {
    "anthropic": {"baseUrl": "https://old.invalid", "headers": {"x-extra": "yes"}},
    "custom": {"baseUrl": "https://custom.example", "api": "openai-completions", "models": [{"id": "local"}]},
  },
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "auth.json"), []byte(`{
  "anthropic": {"type": "api_key", "key": "old-secret"},
  "custom": {"type": "api_key", "key": "custom-secret"}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := preparePiAgentDir(source, target, "http://127.0.0.1:1234/openai", "http://127.0.0.1:1234/anthropic"); err != nil {
		t.Fatal(err)
	}
	var models struct {
		Providers map[string]struct {
			BaseURL string            `json:"baseUrl"`
			Headers map[string]string `json:"headers"`
		} `json:"providers"`
	}
	readJSONFile(t, filepath.Join(target, "models.json"), &models)
	if got := models.Providers["anthropic"].BaseURL; got != "http://127.0.0.1:1234/anthropic" {
		t.Fatalf("Anthropic base URL=%q", got)
	}
	if got := models.Providers["openai"].BaseURL; got != "http://127.0.0.1:1234/openai" {
		t.Fatalf("OpenAI base URL=%q", got)
	}
	if got := models.Providers["anthropic"].Headers["x-extra"]; got != "yes" {
		t.Fatalf("Anthropic provider setting was not preserved: %q", got)
	}
	if got := models.Providers["custom"].BaseURL; got != "https://custom.example" {
		t.Fatalf("custom provider was not preserved: %q", got)
	}
	var auth map[string]struct {
		Type string `json:"type"`
		Key  string `json:"key"`
	}
	readJSONFile(t, filepath.Join(target, "auth.json"), &auth)
	if got := auth["anthropic"].Key; got != "$ANTHROPIC_API_KEY" {
		t.Fatalf("Anthropic credential=%q", got)
	}
	if got := auth["openai"].Key; got != "$OPENAI_API_KEY" {
		t.Fatalf("OpenAI credential=%q", got)
	}
	if got := auth["custom"].Key; got != "custom-secret" {
		t.Fatalf("custom credential was not preserved: %q", got)
	}
	if info, err := os.Lstat(filepath.Join(target, "settings.json")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("settings link: info=%v err=%v", info, err)
	}
}

func TestGitHTTPSHelperRewritesOnlyGitHub(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(root, "capture")
	originalHTTP := filepath.Join(original, "git-remote-http")
	writeExecutable(t, originalHTTP, "#!/bin/sh\nprintf '%s\\n' \"$@\" > "+shellQuote(capture)+"\n")
	fakeGit := filepath.Join(root, "git")
	writeExecutable(t, fakeGit, "#!/bin/sh\nprintf '%s\\n' "+shellQuote(original)+"\n")
	target, err := prepareGitExec(fakeGit, filepath.Join(root, "git-core"), "http://127.0.0.1:43210", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(target, "git-remote-https")
	if err := exec.Command(helper, "origin", "https://github.com/acme/project.git").Run(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "origin\nhttp://x-access-token:abc123@127.0.0.1:43210/github-git/acme/project.git\n"; got != want {
		t.Fatalf("rewritten args=%q, want %q", got, want)
	}
	if err := exec.Command(helper, "origin", "https://gitlab.com/acme/project.git").Run(); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "origin\nhttps://gitlab.com/acme/project.git\n"; got != want {
		t.Fatalf("delegated args=%q, want %q", got, want)
	}
}

func TestRunRejectsMissingOpenAIBaseAndCleansSession(t *testing.T) {
	control := &controlFake{dir: t.TempDir()}
	fakeCodex := filepath.Join(t.TempDir(), "codex")
	writeExecutable(t, fakeCodex, "#!/bin/sh\nexit 0\n")
	fakeGit := filepath.Join(t.TempDir(), "git")
	original := filepath.Join(t.TempDir(), "git-core")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(original, "git-remote-http"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, fakeGit, "#!/bin/sh\nprintf '%s\\n' "+shellQuote(original)+"\n")
	err := Run(context.Background(), control, Options{
		Profile: domain.Profile{Name: "prod", Routes: []domain.Route{}, Credentials: map[string]string{}, Environment: map[string]string{}},
		Agent:   AgentCodex, AgentBin: fakeCodex, GitBin: fakeGit, SocketDir: control.dir,
	})
	if err == nil || !strings.Contains(err.Error(), "OPENAI_BASE_URL") {
		t.Fatalf("unexpected error: %v", err)
	}
	if control.added == "" || control.deleted != control.added {
		t.Fatalf("session lifecycle added=%q deleted=%q", control.added, control.deleted)
	}
}

func TestRunForwardsCodexRequestAndCleansSession(t *testing.T) {
	requestSeen := make(chan *http.Request, 1)
	control := &controlFake{dir: t.TempDir(), handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- r.Clone(context.Background())
		_, _ = io.WriteString(w, "ok")
	})}
	root := t.TempDir()
	fakeCodex := filepath.Join(root, "codex")
	writeExecutable(t, fakeCodex, "#!/bin/sh\nset -eu\ncurl -fsS -H \"Authorization: Bearer $OPENAI_API_KEY\" \"$OPENAI_BASE_URL/v1/models\" >/dev/null\n")
	original := filepath.Join(root, "git-core-original")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(original, "git-remote-http"), "#!/bin/sh\nexit 0\n")
	fakeGit := filepath.Join(root, "git")
	writeExecutable(t, fakeGit, "#!/bin/sh\nprintf '%s\\n' "+shellQuote(original)+"\n")
	profile := domain.Profile{
		Name: "prod", Routes: []domain.Route{}, Credentials: map[string]string{},
		Environment: map[string]string{"OPENAI_BASE_URL": "http://127.0.0.1:8787/cloudflare/prod/openai"},
	}
	err := Run(context.Background(), control, Options{
		Profile: profile, Agent: AgentCodex, AgentBin: fakeCodex, GitBin: fakeGit, SocketDir: control.dir,
		Environment: os.Environ(), Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case request := <-requestSeen:
		if request.URL.Path != "/cloudflare/prod/openai/v1/models" {
			t.Fatalf("path=%q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("session authorization reached the Agentbox data plane")
		}
	case <-time.After(time.Second):
		t.Fatal("Codex request did not reach the host-session socket")
	}
	if control.added == "" || control.deleted != control.added {
		t.Fatalf("session lifecycle added=%q deleted=%q", control.added, control.deleted)
	}
}

func TestRunForwardsClaudeRequestAndCleansSession(t *testing.T) {
	requestSeen := make(chan *http.Request, 1)
	control := &controlFake{dir: t.TempDir(), handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- r.Clone(context.Background())
		_, _ = io.WriteString(w, "ok")
	})}
	root := t.TempDir()
	fakeClaude := filepath.Join(root, "claude")
	writeExecutable(t, fakeClaude, "#!/bin/sh\nset -eu\ntest \"${ANTHROPIC_API_KEY+x}\" != x\ntest \"${CLAUDE_CODE_OAUTH_TOKEN+x}\" != x\ntest \"$CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC\" = 1\ncurl -fsS -H \"Authorization: Bearer $ANTHROPIC_AUTH_TOKEN\" \"$ANTHROPIC_BASE_URL/v1/messages\" >/dev/null\n")
	profile := domain.Profile{
		Name: "prod", Routes: []domain.Route{}, Credentials: map[string]string{},
		Environment: map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:8787/cloudflare/prod/anthropic"},
	}
	err := Run(context.Background(), control, Options{
		Profile: profile, Agent: AgentClaude, AgentBin: fakeClaude, GitBin: makeFakeGit(t, root), SocketDir: control.dir,
		Environment: append(os.Environ(), "ANTHROPIC_API_KEY=user-key", "CLAUDE_CODE_OAUTH_TOKEN=user-token"),
		Stdout:      io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case request := <-requestSeen:
		if request.URL.Path != "/cloudflare/prod/anthropic/v1/messages" {
			t.Fatalf("path=%q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("session authorization reached the Agentbox data plane")
		}
	case <-time.After(time.Second):
		t.Fatal("Claude request did not reach the host-session socket")
	}
	if control.added == "" || control.deleted != control.added {
		t.Fatalf("session lifecycle added=%q deleted=%q", control.added, control.deleted)
	}
}

func TestRunForwardsPiRequestAndCleansSession(t *testing.T) {
	requestSeen := make(chan *http.Request, 1)
	control := &controlFake{dir: t.TempDir(), handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- r.Clone(context.Background())
		_, _ = io.WriteString(w, "ok")
	})}
	root := t.TempDir()
	fakePi := filepath.Join(root, "pi")
	writeExecutable(t, fakePi, "#!/bin/sh\nset -eu\ntest \"$PI_OFFLINE\" = 1\ntest -f \"$PI_CODING_AGENT_DIR/models.json\"\ntest -f \"$PI_CODING_AGENT_DIR/auth.json\"\ncurl -fsS -H \"Authorization: Bearer $OPENAI_API_KEY\" \"$OPENAI_BASE_URL/responses\" >/dev/null\n")
	profile := domain.Profile{
		Name: "prod", Routes: []domain.Route{}, Credentials: map[string]string{},
		Environment: map[string]string{
			"OPENAI_BASE_URL":    "http://127.0.0.1:8787/cloudflare/prod/openai",
			"ANTHROPIC_BASE_URL": "http://127.0.0.1:8787/cloudflare/prod/anthropic",
		},
	}
	err := Run(context.Background(), control, Options{
		Profile: profile, Agent: AgentPi, AgentBin: fakePi, GitBin: makeFakeGit(t, root), SocketDir: control.dir,
		Environment: []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root}, Stdout: io.Discard, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case request := <-requestSeen:
		if request.URL.Path != "/cloudflare/prod/openai/responses" {
			t.Fatalf("path=%q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "" {
			t.Fatal("session authorization reached the Agentbox data plane")
		}
	case <-time.After(time.Second):
		t.Fatal("Pi request did not reach the host-session socket")
	}
	if control.added == "" || control.deleted != control.added {
		t.Fatalf("session lifecycle added=%q deleted=%q", control.added, control.deleted)
	}
}

type controlFake struct {
	dir            string
	added, deleted string
	listener       *http.Server
	handler        http.Handler
}

func (c *controlFake) AddHostSession(_ context.Context, value domain.Container) (domain.Container, error) {
	c.added = value.Name
	value.CreatedAt = value.CreatedAt.UTC()
	handler := c.handler
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	listener, err := newUnixHTTPServer(filepath.Join(c.dir, value.Name+".sock"), handler)
	if err != nil {
		return domain.Container{}, err
	}
	c.listener = listener
	return value, nil
}

func (c *controlFake) DeleteHostSession(_ context.Context, name string) error {
	c.deleted = name
	if c.listener != nil {
		_ = c.listener.Close()
	}
	return nil
}

func newUnixHTTPServer(path string, handler http.Handler) (*http.Server, error) {
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	return server, nil
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
}

func makeFakeGit(t *testing.T, root string) string {
	t.Helper()
	original := filepath.Join(root, "git-core-for-"+filepath.Base(root))
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(original, "git-remote-http"), "#!/bin/sh\nexit 0\n")
	fake := filepath.Join(root, "git-for-"+filepath.Base(root))
	writeExecutable(t, fake, "#!/bin/sh\nprintf '%s\\n' "+shellQuote(original)+"\n")
	return fake
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
