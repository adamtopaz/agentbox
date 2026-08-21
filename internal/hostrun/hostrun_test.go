package hostrun

import (
	"context"
	"encoding/base64"
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
		Profile:  domain.Profile{Name: "prod", Routes: []domain.Route{}, Credentials: map[string]string{}, Environment: map[string]string{}},
		CodexBin: fakeCodex, GitBin: fakeGit, SocketDir: control.dir,
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
		Profile: profile, CodexBin: fakeCodex, GitBin: fakeGit, SocketDir: control.dir,
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
