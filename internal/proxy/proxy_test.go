package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agentbox/internal/domain"
	"agentbox/internal/engine"
	"agentbox/internal/profile"
)

type snapshots struct{ s *engine.Snapshot }

func (s snapshots) Snapshot() *engine.Snapshot { return s.s }

type resolver map[string][]byte

func (r resolver) Resolve(_ context.Context, _ string, ref domain.MaterialReference) ([]byte, error) {
	value, ok := r[ref.Name]
	if !ok {
		return nil, errors.New("missing material")
	}
	return append([]byte(nil), value...), nil
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDefaultTransportHasProductionBounds(t *testing.T) {
	if defaultTransport.TLSClientConfig == nil || defaultTransport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("default transport permits TLS older than 1.2")
	}
	if defaultTransport.ResponseHeaderTimeout <= 0 || defaultTransport.MaxResponseHeaderBytes <= 0 || defaultTransport.MaxConnsPerHost <= 0 {
		t.Fatalf("default transport is unbounded: %+v", defaultTransport)
	}
	if defaultMaxConnections <= 0 {
		t.Fatal("per-container connection limit is disabled")
	}
}

func TestProxyStripsThenInjects(t *testing.T) {
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = []domain.Route{{Name: "api", Scope: "prod", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://upstream.invalid/base", StripPrefix: true,
		SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "Bearer {secret:token}"}, {Name: "cf-aig-authorization", Value: "{secret:token}"}}}}
	snapshot, err := engine.Compile(state)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://upstream.invalid/base/messages?q=kept" {
			t.Errorf("URL: %s", r.URL)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer real" {
			t.Errorf("Authorization=%q", got)
		}
		if got := r.Header.Get("cf-aig-authorization"); got != "real" {
			t.Errorf("cf-aig-authorization=%q", got)
		}
		for _, absent := range []string{"Cookie", "X-Api-Key", "X-Forwarded-For"} {
			if values, ok := r.Header[http.CanonicalHeaderKey(absent)]; ok && values != nil {
				t.Errorf("%s survived: %v", absent, values)
			}
		}
		if r.Header.Get("Cf-Aig-Collect-Log") != "false" {
			t.Errorf("non-auth gateway header changed: %v", r.Header)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	server := &Server{Snapshots: snapshots{snapshot}, Materials: resolver{"token": []byte("real")}, Transport: transport, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPost, "http://agentbox/api/messages?q=kept", nil)
	req.Header.Set("Authorization", "Bearer fake")
	req.Header.Set("Cookie", "secret")
	req.Header.Set("X-Api-Key", "fake")
	req.Header.Set("Cf-Aig-Collect-Log", "false")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	rec := httptest.NewRecorder()
	server.Handler("dev").ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestProxyPreservesProviderNativeRequest(t *testing.T) {
	routes, err := profile.CloudflareRoutes("0123456789abcdef0123456789abcdef", []string{"prod"})
	if err != nil {
		t.Fatal(err)
	}
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = routes
	snapshot, err := engine.Compile(state)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte("{\n  \"model\": \"claude-opus-5\",\n  \"system\": [{\"type\":\"text\",\"text\":\"rules\",\"cache_control\":{\"type\":\"ephemeral\"}}],\n  \"messages\": [{\"role\":\"system\",\"content\":[{\"type\":\"text\",\"text\":\"more rules\"}]},{\"role\":\"user\",\"content\":\"say ok\"}],\n  \"context_management\": {\"edits\": []}\n}\n")
	transport := roundTrip(func(request *http.Request) (*http.Response, error) {
		wantURL := "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/prod/anthropic/v1/messages?beta=true&feature=%2Fraw"
		if request.URL.String() != wantURL {
			t.Errorf("URL=%q want %q", request.URL, wantURL)
		}
		gotBody, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(gotBody, body) {
			t.Errorf("request body changed:\n got: %q\nwant: %q", gotBody, body)
		}
		if request.ContentLength != int64(len(body)) {
			t.Errorf("ContentLength=%d want %d", request.ContentLength, len(body))
		}
		if request.Header.Get("Content-Type") != "application/json; charset=utf-8" ||
			request.Header.Get("Anthropic-Version") != "2023-06-01" ||
			request.Header.Get("Anthropic-Beta") != "context-management-2025-06-27" {
			t.Errorf("provider headers changed: %v", request.Header)
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("X-Api-Key") != "" {
			t.Errorf("container credentials survived: %v", request.Header)
		}
		if request.Header.Get("cf-aig-authorization") != "Bearer cloudflare-token" {
			t.Errorf("gateway auth=%q", request.Header.Get("cf-aig-authorization"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})
	server := &Server{
		Snapshots: snapshots{snapshot}, Materials: resolver{"cf-aig-token-prod": []byte("cloudflare-token")},
		Transport: transport, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	request := httptest.NewRequest(http.MethodPost, "http://agentbox/cloudflare/prod/anthropic/v1/messages?beta=true&feature=%2Fraw", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Anthropic-Version", "2023-06-01")
	request.Header.Set("Anthropic-Beta", "context-management-2025-06-27")
	request.Header.Set("Authorization", "Bearer dummy")
	request.Header.Set("X-Api-Key", "dummy")
	recorder := httptest.NewRecorder()
	server.Handler("dev").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestProxyPreservesOpenAIProviderNativeRequest(t *testing.T) {
	routes, err := profile.CloudflareRoutes("0123456789abcdef0123456789abcdef", []string{"prod"})
	if err != nil {
		t.Fatal(err)
	}
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = routes
	snapshot, err := engine.Compile(state)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte("{\n  \"model\": \"gpt-5.4\",\n  \"input\": [{\"role\":\"user\",\"content\":\"say ok\"}],\n  \"store\": false\n}\n")
	transport := roundTrip(func(request *http.Request) (*http.Response, error) {
		wantURL := "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/prod/openai/responses?include%5B%5D=reasoning.encrypted_content"
		if request.URL.String() != wantURL {
			t.Errorf("URL=%q want %q", request.URL, wantURL)
		}
		gotBody, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(gotBody, body) {
			t.Errorf("request body changed:\n got: %q\nwant: %q", gotBody, body)
		}
		if request.Header.Get("OpenAI-Beta") != "responses=v1" {
			t.Errorf("OpenAI feature header changed: %v", request.Header)
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("cf-aig-authorization") != "Bearer cloudflare-token" {
			t.Errorf("unexpected authentication headers: %v", request.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})
	server := &Server{
		Snapshots: snapshots{snapshot}, Materials: resolver{"cf-aig-token-prod": []byte("cloudflare-token")},
		Transport: transport, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	request := httptest.NewRequest(http.MethodPost, "http://agentbox/cloudflare/prod/openai/responses?include%5B%5D=reasoning.encrypted_content", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("OpenAI-Beta", "responses=v1")
	request.Header.Set("Authorization", "Bearer dummy")
	recorder := httptest.NewRecorder()
	server.Handler("dev").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

type credentialResolver struct {
	principal string
	ref       domain.MaterialReference
}

func (r *credentialResolver) Resolve(_ context.Context, principal string, ref domain.MaterialReference) ([]byte, error) {
	r.principal, r.ref = principal, ref
	return []byte("ghs_installation"), nil
}

func TestProxyResolvesCredentialForListenerPrincipal(t *testing.T) {
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = []domain.Route{{
		Name: "github", Scope: "*", Match: domain.Match{Host: "api.github.com"}, Upstream: "https://api.github.com",
		SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "Bearer {credential:github}"}},
	}}
	snapshot, err := engine.Compile(state)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &credentialResolver{}
	server := &Server{
		Snapshots: snapshots{snapshot}, Materials: resolver,
		Transport: roundTrip(func(request *http.Request) (*http.Response, error) {
			if got := request.Header.Get("Authorization"); got != "Bearer ghs_installation" {
				t.Errorf("Authorization=%q", got)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
		}),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	request := httptest.NewRequest(http.MethodGet, "http://agentbox/repos/o/r", nil)
	request.Host = "api.github.com"
	request.Header.Set("Authorization", "Bearer agentbox-dummy")
	recorder := httptest.NewRecorder()
	server.Handler("dev").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || resolver.principal != "dev" || resolver.ref.Kind != domain.MaterialCredential || resolver.ref.Name != "github" {
		t.Fatalf("status=%d principal=%q ref=%+v", recorder.Code, resolver.principal, resolver.ref)
	}
}

func TestProxyFailsClosed(t *testing.T) {
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = []domain.Route{{Name: "api", Scope: "prod", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://upstream.invalid", SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "{secret:missing}"}}}}
	snapshot, _ := engine.Compile(state)
	called := false
	server := &Server{Snapshots: snapshots{snapshot}, Materials: resolver{}, Transport: roundTrip(func(*http.Request) (*http.Response, error) { called = true; return nil, context.Canceled }), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, path := range []string{"/api/x", "/api/%2e%2e/x"} {
		rec := httptest.NewRecorder()
		server.Handler("dev").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://agentbox"+path, nil))
		if path == "/api/x" && rec.Code != 503 {
			t.Fatalf("missing key status=%d", rec.Code)
		}
		if path != "/api/x" && rec.Code != 404 {
			t.Fatalf("unsafe path status=%d", rec.Code)
		}
	}
	if called {
		t.Fatal("upstream called without credential")
	}
}

func TestTransportErrorDetailsAreNotLogged(t *testing.T) {
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = []domain.Route{{Name: "api", Scope: "prod", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://upstream.invalid"}}
	snapshot, err := engine.Compile(state)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	server := &Server{
		Snapshots: snapshots{snapshot}, Materials: resolver{},
		Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport included URL ?token=QUERYSECRET")
		}),
		Log: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	recorder := httptest.NewRecorder()
	server.Handler("dev").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://agentbox/api/x?token=QUERYSECRET", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", recorder.Code)
	}
	if strings.Contains(logs.String(), "QUERYSECRET") {
		t.Fatalf("transport detail leaked into log: %s", logs.String())
	}
}

type queuedListener struct {
	connections chan net.Conn
	closed      chan struct{}
}

func (l *queuedListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *queuedListener) Close() error   { close(l.closed); return nil }
func (l *queuedListener) Addr() net.Addr { return testAddr("queue") }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func TestLimitListenerReleasesSlotsAndUnblocksOnClose(t *testing.T) {
	base := &queuedListener{connections: make(chan net.Conn, 2), closed: make(chan struct{})}
	limited := newLimitListener(base, 1)
	serverOne, clientOne := net.Pipe()
	defer clientOne.Close()
	base.connections <- serverOne
	first, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}

	serverTwo, clientTwo := net.Pipe()
	defer clientTwo.Close()
	base.connections <- serverTwo
	accepted := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		connection, err := limited.Accept()
		if err != nil {
			errs <- err
			return
		}
		accepted <- connection
	}()
	select {
	case <-accepted:
		t.Fatal("second connection bypassed the limit")
	case err := <-errs:
		t.Fatalf("second accept failed early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case second := <-accepted:
		if err := second.Close(); err != nil {
			t.Fatal(err)
		}
	case err := <-errs:
		t.Fatalf("second accept failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("released slot did not unblock accept")
	}

	serverThree, clientThree := net.Pipe()
	defer clientThree.Close()
	base.connections <- serverThree
	third, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}
	serverFour, clientFour := net.Pipe()
	defer serverFour.Close()
	defer clientFour.Close()
	base.connections <- serverFour
	thirdErr := make(chan error, 1)
	go func() {
		_, err := limited.Accept()
		thirdErr <- err
	}()
	if err := limited.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-thirdErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked accept error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener close did not unblock accept")
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}
