package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agentbox/internal/domain"
	"agentbox/internal/engine"
)

type snapshots struct{ s *engine.Snapshot }

func (s snapshots) Snapshot() *engine.Snapshot { return s.s }

type resolver map[string][]byte

func (r resolver) Resolve(name string) ([]byte, bool) { value, ok := r[name]; return value, ok }

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProxyStripsThenInjects(t *testing.T) {
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = []domain.Route{{Name: "api", Scope: "prod", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://upstream.invalid/base", StripPrefix: true,
		PathMap:    []domain.PathRewrite{{Path: "/messages", To: "/v1/messages"}},
		SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "Bearer {secret:token}"}, {Name: "cf-aig-authorization", Value: "{secret:token}"}}}}
	snapshot, err := engine.Compile(state)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://upstream.invalid/base/v1/messages?q=kept" {
			t.Errorf("URL: %s", r.URL)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer real" {
			t.Errorf("Authorization=%q", got)
		}
		if got := r.Header.Get("cf-aig-authorization"); got != "real" {
			t.Errorf("cf-aig-authorization=%q", got)
		}
		for _, absent := range []string{"Cookie", "X-Api-Key", "Cf-Aig-Collect-Log", "X-Forwarded-For"} {
			if values, ok := r.Header[http.CanonicalHeaderKey(absent)]; ok && values != nil {
				t.Errorf("%s survived: %v", absent, values)
			}
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	server := &Server{Snapshots: snapshots{snapshot}, Secrets: resolver{"token": []byte("real")}, Transport: transport, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
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

func TestProxyFailsClosed(t *testing.T) {
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = []domain.Route{{Name: "api", Scope: "prod", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://upstream.invalid", SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "{secret:missing}"}}}}
	snapshot, _ := engine.Compile(state)
	called := false
	server := &Server{Snapshots: snapshots{snapshot}, Secrets: resolver{}, Transport: roundTrip(func(*http.Request) (*http.Response, error) { called = true; return nil, context.Canceled }), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
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
		Snapshots: snapshots{snapshot}, Secrets: resolver{},
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
