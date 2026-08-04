package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
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

func TestProxyTransformsTopLevelJSONStringPrefixes(t *testing.T) {
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = []domain.Route{{
		Name: "unified", Scope: "prod", Match: domain.Match{PathPrefix: "/anthropic"},
		Upstream: "https://upstream.invalid/ai/v1", StripPrefix: true, DropQuery: true,
		PathMap: []domain.PathRewrite{{Path: "/v1/messages", To: "/messages"}},
		RequestJSON: &domain.JSONTransform{
			JoinStringArrays: []domain.JSONArrayStringJoin{{Field: "system", ElementField: "text", Separator: "\n\n"}},
			HoistArrayObjectStrings: []domain.JSONArrayObjectStringHoist{{
				SourceField: "messages", MatchField: "role", MatchValue: "system", ValueField: "content", ElementField: "text", TargetField: "system", Separator: "\n\n",
			}},
			StringPrefixes: []domain.JSONStringPrefix{{Field: "model", Prefix: "anthropic/"}},
			RemoveFields:   []string{"context_management"},
		},
	}}
	snapshot, err := engine.Compile(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, model := range []string{"claude-fable-5", "anthropic/claude-fable-5"} {
		t.Run(model, func(t *testing.T) {
			transport := roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://upstream.invalid/ai/v1/messages" {
					t.Errorf("URL: %s", r.URL)
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var payload map[string]any
				if err := json.Unmarshal(data, &payload); err != nil {
					t.Fatal(err)
				}
				if payload["model"] != "anthropic/claude-fable-5" || payload["system"] != "first\n\nsecond\n\nthird\n\nfourth" || payload["keep"] != "value" {
					t.Errorf("payload=%v", payload)
				}
				if _, exists := payload["context_management"]; exists {
					t.Errorf("context_management survived: %v", payload)
				}
				messages, ok := payload["messages"].([]any)
				if !ok || len(messages) != 1 || messages[0].(map[string]any)["role"] != "user" {
					t.Errorf("messages=%v", payload["messages"])
				}
				if r.ContentLength != int64(len(data)) || r.Header.Get("Content-Length") != fmt.Sprint(len(data)) {
					t.Errorf("content length field=%d header=%q body=%d", r.ContentLength, r.Header.Get("Content-Length"), len(data))
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
			})
			server := &Server{Snapshots: snapshots{snapshot}, Materials: resolver{}, Transport: transport, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			request := httptest.NewRequest(http.MethodPost, "http://agentbox/anthropic/v1/messages?beta=true", strings.NewReader(`{"model":"`+model+`","system":[{"type":"text","text":"first"},{"type":"text","text":"second"}],"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]},{"role":"system","content":[{"type":"text","text":"third"},{"type":"text","text":"fourth"}]}],"context_management":{"edits":[]},"keep":"value"}`))
			request.Header.Set("Content-Type", "application/json; charset=utf-8")
			recorder := httptest.NewRecorder()
			server.Handler("dev").ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%q", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestJSONArrayObjectStringHoistSupportsStringsAndIsIdempotent(t *testing.T) {
	transform := domain.JSONTransform{HoistArrayObjectStrings: []domain.JSONArrayObjectStringHoist{{
		SourceField: "messages", MatchField: "role", MatchValue: "system", ValueField: "content", ElementField: "text", TargetField: "system", Separator: "\n\n",
	}}}
	request := httptest.NewRequest(http.MethodPost, "http://agentbox/", strings.NewReader(`{"messages":[{"role":"system","content":"rules"},{"role":"user","content":"hello"}]}`))
	request.Header.Set("Content-Type", "application/json")
	if got := transformJSONRequest(request, transform, 1024); got != nil {
		t.Fatalf("first transform failed: %+v", got)
	}
	if got := transformJSONRequest(request, transform, 1024); got != nil {
		t.Fatalf("second transform failed: %+v", got)
	}
	var payload map[string]any
	if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["system"] != "rules" || len(payload["messages"].([]any)) != 1 {
		t.Fatalf("payload=%v", payload)
	}
}

func TestJSONArrayObjectStringHoistRejectsInvalidShapes(t *testing.T) {
	transform := domain.JSONTransform{HoistArrayObjectStrings: []domain.JSONArrayObjectStringHoist{{
		SourceField: "messages", MatchField: "role", MatchValue: "system", ValueField: "content", ElementField: "text", TargetField: "system", Separator: "\n\n",
	}}}
	for name, body := range map[string]string{
		"missing source":          `{}`,
		"source not array":        `{"messages":{}}`,
		"source null":             `{"messages":null}`,
		"element not object":      `{"messages":["bad"]}`,
		"missing match":           `{"messages":[{"content":"bad"}]}`,
		"match not string":        `{"messages":[{"role":1,"content":"bad"}]}`,
		"missing value":           `{"messages":[{"role":"system"}]}`,
		"invalid value":           `{"messages":[{"role":"system","content":1}]}`,
		"invalid content element": `{"messages":[{"role":"system","content":[{"text":1}]}]}`,
		"target not string":       `{"system":[],"messages":[{"role":"system","content":"rules"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://agentbox/", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			got := transformJSONRequest(request, transform, 1024)
			if got == nil || got.status != http.StatusBadRequest {
				t.Fatalf("error=%+v", got)
			}
		})
	}
}

func TestJSONTransformRejectsUnsafeBodies(t *testing.T) {
	transform := domain.JSONTransform{StringPrefixes: []domain.JSONStringPrefix{{Field: "model", Prefix: "anthropic/"}}}
	tests := []struct {
		name, body, contentType, contentEncoding string
		limit                                    int64
		status                                   int
	}{
		{name: "not JSON", body: `{}`, contentType: "text/plain", limit: 100, status: http.StatusUnsupportedMediaType},
		{name: "encoded", body: `{}`, contentType: "application/json", contentEncoding: "gzip", limit: 100, status: http.StatusUnsupportedMediaType},
		{name: "too large", body: `{"model":"x"}`, contentType: "application/json", limit: 5, status: http.StatusRequestEntityTooLarge},
		{name: "malformed", body: `{`, contentType: "application/json", limit: 100, status: http.StatusBadRequest},
		{name: "missing field", body: `{}`, contentType: "application/json", limit: 100, status: http.StatusBadRequest},
		{name: "wrong field type", body: `{"model":1}`, contentType: "application/json", limit: 100, status: http.StatusBadRequest},
		{name: "trailing JSON", body: `{"model":"x"} {}`, contentType: "application/json", limit: 100, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://agentbox/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			if test.contentEncoding != "" {
				request.Header.Set("Content-Encoding", test.contentEncoding)
			}
			got := transformJSONRequest(request, transform, test.limit)
			if got == nil || got.status != test.status {
				t.Fatalf("error=%+v want status=%d", got, test.status)
			}
		})
	}
}

func TestJSONArrayStringJoinRejectsInvalidShapesAndAllowsOptionalField(t *testing.T) {
	transform := domain.JSONTransform{JoinStringArrays: []domain.JSONArrayStringJoin{{Field: "system", ElementField: "text", Separator: "\n\n"}}}
	for name, body := range map[string]string{
		"not array":             `{"system":"text"}`,
		"null array":            `{"system":null}`,
		"non-object element":    `{"system":["text"]}`,
		"missing element field": `{"system":[{"type":"text"}]}`,
		"wrong element type":    `{"system":[{"text":1}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://agentbox/", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			got := transformJSONRequest(request, transform, 1024)
			if got == nil || got.status != http.StatusBadRequest {
				t.Fatalf("error=%+v", got)
			}
		})
	}

	optional := domain.JSONTransform{JoinStringArrays: []domain.JSONArrayStringJoin{{Field: "system", ElementField: "text", Optional: true}}}
	request := httptest.NewRequest(http.MethodPost, "http://agentbox/", strings.NewReader(`{"model":"test"}`))
	request.Header.Set("Content-Type", "application/json")
	if got := transformJSONRequest(request, optional, 1024); got != nil {
		t.Fatalf("optional field failed: %+v", got)
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
