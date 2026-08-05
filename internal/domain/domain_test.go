package domain

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

type mapResolver map[string][]byte

func (m mapResolver) Resolve(_ context.Context, _ string, ref MaterialReference) ([]byte, error) {
	v, ok := m[ref.Name]
	if !ok {
		return nil, fmt.Errorf("missing %s %q", ref.Kind, ref.Name)
	}
	return append([]byte(nil), v...), nil
}

func validRoute() Route {
	return Route{Name: "example", Match: Match{PathPrefix: "/api"}, Upstream: "https://example.com/base",
		StripPrefix: true, SetHeaders: []HeaderValue{{Name: "Authorization", Value: "Bearer {secret:token}"}}}
}

func TestValidateState(t *testing.T) {
	s := NewState()
	s.Profiles = []Profile{{Name: "prod", Routes: []Route{validRoute()}, Credentials: map[string]string{}, Environment: map[string]string{"AGENTBOX_PROFILE": "prod"}}}
	s.Containers = []Container{{Name: "dev", Profile: "prod", CreatedAt: time.Now()}}
	if err := ValidateState(s); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*State)
	}{
		{"invalid profile name", func(s *State) { s.Profiles[0].Name = "*" }},
		{"both selectors", func(s *State) { s.Profiles[0].Routes[0].Match.Host = "api.example.com" }},
		{"unsafe path", func(s *State) { s.Profiles[0].Routes[0].Match.PathPrefix = "/api/../x" }},
		{"bad upstream", func(s *State) { s.Profiles[0].Routes[0].Upstream = "file:///tmp/x" }},
		{"bad template", func(s *State) { s.Profiles[0].Routes[0].SetHeaders[0].Value = "{env:TOKEN}" }},
		{"universal container", func(s *State) { s.Containers[0].Profile = "*" }},
		{"unknown profile", func(s *State) { s.Containers[0].Profile = "missing" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := CloneState(s)
			tt.mutate(&candidate)
			if ValidateState(candidate) == nil {
				t.Fatal("accepted invalid state")
			}
		})
	}
}

func TestTemplate(t *testing.T) {
	tpl, err := ParseTemplate("Basic {basic:x-access-token:github-pat} / {secret:suffix}")
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.Render(context.Background(), "dev", mapResolver{"github-pat": []byte("pat"), "suffix": []byte("ok")})
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := "Basic eC1hY2Nlc3MtdG9rZW46cGF0 / ok"
	if got != wantPrefix {
		t.Fatalf("got %q want %q", got, wantPrefix)
	}
	if !bytes.Equal([]byte(tpl.Keys()[0]), []byte("github-pat")) {
		t.Fatalf("keys: %v", tpl.Keys())
	}
	if _, err := tpl.Render(context.Background(), "dev", mapResolver{}); err == nil {
		t.Fatal("missing secret accepted")
	}
}

func TestCredentialTemplate(t *testing.T) {
	tpl, err := ParseTemplate("Bearer {credential:github} / Basic {basic:x-access-token:credential:github}")
	if err != nil {
		t.Fatal(err)
	}
	got, err := tpl.Render(context.Background(), "dev", mapResolver{"github": []byte("ghs_token")})
	if err != nil {
		t.Fatal(err)
	}
	if got != "Bearer ghs_token / Basic eC1hY2Nlc3MtdG9rZW46Z2hzX3Rva2Vu" {
		t.Fatalf("rendered=%q", got)
	}
	if len(tpl.Keys()) != 0 || len(tpl.Credentials()) != 1 || tpl.Credentials()[0] != "github" {
		t.Fatalf("keys=%v credentials=%v", tpl.Keys(), tpl.Credentials())
	}
	for _, invalid := range []string{"{credential:Bad}", "{basic:x:credential:Bad}", "{basic:x:other:name}"} {
		if _, err := ParseTemplate(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}

func TestCredentialStateReferences(t *testing.T) {
	state := NewState()
	state.CredentialSources = []CredentialSource{{Name: "github-prod", Provider: "github-app", Parameters: map[string]string{"installation-id": "1"}, Secrets: map[string]string{"private-key": "app.pem"}}}
	state.Profiles = []Profile{{Name: "prod", Routes: []Route{}, Credentials: map[string]string{"github": "github-prod"}, Environment: map[string]string{}}}
	state.Containers = []Container{{Name: "dev", Profile: "prod", CreatedAt: time.Now()}}
	if err := ValidateState(state); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*State){
		func(s *State) { s.Profiles[0].Credentials["github"] = "missing" },
		func(s *State) { s.Profiles[0].Credentials["Bad"] = "github-prod" },
		func(s *State) { s.Profiles = append(s.Profiles, s.Profiles[0]) },
	} {
		candidate := CloneState(state)
		mutate(&candidate)
		if ValidateState(candidate) == nil {
			t.Fatal("accepted invalid credential references")
		}
	}
}

func TestCloneStateIsDeep(t *testing.T) {
	s := NewState()
	s.Profiles = []Profile{{Name: "prod", Routes: []Route{validRoute()}, Credentials: map[string]string{}, Environment: map[string]string{}}}
	clone := CloneState(s)
	clone.Profiles[0].Routes[0].SetHeaders[0].Value = "changed"
	clone.CredentialSources = []CredentialSource{{Name: "source", Provider: "provider", Parameters: map[string]string{"a": "b"}, Secrets: map[string]string{}}}
	original := CloneState(clone)
	clone.CredentialSources[0].Parameters["a"] = "changed"
	if s.Profiles[0].Routes[0].SetHeaders[0].Value == "changed" {
		t.Fatal("nested route data was shared")
	}
	if original.CredentialSources[0].Parameters["a"] == "changed" {
		t.Fatal("credential source maps were shared")
	}
}

func TestHostRouteAllowsSingleLabelNames(t *testing.T) {
	route := validRoute()
	route.Match = Match{Host: "upstream"}
	route.StripPrefix = false
	if err := ValidateRoute(route); err != nil {
		t.Fatalf("single-label host rejected: %v", err)
	}
}

func TestMaterialRequiresEncryptedOrLoopbackTransport(t *testing.T) {
	for _, upstream := range []string{"http://example.com", "http://localhost:8080"} {
		route := validRoute()
		route.Upstream = upstream
		if err := ValidateRoute(route); err == nil {
			t.Fatalf("material-bearing route accepted plaintext upstream %q", upstream)
		}
	}
	for _, upstream := range []string{"https://example.com", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		route := validRoute()
		route.Upstream = upstream
		if err := ValidateRoute(route); err != nil {
			t.Fatalf("safe upstream %q rejected: %v", upstream, err)
		}
	}

	route := validRoute()
	route.Upstream = "http://example.com"
	route.SetHeaders = []HeaderValue{{Name: "X-Mode", Value: "non-secret"}}
	if err := ValidateRoute(route); err != nil {
		t.Fatalf("plaintext route without material rejected: %v", err)
	}
}
