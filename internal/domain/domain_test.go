package domain

import (
	"bytes"
	"testing"
	"time"
)

type mapResolver map[string][]byte

func (m mapResolver) Resolve(name string) ([]byte, bool) { v, ok := m[name]; return v, ok }

func validRoute() Route {
	return Route{Name: "example", Scope: "prod", Match: Match{PathPrefix: "/api"}, Upstream: "https://example.com/base",
		StripPrefix: true, SetHeaders: []HeaderValue{{Name: "Authorization", Value: "Bearer {secret:token}"}}}
}

func TestValidateState(t *testing.T) {
	s := NewState()
	s.Routes = []Route{validRoute()}
	s.Containers = []Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	if err := ValidateState(s); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*State)
	}{
		{"missing scope", func(s *State) { s.Routes[0].Scope = "" }},
		{"both selectors", func(s *State) { s.Routes[0].Match.Host = "api.example.com" }},
		{"unsafe path", func(s *State) { s.Routes[0].Match.PathPrefix = "/api/../x" }},
		{"bad upstream", func(s *State) { s.Routes[0].Upstream = "file:///tmp/x" }},
		{"bad template", func(s *State) { s.Routes[0].SetHeaders[0].Value = "{env:TOKEN}" }},
		{"universal container", func(s *State) { s.Containers[0].Scope = UniversalScope }},
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
	got, err := tpl.Render(mapResolver{"github-pat": []byte("pat"), "suffix": []byte("ok")})
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
	if _, err := tpl.Render(mapResolver{}); err == nil {
		t.Fatal("missing secret accepted")
	}
}

func TestCloneStateIsDeep(t *testing.T) {
	s := NewState()
	s.Routes = []Route{validRoute()}
	clone := CloneState(s)
	clone.Routes[0].SetHeaders[0].Value = "changed"
	if s.Routes[0].SetHeaders[0].Value == "changed" {
		t.Fatal("nested route data was shared")
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
