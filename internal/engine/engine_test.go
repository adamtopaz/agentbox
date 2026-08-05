package engine

import (
	"testing"
	"time"

	"agentbox/internal/domain"
)

func TestProfileRoutingAndPathPreservation(t *testing.T) {
	state := domain.NewState()
	state.Profiles = []domain.Profile{{Name: "prod", Credentials: map[string]string{}, Environment: map[string]string{}, Routes: []domain.Route{
		{Name: "api", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://prod.example", StripPrefix: true},
		{Name: "deep", Match: domain.Match{PathPrefix: "/api/special"}, Upstream: "https://special.example", StripPrefix: true},
	}}, {Name: "staging", Credentials: map[string]string{}, Environment: map[string]string{}, Routes: []domain.Route{
		{Name: "api", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://staging.example", StripPrefix: true},
	}}}
	state.Containers = []domain.Container{{Name: "dev", Profile: "prod", CreatedAt: time.Now()}}
	snapshot, err := Compile(state)
	if err != nil {
		t.Fatal(err)
	}
	route, path, ok := snapshot.Match("prod", "", "/api/messages")
	if !ok || route.Name != "api" || path != "/messages" {
		t.Fatalf("route=%v path=%q ok=%v", route.Name, path, ok)
	}
	route, _, _ = snapshot.Match("prod", "", "/api/special/x")
	if route.Name != "deep" {
		t.Fatalf("longest prefix lost: %s", route.Name)
	}
	staging, _, ok := snapshot.Match("staging", "", "/api/messages")
	if !ok || staging.Target.Host != "staging.example" {
		t.Fatalf("staging route=%+v ok=%v", staging, ok)
	}
	if _, _, ok := snapshot.Match("other", "", "/api/messages"); ok {
		t.Fatal("route escaped its profile")
	}
}

func TestHostBeforePath(t *testing.T) {
	state := domain.NewState()
	state.Profiles = []domain.Profile{{Name: "prod", Credentials: map[string]string{}, Environment: map[string]string{}, Routes: []domain.Route{
		{Name: "host", Match: domain.Match{Host: "api.example.com"}, Upstream: "https://specific.example"},
		{Name: "path", Match: domain.Match{PathPrefix: "/"}, Upstream: "https://path.example"},
	}}}
	snapshot, err := Compile(state)
	if err != nil {
		t.Fatal(err)
	}
	route, _, ok := snapshot.Match("prod", "API.EXAMPLE.COM:443", "/anything")
	if !ok || route.Name != "host" {
		t.Fatalf("host route did not win: %+v, ok=%v", route, ok)
	}
}

func TestRootPrefixMatchesEveryAbsolutePath(t *testing.T) {
	state := domain.NewState()
	state.Profiles = []domain.Profile{{Name: "dev", Credentials: map[string]string{}, Environment: map[string]string{}, Routes: []domain.Route{{
		Name: "root", Match: domain.Match{PathPrefix: "/"}, Upstream: "https://example.com", StripPrefix: true,
	}}}}
	snapshot, err := Compile(state)
	if err != nil {
		t.Fatal(err)
	}
	route, path, ok := snapshot.Match("dev", "", "/messages")
	if !ok || route.Name != "root" || path != "/messages" {
		t.Fatalf("route=%v path=%q ok=%v", route, path, ok)
	}
}
