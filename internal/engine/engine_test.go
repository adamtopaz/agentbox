package engine

import (
	"testing"
	"time"

	"agentbox/internal/domain"
)

func TestScopePrecedenceAndPathMap(t *testing.T) {
	s := domain.NewState()
	s.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	s.Routes = []domain.Route{
		{Name: "all-api", Scope: "*", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://all.example", StripPrefix: true},
		{Name: "prod-api", Scope: "prod", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://prod.example", StripPrefix: true,
			PathMap: []domain.PathRewrite{{Path: "/messages", To: "/v1/messages"}}},
		{Name: "deep", Scope: "prod", Match: domain.Match{PathPrefix: "/api/special"}, Upstream: "https://special.example", StripPrefix: true},
	}
	snapshot, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	route, path, ok := snapshot.Match("prod", "", "/api/messages")
	if !ok || route.Name != "prod-api" || path != "/v1/messages" {
		t.Fatalf("route=%v path=%q ok=%v", route.Name, path, ok)
	}
	route, _, _ = snapshot.Match("prod", "", "/api/special/x")
	if route.Name != "deep" {
		t.Fatalf("longest prefix lost: %s", route.Name)
	}
	route, _, _ = snapshot.Match("other", "", "/api/messages")
	if route.Name != "all-api" {
		t.Fatalf("universal fallback lost: %s", route.Name)
	}
}

func TestHostBeforePathAndSpecificBeforeUniversal(t *testing.T) {
	s := domain.NewState()
	s.Routes = []domain.Route{
		{Name: "universal-host", Scope: "*", Match: domain.Match{Host: "api.example.com"}, Upstream: "https://universal.example"},
		{Name: "specific-host", Scope: "prod", Match: domain.Match{Host: "api.example.com"}, Upstream: "https://specific.example"},
		{Name: "specific-path", Scope: "prod", Match: domain.Match{PathPrefix: "/"}, Upstream: "https://path.example"},
	}
	snapshot, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	route, _, ok := snapshot.Match("prod", "API.EXAMPLE.COM:443", "/anything")
	if !ok || route.Name != "specific-host" {
		t.Fatalf("specific host route did not win: %+v, ok=%v", route, ok)
	}
	route, _, ok = snapshot.Match("dev", "api.example.com", "/anything")
	if !ok || route.Name != "universal-host" {
		t.Fatalf("universal host fallback did not win: %+v, ok=%v", route, ok)
	}
}

func TestRootPrefixMatchesEveryAbsolutePath(t *testing.T) {
	s := domain.NewState()
	s.Routes = []domain.Route{{
		Name: "root", Scope: "*", Match: domain.Match{PathPrefix: "/"},
		Upstream: "https://example.com", StripPrefix: true,
		PathMap: []domain.PathRewrite{{Path: "/messages", To: "/v1/messages"}},
	}}
	snapshot, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	route, path, ok := snapshot.Match("dev", "", "/messages")
	if !ok || route.Name != "root" || path != "/v1/messages" {
		t.Fatalf("route=%v path=%q ok=%v", route, path, ok)
	}
}
