package profile

import (
	"testing"

	"agentbox/internal/domain"
)

func TestProfilesAreOrdinaryValidRoutes(t *testing.T) {
	cloudflare, err := CloudflareRoutes("0123456789abcdef0123456789abcdef", []string{"prod", "test"})
	if err != nil {
		t.Fatal(err)
	}
	routes := append(GitHubRoutes(), cloudflare...)
	state := domain.NewState()
	state.Routes = routes
	if err := domain.ValidateState(state); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 8 {
		t.Fatalf("got %d routes", len(routes))
	}
	credentials, err := domain.ReferencedCredentials(GitHubRoutes())
	if err != nil || len(credentials) != 1 || credentials[0] != "github" {
		t.Fatalf("GitHub credentials=%v err=%v", credentials, err)
	}
	keys, err := domain.ReferencedKeys(GitHubRoutes())
	if err != nil || len(keys) != 0 {
		t.Fatalf("GitHub static keys=%v err=%v", keys, err)
	}
}

func TestReplaceOwnedPreservesOperatorRoutes(t *testing.T) {
	existing := []domain.Route{{Name: "github-old"}, {Name: "mine"}}
	generated := []domain.Route{{Name: "github-new"}}
	got := ReplaceOwned(existing, generated, OwnsGitHub)
	if len(got) != 2 || got[0].Name != "github-new" || got[1].Name != "mine" {
		t.Fatalf("%+v", got)
	}
}
