package profile

import (
	"testing"

	"agentbox/internal/domain"
)

func TestProfilesAreOrdinaryValidRoutes(t *testing.T) {
	cloudflare, err := CloudflareRoutes("0123456789abcdef0123456789abcdef", []string{"prod", "test"}, "cloudflare-api")
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
	byName := map[string]*domain.Route{}
	for i := range cloudflare {
		byName[cloudflare[i].Name] = &cloudflare[i]
	}
	prod := byName["cloudflare-prod"]
	if prod == nil {
		t.Fatalf("prod provider-native route is missing: %+v", byName)
	}
	wantUpstream := "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/prod"
	if prod.Match.PathPrefix != "/cloudflare/prod" || prod.Upstream != wantUpstream || !prod.StripPrefix {
		t.Fatalf("unexpected provider-native route: %+v", prod)
	}
	if len(prod.SetHeaders) != 1 || prod.SetHeaders[0] != (domain.HeaderValue{
		Name: "cf-aig-authorization", Value: "Bearer {secret:cloudflare-api}",
	}) {
		t.Fatalf("unexpected gateway authentication: %+v", prod.SetHeaders)
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

func TestCloudflareRoutesRequireExplicitValidKeyReference(t *testing.T) {
	for _, privateKey := range []string{"", "Cloudflare-Key", "path/to/key"} {
		if _, err := CloudflareRoutes("0123456789abcdef0123456789abcdef", []string{"prod"}, privateKey); err == nil {
			t.Fatalf("accepted invalid private key reference %q", privateKey)
		}
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
