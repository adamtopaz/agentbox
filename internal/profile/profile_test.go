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
	if len(routes) != 10 {
		t.Fatalf("got %d routes", len(routes))
	}
	var unified *domain.Route
	for i := range cloudflare {
		if cloudflare[i].Name == "cloudflare-u-prod" {
			unified = &cloudflare[i]
			break
		}
	}
	if unified == nil {
		t.Fatal("prod unified Anthropic route is missing")
	}
	if unified.Match.PathPrefix != "/cloudflare/prod/anthropic" || unified.Upstream != "https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/ai/v1" {
		t.Fatalf("unexpected unified route: %+v", unified)
	}
	if !unified.DropQuery {
		t.Fatal("unified route preserves unsupported query parameters")
	}
	if unified.RequestJSON == nil || len(unified.RequestJSON.JoinStringArrays) != 1 || unified.RequestJSON.JoinStringArrays[0] != (domain.JSONArrayStringJoin{Field: "system", ElementField: "text", Separator: "\n\n", Optional: true}) || len(unified.RequestJSON.HoistArrayObjectStrings) != 1 || unified.RequestJSON.HoistArrayObjectStrings[0] != (domain.JSONArrayObjectStringHoist{SourceField: "messages", MatchField: "role", MatchValue: "system", ValueField: "content", ElementField: "text", TargetField: "system", Separator: "\n\n"}) || len(unified.RequestJSON.StringPrefixes) != 1 || unified.RequestJSON.StringPrefixes[0] != (domain.JSONStringPrefix{Field: "model", Prefix: "anthropic/"}) || len(unified.RequestJSON.RemoveFields) != 1 || unified.RequestJSON.RemoveFields[0] != "context_management" {
		t.Fatalf("unexpected unified request transform: %+v", unified.RequestJSON)
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
