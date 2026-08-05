package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/domain"
)

func TestStoreRoundTripAndStrictInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := Store{Path: path}
	state := domain.NewState()
	state.CredentialSources = []domain.CredentialSource{{Name: "source", Provider: "provider", Parameters: map[string]string{"public": "value"}, Secrets: map[string]string{"root": "root-key"}}}
	state.Profiles = []domain.Profile{{Name: "prod", Routes: []domain.Route{{Name: "api", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://example.com"}}, Credentials: map[string]string{"api": "source"}, Environment: map[string]string{"AGENTBOX_PROFILE": "prod"}}}
	state.Containers = []domain.Container{{Name: "dev", Profile: "prod", CreatedAt: time.Now()}}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Profiles) != 1 || len(loaded.Profiles[0].Routes) != 1 || len(loaded.Containers) != 1 || len(loaded.CredentialSources) != 1 {
		t.Fatalf("unexpected state: %+v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}

	if err := os.WriteFile(path, []byte(`{"version":3,"profiles":[],"containers":[],"credential_sources":[],"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("unknown state field was accepted")
	}
}

func TestStoreMigratesV2IntoReusableProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	data := `{
		"version": 2,
		"routes": [
			{"name":"cloudflare-prod","scope":"prod","match":{"path_prefix":"/cloudflare/prod"},"upstream":"https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/ff-prod","strip_prefix":true,"set_headers":[{"name":"cf-aig-authorization","value":"Bearer {secret:cf-token}"}]},
			{"name":"github-api","scope":"*","match":{"path_prefix":"/github-api"},"upstream":"https://api.github.com","strip_prefix":true,"set_headers":[{"name":"Authorization","value":"Bearer {credential:github}"}]}
		],
		"containers": [{"name":"dev","scope":"prod","created_at":"2026-08-05T00:00:00Z"}],
		"credential_sources": [{"name":"github-prod","provider":"github-app","parameters":{"installation-id":"1"},"secrets":{"private-key":"app-key"}}],
		"credential_grants": [{"container":"dev","credential":"github","source":"github-prod"}]
	}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := (Store{Path: path}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != domain.StateVersion || len(loaded.Profiles) != 1 || loaded.Profiles[0].Name != "prod" || len(loaded.Profiles[0].Routes) != 2 {
		t.Fatalf("unexpected migrated state: %+v", loaded)
	}
	if loaded.Containers[0].Profile != "prod" || loaded.Profiles[0].Credentials["github"] != "github-prod" {
		t.Fatalf("container/profile binding not migrated: %+v", loaded)
	}
	if loaded.Profiles[0].Environment["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:8787/cloudflare/prod/anthropic" || loaded.Profiles[0].Environment["GH_TOKEN"] != "agentbox-dummy" {
		t.Fatalf("client environment not migrated: %+v", loaded.Profiles[0].Environment)
	}
}

func TestStoreRejectsV2ScopesWithDifferentContainerGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	data := `{"version":2,"routes":[],"containers":[{"name":"one","scope":"prod","created_at":"2026-08-05T00:00:00Z"},{"name":"two","scope":"prod","created_at":"2026-08-05T00:00:00Z"}],"credential_sources":[{"name":"source","provider":"fake","parameters":{},"secrets":{}}],"credential_grants":[{"container":"one","credential":"api","source":"source"}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Path: path}).Load(); err == nil || !strings.Contains(err.Error(), "different credential grants") {
		t.Fatalf("unsafe migration error=%v", err)
	}
}

func TestStoreMigratesV1AndDropsTransformingRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	data := `{
		"version": 1,
		"routes": [
			{"name":"plain","scope":"prod","match":{"path_prefix":"/plain"},"upstream":"https://example.com","strip_prefix":true,"set_headers":[{"name":"Authorization","value":"Bearer {secret:token}"}]},
			{"name":"mapped","scope":"prod","match":{"path_prefix":"/mapped"},"upstream":"https://example.com","path_map":[{"path":"/a","to":"/b"}]},
			{"name":"query","scope":"prod","match":{"path_prefix":"/query"},"upstream":"https://example.com","drop_query":true},
			{"name":"body","scope":"prod","match":{"path_prefix":"/body"},"upstream":"https://example.com","request_json":{"operations":[{"remove_field":{"field":"x"}}]}}
		],
		"containers": [{"name":"dev","scope":"prod","created_at":"2026-08-05T00:00:00Z"}],
		"credential_sources": [],
		"credential_grants": []
	}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := (Store{Path: path}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != domain.StateVersion || len(loaded.Profiles) != 1 || len(loaded.Profiles[0].Routes) != 1 || loaded.Profiles[0].Routes[0].Name != "plain" {
		t.Fatalf("unexpected migrated state: %+v", loaded)
	}
}
