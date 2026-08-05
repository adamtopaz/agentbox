package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"agentbox/internal/domain"
)

func TestStoreRoundTripAndStrictInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := Store{Path: path}
	state := domain.NewState()
	state.Containers = []domain.Container{{Name: "dev", Scope: "prod", CreatedAt: time.Now()}}
	state.Routes = []domain.Route{{Name: "api", Scope: "prod", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://example.com"}}
	state.CredentialSources = []domain.CredentialSource{{Name: "source", Provider: "provider", Parameters: map[string]string{"public": "value"}, Secrets: map[string]string{"root": "root-key"}}}
	state.CredentialGrants = []domain.CredentialGrant{{Container: "dev", Credential: "api", Source: "source"}}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Routes) != 1 || len(loaded.Containers) != 1 || len(loaded.CredentialSources) != 1 || len(loaded.CredentialGrants) != 1 {
		t.Fatalf("unexpected state: %+v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}

	if err := os.WriteFile(path, []byte(`{"version":2,"routes":[],"containers":[],"credential_sources":[],"credential_grants":[],"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("unknown state field was accepted")
	}
}

func TestStoreLoadsStateWithoutCredentialFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	data := `{"version":1,"routes":[],"containers":[]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := (Store{Path: path}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CredentialSources == nil || loaded.CredentialGrants == nil {
		t.Fatalf("credential collections were not normalized: %+v", loaded)
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
	if loaded.Version != domain.StateVersion || len(loaded.Routes) != 1 || loaded.Routes[0].Name != "plain" {
		t.Fatalf("unexpected migrated state: %+v", loaded)
	}
	if len(loaded.Containers) != 1 || loaded.Containers[0].Name != "dev" || len(loaded.Routes[0].SetHeaders) != 1 {
		t.Fatalf("ordinary v1 state was not preserved: %+v", loaded)
	}
}
