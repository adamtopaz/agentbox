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
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Routes) != 1 || len(loaded.Containers) != 1 {
		t.Fatalf("unexpected state: %+v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}

	if err := os.WriteFile(path, []byte(`{"version":1,"routes":[],"containers":[],"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("unknown state field was accepted")
	}
}
