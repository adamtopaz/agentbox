package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"agentbox/internal/domain"
	"agentbox/internal/secret"
	"agentbox/internal/state"
)

type listenerFake struct {
	fail bool
	seen []domain.Container
}

func (l *listenerFake) Reconcile(c []domain.Container) error {
	if l.fail {
		return errors.New("listen failed")
	}
	l.seen = append([]domain.Container(nil), c...)
	return nil
}

func testService(t *testing.T) (*Service, state.Store) {
	t.Helper()
	dir := t.TempDir()
	keys, err := secret.Open(filepath.Join(dir, "keys"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := state.Store{Path: filepath.Join(dir, "state.json")}
	service, err := Open(store, keys)
	if err != nil {
		t.Fatal(err)
	}
	return service, store
}

func TestServiceCommitsAndRollsBack(t *testing.T) {
	service, store := testService(t)
	listeners := &listenerFake{}
	if err := service.AttachListeners(listeners); err != nil {
		t.Fatal(err)
	}
	c := domain.Container{Name: "dev", Scope: "prod", CreatedAt: time.Now()}
	if _, err := service.AddContainer(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(listeners.seen) != 1 {
		t.Fatalf("listeners: %v", listeners.seen)
	}
	listeners.fail = true
	if _, err := service.AddContainer(context.Background(), domain.Container{Name: "bad", Scope: "prod", CreatedAt: time.Now()}); err == nil {
		t.Fatal("listener failure accepted")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Containers) != 1 || loaded.Containers[0].Name != "dev" {
		t.Fatalf("rollback failed: %+v", loaded.Containers)
	}
}

func TestDeleteReferencedKeyRefused(t *testing.T) {
	service, _ := testService(t)
	ctx := context.Background()
	if err := service.SetKey(ctx, "token", []byte("value")); err != nil {
		t.Fatal(err)
	}
	route := domain.Route{Name: "api", Scope: "*", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://example.com", SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "{secret:token}"}}}
	if err := service.PutRoute(ctx, route); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteKey(ctx, "token"); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v", err)
	}
}
