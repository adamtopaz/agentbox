package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"agentbox/internal/credential"
	"agentbox/internal/domain"
	"agentbox/internal/secret"
	"agentbox/internal/state"
)

type listenerFake struct {
	fail bool
	seen []domain.Container
}

type credentialProviderFake struct{ calls int }

func (p *credentialProviderFake) Name() string { return "fake" }
func (p *credentialProviderFake) Validate(source domain.CredentialSource) error {
	if source.Provider != p.Name() {
		return errors.New("wrong provider")
	}
	return nil
}
func (p *credentialProviderFake) Issue(_ context.Context, _ domain.CredentialSource, _ credential.SecretResolver) (credential.Lease, error) {
	p.calls++
	return credential.Lease{Value: []byte("leased"), ExpiresAt: time.Now().Add(time.Hour)}, nil
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

func TestCredentialSourceGrantLifecycle(t *testing.T) {
	service, store := testService(t)
	ctx := context.Background()
	if _, err := service.AddContainer(ctx, domain.Container{Name: "dev", Scope: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := service.SetKey(ctx, "app-key", []byte("private")); err != nil {
		t.Fatal(err)
	}
	source := domain.CredentialSource{
		Name: "github-prod", Provider: "github-app",
		Parameters: map[string]string{"client-id": "Iv1.example", "installation-id": "123"},
		Secrets:    map[string]string{"private-key": "app-key"},
	}
	if err := service.PutCredentialSource(ctx, source); err != nil {
		t.Fatal(err)
	}
	grant := domain.CredentialGrant{Container: "dev", Credential: "github", Source: "github-prod"}
	if err := service.PutCredentialGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	health := service.Health(ctx)
	if health.CredentialSources != 1 || health.CredentialGrants != 1 {
		t.Fatalf("health=%+v", health)
	}
	if err := service.DeleteKey(ctx, "app-key"); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete referenced key=%v", err)
	}
	if err := service.DeleteCredentialSource(ctx, "github-prod"); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete granted source=%v", err)
	}
	if err := service.DeleteContainer(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	if len(service.CredentialGrants(ctx)) != 0 {
		t.Fatal("container deletion left a credential grant")
	}
	if err := service.DeleteCredentialSource(ctx, "github-prod"); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.CredentialSources) != 0 || len(loaded.CredentialGrants) != 0 {
		t.Fatalf("persisted state=%+v", loaded)
	}
}

func TestServiceResolvesContainerCredential(t *testing.T) {
	dir := t.TempDir()
	keys, err := secret.Open(filepath.Join(dir, "keys"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	provider := &credentialProviderFake{}
	service, err := OpenWithProviders(state.Store{Path: filepath.Join(dir, "state.json")}, keys, []credential.Provider{provider}, credential.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	ctx := context.Background()
	if _, err := service.AddContainer(ctx, domain.Container{Name: "dev", Scope: "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := service.PutCredentialSource(ctx, domain.CredentialSource{Name: "source", Provider: "fake", Parameters: map[string]string{}, Secrets: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if err := service.PutCredentialGrant(ctx, domain.CredentialGrant{Container: "dev", Credential: "api", Source: "source"}); err != nil {
		t.Fatal(err)
	}
	value, err := service.Resolve(ctx, "dev", domain.MaterialReference{Kind: domain.MaterialCredential, Name: "api"})
	if err != nil || string(value) != "leased" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	if _, err := service.Resolve(ctx, "other", domain.MaterialReference{Kind: domain.MaterialCredential, Name: "api"}); err == nil {
		t.Fatal("ungranted principal resolved credential")
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls=%d", provider.calls)
	}
}

func TestInvalidProviderConfigurationDoesNotCommit(t *testing.T) {
	service, store := testService(t)
	err := service.PutCredentialSource(context.Background(), domain.CredentialSource{Name: "bad", Provider: "unknown", Parameters: map[string]string{}, Secrets: map[string]string{}})
	if err == nil {
		t.Fatal("unknown provider committed")
	}
	loaded, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(loaded.CredentialSources) != 0 {
		t.Fatalf("state changed: %+v", loaded.CredentialSources)
	}
}
