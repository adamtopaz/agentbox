package control

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"agentbox/internal/app"
	"agentbox/internal/domain"
	"agentbox/internal/secret"
	"agentbox/internal/state"
)

func TestUnixSocketRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keys, err := secret.Open(filepath.Join(dir, "secrets"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.Open(state.Store{Path: filepath.Join(dir, "state.json")}, keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)

	socket := filepath.Join(dir, "control.sock")
	server := &Server{
		Socket:  socket,
		Handler: API{Service: service, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}.Handler(),
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })

	ctx := context.Background()
	client := NewClient(socket)
	if err := client.SetKey(ctx, "api-token", []byte("not-in-state")); err != nil {
		t.Fatal(err)
	}
	route := domain.Route{
		Name: "api", Scope: "dev", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://example.com",
		SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "Bearer {secret:api-token}"}},
	}
	if err := client.PutRoute(ctx, route); err != nil {
		t.Fatal(err)
	}
	created, err := client.AddContainer(ctx, domain.Container{Name: "work", Scope: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if created.CreatedAt.IsZero() {
		t.Fatal("server did not return its canonical creation timestamp")
	}
	source := domain.CredentialSource{
		Name: "github-test", Provider: "github-app",
		Parameters: map[string]string{"client-id": "Iv1.example", "installation-id": "123"},
		Secrets:    map[string]string{"private-key": "api-token"},
	}
	if err := client.PutCredentialSource(ctx, source); err != nil {
		t.Fatal(err)
	}
	grant := domain.CredentialGrant{Container: "work", Credential: "github", Source: "github-test"}
	if err := client.PutCredentialGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}

	health, err := client.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.Routes != 1 || health.Keys != 1 || health.Containers != 1 || health.CredentialSources != 1 || health.CredentialGrants != 1 {
		t.Fatalf("unexpected health: %+v", health)
	}
	routes, err := client.Routes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Name != "api" {
		t.Fatalf("unexpected routes: %+v", routes)
	}
	sources, err := client.CredentialSources(ctx)
	if err != nil || len(sources) != 1 || sources[0].Name != "github-test" {
		t.Fatalf("sources=%+v err=%v", sources, err)
	}
	grants, err := client.CredentialGrants(ctx)
	if err != nil || len(grants) != 1 || grants[0] != grant {
		t.Fatalf("grants=%+v err=%v", grants, err)
	}
}

func TestControlSocketRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := &Server{Socket: path, Handler: http.NotFoundHandler()}
	if err := server.Start(); err == nil {
		t.Fatal("regular socket path was replaced")
	}
}
