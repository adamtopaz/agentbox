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

	health, err := client.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.Routes != 1 || health.Keys != 1 || health.Containers != 1 {
		t.Fatalf("unexpected health: %+v", health)
	}
	routes, err := client.Routes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Name != "api" {
		t.Fatalf("unexpected routes: %+v", routes)
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
