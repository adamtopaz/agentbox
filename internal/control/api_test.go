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

	adminSocket := filepath.Join(dir, "admin.sock")
	userSocket := filepath.Join(dir, "user.sock")
	api := API{Service: service, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), AdminUID: uint32(os.Getuid())}
	server := &Server{
		Socket:  adminSocket,
		Handler: api.Handler(),
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	userServer := &Server{Socket: userSocket, Handler: api.UserHandler(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := userServer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = userServer.Close(context.Background()) })

	ctx := context.Background()
	client := NewClient(adminSocket)
	userClient := NewClient(userSocket)
	if err := client.SetKey(ctx, "api-token", []byte("not-in-state")); err != nil {
		t.Fatal(err)
	}
	source := domain.CredentialSource{
		Name: "github-test", Provider: "github-app",
		Parameters: map[string]string{"client-id": "Iv1.example", "installation-id": "123"},
		Secrets:    map[string]string{"private-key": "api-token"},
	}
	if err := client.PutCredentialSource(ctx, source); err != nil {
		t.Fatal(err)
	}
	route := domain.Route{
		Name: "api", Match: domain.Match{PathPrefix: "/api"}, Upstream: "https://example.com",
		SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "Bearer {secret:api-token}"}},
	}
	current := domain.Profile{Name: "dev", Routes: []domain.Route{route}, Credentials: map[string]string{"github": "github-test"}, Environment: map[string]string{"AGENTBOX_PROFILE": "dev"}}
	if err := client.PutProfile(ctx, current); err != nil {
		t.Fatal(err)
	}
	created, err := client.AddContainer(ctx, domain.Container{Name: "work", Profile: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if created.CreatedAt.IsZero() {
		t.Fatal("server did not return its canonical creation timestamp")
	}
	uid := uint32(os.Getuid())
	if err := client.PutProfileGrant(ctx, uid, "dev"); err != nil {
		t.Fatal(err)
	}
	userProfiles, err := userClient.UserProfiles(ctx)
	if err != nil || len(userProfiles) != 1 || userProfiles[0].Name != "dev" || userProfiles[0].Environment["AGENTBOX_PROFILE"] != "dev" {
		t.Fatalf("user profiles=%+v err=%v", userProfiles, err)
	}
	if _, err := userClient.Keys(ctx); err == nil {
		t.Fatal("user API exposed administrator key endpoint")
	}
	host, err := userClient.AddHostSession(ctx, "dev")
	if err != nil || host.CreatedAt.IsZero() {
		t.Fatalf("host session=%+v err=%v", host, err)
	}

	health, err := client.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.Profiles != 1 || health.Routes != 1 || health.Keys != 1 || health.Containers != 1 || health.HostSessions != 1 || health.CredentialSources != 1 || health.CredentialBindings != 1 {
		t.Fatalf("unexpected health: %+v", health)
	}
	if err := userClient.DeleteHostSession(ctx, host.Name); err != nil {
		t.Fatal(err)
	}
	routes, err := client.Routes(ctx, "dev")
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
	profiles, err := client.Profiles(ctx)
	if err != nil || len(profiles) != 1 || profiles[0].Credentials["github"] != "github-test" {
		t.Fatalf("profiles=%+v err=%v", profiles, err)
	}
}

func TestAdministratorAPIRejectsOtherUID(t *testing.T) {
	service, _ := testControlService(t)
	handler := API{Service: service, AdminUID: uint32(os.Getuid()) + 1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}.Handler()
	request, err := http.NewRequest(http.MethodGet, "/v1/keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(context.WithValue(request.Context(), peerKey{}, Peer{UID: uint32(os.Getuid())}))
	response := &responseRecorder{header: http.Header{}}
	handler.ServeHTTP(response, request)
	if response.status != http.StatusForbidden {
		t.Fatalf("status=%d", response.status)
	}
}

type responseRecorder struct {
	header http.Header
	status int
}

func (r *responseRecorder) Header() http.Header    { return r.header }
func (r *responseRecorder) WriteHeader(status int) { r.status = status }
func (r *responseRecorder) Write(value []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(value), nil
}

func testControlService(t *testing.T) (*app.Service, state.Store) {
	t.Helper()
	dir := t.TempDir()
	keys, err := secret.Open(filepath.Join(dir, "secrets"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := state.Store{Path: filepath.Join(dir, "state.json")}
	service, err := app.Open(store, keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return service, store
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
