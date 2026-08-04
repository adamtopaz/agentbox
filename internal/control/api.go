// Package control adapts the typed application service to a versioned HTTP
// API. The handler itself is transport-neutral; production serves it on a
// permission-protected Unix socket.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agentbox/internal/app"
	"agentbox/internal/domain"
)

const maxBody = 1 << 20

type Service interface {
	Health(context.Context) app.Health
	Routes(context.Context) []domain.Route
	PutRoute(context.Context, domain.Route) error
	ReplaceRoutes(context.Context, []domain.Route) error
	DeleteRoute(context.Context, string) error
	Keys(context.Context) []domain.KeyInfo
	SetKey(context.Context, string, []byte) error
	DeleteKey(context.Context, string) error
	Containers(context.Context) []domain.Container
	AddContainer(context.Context, domain.Container) (domain.Container, error)
	SetContainerBlocked(context.Context, string, bool) error
	DeleteContainer(context.Context, string) error
}

type API struct {
	Service Service
	Log     *slog.Logger
}

func (a API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.Service.Health(r.Context()))
	})
	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.Service.Routes(r.Context()))
	})
	mux.HandleFunc("PUT /v1/routes", a.replaceRoutes)
	mux.HandleFunc("PUT /v1/routes/{name}", a.putRoute)
	mux.HandleFunc("DELETE /v1/routes/{name}", a.deleteRoute)
	mux.HandleFunc("GET /v1/keys", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, a.Service.Keys(r.Context())) })
	mux.HandleFunc("PUT /v1/keys/{name}", a.putKey)
	mux.HandleFunc("DELETE /v1/keys/{name}", a.deleteKey)
	mux.HandleFunc("GET /v1/containers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.Service.Containers(r.Context()))
	})
	mux.HandleFunc("POST /v1/containers", a.addContainer)
	mux.HandleFunc("PATCH /v1/containers/{name}", a.patchContainer)
	mux.HandleFunc("DELETE /v1/containers/{name}", a.deleteContainer)
	return a.logRequests(mux)
}

func (a API) replaceRoutes(w http.ResponseWriter, r *http.Request) {
	var routes []domain.Route
	if !decodeJSON(w, r, &routes) {
		return
	}
	if err := a.Service.ReplaceRoutes(r.Context(), routes); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a API) putRoute(w http.ResponseWriter, r *http.Request) {
	var route domain.Route
	if !decodeJSON(w, r, &route) {
		return
	}
	if route.Name != r.PathValue("name") {
		writeErrorStatus(w, http.StatusBadRequest, "route name must match URL")
		return
	}
	if err := a.Service.PutRoute(r.Context(), route); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a API) deleteRoute(w http.ResponseWriter, r *http.Request) {
	if err := a.Service.DeleteRoute(r.Context(), r.PathValue("name")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a API) putKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	value, err := io.ReadAll(r.Body)
	if err != nil {
		writeErrorStatus(w, http.StatusBadRequest, "read key: "+err.Error())
		return
	}
	defer clear(value)
	if err := a.Service.SetKey(r.Context(), r.PathValue("name"), value); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a API) deleteKey(w http.ResponseWriter, r *http.Request) {
	if err := a.Service.DeleteKey(r.Context(), r.PathValue("name")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a API) addContainer(w http.ResponseWriter, r *http.Request) {
	var container domain.Container
	if !decodeJSON(w, r, &container) {
		return
	}
	created, err := a.Service.AddContainer(r.Context(), container)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (a API) patchContainer(w http.ResponseWriter, r *http.Request) {
	var patch struct {
		Blocked *bool `json:"blocked"`
	}
	if !decodeJSON(w, r, &patch) {
		return
	}
	if patch.Blocked == nil {
		writeErrorStatus(w, http.StatusBadRequest, "blocked is required")
		return
	}
	if err := a.Service.SetContainerBlocked(r.Context(), r.PathValue("name"), *patch.Blocked); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a API) deleteContainer(w http.ResponseWriter, r *http.Request) {
	if err := a.Service.DeleteContainer(r.Context(), r.PathValue("name")); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a API) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		peer, _ := r.Context().Value(peerKey{}).(Peer)
		next.ServeHTTP(w, r)
		a.logger().Info("control request", "method", r.Method, "path", r.URL.Path,
			"peer_uid", peer.UID, "peer_gid", peer.GID, "peer_pid", peer.PID,
			"duration_ms", time.Since(started).Milliseconds())
	})
}

func (a API) logger() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErrorStatus(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeErrorStatus(w, http.StatusBadRequest, "trailing JSON data")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, app.ErrNotFound) {
		status = http.StatusNotFound
	}
	if errors.Is(err, app.ErrConflict) {
		status = http.StatusConflict
	}
	writeErrorStatus(w, status, err.Error())
}

func writeErrorStatus(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

type Peer struct {
	UID, GID uint32
	PID      int32
}
type peerKey struct{}

type Server struct {
	Socket   string
	Handler  http.Handler
	Log      *slog.Logger
	server   *http.Server
	listener net.Listener
}

func (s *Server) Start() error {
	if s.Socket == "" || !filepath.IsAbs(s.Socket) {
		return fmt.Errorf("control socket must be absolute, got %q", s.Socket)
	}
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0o750); err != nil {
		return err
	}
	if info, err := os.Lstat(s.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket path %s", s.Socket)
		}
		if err := os.Remove(s.Socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", s.Socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.Socket, 0o660); err != nil {
		ln.Close()
		return err
	}
	s.listener = ln
	s.server = &http.Server{
		Handler: s.Handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if peer, err := peerCredentials(conn); err == nil {
				return context.WithValue(ctx, peerKey{}, peer)
			}
			return ctx
		},
	}
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.logger().Error("control server failed", "err", err)
		}
	}()
	return nil
}

func (s *Server) Close(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	return err
}

func (s *Server) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// APIError is returned by Client for a non-2xx control response.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("control API: %s (%d)", e.Message, e.Status) }

type Client struct {
	socket string
	http   *http.Client
}

func NewClient(socket string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	return &Client{socket: socket, http: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
}

func (c *Client) Health(ctx context.Context) (app.Health, error) {
	var out app.Health
	err := c.json(ctx, http.MethodGet, "/v1/health", nil, &out)
	return out, err
}
func (c *Client) Routes(ctx context.Context) ([]domain.Route, error) {
	var out []domain.Route
	err := c.json(ctx, http.MethodGet, "/v1/routes", nil, &out)
	return out, err
}
func (c *Client) ReplaceRoutes(ctx context.Context, routes []domain.Route) error {
	return c.json(ctx, http.MethodPut, "/v1/routes", routes, nil)
}
func (c *Client) PutRoute(ctx context.Context, route domain.Route) error {
	return c.json(ctx, http.MethodPut, "/v1/routes/"+route.Name, route, nil)
}
func (c *Client) DeleteRoute(ctx context.Context, name string) error {
	return c.json(ctx, http.MethodDelete, "/v1/routes/"+name, nil, nil)
}
func (c *Client) Keys(ctx context.Context) ([]domain.KeyInfo, error) {
	var out []domain.KeyInfo
	err := c.json(ctx, http.MethodGet, "/v1/keys", nil, &out)
	return out, err
}
func (c *Client) SetKey(ctx context.Context, name string, value []byte) error {
	return c.request(ctx, http.MethodPut, "/v1/keys/"+name, "application/octet-stream", bytes.NewReader(value), nil)
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
func (c *Client) DeleteKey(ctx context.Context, name string) error {
	return c.json(ctx, http.MethodDelete, "/v1/keys/"+name, nil, nil)
}
func (c *Client) Containers(ctx context.Context) ([]domain.Container, error) {
	var out []domain.Container
	err := c.json(ctx, http.MethodGet, "/v1/containers", nil, &out)
	return out, err
}
func (c *Client) AddContainer(ctx context.Context, value domain.Container) (domain.Container, error) {
	var created domain.Container
	err := c.json(ctx, http.MethodPost, "/v1/containers", value, &created)
	return created, err
}
func (c *Client) SetContainerBlocked(ctx context.Context, name string, blocked bool) error {
	return c.json(ctx, http.MethodPatch, "/v1/containers/"+name, map[string]bool{"blocked": blocked}, nil)
}
func (c *Client) DeleteContainer(ctx context.Context, name string) error {
	return c.json(ctx, http.MethodDelete, "/v1/containers/"+name, nil, nil)
}

func (c *Client) json(ctx context.Context, method, path string, body, dst any) error {
	var reader io.Reader
	if body != nil {
		var b strings.Builder
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			return err
		}
		reader = strings.NewReader(b.String())
	}
	return c.request(ctx, method, path, "application/json", reader, dst)
}

func (c *Client) request(ctx context.Context, method, path, contentType string, body io.Reader, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://agentbox"+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&payload)
		if payload.Error == "" {
			payload.Error = resp.Status
		}
		return &APIError{Status: resp.StatusCode, Message: payload.Error}
	}
	if dst != nil {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return err
		}
	}
	return nil
}
