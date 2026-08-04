// Package proxy is agentbox's data plane. It serves the same HTTP handler on
// one host-side Unix socket per container; the socket on which a request
// arrives is the container's unforgeable identity.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"agentbox/internal/domain"
	"agentbox/internal/engine"
)

type SnapshotSource interface{ Snapshot() *engine.Snapshot }

type Server struct {
	Snapshots SnapshotSource
	Secrets   domain.Resolver
	Transport http.RoundTripper
	Log       *slog.Logger
}

func (s *Server) Handler(containerName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		status := http.StatusOK
		routeName := "-"
		defer func() {
			s.logger().Info("proxy request", "container", containerName, "route", routeName,
				"method", r.Method, "status", status, "duration_ms", time.Since(started).Milliseconds())
		}()

		snapshot := s.Snapshots.Snapshot()
		container, ok := snapshot.Container(containerName)
		if !ok {
			status = http.StatusNotFound
			http.Error(w, "unknown container", status)
			return
		}
		if container.Blocked {
			status = http.StatusForbidden
			http.Error(w, "container blocked", status)
			return
		}
		if !safeRequestPath(r) {
			status = http.StatusNotFound
			http.Error(w, "unknown route", status)
			return
		}

		route, routedPath, ok := snapshot.Match(container.Scope, domain.Hostname(r.Host), r.URL.Path)
		if !ok {
			status = http.StatusNotFound
			http.Error(w, "unknown route", status)
			return
		}
		routeName = route.Name
		if route.StripPrefix && r.URL.Path == route.Match.PathPrefix {
			location := route.Match.PathPrefix + "/"
			if r.URL.RawQuery != "" {
				location += "?" + r.URL.RawQuery
			}
			status = http.StatusPermanentRedirect
			http.Redirect(w, r, location, status)
			return
		}

		headers := make(http.Header, len(route.Headers))
		for _, h := range route.Headers {
			value, err := h.Template.Render(s.Secrets)
			if err != nil {
				s.logger().Warn("route credential unavailable", "container", containerName, "route", route.Name, "err", err)
				status = http.StatusServiceUnavailable
				http.Error(w, "route credential unavailable", status)
				return
			}
			headers.Set(h.Name, value)
		}

		rp := &httputil.ReverseProxy{
			Transport:     s.transport(),
			FlushInterval: -1,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme = route.Target.Scheme
				pr.Out.URL.Host = route.Target.Host
				pr.Out.URL.Path = joinURLPath(route.Target.Path, routedPath)
				pr.Out.URL.RawPath = ""
				pr.Out.Host = route.Target.Host
				sanitizeRequestHeaders(pr.Out.Header)
				for name, values := range headers {
					pr.Out.Header.Del(name)
					for _, value := range values {
						pr.Out.Header.Add(name, value)
					}
				}
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				status = http.StatusBadGateway
				// Transport errors are deliberately opaque: implementations may
				// include the full request URL (and therefore its query) in Error().
				s.logger().Warn("upstream request failed", "container", containerName, "route", route.Name)
				http.Error(w, "upstream unavailable", status)
			},
		}
		rw := &statusWriter{ResponseWriter: w}
		rp.ServeHTTP(rw, r)
		if rw.status == 0 {
			status = http.StatusOK
		} else {
			status = rw.status
		}
	})
}

func (s *Server) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) transport() http.RoundTripper {
	if s.Transport != nil {
		return s.Transport
	}
	return defaultTransport
}

var defaultTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: time.Second,
}

func sanitizeRequestHeaders(h http.Header) {
	// These names either carry credentials or let a container forge proxy and
	// gateway controls. Route-provided values are applied only after this pass.
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key",
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Forwarded-Port", "X-Real-Ip", "Cf-Access-Client-Id", "Cf-Access-Client-Secret",
	} {
		h.Del(name)
	}
	for name := range h {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "cf-aig-") {
			h.Del(name)
		}
	}
	// A nil value tells ReverseProxy not to synthesize X-Forwarded-For.
	h["X-Forwarded-For"] = nil
}

func safeRequestPath(r *http.Request) bool {
	escaped := strings.ToLower(r.URL.EscapedPath())
	if escaped == "" || escaped[0] != '/' || strings.Contains(r.URL.Path, "\\") || strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, ";") {
		return false
	}
	for _, bad := range []string{"%2e", "%2f", "%5c", "%25"} {
		if strings.Contains(escaped, bad) {
			return false
		}
	}
	for _, segment := range strings.Split(r.URL.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	for _, b := range []byte(r.RequestURI) {
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

func joinURLPath(base, suffix string) string {
	if base == "" {
		if suffix == "" {
			return "/"
		}
		return suffix
	}
	if suffix == "" || suffix == "/" {
		return strings.TrimSuffix(base, "/") + "/"
	}
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(suffix, "/")
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}
func (w *statusWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ListenerManager reconciles the set of per-container Unix HTTP servers.
type ListenerManager struct {
	Dir    string
	Proxy  *Server
	Log    *slog.Logger
	mu     sync.Mutex
	active map[string]*listener
}

type listener struct {
	server *http.Server
	socket net.Listener
}

func (m *ListenerManager) Reconcile(containers []domain.Container) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		m.active = map[string]*listener{}
	}
	if err := os.MkdirAll(m.Dir, 0o750); err != nil {
		return err
	}
	if err := os.Chmod(m.Dir, 0o750); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, c := range containers {
		want[c.Name] = true
		if _, ok := m.active[c.Name]; ok {
			continue
		}
		if err := m.start(c.Name); err != nil {
			return err
		}
	}
	for name, l := range m.active {
		if want[name] {
			continue
		}
		_ = l.server.Close()
		_ = l.socket.Close()
		delete(m.active, name)
	}
	return nil
}

func (m *ListenerManager) start(name string) error {
	path := m.Dir + "/" + name + ".sock"
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{
		Handler:           m.Proxy.Handler(name),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	m.active[name] = &listener{server: srv, socket: ln}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			m.logger().Error("container listener failed", "container", name, "err", err)
		}
	}()
	return nil
}

func (m *ListenerManager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for name, l := range m.active {
		if err := l.server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		_ = l.socket.Close()
		delete(m.active, name)
	}
	return errors.Join(errs...)
}

func (m *ListenerManager) SocketPath(name string) string { return m.Dir + "/" + name + ".sock" }
func (m *ListenerManager) logger() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}
