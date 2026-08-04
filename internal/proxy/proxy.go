// Package proxy is agentbox's data plane. It serves the same HTTP handler on
// one host-side Unix socket per container; the socket on which a request
// arrives is the container's unforgeable identity.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
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

const (
	defaultMaxConnections          = 128
	maxTransformedRequestBodyBytes = 64 << 20
)

type Server struct {
	Snapshots SnapshotSource
	Materials domain.Resolver
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
		if route.RequestJSON != nil {
			if transformErr := transformJSONRequest(r, *route.RequestJSON, maxTransformedRequestBodyBytes); transformErr != nil {
				status = transformErr.status
				http.Error(w, transformErr.message, status)
				return
			}
		}

		headers := make(http.Header, len(route.Headers))
		for _, h := range route.Headers {
			value, err := h.Template.Render(r.Context(), containerName, s.Materials)
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
				if route.DropQuery {
					pr.Out.URL.RawQuery = ""
				}
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

type requestTransformError struct {
	status  int
	message string
}

func transformJSONRequest(r *http.Request, transform domain.JSONTransform, maxBytes int64) *requestTransformError {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json")) {
		return &requestTransformError{status: http.StatusUnsupportedMediaType, message: "route requires a JSON request body"}
	}
	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return &requestTransformError{status: http.StatusUnsupportedMediaType, message: "route cannot transform an encoded request body"}
	}
	if r.Body == nil || r.Body == http.NoBody {
		return &requestTransformError{status: http.StatusBadRequest, message: "route requires a JSON request body"}
	}

	original := r.Body
	data, err := io.ReadAll(io.LimitReader(original, maxBytes+1))
	_ = original.Close()
	if err != nil {
		return &requestTransformError{status: http.StatusBadRequest, message: "could not read JSON request body"}
	}
	if int64(len(data)) > maxBytes {
		return &requestTransformError{status: http.StatusRequestEntityTooLarge, message: "JSON request body exceeds route transform limit"}
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return &requestTransformError{status: http.StatusBadRequest, message: "route requires a JSON object request body"}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return &requestTransformError{status: http.StatusBadRequest, message: "route requires one JSON object request body"}
	}

	for _, operation := range transform.JoinStringArrays {
		raw, ok := object[operation.Field]
		if !ok {
			if operation.Optional {
				continue
			}
			return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q is required", operation.Field)}
		}
		var elements []json.RawMessage
		if err := json.Unmarshal(raw, &elements); err != nil || elements == nil {
			return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q must be an array", operation.Field)}
		}
		parts := make([]string, 0, len(elements))
		for _, element := range elements {
			var item map[string]json.RawMessage
			if err := json.Unmarshal(element, &item); err != nil || item == nil {
				return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q must contain objects", operation.Field)}
			}
			rawValue, ok := item[operation.ElementField]
			if !ok {
				return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("objects in JSON request field %q require string field %q", operation.Field, operation.ElementField)}
			}
			var value string
			if err := json.Unmarshal(rawValue, &value); err != nil {
				return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("objects in JSON request field %q require string field %q", operation.Field, operation.ElementField)}
			}
			parts = append(parts, value)
		}
		joined, err := json.Marshal(strings.Join(parts, operation.Separator))
		if err != nil {
			return &requestTransformError{status: http.StatusBadRequest, message: "could not transform JSON request body"}
		}
		object[operation.Field] = joined
	}

	for _, operation := range transform.HoistArrayObjectStrings {
		raw, ok := object[operation.SourceField]
		if !ok {
			return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q is required", operation.SourceField)}
		}
		var elements []json.RawMessage
		if err := json.Unmarshal(raw, &elements); err != nil || elements == nil {
			return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q must be an array", operation.SourceField)}
		}
		remaining := make([]json.RawMessage, 0, len(elements))
		var hoisted []string
		for _, element := range elements {
			var item map[string]json.RawMessage
			if err := json.Unmarshal(element, &item); err != nil || item == nil {
				return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q must contain objects", operation.SourceField)}
			}
			rawMatch, ok := item[operation.MatchField]
			if !ok {
				return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("objects in JSON request field %q require string field %q", operation.SourceField, operation.MatchField)}
			}
			var match string
			if err := json.Unmarshal(rawMatch, &match); err != nil {
				return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("objects in JSON request field %q require string field %q", operation.SourceField, operation.MatchField)}
			}
			if match != operation.MatchValue {
				remaining = append(remaining, element)
				continue
			}
			rawValue, ok := item[operation.ValueField]
			if !ok {
				return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("matching objects in JSON request field %q require field %q", operation.SourceField, operation.ValueField)}
			}
			parts, err := jsonStringOrObjectArray(rawValue, operation.ElementField)
			if err != nil {
				return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("field %q in matching objects in JSON request field %q must be a string or an array of objects with string field %q", operation.ValueField, operation.SourceField, operation.ElementField)}
			}
			hoisted = append(hoisted, parts...)
		}
		encodedRemaining, err := json.Marshal(remaining)
		if err != nil {
			return &requestTransformError{status: http.StatusBadRequest, message: "could not transform JSON request body"}
		}
		object[operation.SourceField] = encodedRemaining
		if len(hoisted) != 0 {
			var target string
			if rawTarget, exists := object[operation.TargetField]; exists {
				if err := json.Unmarshal(rawTarget, &target); err != nil {
					return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q must be a string", operation.TargetField)}
				}
			}
			if target != "" {
				target += operation.Separator
			}
			target += strings.Join(hoisted, operation.Separator)
			encodedTarget, err := json.Marshal(target)
			if err != nil {
				return &requestTransformError{status: http.StatusBadRequest, message: "could not transform JSON request body"}
			}
			object[operation.TargetField] = encodedTarget
		}
	}

	for _, operation := range transform.StringPrefixes {
		raw, ok := object[operation.Field]
		if !ok {
			return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q is required", operation.Field)}
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return &requestTransformError{status: http.StatusBadRequest, message: fmt.Sprintf("JSON request field %q must be a string", operation.Field)}
		}
		if !strings.HasPrefix(value, operation.Prefix) {
			value = operation.Prefix + value
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return &requestTransformError{status: http.StatusBadRequest, message: "could not transform JSON request body"}
		}
		object[operation.Field] = encoded
	}
	for _, field := range transform.RemoveFields {
		delete(object, field)
	}

	rewritten, err := json.Marshal(object)
	if err != nil {
		return &requestTransformError{status: http.StatusBadRequest, message: "could not transform JSON request body"}
	}
	if int64(len(rewritten)) > maxBytes {
		return &requestTransformError{status: http.StatusRequestEntityTooLarge, message: "transformed JSON request body exceeds route transform limit"}
	}
	r.Body = io.NopCloser(bytes.NewReader(rewritten))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(rewritten)), nil }
	r.ContentLength = int64(len(rewritten))
	r.TransferEncoding = nil
	r.Trailer = nil
	r.Header.Set("Content-Length", fmt.Sprint(len(rewritten)))
	r.Header.Del("Content-Encoding")
	return nil
}

func jsonStringOrObjectArray(raw json.RawMessage, elementField string) ([]string, error) {
	var direct string
	if err := json.Unmarshal(raw, &direct); err == nil {
		return []string{direct}, nil
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil || elements == nil {
		return nil, errors.New("not a string or array")
	}
	parts := make([]string, 0, len(elements))
	for _, element := range elements {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(element, &item); err != nil || item == nil {
			return nil, errors.New("array element is not an object")
		}
		rawValue, ok := item[elementField]
		if !ok {
			return nil, errors.New("array element field is missing")
		}
		var value string
		if err := json.Unmarshal(rawValue, &value); err != nil {
			return nil, errors.New("array element field is not a string")
		}
		parts = append(parts, value)
	}
	return parts, nil
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
	Proxy:                  nil,
	DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:      true,
	TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	MaxIdleConns:           100,
	MaxIdleConnsPerHost:    32,
	MaxConnsPerHost:        256,
	IdleConnTimeout:        90 * time.Second,
	TLSHandshakeTimeout:    10 * time.Second,
	ResponseHeaderTimeout:  30 * time.Second,
	ExpectContinueTimeout:  time.Second,
	MaxResponseHeaderBytes: 1 << 20,
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
	Dir            string
	Proxy          *Server
	Log            *slog.Logger
	MaxConnections int
	mu             sync.Mutex
	active         map[string]*listener
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
	maxConnections := m.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	if maxConnections < 0 {
		ln.Close()
		return errors.New("max connections must not be negative")
	}
	if maxConnections > 0 {
		ln = newLimitListener(ln, maxConnections)
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

type limitListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newLimitListener(listener net.Listener, max int) net.Listener {
	return &limitListener{Listener: listener, slots: make(chan struct{}, max), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: connection, release: func() { <-l.slots }}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
