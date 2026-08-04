// Package domain defines agentbox's transport- and provider-independent model.
// It deliberately contains no Cloudflare, GitHub, Incus, HTTP server, or
// persistence code. Those concerns consume this model through adapters.
package domain

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	StateVersion   = 1
	UniversalScope = "*"
)

var (
	nameRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	scopeRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}$`)
	keyRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	hostRE      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	headerRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	basicUserRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Route describes one reverse-proxy rule. Scope is an arbitrary isolation
// label; a listener sees routes in its own scope plus routes in "*".
type Route struct {
	Name        string        `json:"name"`
	Scope       string        `json:"scope"`
	Match       Match         `json:"match"`
	Upstream    string        `json:"upstream"`
	StripPrefix bool          `json:"strip_prefix,omitempty"`
	PathMap     []PathRewrite `json:"path_map,omitempty"`
	SetHeaders  []HeaderValue `json:"set_headers,omitempty"`
}

// Match selects either an exact Host or a path prefix. Exactly one is set.
type Match struct {
	Host       string `json:"host,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

// PathRewrite maps one exact post-prefix path to a literal target path.
type PathRewrite struct {
	Path string `json:"path"`
	To   string `json:"to"`
}

// HeaderValue sets a request header after agent-supplied credentials have
// been stripped. Templates may reference durable secrets or credentials
// resolved for the container on whose listener the request arrived.
type HeaderValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Container struct {
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	Blocked   bool      `json:"blocked,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// CredentialSource is provider-neutral configuration for an object capable
// of issuing request credentials. Parameters are public configuration;
// Secrets maps provider-defined roles to encrypted key-store entries.
type CredentialSource struct {
	Name       string            `json:"name"`
	Provider   string            `json:"provider"`
	Parameters map[string]string `json:"parameters"`
	Secrets    map[string]string `json:"secrets"`
}

// CredentialGrant binds a logical route credential to one container. The
// per-container proxy listener is the principal: request data can never select
// a different grant.
type CredentialGrant struct {
	Container  string `json:"container"`
	Credential string `json:"credential"`
	Source     string `json:"source"`
}

type State struct {
	Version           int                `json:"version"`
	Routes            []Route            `json:"routes"`
	Containers        []Container        `json:"containers"`
	CredentialSources []CredentialSource `json:"credential_sources"`
	CredentialGrants  []CredentialGrant  `json:"credential_grants"`
}

type KeyInfo struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewState() State {
	return State{Version: StateVersion, Routes: []Route{}, Containers: []Container{},
		CredentialSources: []CredentialSource{}, CredentialGrants: []CredentialGrant{}}
}

func ValidName(s string) bool    { return nameRE.MatchString(s) }
func ValidScope(s string) bool   { return s == UniversalScope || scopeRE.MatchString(s) }
func ValidKeyName(s string) bool { return keyRE.MatchString(s) }

func ValidateState(s State) error {
	if s.Version != StateVersion {
		return fmt.Errorf("unsupported state version %d (want %d)", s.Version, StateVersion)
	}
	routeNames := map[string]bool{}
	selectors := map[string]bool{}
	for i := range s.Routes {
		if err := ValidateRoute(s.Routes[i]); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
		r := s.Routes[i]
		if routeNames[r.Name] {
			return fmt.Errorf("duplicate route name %q", r.Name)
		}
		routeNames[r.Name] = true
		selector := r.Scope + "\x00" + r.Match.selector()
		if selectors[selector] {
			return fmt.Errorf("duplicate selector %q in scope %q", r.Match.selector(), r.Scope)
		}
		selectors[selector] = true
	}
	containers := map[string]bool{}
	for i, c := range s.Containers {
		if err := ValidateContainer(c); err != nil {
			return fmt.Errorf("container %d: %w", i, err)
		}
		if containers[c.Name] {
			return fmt.Errorf("duplicate container name %q", c.Name)
		}
		containers[c.Name] = true
	}
	sources := map[string]bool{}
	for i, source := range s.CredentialSources {
		if err := ValidateCredentialSource(source); err != nil {
			return fmt.Errorf("credential source %d: %w", i, err)
		}
		if sources[source.Name] {
			return fmt.Errorf("duplicate credential source name %q", source.Name)
		}
		sources[source.Name] = true
	}
	grants := map[string]bool{}
	for i, grant := range s.CredentialGrants {
		if err := ValidateCredentialGrant(grant); err != nil {
			return fmt.Errorf("credential grant %d: %w", i, err)
		}
		if !containers[grant.Container] {
			return fmt.Errorf("credential grant %d: unknown container %q", i, grant.Container)
		}
		if !sources[grant.Source] {
			return fmt.Errorf("credential grant %d: unknown source %q", i, grant.Source)
		}
		key := grant.Container + "\x00" + grant.Credential
		if grants[key] {
			return fmt.Errorf("duplicate credential %q for container %q", grant.Credential, grant.Container)
		}
		grants[key] = true
	}
	return nil
}

func ValidateCredentialSource(source CredentialSource) error {
	if !ValidName(source.Name) {
		return fmt.Errorf("invalid name %q (want a lowercase slug, max 63 characters)", source.Name)
	}
	if !ValidName(source.Provider) {
		return fmt.Errorf("invalid provider %q", source.Provider)
	}
	for name, value := range source.Parameters {
		if !ValidKeyName(name) {
			return fmt.Errorf("invalid parameter name %q", name)
		}
		if value == "" {
			return fmt.Errorf("parameter %q must not be empty", name)
		}
		if len(value) > 64<<10 {
			return fmt.Errorf("parameter %q exceeds 65536 bytes", name)
		}
		for _, ch := range []byte(value) {
			if ch < 0x20 || ch > 0x7e {
				return fmt.Errorf("parameter %q contains a non-printable or non-ASCII byte", name)
			}
		}
	}
	for role, key := range source.Secrets {
		if !ValidKeyName(role) {
			return fmt.Errorf("invalid secret role %q", role)
		}
		if !ValidKeyName(key) {
			return fmt.Errorf("invalid key name %q for secret role %q", key, role)
		}
	}
	return nil
}

func ValidateCredentialGrant(grant CredentialGrant) error {
	if !ValidName(grant.Container) {
		return fmt.Errorf("invalid container %q", grant.Container)
	}
	if !ValidName(grant.Credential) {
		return fmt.Errorf("invalid credential %q", grant.Credential)
	}
	if !ValidName(grant.Source) {
		return fmt.Errorf("invalid source %q", grant.Source)
	}
	return nil
}

func ValidateContainer(c Container) error {
	if !ValidName(c.Name) {
		return fmt.Errorf("invalid name %q (want a lowercase slug, max 63 characters)", c.Name)
	}
	if c.Scope == UniversalScope || !ValidScope(c.Scope) {
		return fmt.Errorf("invalid scope %q (containers require one concrete scope)", c.Scope)
	}
	if c.CreatedAt.IsZero() {
		return errors.New("created_at is required")
	}
	return nil
}

func ValidateRoute(r Route) error {
	if !ValidName(r.Name) {
		return fmt.Errorf("invalid name %q (want a lowercase slug, max 63 characters)", r.Name)
	}
	if !ValidScope(r.Scope) {
		return fmt.Errorf("invalid scope %q", r.Scope)
	}
	if (r.Match.Host == "") == (r.Match.PathPrefix == "") {
		return errors.New("match must set exactly one of host or path_prefix")
	}
	if r.Match.Host != "" {
		if r.StripPrefix {
			return errors.New("strip_prefix is only valid for path-prefix routes")
		}
		if len(r.PathMap) != 0 {
			return errors.New("path_map is only valid for path-prefix routes")
		}
		if !hostRE.MatchString(strings.ToLower(r.Match.Host)) || strings.Contains(r.Match.Host, ":") {
			return fmt.Errorf("invalid host %q", r.Match.Host)
		}
	} else if err := validatePath(r.Match.PathPrefix, "path prefix"); err != nil {
		return err
	}

	u, err := url.Parse(r.Upstream)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("upstream must be an absolute http(s) URL without userinfo, query, or fragment, got %q", r.Upstream)
	}
	if u.Path != "" {
		if err := validatePath(u.Path, "upstream path"); err != nil {
			return err
		}
	}

	mapped := map[string]bool{}
	for _, m := range r.PathMap {
		if err := validatePath(m.Path, "path_map path"); err != nil {
			return err
		}
		if err := validatePath(m.To, "path_map target"); err != nil {
			return err
		}
		if mapped[m.Path] {
			return fmt.Errorf("duplicate path_map path %q", m.Path)
		}
		mapped[m.Path] = true
	}
	for _, m := range r.PathMap {
		if mapped[m.To] {
			return fmt.Errorf("path_map target %q is also a source path", m.To)
		}
	}

	headerNames := map[string]bool{}
	hasMaterial := false
	forbiddenHeaders := map[string]bool{
		"connection": true, "proxy-connection": true, "keep-alive": true,
		"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
		"host": true, "content-length": true,
	}
	for _, h := range r.SetHeaders {
		if !headerRE.MatchString(h.Name) {
			return fmt.Errorf("invalid header name %q", h.Name)
		}
		canonical := strings.ToLower(h.Name)
		if forbiddenHeaders[canonical] {
			return fmt.Errorf("header %q is controlled by the HTTP transport and cannot be set by a route", h.Name)
		}
		if headerNames[canonical] {
			return fmt.Errorf("header %q is set more than once", h.Name)
		}
		headerNames[canonical] = true
		template, err := ParseTemplate(h.Value)
		if err != nil {
			return fmt.Errorf("header %q: %w", h.Name, err)
		}
		if len(template.Keys()) != 0 || len(template.Credentials()) != 0 {
			hasMaterial = true
		}
	}
	if u.Scheme == "http" && hasMaterial {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return errors.New("routes that inject secrets or credentials require HTTPS or a literal loopback HTTP upstream")
		}
	}
	return nil
}

func validatePath(p, label string) error {
	if p == "" || p[0] != '/' || strings.ContainsAny(p, "?#\\") || strings.Contains(p, "//") {
		return fmt.Errorf("invalid %s %q (want a clean absolute path)", label, p)
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." || strings.Contains(segment, "%") || strings.Contains(segment, "{") || strings.Contains(segment, "}") {
			return fmt.Errorf("invalid %s %q (escapes, templates, and dot segments are not allowed)", label, p)
		}
	}
	return nil
}

func (m Match) selector() string {
	if m.Host != "" {
		return "host:" + strings.ToLower(m.Host)
	}
	return "path:" + m.PathPrefix
}

// NormalizeState returns a deterministic copy for persistence and API output.
func NormalizeState(s State) State {
	s = CloneState(s)
	for i := range s.Routes {
		s.Routes[i].Match.Host = strings.ToLower(s.Routes[i].Match.Host)
		s.Routes[i].Upstream = strings.TrimSuffix(s.Routes[i].Upstream, "/")
		sort.Slice(s.Routes[i].PathMap, func(a, b int) bool { return s.Routes[i].PathMap[a].Path < s.Routes[i].PathMap[b].Path })
		sort.Slice(s.Routes[i].SetHeaders, func(a, b int) bool {
			return strings.ToLower(s.Routes[i].SetHeaders[a].Name) < strings.ToLower(s.Routes[i].SetHeaders[b].Name)
		})
	}
	sort.Slice(s.Routes, func(i, j int) bool { return s.Routes[i].Name < s.Routes[j].Name })
	sort.Slice(s.Containers, func(i, j int) bool { return s.Containers[i].Name < s.Containers[j].Name })
	sort.Slice(s.CredentialSources, func(i, j int) bool { return s.CredentialSources[i].Name < s.CredentialSources[j].Name })
	sort.Slice(s.CredentialGrants, func(i, j int) bool {
		if s.CredentialGrants[i].Container != s.CredentialGrants[j].Container {
			return s.CredentialGrants[i].Container < s.CredentialGrants[j].Container
		}
		return s.CredentialGrants[i].Credential < s.CredentialGrants[j].Credential
	})
	return s
}

// CloneState makes a deep copy suitable for mutation while another goroutine
// continues serving an older immutable snapshot.
func CloneState(s State) State {
	out := State{Version: s.Version}
	out.Containers = append([]Container(nil), s.Containers...)
	out.Routes = make([]Route, len(s.Routes))
	for i, r := range s.Routes {
		out.Routes[i] = r
		out.Routes[i].PathMap = append([]PathRewrite(nil), r.PathMap...)
		out.Routes[i].SetHeaders = append([]HeaderValue(nil), r.SetHeaders...)
	}
	out.CredentialSources = make([]CredentialSource, len(s.CredentialSources))
	for i, source := range s.CredentialSources {
		out.CredentialSources[i] = source
		out.CredentialSources[i].Parameters = cloneMap(source.Parameters)
		out.CredentialSources[i].Secrets = cloneMap(source.Secrets)
	}
	out.CredentialGrants = append([]CredentialGrant(nil), s.CredentialGrants...)
	if out.Routes == nil {
		out.Routes = []Route{}
	}
	if out.Containers == nil {
		out.Containers = []Container{}
	}
	if out.CredentialSources == nil {
		out.CredentialSources = []CredentialSource{}
	}
	if out.CredentialGrants == nil {
		out.CredentialGrants = []CredentialGrant{}
	}
	return out
}

func cloneMap(source map[string]string) map[string]string {
	if source == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

// Hostname removes an optional port and normalizes a request Host for matching.
func Hostname(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(strings.TrimSuffix(hostport, "."))
}

// ReferencedKeys returns the de-duplicated secret names used by routes.
func ReferencedKeys(routes []Route) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, r := range routes {
		for _, h := range r.SetHeaders {
			t, err := ParseTemplate(h.Value)
			if err != nil {
				return nil, err
			}
			for _, name := range t.Keys() {
				if !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// ReferencedCredentials returns logical credential names used by routes.
func ReferencedCredentials(routes []Route) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, r := range routes {
		for _, h := range r.SetHeaders {
			t, err := ParseTemplate(h.Value)
			if err != nil {
				return nil, err
			}
			for _, name := range t.Credentials() {
				if !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
