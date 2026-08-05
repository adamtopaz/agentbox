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
	StateVersion = 3
)

var (
	nameRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	profileRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}$`)
	keyRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	hostRE      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	headerRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	basicUserRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Route describes one reverse-proxy rule. It is profile-neutral; ownership
// comes from the Profile containing it.
type Route struct {
	Name        string        `json:"name"`
	Match       Match         `json:"match"`
	Upstream    string        `json:"upstream"`
	StripPrefix bool          `json:"strip_prefix,omitempty"`
	SetHeaders  []HeaderValue `json:"set_headers,omitempty"`
}

// Match selects either an exact Host or a path prefix. Exactly one is set.
type Match struct {
	Host       string `json:"host,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

// HeaderValue sets a request header after agent-supplied credentials have
// been stripped. Templates may reference durable secrets or credentials
// resolved for the container on whose listener the request arrived.
type HeaderValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Profile is a reusable container policy. Routes remain the generic data-plane
// primitive, Credentials bind logical renewable credentials to sources, and
// Environment contains only public container-side configuration.
type Profile struct {
	Name        string            `json:"name"`
	Routes      []Route           `json:"routes"`
	Credentials map[string]string `json:"credentials"`
	Environment map[string]string `json:"environment"`
}

type Container struct {
	Name      string    `json:"name"`
	Profile   string    `json:"profile"`
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

// CredentialGrant is the version-1/version-2 persistence shape retained only
// for migration into profile credential bindings.
type CredentialGrant struct {
	Container  string `json:"container"`
	Credential string `json:"credential"`
	Source     string `json:"source"`
}

type State struct {
	Version           int                `json:"version"`
	Profiles          []Profile          `json:"profiles"`
	Containers        []Container        `json:"containers"`
	CredentialSources []CredentialSource `json:"credential_sources"`
}

type KeyInfo struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewState() State {
	return State{Version: StateVersion, Profiles: []Profile{}, Containers: []Container{},
		CredentialSources: []CredentialSource{}}
}

func ValidName(s string) bool        { return nameRE.MatchString(s) }
func ValidProfileName(s string) bool { return profileRE.MatchString(s) }
func ValidKeyName(s string) bool     { return keyRE.MatchString(s) }

func ValidateState(s State) error {
	if s.Version != StateVersion {
		return fmt.Errorf("unsupported state version %d (want %d)", s.Version, StateVersion)
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
	profiles := map[string]bool{}
	for i, profile := range s.Profiles {
		if err := ValidateProfile(profile); err != nil {
			return fmt.Errorf("profile %d: %w", i, err)
		}
		if profiles[profile.Name] {
			return fmt.Errorf("duplicate profile name %q", profile.Name)
		}
		profiles[profile.Name] = true
		for credential, source := range profile.Credentials {
			if !sources[source] {
				return fmt.Errorf("profile %q credential %q: unknown source %q", profile.Name, credential, source)
			}
		}
	}
	containers := map[string]bool{}
	for i, c := range s.Containers {
		if err := ValidateContainer(c); err != nil {
			return fmt.Errorf("container %d: %w", i, err)
		}
		if containers[c.Name] {
			return fmt.Errorf("duplicate container name %q", c.Name)
		}
		if !profiles[c.Profile] {
			return fmt.Errorf("container %d: unknown profile %q", i, c.Profile)
		}
		containers[c.Name] = true
	}
	return nil
}

func ValidateProfile(profile Profile) error {
	if !ValidProfileName(profile.Name) {
		return fmt.Errorf("invalid name %q (want a lowercase slug, max 50 characters)", profile.Name)
	}
	routeNames := map[string]bool{}
	selectors := map[string]bool{}
	for i, route := range profile.Routes {
		if err := ValidateRoute(route); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
		if routeNames[route.Name] {
			return fmt.Errorf("duplicate route name %q", route.Name)
		}
		routeNames[route.Name] = true
		selector := route.Match.selector()
		if selectors[selector] {
			return fmt.Errorf("duplicate selector %q", selector)
		}
		selectors[selector] = true
	}
	for credential, source := range profile.Credentials {
		if !ValidName(credential) {
			return fmt.Errorf("invalid credential %q", credential)
		}
		if !ValidName(source) {
			return fmt.Errorf("invalid source %q for credential %q", source, credential)
		}
	}
	for name, value := range profile.Environment {
		if !validEnvironmentName(name) {
			return fmt.Errorf("invalid environment name %q", name)
		}
		if value == "" || len(value) > 64<<10 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("environment %q must be a non-empty single-line value no larger than 65536 bytes", name)
		}
	}
	return nil
}

func validEnvironmentName(name string) bool {
	if name == "" || !((name[0] >= 'A' && name[0] <= 'Z') || name[0] == '_') {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !((name[i] >= 'A' && name[i] <= 'Z') || (name[i] >= '0' && name[i] <= '9') || name[i] == '_') {
			return false
		}
	}
	return true
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
	if !ValidProfileName(c.Profile) {
		return fmt.Errorf("invalid profile %q", c.Profile)
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
	if (r.Match.Host == "") == (r.Match.PathPrefix == "") {
		return errors.New("match must set exactly one of host or path_prefix")
	}
	if r.Match.Host != "" {
		if r.StripPrefix {
			return errors.New("strip_prefix is only valid for path-prefix routes")
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
	for i := range s.Profiles {
		for j := range s.Profiles[i].Routes {
			route := &s.Profiles[i].Routes[j]
			route.Match.Host = strings.ToLower(route.Match.Host)
			route.Upstream = strings.TrimSuffix(route.Upstream, "/")
			sort.Slice(route.SetHeaders, func(a, b int) bool {
				return strings.ToLower(route.SetHeaders[a].Name) < strings.ToLower(route.SetHeaders[b].Name)
			})
		}
		sort.Slice(s.Profiles[i].Routes, func(a, b int) bool { return s.Profiles[i].Routes[a].Name < s.Profiles[i].Routes[b].Name })
	}
	sort.Slice(s.Profiles, func(i, j int) bool { return s.Profiles[i].Name < s.Profiles[j].Name })
	sort.Slice(s.Containers, func(i, j int) bool { return s.Containers[i].Name < s.Containers[j].Name })
	sort.Slice(s.CredentialSources, func(i, j int) bool { return s.CredentialSources[i].Name < s.CredentialSources[j].Name })
	return s
}

// CloneState makes a deep copy suitable for mutation while another goroutine
// continues serving an older immutable snapshot.
func CloneState(s State) State {
	out := State{Version: s.Version}
	out.Containers = append([]Container(nil), s.Containers...)
	out.Profiles = make([]Profile, len(s.Profiles))
	for i, profile := range s.Profiles {
		out.Profiles[i] = profile
		out.Profiles[i].Credentials = cloneMap(profile.Credentials)
		out.Profiles[i].Environment = cloneMap(profile.Environment)
		out.Profiles[i].Routes = make([]Route, len(profile.Routes))
		for j, route := range profile.Routes {
			out.Profiles[i].Routes[j] = route
			out.Profiles[i].Routes[j].SetHeaders = append([]HeaderValue(nil), route.SetHeaders...)
		}
	}
	out.CredentialSources = make([]CredentialSource, len(s.CredentialSources))
	for i, source := range s.CredentialSources {
		out.CredentialSources[i] = source
		out.CredentialSources[i].Parameters = cloneMap(source.Parameters)
		out.CredentialSources[i].Secrets = cloneMap(source.Secrets)
	}
	if out.Profiles == nil {
		out.Profiles = []Profile{}
	}
	if out.Containers == nil {
		out.Containers = []Container{}
	}
	if out.CredentialSources == nil {
		out.CredentialSources = []CredentialSource{}
	}
	return out
}

// AllRoutes returns a detached flat view of the routes contained by profiles.
func AllRoutes(state State) []Route {
	var routes []Route
	for _, profile := range state.Profiles {
		for _, route := range profile.Routes {
			copy := route
			copy.SetHeaders = append([]HeaderValue(nil), route.SetHeaders...)
			routes = append(routes, copy)
		}
	}
	return routes
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
