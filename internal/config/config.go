// Package config loads and validates the agentbox route table
// (/etc/agentbox/routes.json).
//
// The reconcile/render code only ever handles secret *names*; secret values
// are read by Caddy itself via {file.*} placeholders. The one exception is
// `agentbox setup` (root), which reads {basic:USER:NAME} source secrets to
// write the pre-encoded base64 companion files Caddy needs.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Header is one injected (or, in principle, overridden) request header.
type Header struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}

// PathMap rewrites one exact request path to another before proxying, so a
// single base URL can front upstreams that live at different paths.
//
// It exists because clients that take one base URL per provider still append a
// different suffix per API shape. pi, for instance, gives its
// cloudflare-ai-gateway provider a single base URL and then appends
// /v1/messages, /responses or /chat/completions depending on the model — which
// on Cloudflare live under /anthropic, /openai and /compat respectively. The
// suffixes are disjoint, so the segment is recoverable from the path alone.
//
// Path is matched as a whole path — no wildcard, no prefix match — against the
// request path after the route's prefix has been stripped; To replaces it
// (still relative to the upstream's own path). Whole-path rather than pattern
// matching is deliberate: a finite set is enumerable, so what a mapping can
// reach is decidable by reading it.
//
// "Whole path", not "byte-exact": Caddy's `path` matcher is case-insensitive
// and sees the cleaned, percent-decoded path, so /V1/Messages, //v1/messages
// and /v1%2Fmessages all hit a mapping written as /v1/messages. That widens
// which spellings reach the mapped target, never which target they reach — the
// target is a literal under the route's own upstream path, so no spelling
// yields a URL the pass-through could not already produce. Anything
// unmatched falls through to the route's normal pass-through behaviour, which
// is what keeps an explicitly-addressed path (/cloudflare/gw/anthropic/v1/messages)
// working unchanged alongside its mapped alias (/cloudflare/gw/v1/messages).
//
// A mapping grants no authority the route did not already have: it targets the
// same upstream with the same injected credential, and is reachable only from
// containers that already carry the route.
type PathMap struct {
	Path string `json:"path"`
	To   string `json:"to"`
}

// Route maps container traffic to an upstream, with headers to inject.
// Exactly one selector is set:
//
//   - Prefix: a container-visible path prefix (/anthropic), stripped before
//     proxying. This is how agents reach the proxy at 127.0.0.1:8787.
//   - Host: a request Host header (api.github.com), matched verbatim with the
//     path untouched. This serves clients that cannot be given a base URL and
//     instead dial a unix socket while still addressing the real hostname —
//     notably `gh` via its http_unix_socket setting.
//
// Inject values may reference secrets by name via templates; see ParseValue.
type Route struct {
	Name     string   `json:"name"`
	Prefix   string   `json:"prefix,omitempty"`
	Host     string   `json:"host,omitempty"`
	Upstream string   `json:"upstream"`
	Inject   []Header `json:"inject,omitempty"`
	// PathMap aliases exact paths onto other upstream paths; see PathMap.
	// Prefix routes only.
	PathMap []PathMap `json:"path_map,omitempty"`
	// Gateway restricts this route to containers created against that AI
	// Gateway. It is REQUIRED: "*" declares a route universal. Making it
	// mandatory rather than defaulting an empty value to universal is
	// deliberate — a route that forgets it would otherwise silently dissolve
	// the per-container gateway boundary instead of being rejected by it.
	Gateway string `json:"gateway"`
}

// IsHostRoute reports whether the route matches on Host rather than a path
// prefix.
func (r Route) IsHostRoute() bool { return r.Host != "" }

// Selector returns the route's matching key, for messages and sorting.
func (r Route) Selector() string {
	if r.IsHostRoute() {
		return r.Host
	}
	return r.Prefix
}

type Config struct {
	Routes []Route `json:"routes"`
}

var (
	nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	// One or more slug segments: /github-api, /cloudflare/prod.
	prefixRE = regexp.MustCompile(`^(/[a-z0-9][a-z0-9-]*)+$`)
	secretRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	hostRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	userRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	// A leading '-' must not be accepted: Caddy reads `header_up -Name` as a
	// deletion, so `{"header":"-Authorization"}` would render a credential
	// injection as a silent strip.
	headerRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
)

// Load reads, parses, and validates a routes.json file. The returned config
// has normalized upstream URLs (trailing slash stripped).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse %s: trailing data after JSON document", path)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Validate checks every rule the renderer and setup rely on. It also
// normalizes upstream URLs in place.
func (c *Config) Validate() error {
	if len(c.Routes) == 0 {
		return errors.New("no routes defined")
	}
	names := make(map[string]bool)
	selectors := make(map[string]bool)
	basicUsers := make(map[string]string)
	for i := range c.Routes {
		r := &c.Routes[i]
		if !nameRE.MatchString(r.Name) {
			return fmt.Errorf("route %d: invalid name %q (want lowercase slug)", i, r.Name)
		}
		if names[r.Name] {
			return fmt.Errorf("duplicate route name %q", r.Name)
		}
		names[r.Name] = true

		switch {
		case r.Prefix != "" && r.Host != "":
			return fmt.Errorf("route %q: set either prefix or host, not both", r.Name)
		case r.Host != "":
			if !hostRE.MatchString(r.Host) {
				return fmt.Errorf("route %q: invalid host %q (want a hostname like api.github.com)", r.Name, r.Host)
			}
		case r.Prefix != "":
			if !prefixRE.MatchString(r.Prefix) {
				return fmt.Errorf("route %q: invalid prefix %q (want slug path segments like /github-api or /cloudflare/prod)", r.Name, r.Prefix)
			}
		default:
			return fmt.Errorf("route %q: needs either a prefix or a host", r.Name)
		}
		if selectors[r.Selector()] {
			return fmt.Errorf("duplicate route selector %q", r.Selector())
		}
		selectors[r.Selector()] = true

		switch {
		case r.Gateway == "":
			return fmt.Errorf("route %q: %q is required (%q for a route every container may use, "+
				"or a gateway name to restrict it). A route without it would be reachable from every "+
				"container regardless of the gateway it was created against", r.Name, "gateway", AnyGateway)
		case r.Gateway == AnyGateway:
		case !ValidGatewayName(r.Gateway):
			return fmt.Errorf("route %q: invalid gateway %q", r.Name, r.Gateway)
		}

		u, err := url.Parse(r.Upstream)
		if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") ||
			u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
			return fmt.Errorf("route %q: upstream must be an absolute http(s) URL without query/fragment/userinfo, got %q", r.Name, r.Upstream)
		}
		u.Path = strings.TrimSuffix(u.Path, "/")
		u.RawPath = ""
		r.Upstream = u.String()

		// Path mappings are only meaningful where a prefix was stripped: a host
		// route forwards the path verbatim by design, and silently rewriting it
		// there would contradict that.
		if len(r.PathMap) > 0 && r.IsHostRoute() {
			return fmt.Errorf("route %q: path_map needs a prefix route (a host route forwards the path unchanged)", r.Name)
		}
		mapped := make(map[string]bool)
		for _, m := range r.PathMap {
			if !prefixRE.MatchString(m.Path) {
				return fmt.Errorf("route %q: invalid path_map path %q (want exact slug path segments like /v1/messages)", r.Name, m.Path)
			}
			if !prefixRE.MatchString(m.To) {
				return fmt.Errorf("route %q: invalid path_map target %q for %q (want exact slug path segments like /anthropic/v1/messages)", r.Name, m.To, m.Path)
			}
			if mapped[m.Path] {
				return fmt.Errorf("route %q: duplicate path_map path %q", r.Name, m.Path)
			}
			mapped[m.Path] = true
		}
		// Refuse a target that is another entry's source. Caddy will not
		// actually chain them (the adapter puts a block's rewrites in one
		// mutually-exclusive group), but a reader cannot see that from the
		// config, and "what this mapping reaches is decidable by reading it" is
		// the property that makes an exact-match table reviewable. A->B->C
		// spelled out in the table defeats it whether or not it executes.
		for _, m := range r.PathMap {
			if mapped[m.To] {
				return fmt.Errorf("route %q: path_map target %q is also a mapped path; chained mappings are refused because they make the table's reach unreadable", r.Name, m.To)
			}
		}

		for _, h := range r.Inject {
			if !headerRE.MatchString(h.Header) {
				return fmt.Errorf("route %q: invalid header name %q", r.Name, h.Header)
			}
			if err := checkValueCharset(h.Value); err != nil {
				return fmt.Errorf("route %q header %q: %w", r.Name, h.Header, err)
			}
			parts, err := ParseValue(h.Value)
			if err != nil {
				return fmt.Errorf("route %q header %q: %w", r.Name, h.Header, err)
			}
			for _, p := range parts {
				if p.BasicSecret == "" {
					continue
				}
				if prev, ok := basicUsers[p.BasicSecret]; ok && prev != p.BasicUser {
					return fmt.Errorf("secret %q used in {basic:...} templates with two different users (%q and %q)", p.BasicSecret, prev, p.BasicUser)
				}
				basicUsers[p.BasicSecret] = p.BasicUser
			}
		}
	}
	// A prefix that contains another shadows it: inside the rendered route
	// block, written order is execution order and the shorter prefix sorts
	// first, so /cloudflare would swallow every /cloudflare/<gw> route — and
	// serve them with its own credential.
	for i, a := range c.Routes {
		if a.IsHostRoute() {
			continue
		}
		for j, b := range c.Routes {
			if i == j || b.IsHostRoute() {
				continue
			}
			if strings.HasPrefix(b.Prefix, a.Prefix+"/") {
				return fmt.Errorf("route %q (%s) shadows route %q (%s); a prefix must not contain another",
					a.Name, a.Prefix, b.Name, b.Prefix)
			}
		}
	}
	return nil
}

// checkValueCharset rejects characters that could break out of the quoted
// Caddyfile token the value is rendered into. Fail closed: printable ASCII
// only, no quotes, backticks, or backslashes.
func checkValueCharset(v string) error {
	for _, ch := range v {
		if ch < 0x20 || ch > 0x7e {
			return fmt.Errorf("value contains non-printable or non-ASCII character %q", ch)
		}
		if ch == '"' || ch == '`' || ch == '\\' {
			return fmt.Errorf("value contains forbidden character %q", ch)
		}
	}
	return nil
}

// ValidSecretName reports whether a name can be referenced from a
// {secret:NAME} template, which is the constraint a stored source secret has
// to satisfy to be usable at all.
func ValidSecretName(s string) bool { return secretRE.MatchString(s) }

// ValuePart is one piece of a parsed inject value: exactly one of Literal,
// Secret, or the Basic pair is set.
type ValuePart struct {
	Literal     string // literal text
	Secret      string // {secret:NAME} -> NAME
	BasicUser   string // {basic:USER:NAME} -> USER
	BasicSecret string // {basic:USER:NAME} -> NAME
}

// ParseValue splits an inject value into literal and template parts.
// Recognized templates: {secret:NAME} and {basic:USER:NAME}. Any other use of
// braces is an error so that nothing that *looks* like a template silently
// renders as a literal.
func ParseValue(v string) ([]ValuePart, error) {
	var parts []ValuePart
	rest := v
	for rest != "" {
		i := strings.IndexAny(rest, "{}")
		if i == -1 {
			parts = append(parts, ValuePart{Literal: rest})
			break
		}
		if rest[i] == '}' {
			return nil, fmt.Errorf("unmatched '}' in value %q", v)
		}
		if i > 0 {
			parts = append(parts, ValuePart{Literal: rest[:i]})
			rest = rest[i:]
		}
		end := strings.IndexByte(rest, '}')
		if end == -1 {
			return nil, fmt.Errorf("unclosed '{' in value %q", v)
		}
		tok := rest[1:end]
		if strings.ContainsRune(tok, '{') {
			return nil, fmt.Errorf("nested '{' in template %q", tok)
		}
		switch {
		case strings.HasPrefix(tok, "secret:"):
			name := strings.TrimPrefix(tok, "secret:")
			if !secretRE.MatchString(name) {
				return nil, fmt.Errorf("invalid secret name %q in value %q", name, v)
			}
			parts = append(parts, ValuePart{Secret: name})
		case strings.HasPrefix(tok, "basic:"):
			user, name, ok := strings.Cut(strings.TrimPrefix(tok, "basic:"), ":")
			if !ok || !userRE.MatchString(user) || !secretRE.MatchString(name) {
				return nil, fmt.Errorf("invalid template {%s} (want {basic:USER:SECRET-NAME})", tok)
			}
			parts = append(parts, ValuePart{BasicUser: user, BasicSecret: name})
		default:
			return nil, fmt.Errorf("unknown template {%s} (want {secret:NAME} or {basic:USER:NAME})", tok)
		}
		rest = rest[end+1:]
	}
	return parts, nil
}

// SecretNames returns the sorted, de-duplicated names of all secrets
// referenced via {secret:NAME} templates.
func (c *Config) SecretNames() []string {
	seen := make(map[string]bool)
	for _, r := range c.Routes {
		for _, h := range r.Inject {
			parts, err := ParseValue(h.Value)
			if err != nil {
				continue // Validate reports this; nothing to collect
			}
			for _, p := range parts {
				if p.Secret != "" {
					seen[p.Secret] = true
				}
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// BasicSecrets returns secret name -> user for all {basic:USER:NAME}
// templates. Validate guarantees each name maps to a single user.
func (c *Config) BasicSecrets() map[string]string {
	out := make(map[string]string)
	for _, r := range c.Routes {
		for _, h := range r.Inject {
			parts, err := ParseValue(h.Value)
			if err != nil {
				continue
			}
			for _, p := range parts {
				if p.BasicSecret != "" {
					out[p.BasicSecret] = p.BasicUser
				}
			}
		}
	}
	return out
}
