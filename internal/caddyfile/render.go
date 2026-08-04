// Package caddyfile renders the agentbox Caddy configuration: a pure,
// deterministic function from (route table, container list) to Caddyfile
// text. Every security rule of the data plane lives in this output — auth
// header stripping, credential injection via {file.*} placeholders,
// dot-segment rejection, and metadata-only access logs — so the renderer is
// golden-file tested and the output carries no secret values, only secret
// names inside {file.*} references.
package caddyfile

import (
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"agentbox/internal/config"
	"agentbox/internal/state"
)

// Options are the inputs to Render. Paths must be absolute.
type Options struct {
	Routes         []config.Route    // validated route table (secret NAMES only)
	Containers     []state.Container // rendered as one site each
	SocketDir      string            // e.g. /run/agentbox/containers
	CredentialsDir string            // e.g. /run/credentials/caddy.service
	AdminAddr      string            // unix//run/agentbox/admin.sock|0660; required (reload uses it)
	GracePeriod    string            // e.g. 10s; empty omits the directive
	// InstalledSecrets, when non-nil, is the set of secret names actually
	// present on the host. Routes referencing a missing secret render as 503
	// instead of proxying: Caddy expands {file.*} of an absent file to the
	// empty string, which would otherwise send an unauthenticated request
	// upstream. nil disables the check (used by tests and by pure rendering).
	InstalledSecrets map[string]bool
}

// headerStrips is every request header removed before proxying, so no
// container-supplied credential or upstream-control material reaches an
// upstream.
//
// These are emitted as a `request_header` handler *before* the reverse_proxy,
// not as `header_up -` inside it. Inside reverse_proxy all header_up
// directives collapse into one header-ops struct that Caddy applies as
// add → set → delete, so a delete would beat the injection's set no matter
// which line came first — silently forwarding an unauthenticated request. In
// a separate earlier handler, written order is execution order: the strip
// runs first, the injection then sets the real value. That keeps the full
// wildcard list intact even on routes that inject a matching header, which
// matters for families like Cf-Aig-* where the non-auth members
// (cf-aig-collect-log, cf-aig-custom-cost, …) are upstream *controls* a
// container must not be able to set.
var headerStrips = []string{
	"Authorization",
	"Proxy-Authorization",
	"X-Api-Key",
	"Api-Key",
	"X-Goog-Api-Key",
	"X-Auth-Token",
	"Cookie",
	"Cf-Aig-*",
	"X-Aig-*",
}

// proxyHeaderStrips must stay inside reverse_proxy: Caddy adds these itself
// when proxying, so removing them earlier would not help.
var proxyHeaderStrips = []string{
	"Forwarded",
	"X-Forwarded-*",
}

// dotsPattern rejects any dot-segment, in raw, percent-encoded, or
// double-encoded form, bounded by a forward slash, a backslash, a semicolon
// (path parameters, which some upstreams strip before resolving the path), or
// the end of the path.
const dotsPattern = `(^|/|\\|%5c|%5C|;|%3b|%3B)(\.|%2e|%2E|%252e|%252E){1,2}(/|\\|%5c|%5C|;|%3b|%3B|$)`

// escapePattern is the companion guard. The matcher sees the *decoded* path,
// which is why the dot rule above catches %2e forms — but it also means a
// percent-escape cannot be matched as text. Anything that decodes to a
// control byte or a non-ASCII byte is refused instead: %00, %09 and overlong
// UTF-8 (%c0%ae) all reached the upstream verbatim in review, and with
// per-gateway routes the neighbouring gateway sits one successful "../" away.
// Doubly-encoded forms survive decoding as literal %2e/%2f/%5c/%25 text, so
// those are matched directly. Printable ASCII, spaces included, passes: real
// GitHub paths contain encoded spaces.
const escapePattern = `([^\x20-\x7e]|%2[eEfF]|%5[cC]|%25)`

// sitePortBase numbers the per-container site addresses. These ports are
// never bound (the bind directive replaces the listener with the unix
// socket); they only give each site a unique address.
const sitePortBase = 8100

// maxContainers keeps the generated site labels inside the port range.
const maxContainers = 65535 - sitePortBase

// maxSocketPath is the portable limit on sun_path (Linux allows 108 bytes
// including the terminator). A longer path fails at bind time, inside Caddy,
// with an error the operator would have to go digging for.
const maxSocketPath = 107

var (
	// adminRE accepts host:port or a unix socket with an optional |mode
	// suffix (unix//run/agentbox/admin.sock|0660).
	adminRE = regexp.MustCompile(`^(unix/[A-Za-z0-9./_-]+(\|[0-7]{3,4})?|[A-Za-z0-9.:\[\]-]+)$`)
	durRE   = regexp.MustCompile(`^[0-9]+(ns|us|ms|s|m|h)$`)
)

// Render produces the full Caddyfile text.
func Render(o Options) (string, error) {
	if err := checkOptions(&o); err != nil {
		return "", err
	}

	// Host routes first: they select on the Host header, path untouched, so
	// they must not be shadowed by a prefix handler that happens to match.
	routes := append([]config.Route(nil), o.Routes...)
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].IsHostRoute() != routes[j].IsHostRoute() {
			return routes[i].IsHostRoute()
		}
		return routes[i].Selector() < routes[j].Selector()
	})
	containers := append([]state.Container(nil), o.Containers...)
	sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })

	var b strings.Builder
	b.WriteString("# GENERATED by agentbox — do not edit; changes are overwritten on reconcile.\n")
	b.WriteString("{\n")
	fmt.Fprintf(&b, "\tadmin %s\n", o.AdminAddr)
	b.WriteString("\tpersist_config off\n")
	b.WriteString("\tauto_https off\n")
	if o.GracePeriod != "" {
		fmt.Fprintf(&b, "\tgrace_period %s\n", o.GracePeriod)
	}
	// The default logger catches everything the per-site access logs do not —
	// crucially http.log.error.*, which logs the full URI and request headers
	// of any failed proxy attempt. It must be filtered exactly like the access
	// logs or the most common failure path leaks what §3a forbids.
	b.WriteString("\tlog default {\n")
	writeLogFormat(&b, 2)
	b.WriteString("\t}\n")
	b.WriteString("}\n\n")

	// The explicit route block makes written order the execution order, so
	// the dot-segment rejection runs before any handler. It must match the
	// PRE-REWRITE path ({http.request.orig_uri.path}): Caddy normalizes the
	// path for matcher evaluation, so a path_regexp matcher never sees the
	// dot segments that are nevertheless forwarded upstream (verified
	// empirically against caddy 2.11).
	// A container pinned to a gateway with no route reaches no gateway at
	// all. That fails closed, but silently, so say so — it is the shape of
	// "added a gateway to agentbox.json but never regenerated routes.json".
	haveGateway := map[string]bool{}
	for _, r := range routes {
		if r.Gateway != "" && r.Gateway != config.AnyGateway {
			haveGateway[r.Gateway] = true
		}
	}
	for _, c := range containers {
		if c.Gateway != "" && !haveGateway[c.Gateway] {
			slog.Warn("container is pinned to a gateway with no route; it can reach no gateway",
				"container", c.Name, "gateway", c.Gateway,
				"hint", "add it to agentbox.json's gateways and run: sudo agentbox setup")
		}
	}

	// A snippet per gateway in use, plus one for containers with no gateway.
	// A container's site imports only its own, so a route belonging to another
	// gateway is not merely unauthorized for it — it does not exist on that
	// socket at all.
	for _, gw := range snippetGateways(containers) {
		fmt.Fprintf(&b, "(%s) {\n", snippetName(gw))
		b.WriteString("\troute {\n")
		fmt.Fprintf(&b, "\t\t@agentbox_dots vars_regexp {http.request.orig_uri.path} %s\n", dotsPattern)
		b.WriteString("\t\trespond @agentbox_dots 404\n")
		fmt.Fprintf(&b, "\t\t@agentbox_escapes vars_regexp {http.request.orig_uri.path} %s\n", escapePattern)
		b.WriteString("\t\trespond @agentbox_escapes 404\n")
		for _, r := range routes {
			if r.Gateway != config.AnyGateway && r.Gateway != gw {
				continue
			}
			if err := writeRoute(&b, r, o.CredentialsDir, missingSecrets(r, o.InstalledSecrets)); err != nil {
				return "", err
			}
		}
		// Fallback: never enumerate routes to the container.
		b.WriteString("\t\thandle {\n")
		b.WriteString("\t\t\trespond \"unknown route\" 404\n")
		b.WriteString("\t\t}\n")
		b.WriteString("\t}\n")
		b.WriteString("}\n")
	}

	if len(containers) > maxContainers {
		return "", fmt.Errorf("too many containers (%d); maximum is %d", len(containers), maxContainers)
	}
	for i, c := range containers {
		if !state.ValidName(c.Name) {
			return "", fmt.Errorf("invalid container name %q", c.Name)
		}
		// Render must be safe even if a caller skipped validation.
		if c.Gateway != "" && !config.ValidGatewayName(c.Gateway) {
			return "", fmt.Errorf("container %q has invalid gateway %q", c.Name, c.Gateway)
		}
		sock := path.Join(o.SocketDir, c.Name+".sock")
		if len(sock) > maxSocketPath {
			return "", fmt.Errorf("socket path %q is %d bytes, over the %d-byte unix socket limit; use a shorter container name or run dir",
				sock, len(sock), maxSocketPath)
		}
		b.WriteString("\n")
		if c.Blocked {
			fmt.Fprintf(&b, "# container: %s (BLOCKED)\n", c.Name)
		} else {
			fmt.Fprintf(&b, "# container: %s\n", c.Name)
		}
		// The :port site address is a unique label only — `bind` replaces the
		// listener with the unix socket, so the port is never opened (verified
		// empirically; bare unix site addresses are not accepted by caddy).
		fmt.Fprintf(&b, ":%d {\n", sitePortBase+i)
		// |0660 is required, not cosmetic: Caddy defaults unix sockets to
		// 0200, and connecting to a unix socket needs the write bit. Without
		// it the CLI (group agentbox) cannot probe the socket at all, so
		// `create` times out waiting for it and `list` reports every
		// container's socket as absent.
		fmt.Fprintf(&b, "\tbind unix/%s|0660\n", sock)
		writeSiteLog(&b)
		fmt.Fprintf(&b, "\tlog_append container %s\n", c.Name)
		if c.Blocked {
			b.WriteString("\trespond \"container blocked\" 403\n")
		} else {
			fmt.Fprintf(&b, "\timport %s\n", snippetName(c.Gateway))
		}
		b.WriteString("}\n")
	}

	return b.String(), nil
}

func checkOptions(o *Options) error {
	if !path.IsAbs(o.SocketDir) || !safePathToken(o.SocketDir) {
		return fmt.Errorf("socket dir must be an absolute plain path, got %q", o.SocketDir)
	}
	if !path.IsAbs(o.CredentialsDir) || !safePathToken(o.CredentialsDir) {
		return fmt.Errorf("credentials dir must be an absolute plain path, got %q", o.CredentialsDir)
	}
	if o.AdminAddr == "" || !adminRE.MatchString(o.AdminAddr) || strings.Contains(o.AdminAddr, "..") {
		return fmt.Errorf("admin address must be a plain host:port or unix socket path, got %q", o.AdminAddr)
	}
	if o.GracePeriod != "" && !durRE.MatchString(o.GracePeriod) {
		return fmt.Errorf("grace period must be a plain duration like 10s, got %q", o.GracePeriod)
	}
	// Re-validate routes: Render must be safe even if a caller skips Load.
	cfg := config.Config{Routes: append([]config.Route(nil), o.Routes...)}
	if len(cfg.Routes) > 0 {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid routes: %w", err)
		}
		o.Routes = cfg.Routes // normalized upstreams
	}
	return nil
}

// safePathToken reports whether s can be emitted as a single unquoted
// Caddyfile token without any risk of being parsed as something else.
func safePathToken(s string) bool {
	for _, ch := range s {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			continue
		}
		switch ch {
		case '/', '.', '-', '_':
		default:
			return false
		}
	}
	return s != "" && !strings.Contains(s, "..")
}

// snippetName is the route-set a container with this gateway imports. Real
// gateways are namespaced under _gw_ so no gateway name can collide with the
// sentinel used for containers that have none (an older state file).
func snippetName(gateway string) string {
	if gateway == "" {
		return "agentbox_routes_nogateway"
	}
	return "agentbox_routes_gw_" + sanitizeLabel(gateway)
}

// snippetGateways lists the gateways needing a rendered route set: every
// gateway a container is assigned to, plus "" when some container has none.
// Gateways with no container get no snippet — nothing would import it.
func snippetGateways(containers []state.Container) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range containers {
		if !seen[c.Gateway] {
			seen[c.Gateway] = true
			out = append(out, c.Gateway)
		}
	}
	// Always emit at least one so the config is valid with no containers.
	if len(out) == 0 {
		out = append(out, "")
	}
	sort.Strings(out)
	return out
}

// sanitizeLabel makes a route name usable inside a Caddyfile matcher token.
func sanitizeLabel(name string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(name)
}

// routeSecretFiles returns the credential file paths a route's injections
// depend on, sorted and de-duplicated.
func routeSecretFiles(r config.Route, credsDir string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range r.Inject {
		parts, err := config.ParseValue(h.Value)
		if err != nil {
			continue // Validate reports this
		}
		for _, p := range parts {
			name := p.Secret
			if p.BasicSecret != "" {
				name = p.BasicSecret + ".basic"
			}
			if name == "" {
				continue
			}
			path := path.Join(credsDir, name)
			if !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out
}

// missingSecrets returns the sorted names of secrets a route needs that are
// not installed. An empty result means the route is fully credentialed (or
// checking is disabled).
func missingSecrets(r config.Route, installed map[string]bool) []string {
	if installed == nil {
		return nil
	}
	var missing []string
	seen := map[string]bool{}
	for _, h := range r.Inject {
		parts, err := config.ParseValue(h.Value)
		if err != nil {
			continue // Validate already rejected this
		}
		for _, p := range parts {
			name := p.Secret
			if p.BasicSecret != "" {
				name = p.BasicSecret + ".basic"
			}
			if name == "" || seen[name] || installed[name] {
				continue
			}
			seen[name] = true
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

func writeRoute(b *strings.Builder, r config.Route, credsDir string, missing []string) error {
	u, err := url.Parse(r.Upstream)
	if err != nil {
		return fmt.Errorf("route %q: %w", r.Name, err)
	}
	dial := u.Scheme + "://" + u.Host

	if r.IsHostRoute() {
		matcher := "@host_" + sanitizeLabel(r.Name)
		fmt.Fprintf(b, "\t\t%s host %s\n", matcher, r.Host)
		fmt.Fprintf(b, "\t\thandle %s {\n", matcher)
	} else {
		// handle_path matches the prefixed subtree only; send the bare prefix
		// into it so /github-api and /github-api/ behave the same.
		fmt.Fprintf(b, "\t\tredir %s %s/ 308\n", r.Prefix, r.Prefix)
		fmt.Fprintf(b, "\t\thandle_path %s/* {\n", r.Prefix)
	}
	if len(missing) > 0 {
		// Fail closed: without the credential this route can only produce an
		// unauthenticated upstream call.
		fmt.Fprintf(b, "\t\t\t# secret(s) not installed on this host: %s\n", strings.Join(missing, ", "))
		fmt.Fprintf(b, "\t\t\trespond \"route %s unavailable: credential not installed\" 503\n", r.Name)
		b.WriteString("\t\t}\n")
		return nil
	}
	if u.Path != "" && !safePathToken(u.Path) {
		return fmt.Errorf("route %q: upstream path %q not renderable", r.Name, u.Path)
	}
	// Exact-path aliases first, each behind its own matcher, then the
	// pass-through rewrite behind the negation of all of them.
	//
	// What actually guarantees only one rewrite takes effect is Caddy's
	// adapter: it puts every `rewrite` from one block into a single
	// mutually-exclusive route group (visible as "group":"group0" in
	// `caddy adapt` output), and Caddy runs only the first matching route of a
	// group. Verified by execution — with the negation removed the rendered
	// config behaves identically, so the upstream path is *not* prepended
	// twice. The negation is therefore belt-and-braces, kept for two reasons:
	// it makes the exclusivity legible without knowing the adapter's grouping
	// behaviour, and it does not depend on it. Do not "simplify" it away on the
	// assumption that it is what protects us, and do not assume it is.
	mappedPaths := make([]string, 0, len(r.PathMap))
	for i, m := range r.PathMap {
		if !safePathToken(m.Path) || !safePathToken(m.To) {
			return fmt.Errorf("route %q: path mapping %q -> %q not renderable", r.Name, m.Path, m.To)
		}
		matcher := fmt.Sprintf("@map_%s_%d", sanitizeLabel(r.Name), i)
		fmt.Fprintf(b, "\t\t\t%s path %s\n", matcher, m.Path)
		fmt.Fprintf(b, "\t\t\trewrite %s %s%s\n", matcher, u.Path, m.To)
		mappedPaths = append(mappedPaths, m.Path)
	}
	if u.Path != "" {
		if len(mappedPaths) > 0 {
			matcher := "@unmapped_" + sanitizeLabel(r.Name)
			fmt.Fprintf(b, "\t\t\t%s not path %s\n", matcher, strings.Join(mappedPaths, " "))
			fmt.Fprintf(b, "\t\t\trewrite %s %s{uri}\n", matcher, u.Path)
		} else {
			fmt.Fprintf(b, "\t\t\trewrite * %s{uri}\n", u.Path)
		}
	}
	// Runtime fail-closed guard. Caddy expands {file.…} of an absent or empty
	// credential to the empty string and proxies anyway, so a control-plane
	// check alone leaves a window: the drop-in and manifest describe what
	// caddy *will* load at next start, not what the running process holds.
	// Comparing the placeholder per request closes that window in the data
	// plane itself, where it cannot drift from the config that produced it.
	for i, secretFile := range routeSecretFiles(r, credsDir) {
		matcher := fmt.Sprintf("@nocred_%s_%d", sanitizeLabel(r.Name), i)
		fmt.Fprintf(b, "\t\t\t%s vars {file.%s} \"\"\n", matcher, secretFile)
		fmt.Fprintf(b, "\t\t\trespond %s \"route %s unavailable: credential not installed\" 503\n",
			matcher, r.Name)
	}
	// Strip first, in its own handler, so the injection below cannot be
	// undone by it — see the headerStrips comment.
	for _, h := range headerStrips {
		fmt.Fprintf(b, "\t\t\trequest_header -%s\n", h)
	}
	fmt.Fprintf(b, "\t\t\treverse_proxy %s {\n", dial)
	b.WriteString("\t\t\t\tflush_interval -1\n")
	b.WriteString("\t\t\t\theader_up Host {upstream_hostport}\n")
	for _, h := range proxyHeaderStrips {
		fmt.Fprintf(b, "\t\t\t\theader_up -%s\n", h)
	}
	for _, h := range r.Inject {
		rendered, err := renderValue(h.Value, credsDir)
		if err != nil {
			return fmt.Errorf("route %q header %q: %w", r.Name, h.Header, err)
		}
		fmt.Fprintf(b, "\t\t\t\theader_up %s \"%s\"\n", h.Header, rendered)
	}
	b.WriteString("\t\t\t}\n")
	b.WriteString("\t\t}\n")
	return nil
}

// renderValue turns an inject value into the quoted Caddyfile form: literals
// pass through (charset already validated), {secret:NAME} becomes a {file.*}
// placeholder, {basic:USER:NAME} becomes `Basic ` + the {file.*} placeholder
// of the pre-encoded companion secret.
func renderValue(v, credsDir string) (string, error) {
	parts, err := config.ParseValue(v)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, p := range parts {
		switch {
		case p.Secret != "":
			fmt.Fprintf(&out, "{file.%s}", path.Join(credsDir, p.Secret))
		case p.BasicSecret != "":
			fmt.Fprintf(&out, "Basic {file.%s}", path.Join(credsDir, p.BasicSecret+".basic"))
		default:
			out.WriteString(p.Literal)
		}
	}
	return out.String(), nil
}

// writeSiteLog emits the mandatory metadata-only access log config: the query
// string is stripped from the logged URI, and request/response headers are
// dropped entirely.
func writeSiteLog(b *strings.Builder) {
	b.WriteString("\tlog {\n")
	b.WriteString("\t\toutput stderr\n")
	writeLogFormat(b, 2)
	b.WriteString("\t}\n")
}

// writeLogFormat emits the shared metadata-only encoder, indented depth tabs.
func writeLogFormat(b *strings.Builder, depth int) {
	ind := strings.Repeat("\t", depth)
	b.WriteString(ind + "format filter {\n")
	b.WriteString(ind + "\twrap json\n")
	b.WriteString(ind + "\tfields {\n")
	b.WriteString(ind + "\t\trequest>headers delete\n")
	b.WriteString(ind + "\t\tresp_headers delete\n")
	b.WriteString(ind + "\t\trequest>uri regexp \\?.* \"\"\n")
	b.WriteString(ind + "\t}\n")
	b.WriteString(ind + "}\n")
}
