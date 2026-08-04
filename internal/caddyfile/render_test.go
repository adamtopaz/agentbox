package caddyfile

import (
	"flag"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/caddyctl"
	"agentbox/internal/config"
	"agentbox/internal/state"
)

var update = flag.Bool("update", false, "rewrite golden files")

func testRoutes() []config.Route {
	return []config.Route{
		{Name: "anthropic", Prefix: "/anthropic",
			Upstream: "https://gateway.ai.cloudflare.com/v1/ACCT/GW/anthropic",
			Inject:   []config.Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token}"}}},
		{Name: "github-git", Prefix: "/github-git", Upstream: "https://github.com",
			Inject: []config.Header{{Header: "Authorization", Value: "{basic:x-access-token:gh-pat}"}}},
		{Name: "passthrough", Prefix: "/echo", Upstream: "http://127.0.0.1:9999"},
		{Name: "gh-api", Host: "api.github.com", Upstream: "https://api.github.com",
			Inject: []config.Header{{Header: "Authorization", Value: "Bearer {secret:gh-pat}"}}},
	}
}

func baseOptions() Options {
	return Options{
		Routes:         testRoutes(),
		SocketDir:      "/run/agentbox/containers",
		CredentialsDir: "/run/credentials/caddy.service",
		AdminAddr:      "unix//run/agentbox/admin.sock|0660",
		GracePeriod:    "10s",
	}
}

func render(t *testing.T, o Options) string {
	t.Helper()
	got, err := Render(o)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (regenerate with: go test ./internal/caddyfile -update)", err)
	}
	if string(want) != got {
		t.Errorf("rendered output differs from %s.\nGot:\n%s", path, got)
	}
}

func TestGolden(t *testing.T) {
	cases := map[string]Options{
		"empty.caddyfile": baseOptions(),
		"one.caddyfile": func() Options {
			o := baseOptions()
			o.Containers = []state.Container{{Name: "dev"}}
			return o
		}(),
		"multi-blocked.caddyfile": func() Options {
			o := baseOptions()
			o.Containers = []state.Container{
				{Name: "beta", Blocked: true},
				{Name: "alpha"},
			}
			return o
		}(),
	}
	for name, o := range cases {
		checkGolden(t, name, render(t, o))
	}
}

func TestDeterministicUnderShuffle(t *testing.T) {
	o := baseOptions()
	o.Containers = []state.Container{{Name: "a"}, {Name: "b", Blocked: true}, {Name: "c"}}
	want := render(t, o)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for range 5 {
		o2 := baseOptions()
		o2.Routes = append([]config.Route(nil), o.Routes...)
		o2.Containers = append([]state.Container(nil), o.Containers...)
		rng.Shuffle(len(o2.Routes), func(i, j int) { o2.Routes[i], o2.Routes[j] = o2.Routes[j], o2.Routes[i] })
		rng.Shuffle(len(o2.Containers), func(i, j int) { o2.Containers[i], o2.Containers[j] = o2.Containers[j], o2.Containers[i] })
		if got := render(t, o2); got != want {
			t.Fatal("output depends on input order")
		}
	}
}

// TestStripsPrecedeInjection guards the sharpest edge in the renderer: inside
// a reverse_proxy, Caddy applies header_up deletes AFTER sets regardless of
// line order, so a strip there would silently discard the credential the same
// block injects. The strips therefore live in an earlier request_header
// handler, where written order is execution order — and the full wildcard
// list survives, because families like Cf-Aig-* carry upstream *controls*
// (cf-aig-collect-log, cf-aig-custom-cost) that a container must not be able
// to set even on a route that injects cf-aig-authorization.
func TestStripsPrecedeInjection(t *testing.T) {
	cfg := config.Config{Routes: config.DefaultRoutes(config.Meta{AccountID: "ACCT", GatewayID: "GW"})}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	o := baseOptions()
	o.Routes = cfg.Routes
	o.Containers = []state.Container{{Name: "dev"}}
	got := render(t, o)

	for _, r := range cfg.Routes {
		var block string
		if r.IsHostRoute() {
			block = hostBlock(t, got, strings.ReplaceAll(r.Name, "-", "_"))
		} else {
			block = routeBlock(t, got, r.Prefix)
		}
		// Full strip list on every route, no per-route exceptions.
		for _, pattern := range headerStrips {
			if !strings.Contains(block, "request_header -"+pattern+"\n") {
				t.Errorf("route %q: missing strip %q\n%s", r.Name, pattern, block)
			}
			if strings.Contains(block, "header_up -"+pattern+"\n") {
				t.Errorf("route %q: strip %q sits inside reverse_proxy, where it beats the injection", r.Name, pattern)
			}
		}
		if si, pi := strings.Index(block, "request_header -"), strings.Index(block, "reverse_proxy"); si == -1 || si > pi {
			t.Errorf("route %q: strips do not precede reverse_proxy", r.Name)
		}
		for _, h := range r.Inject {
			if !strings.Contains(block, "header_up "+h.Header+" \"") {
				t.Errorf("route %q: injection of %q missing", r.Name, h.Header)
			}
		}
	}
	if !strings.Contains(got, `header_up cf-aig-authorization "Bearer {file./run/credentials/caddy.service/cf-aig-token}"`) {
		t.Error("gateway credential injection missing")
	}
	// Caddy adds these itself while proxying, so they stay as header_up.
	for _, pattern := range proxyHeaderStrips {
		if !strings.Contains(got, "header_up -"+pattern+"\n") {
			t.Errorf("proxy-added header %q not stripped inside reverse_proxy", pattern)
		}
	}
}

// TestHostRoutesComeFirst pins the ordering that makes host routes work: they
// match on the Host header with the path untouched, so a prefix handler that
// happens to match the same path must not get there first.
func TestHostRoutesComeFirst(t *testing.T) {
	o := baseOptions()
	o.Containers = []state.Container{{Name: "dev"}}
	got := render(t, o)

	firstHost := strings.Index(got, "@host_gh_api host api.github.com")
	firstPrefix := strings.Index(got, "handle_path /anthropic/*")
	if firstHost == -1 || firstPrefix == -1 {
		t.Fatal("expected both a host and a prefix route")
	}
	if firstHost > firstPrefix {
		t.Error("host routes must be emitted before prefix routes")
	}
	// A host route proxies the path as-is: no prefix strip, no rewrite.
	block := hostBlock(t, got, "gh_api")
	if strings.Contains(block, "handle_path") || strings.Contains(block, "rewrite") {
		t.Errorf("host route must not rewrite the path:\n%s", block)
	}
	if !strings.Contains(block, `header_up Authorization "Bearer {file./run/credentials/caddy.service/gh-pat}"`) {
		t.Errorf("host route missing its injection:\n%s", block)
	}
	if strings.Contains(block, "header_up -Authorization\n") {
		t.Errorf("host route strips the header it injects:\n%s", block)
	}
}

// routeBlock returns the rendered text of one route's handle_path block.
func routeBlock(t *testing.T, rendered, prefix string) string {
	t.Helper()
	start := strings.Index(rendered, "handle_path "+prefix+"/* {")
	if start == -1 {
		t.Fatalf("no rendered block for prefix %q", prefix)
	}
	end := strings.Index(rendered[start:], "\n\t\t}\n")
	if end == -1 {
		t.Fatalf("unterminated block for prefix %q", prefix)
	}
	return rendered[start : start+end]
}

// hostBlock returns the rendered text of one host route's handle block.
func hostBlock(t *testing.T, rendered, matcher string) string {
	t.Helper()
	start := strings.Index(rendered, "handle @host_"+matcher+" {")
	if start == -1 {
		t.Fatalf("no rendered block for host matcher %q", matcher)
	}
	end := strings.Index(rendered[start:], "\n\t\t}\n")
	if end == -1 {
		t.Fatalf("unterminated block for host matcher %q", matcher)
	}
	return rendered[start : start+end]
}

func TestMissingSecretRendersUnavailable(t *testing.T) {
	o := baseOptions()
	o.Containers = []state.Container{{Name: "dev"}}
	o.InstalledSecrets = map[string]bool{"cf-aig-token": true} // gh-pat.basic absent
	got := render(t, o)

	if !strings.Contains(got, `respond "route github-git unavailable: credential not installed" 503`) {
		t.Error("route with a missing secret must fail closed with 503")
	}
	// The disabled route must render the respond ALONE — no proxy behind it.
	if strings.Contains(routeBlock(t, got, "/github-git"), "reverse_proxy") {
		t.Error("missing-credential route still proxies with an empty {file.*} placeholder")
	}
	// The credentialed route is unaffected.
	if !strings.Contains(got, "{file./run/credentials/caddy.service/cf-aig-token}") {
		t.Error("installed-secret route should still proxy")
	}
}

func TestSecurityPresence(t *testing.T) {
	o := baseOptions()
	o.Containers = []state.Container{{Name: "dev"}, {Name: "bad", Blocked: true}}
	got := render(t, o)

	// Every route strips every credential-bearing header it does not inject,
	// wildcards included.
	for _, h := range headerStrips {
		want := "request_header -" + h
		if n := strings.Count(got, want); n != len(testRoutes()) {
			t.Errorf("%q appears %d times, want one per route (%d)", want, n, len(testRoutes()))
		}
	}
	for _, want := range []string{
		"header_up Host {upstream_hostport}",
		"flush_interval -1",
		"request_header -Cf-Aig-*",
		"rewrite * /v1/ACCT/GW/anthropic{uri}",
		`header_up cf-aig-authorization "Bearer {file./run/credentials/caddy.service/cf-aig-token}"`,
		`header_up Authorization "Basic {file./run/credentials/caddy.service/gh-pat.basic}"`,
		"bind unix//run/agentbox/containers/dev.sock",
		"log_append container dev",
		"request>headers delete",
		"resp_headers delete",
		`request>uri regexp \?.* ""`,
		"respond \"container blocked\" 403",
		"respond \"unknown route\" 404",
		"@agentbox_dots vars_regexp {http.request.orig_uri.path} " + dotsPattern,
		"respond @agentbox_dots 404",
		"admin unix//run/agentbox/admin.sock|0660",
		"persist_config off",
		"grace_period 10s",
		"redir /anthropic /anthropic/ 308",
		"log default {", // the error log must be filtered too, not just access logs
		"@host_gh_api host api.github.com",
		"handle @host_gh_api {",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered config missing %q", want)
		}
	}

	// Three filtered log configs: one default (covers http.log.error.*) plus
	// one per site.
	if n := strings.Count(got, "format filter"); n != 3 {
		t.Errorf("expected 3 filtered logs (1 default + 2 sites), got %d", n)
	}

	// The blocked site must carry no routes.
	blockedSite := got[strings.Index(got, "bind unix//run/agentbox/containers/bad.sock"):strings.Index(got, "# container: dev")]
	if strings.Contains(blockedSite, "import agentbox_routes") {
		t.Error("blocked site still imports routes")
	}

}

// TestNoSecretValues proves rendering can never embed a secret value: the
// renderer has no access to values at all, so a value planted on disk must
// not appear even when the credentials dir points right at it.
func TestNoSecretValues(t *testing.T) {
	dir := t.TempDir()
	const planted = "test-secret-value-8d1a"
	if err := os.WriteFile(filepath.Join(dir, "cf-aig-token"), []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	o := baseOptions()
	o.CredentialsDir = dir
	o.Containers = []state.Container{{Name: "dev"}}
	got := render(t, o)
	if strings.Contains(got, planted) {
		t.Fatal("secret value leaked into rendered config")
	}
	if !strings.Contains(got, "{file."+dir+"/cf-aig-token}") {
		t.Fatal("expected {file.*} placeholder for the secret")
	}
}

func TestRenderRejects(t *testing.T) {
	bad := []Options{
		func() Options { o := baseOptions(); o.SocketDir = "relative/path"; return o }(),
		func() Options { o := baseOptions(); o.SocketDir = "/run/agent box"; return o }(),
		func() Options { o := baseOptions(); o.SocketDir = "/run/{args[0]}"; return o }(),
		func() Options { o := baseOptions(); o.CredentialsDir = "/run/../etc"; return o }(),
		func() Options { o := baseOptions(); o.AdminAddr = "localhost:2019 {"; return o }(),
		func() Options { o := baseOptions(); o.AdminAddr = "unix//run/../etc/x.sock"; return o }(),
		func() Options { o := baseOptions(); o.AdminAddr = ""; return o }(),
		func() Options { o := baseOptions(); o.GracePeriod = "10s\nadmin off"; return o }(),
		func() Options {
			o := baseOptions()
			o.Containers = []state.Container{{Name: "Bad Name"}}
			return o
		}(),
		func() Options { // socket path over the sun_path limit
			o := baseOptions()
			o.SocketDir = "/run/" + strings.Repeat("d", 120)
			o.Containers = []state.Container{{Name: "dev"}}
			return o
		}(),
		func() Options {
			o := baseOptions()
			o.Routes = []config.Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com",
				Inject: []config.Header{{Header: "X", Value: `inject"ion`}}}}
			return o
		}(),
		func() Options {
			o := baseOptions()
			o.Routes = []config.Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com/p a t h"}}
			return o
		}(),
	}
	for i, o := range bad {
		if _, err := Render(o); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

// TestCaddyValidate runs the real caddy against a representative rendered
// config — the main guard that the generated syntax is real. Skipped unless a
// caddy >= 2.8 is available (env AGENTBOX_TEST_CADDY or PATH).
func TestCaddyValidate(t *testing.T) {
	bin := os.Getenv("AGENTBOX_TEST_CADDY")
	if bin == "" {
		bin = "caddy"
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Skip("no caddy binary available")
	}
	client := caddyctl.Client{Bin: bin}
	v, err := client.Version()
	if err != nil {
		t.Skip("caddy version not detectable")
	}
	if !caddyctl.VersionAtLeast(v, 2, 8) {
		t.Skipf("caddy %s too old for the rendered config (need >= 2.8)", v)
	}

	o := baseOptions()
	// Unix socket paths must exist-able but validate doesn't bind; still use
	// a temp dir to stay hermetic.
	o.SocketDir = filepath.Join(t.TempDir(), "sockets")
	o.Containers = []state.Container{{Name: "dev"}, {Name: "bad", Blocked: true}}
	got := render(t, o)
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := client.Validate(path); err != nil {
		t.Fatalf("caddy validate rejected rendered config:\n%v\n--- config ---\n%s", err, got)
	}
}
