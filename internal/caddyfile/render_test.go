package caddyfile

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/caddyctl"
	"agentbox/internal/config"
	"agentbox/internal/state"
)

var update = flag.Bool("update", false, "rewrite golden files")

func testRoutes() []config.Route {
	return []config.Route{
		{Name: "anthropic", Prefix: "/anthropic", Gateway: "prod",
			Upstream: "https://gateway.ai.cloudflare.com/v1/ACCT/GW/anthropic",
			Inject:   []config.Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token}"}}},
		{Name: "github-git", Prefix: "/github-git", Gateway: config.AnyGateway, Upstream: "https://github.com",
			Inject: []config.Header{{Header: "Authorization", Value: "{basic:x-access-token:gh-pat}"}}},
		{Name: "passthrough", Prefix: "/echo", Gateway: config.AnyGateway, Upstream: "http://127.0.0.1:9999"},
		{Name: "gh-api", Host: "api.github.com", Gateway: config.AnyGateway, Upstream: "https://api.github.com",
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
			o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
			return o
		}(),
		"multi-blocked.caddyfile": func() Options {
			o := baseOptions()
			o.Containers = []state.Container{
				{Name: "beta", Gateway: "prod", Blocked: true},
				{Name: "alpha", Gateway: "prod"},
			}
			return o
		}(),
	}
	for name, o := range cases {
		checkGolden(t, name, render(t, o))
	}
}

// TestGatewayPinning is the isolation property in config form: a container
// sees its own gateway's route and credential, and the other gateway's route
// is absent from its snippet entirely — not present-but-denied.
func TestGatewayPinning(t *testing.T) {
	o := baseOptions()
	o.Routes = []config.Route{
		{Name: "cf-mine", Prefix: "/cloudflare/mine", Gateway: "mine",
			Upstream: "https://gateway.ai.cloudflare.com/v1/ACCT/mine",
			Inject:   []config.Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token-mine}"}}},
		{Name: "cf-other", Prefix: "/cloudflare/other", Gateway: "other",
			Upstream: "https://gateway.ai.cloudflare.com/v1/ACCT/other",
			Inject:   []config.Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token-other}"}}},
		{Name: "github-api", Prefix: "/github-api", Gateway: config.AnyGateway,
			Upstream: "https://api.github.com",
			Inject:   []config.Header{{Header: "Authorization", Value: "Bearer {secret:gh-pat}"}}},
	}
	o.Containers = []state.Container{{Name: "alpha", Gateway: "mine"}, {Name: "beta", Gateway: "other"}}
	got := render(t, o)
	checkGolden(t, "two-gateways.caddyfile", got)

	mine := snippet(t, got, "agentbox_routes_gw_mine")
	other := snippet(t, got, "agentbox_routes_gw_other")
	for _, c := range []struct{ name, block, own, foreign string }{
		{"mine", mine, "mine", "other"},
		{"other", other, "other", "mine"},
	} {
		if !strings.Contains(c.block, "handle_path /cloudflare/"+c.own+"/*") {
			t.Errorf("%s snippet lacks its own gateway route", c.name)
		}
		if strings.Contains(c.block, "/cloudflare/"+c.foreign) {
			t.Errorf("%s snippet contains the other gateway's route", c.name)
		}
		if strings.Contains(c.block, "cf-aig-token-"+c.foreign) {
			t.Errorf("%s snippet references the other gateway's credential", c.name)
		}
		// Universal routes appear in both.
		if !strings.Contains(c.block, "handle_path /github-api/*") {
			t.Errorf("%s snippet lost the universal github route", c.name)
		}
	}
	// Each site imports only its own set.
	if !strings.Contains(got, "import agentbox_routes_gw_mine") ||
		!strings.Contains(got, "import agentbox_routes_gw_other") {
		t.Error("sites do not import per-gateway snippets")
	}
}

// snippet returns the text of one rendered snippet definition.
func snippet(t *testing.T, rendered, name string) string {
	t.Helper()
	start := strings.Index(rendered, "("+name+") {")
	if start == -1 {
		t.Fatalf("no snippet %q", name)
	}
	end := strings.Index(rendered[start:], "\n}\n")
	if end == -1 {
		t.Fatalf("unterminated snippet %q", name)
	}
	return rendered[start : start+end]
}

func TestDeterministicUnderShuffle(t *testing.T) {
	o := baseOptions()
	o.Containers = []state.Container{{Name: "a", Gateway: "prod"}, {Name: "b", Gateway: "prod", Blocked: true}, {Name: "c", Gateway: "prod"}}
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
	cfg := config.Config{Routes: config.DefaultRoutes(config.Meta{AccountID: "ACCT", Gateways: []string{"prod"}})}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	o := baseOptions()
	o.Routes = cfg.Routes
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
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
	if !strings.Contains(got, `header_up cf-aig-authorization "Bearer {file./run/credentials/caddy.service/cf-aig-token-prod}"`) {
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
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
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
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
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
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}, {Name: "bad", Gateway: "prod", Blocked: true}}
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
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
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
			o.Containers = []state.Container{{Name: "Bad Name", Gateway: "prod"}}
			return o
		}(),
		func() Options { // socket path over the sun_path limit
			o := baseOptions()
			o.SocketDir = "/run/" + strings.Repeat("d", 120)
			o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
			return o
		}(),
		func() Options {
			o := baseOptions()
			o.Routes = []config.Route{{Name: "a", Prefix: "/a", Gateway: config.AnyGateway, Upstream: "https://x.com",
				Inject: []config.Header{{Header: "X", Value: `inject"ion`}}}}
			return o
		}(),
		func() Options {
			o := baseOptions()
			o.Routes = []config.Route{{Name: "a", Prefix: "/a", Gateway: config.AnyGateway, Upstream: "https://x.com/p a t h"}}
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
// caddyBinOrSkip resolves a usable caddy binary, or skips the test.
func caddyBinOrSkip(t *testing.T) string {
	t.Helper()
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
	return bin
}

// validateWithCaddy runs `caddy validate` over a rendered config, or skips if
// no usable caddy binary is available.
func validateWithCaddy(t *testing.T, rendered string) {
	t.Helper()
	client := caddyctl.Client{Bin: caddyBinOrSkip(t)}
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := client.Validate(path); err != nil {
		t.Fatalf("caddy validate rejected rendered config:\n%v\n--- config ---\n%s", err, rendered)
	}
}

func TestCaddyValidate(t *testing.T) {
	o := baseOptions()
	// Unix socket paths must exist-able but validate doesn't bind; still use
	// a temp dir to stay hermetic.
	o.SocketDir = filepath.Join(t.TempDir(), "sockets")
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}, {Name: "bad", Gateway: "prod", Blocked: true}}
	validateWithCaddy(t, render(t, o))
}

// TestPathMapRenderedShape pins the rendering path_map is meant to produce.
// It asserts SHAPE, not the safety property: what actually keeps only one
// rewrite in effect is Caddy's adapter grouping every `rewrite` in a block into
// one mutually-exclusive route group (see render.go). The behavioural guarantee
// is covered by TestPathMapRoutesThroughCaddy, which routes real requests. This
// test exists so the deliberate belt-and-braces negation is not dropped
// silently.
func TestPathMapRenderedShape(t *testing.T) {
	o := baseOptions()
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
	o.InstalledSecrets = map[string]bool{"cf-aig-token": true, "gh-pat.basic": true}
	o.Routes = []config.Route{{
		Name: "cf-prod", Prefix: "/cloudflare/prod", Gateway: "prod",
		Upstream: "https://gateway.ai.cloudflare.com/v1/ACCT/prod",
		PathMap:  config.GatewayPathMap,
		Inject:   []config.Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token}"}},
	}}
	block := routeBlock(t, render(t, o), "/cloudflare/prod")

	// The pass-through must stay gated. Caddy's route grouping means an
	// ungated one would in fact still behave correctly, so this is a
	// defence-in-depth check, not the correctness proof.
	if strings.Contains(block, "rewrite * ") {
		t.Errorf("pass-through rewrite is ungated alongside a path_map; the negation is deliberate:\n%s", block)
	}
	want := []string{
		"@map_cf_prod_0 path /v1/messages",
		"rewrite @map_cf_prod_0 /v1/ACCT/prod/anthropic/v1/messages",
		"@map_cf_prod_1 path /responses",
		"rewrite @map_cf_prod_1 /v1/ACCT/prod/openai/responses",
		"@map_cf_prod_2 path /chat/completions",
		"rewrite @map_cf_prod_2 /v1/ACCT/prod/compat/chat/completions",
		"@unmapped_cf_prod not path /v1/messages /responses /chat/completions",
		"rewrite @unmapped_cf_prod /v1/ACCT/prod{uri}",
	}
	for _, w := range want {
		if !strings.Contains(block, w) {
			t.Errorf("missing %q in:\n%s", w, block)
		}
	}
	// A mapped path must not become a way around the fail-closed guard. Source
	// order is not the thing to assert here — Caddy sorts directives by its own
	// order, in which `rewrite` always precedes `respond` regardless of how
	// they are written — so what matters is that the guard is present in the
	// same block and short-circuits before the proxy. A rewritten path that
	// then 503s is fine; a rewritten path that reaches the upstream with an
	// empty credential is not.
	for _, w := range []string{
		`@nocred_cf_prod_0 vars {file./run/credentials/caddy.service/cf-aig-token} ""`,
		`respond @nocred_cf_prod_0 "route cf-prod unavailable: credential not installed" 503`,
	} {
		if !strings.Contains(block, w) {
			t.Errorf("path_map route lost its fail-closed guard: missing %q in:\n%s", w, block)
		}
	}
}

// TestPathMapRoutesThroughCaddy is the behavioural test: it runs the rendered
// config on a real caddy and asserts the upstream path each request lands on.
// Only one rewrite may take effect per request — if two did, the upstream base
// would be prepended twice — and the explicitly-addressed path must keep
// reaching what it always reached.
func TestPathMapRoutesThroughCaddy(t *testing.T) {
	bin := caddyBinOrSkip(t)

	var got struct {
		mu    sync.Mutex
		paths []string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.mu.Lock()
		got.paths = append(got.paths, r.URL.Path)
		got.mu.Unlock()
		fmt.Fprintf(w, "%s", r.URL.Path)
	}))
	defer upstream.Close()

	work := t.TempDir()
	sockDir := filepath.Join(work, "sockets")
	credsDir := filepath.Join(work, "creds")
	for _, d := range []string{sockDir, credsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(credsDir, "cf-aig-token"), []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}

	o := baseOptions()
	o.SocketDir = sockDir
	o.CredentialsDir = credsDir
	o.AdminAddr = "off"
	o.GracePeriod = "1s"
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
	o.InstalledSecrets = map[string]bool{"cf-aig-token": true}
	o.Routes = []config.Route{
		{
			Name: "cf-prod", Prefix: "/cloudflare/prod", Gateway: "prod",
			Upstream: upstream.URL + "/v1/ACCT/prod",
			PathMap:  config.GatewayPathMap,
			Inject:   []config.Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token}"}},
		},
		// The REST route's mapping has the opposite shape: /v1/messages is the
		// one path it must NOT rewrite, because the upstream base already ends
		// where that suffix belongs.
		{
			Name: "cf-rest-prod", Prefix: "/cloudflare-rest/prod", Gateway: "prod",
			Upstream: upstream.URL + "/client/v4/accounts/ACCT/ai",
			PathMap:  config.RestPathMap,
			Inject: []config.Header{
				{Header: "Authorization", Value: "Bearer {secret:cf-aig-token}"},
				{Header: "cf-aig-gateway-id", Value: "prod"},
			},
		},
	}
	cfPath := filepath.Join(work, "Caddyfile")
	if err := os.WriteFile(cfPath, []byte(render(t, o)), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "run", "--config", cfPath, "--adapter", "caddyfile")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	sock := filepath.Join(sockDir, "dev.sock")
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	deadline := time.Now().Add(20 * time.Second)
	for {
		c, err := net.Dial("unix", sock)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("caddy never bound %s: %v", sock, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	cases := []struct{ req, want string }{
		// The three aliases, one per API shape pi speaks.
		{"/cloudflare/prod/v1/messages", "/v1/ACCT/prod/anthropic/v1/messages"},
		{"/cloudflare/prod/responses", "/v1/ACCT/prod/openai/responses"},
		{"/cloudflare/prod/chat/completions", "/v1/ACCT/prod/compat/chat/completions"},
		// The explicit form claude and codex use, which must be untouched.
		{"/cloudflare/prod/anthropic/v1/messages", "/v1/ACCT/prod/anthropic/v1/messages"},
		{"/cloudflare/prod/openai/responses", "/v1/ACCT/prod/openai/responses"},
		// Unmapped paths keep the plain pass-through.
		{"/cloudflare/prod/some/other/path", "/v1/ACCT/prod/some/other/path"},
		// Matching is by whole path, not by prefix: this is not the mapped path.
		{"/cloudflare/prod/v1/messages/extra", "/v1/ACCT/prod/v1/messages/extra"},

		// REST route: /v1/messages must arrive unrewritten, the two OpenAI
		// shapes must gain the /v1 the endpoint expects.
		{"/cloudflare-rest/prod/v1/messages", "/client/v4/accounts/ACCT/ai/v1/messages"},
		{"/cloudflare-rest/prod/chat/completions", "/client/v4/accounts/ACCT/ai/v1/chat/completions"},
		{"/cloudflare-rest/prod/responses", "/client/v4/accounts/ACCT/ai/v1/responses"},
	}
	for _, c := range cases {
		resp, err := hc.Post("http://caddy"+c.req, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: %v", c.req, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s: status %d", c.req, resp.StatusCode)
			continue
		}
		if string(body) != c.want {
			t.Errorf("%s reached %q, want %q", c.req, body, c.want)
		}
	}
}

// TestPathMapWithPathlessUpstream covers the branch where the upstream carries
// no path of its own: the mappings must still render, and there must be no
// pass-through rewrite at all (there is nothing to prepend). Untested branches
// in a renderer that emits security-relevant config are how silent breakage
// gets in.
func TestPathMapWithPathlessUpstream(t *testing.T) {
	o := baseOptions()
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
	o.InstalledSecrets = map[string]bool{"cf-aig-token": true, "gh-pat.basic": true}
	o.Routes = []config.Route{{
		Name: "bare", Prefix: "/bare", Gateway: config.AnyGateway,
		Upstream: "http://127.0.0.1:9911",
		PathMap:  []config.PathMap{{Path: "/a", To: "/b"}},
	}}
	block := routeBlock(t, render(t, o), "/bare")

	if !strings.Contains(block, "@map_bare_0 path /a") || !strings.Contains(block, "rewrite @map_bare_0 /b") {
		t.Errorf("mapping not rendered for a pathless upstream:\n%s", block)
	}
	// No upstream base to prepend, so neither a gated nor an ungated
	// pass-through rewrite should appear.
	if strings.Contains(block, "rewrite * ") || strings.Contains(block, "@unmapped_bare") {
		t.Errorf("pathless upstream should emit no pass-through rewrite:\n%s", block)
	}
	validateWithCaddy(t, render(t, o))
}

// TestGoldenPathMap keeps the package's golden-file discipline covering the
// path_map output shape, including the REST route's mapping, which differs from
// the provider-native one.
func TestGoldenPathMap(t *testing.T) {
	m := config.Meta{AccountID: "ACCT", Gateways: []string{"prod"}}
	o := baseOptions()
	o.Routes = config.DefaultRoutes(m)
	o.Containers = []state.Container{{Name: "dev", Gateway: "prod"}}
	o.InstalledSecrets = map[string]bool{
		config.GatewaySecret("prod"): true, "gh-pat": true, "gh-pat.basic": true,
	}
	checkGolden(t, "pathmap.Caddyfile", render(t, o))
}
