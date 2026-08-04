package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{Routes: []Route{
		{Name: "anthropic", Gateway: AnyGateway, Prefix: "/anthropic",
			Upstream: "https://gateway.ai.cloudflare.com/v1/acct/gw/anthropic",
			Inject:   []Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token}"}}},
		{Name: "github-git", Gateway: AnyGateway, Prefix: "/github-git", Upstream: "https://github.com",
			Inject: []Header{{Header: "Authorization", Value: "{basic:x-access-token:gh-pat}"}}},
	}}
}

func TestValidateOK(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateNormalizesTrailingSlash(t *testing.T) {
	c := Config{Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://example.com/base/"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Routes[0].Upstream != "https://example.com/base" {
		t.Fatalf("upstream not normalized: %q", c.Routes[0].Upstream)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]Config{
		"empty":             {},
		"bad name":          {Routes: []Route{{Name: "Bad_Name", Prefix: "/a", Upstream: "https://x.com"}}},
		"dup name":          {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com"}, {Name: "a", Gateway: AnyGateway, Prefix: "/b", Upstream: "https://x.com"}}},
		"bad prefix":        {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a//b", Upstream: "https://x.com"}}},
		"prefix trailing /": {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a/", Upstream: "https://x.com"}}},
		"prefix uppercase":  {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/A", Upstream: "https://x.com"}}},
		"no slash prefix":   {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "a", Upstream: "https://x.com"}}},
		"dup prefix":        {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com"}, {Name: "b", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com"}}},
		"relative up":       {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "example.com"}}},
		"ftp upstream":      {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "ftp://x.com"}}},
		"query upstream":    {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com/p?q=1"}}},
		"userinfo":          {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://u:p@x.com"}}},
		"bad header":        {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X Y", Value: "v"}}}}},
		"unknown template":  {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "{nope:x}"}}}}},
		"stray brace":       {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "ab}cd"}}}}},
		"quote in value":    {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: `a"b`}}}}},
		"newline in value":  {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "a\nb"}}}}},
		"basic user clash": {Routes: []Route{
			{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "{basic:u1:tok}"}}},
			{Name: "b", Gateway: AnyGateway, Prefix: "/b", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "{basic:u2:tok}"}}},
		}},
	}
	for name, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParseValue(t *testing.T) {
	parts, err := ParseValue("Bearer {secret:tok} and {basic:user:tok2}!")
	if err != nil {
		t.Fatal(err)
	}
	want := []ValuePart{
		{Literal: "Bearer "},
		{Secret: "tok"},
		{Literal: " and "},
		{BasicUser: "user", BasicSecret: "tok2"},
		{Literal: "!"},
	}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("got %+v, want %+v", parts, want)
	}

	for _, bad := range []string{"{", "}", "{secret:}", "{secret:BAD NAME}", "{basic:u}", "{basic:u:}", "a{b{c}d}", "{secret:x", "{}"} {
		if _, err := ParseValue(bad); err == nil {
			t.Errorf("ParseValue(%q): expected error", bad)
		}
	}
}

func TestSecretNamesAndBasics(t *testing.T) {
	c := validConfig()
	if got := c.SecretNames(); !reflect.DeepEqual(got, []string{"cf-aig-token"}) {
		t.Fatalf("SecretNames = %v", got)
	}
	if got := c.BasicSecrets(); !reflect.DeepEqual(got, map[string]string{"gh-pat": "x-access-token"}) {
		t.Fatalf("BasicSecrets = %v", got)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "routes.json")
	good := `{"routes":[{"name":"a","gateway":"*","prefix":"/a","upstream":"https://x.com","inject":[{"header":"X","value":"{secret:tok}"}]}]}`
	if err := os.WriteFile(p, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}

	// A route that omits "gateway" must be refused: silently treating it as
	// universal is what let a legacy route dissolve the pinning boundary.
	nogw := `{"routes":[{"name":"a","prefix":"/a","upstream":"https://x.com"}]}`
	if err := os.WriteFile(p, []byte(nogw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Fatalf("expected a missing-gateway error, got %v", err)
	}

	// Unknown fields fail closed.
	bad := `{"routes":[{"name":"a","gateway":"*","prefix":"/a","upstream":"https://x.com","surprise":true}]}`
	if err := os.WriteFile(p, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestMeta(t *testing.T) {
	if err := (Meta{AccountID: "abc-123", Gateways: []string{"prod"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Meta{
		{},
		{AccountID: "a b", Gateways: []string{"g"}},
		{AccountID: "a"}, // no gateways
		{AccountID: "a", Gateways: []string{"Bad Gateway"}},
		{AccountID: "a", Gateways: []string{"g", "g"}}, // duplicate
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
	routes := DefaultRoutes(Meta{AccountID: "ACCT", Gateways: []string{"prod", "experiments"}})
	c := Config{Routes: routes}
	if err := c.Validate(); err != nil {
		t.Fatalf("default routes must validate: %v", err)
	}
	var prefixes, hosts int
	for _, r := range routes {
		if r.IsHostRoute() {
			hosts++
		} else {
			prefixes++
		}
		if r.Prefix == "/anthropic" || r.Prefix == "/openai" {
			t.Errorf("%q must stay reserved for direct (non-Cloudflare) API access", r.Prefix)
		}
	}
	// Two prefix routes per gateway (provider-native + REST), plus the two
	// github prefix routes.
	if prefixes != 6 || hosts != 4 {
		t.Fatalf("table = %d prefix + %d host routes, want 6 + 4 (2 gateways x 2 routes + 2 github)", prefixes, hosts)
	}

	// Each gateway gets its own route, tagged with its gateway, injecting its
	// own credential — that separation is the point of per-gateway tokens.
	byGateway := map[string]Route{}
	for _, r := range routes {
		// The provider-native route only; the REST route for the same gateway
		// is asserted separately below.
		if r.Gateway != "" && r.Gateway != AnyGateway && r.Prefix == GatewayPrefix+"/"+r.Gateway {
			byGateway[r.Gateway] = r
		}
	}
	if len(byGateway) != 2 {
		t.Fatalf("want one route per gateway, got %d", len(byGateway))
	}
	for _, gw := range []string{"prod", "experiments"} {
		r, ok := byGateway[gw]
		if !ok {
			t.Fatalf("no route for gateway %q", gw)
		}
		if r.Prefix != "/cloudflare/"+gw {
			t.Errorf("gateway %q prefix = %q", gw, r.Prefix)
		}
		if r.Upstream != "https://gateway.ai.cloudflare.com/v1/ACCT/"+gw {
			t.Errorf("gateway %q upstream = %q", gw, r.Upstream)
		}
		want := "Bearer {secret:cf-aig-token-" + gw + "}"
		if len(r.Inject) != 1 || r.Inject[0].Value != want {
			t.Errorf("gateway %q injects %+v, want %q", gw, r.Inject, want)
		}
	}
	// No two gateways may share a credential.
	if byGateway["prod"].Inject[0].Value == byGateway["experiments"].Inject[0].Value {
		t.Error("gateways share a credential")
	}
	// gh follows redirects to the asset host with a signed URL; sending the
	// PAT there would leak it outside the API surface it was scoped for.
	for _, r := range routes {
		if r.Host == "objects.githubusercontent.com" && len(r.Inject) != 0 {
			t.Errorf("route %q must not inject credentials", r.Name)
		}
	}
}

func TestRouteSelectors(t *testing.T) {
	bad := map[string]Config{
		"neither":       {Routes: []Route{{Name: "a", Gateway: AnyGateway, Upstream: "https://x.com"}}},
		"both":          {Routes: []Route{{Name: "a", Gateway: AnyGateway, Prefix: "/a", Host: "x.com", Upstream: "https://x.com"}}},
		"bad host":      {Routes: []Route{{Name: "a", Gateway: AnyGateway, Host: "not a host", Upstream: "https://x.com"}}},
		"host no dot":   {Routes: []Route{{Name: "a", Gateway: AnyGateway, Host: "localhost", Upstream: "https://x.com"}}},
		"host trailing": {Routes: []Route{{Name: "a", Gateway: AnyGateway, Host: "x.com.", Upstream: "https://x.com"}}},
		"dup host": {Routes: []Route{
			{Name: "a", Gateway: AnyGateway, Host: "x.com", Upstream: "https://x.com"},
			{Name: "b", Gateway: AnyGateway, Host: "x.com", Upstream: "https://y.com"},
		}},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	ok := Config{Routes: []Route{
		{Name: "a", Gateway: AnyGateway, Prefix: "/a", Upstream: "https://x.com"},
		{Name: "b", Gateway: AnyGateway, Host: "api.x.com", Upstream: "https://api.x.com"},
	}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Routes[0].Selector() != "/a" || ok.Routes[1].Selector() != "api.x.com" {
		t.Fatal("selectors wrong")
	}
}

func TestPathMapValidation(t *testing.T) {
	base := func(pm []PathMap, host string) *Config {
		r := Route{Name: "cf", Gateway: "prod", Upstream: "https://gateway.ai.cloudflare.com/v1/A/prod", PathMap: pm}
		if host != "" {
			r.Host = host
		} else {
			r.Prefix = "/cloudflare/prod"
		}
		return &Config{Routes: []Route{r}}
	}

	if err := base(GatewayPathMap, "").Validate(); err != nil {
		t.Fatalf("the generated gateway mapping must validate: %v", err)
	}

	cases := []struct {
		name string
		pm   []PathMap
		host string
	}{
		{"host route", GatewayPathMap, "api.github.com"},
		{"relative path", []PathMap{{Path: "v1/messages", To: "/anthropic/v1/messages"}}, ""},
		{"traversal in target", []PathMap{{Path: "/v1/messages", To: "/anthropic/../openai"}}, ""},
		{"wildcard path", []PathMap{{Path: "/v1/*", To: "/anthropic/v1"}}, ""},
		{"empty target", []PathMap{{Path: "/v1/messages", To: ""}}, ""},
		{"empty path", []PathMap{{Path: "", To: "/anthropic"}}, ""},
		{"placeholder injection", []PathMap{{Path: "/v1/messages", To: "/{http.request.uri}"}}, ""},
		{"token break-out", []PathMap{{Path: "/v1/messages", To: `/a" "b`}}, ""},
		{"duplicate path", []PathMap{
			{Path: "/v1/messages", To: "/anthropic/v1/messages"},
			{Path: "/v1/messages", To: "/openai/v1/messages"},
		}, ""},
		// A target that is another entry's source. Caddy would not actually
		// chain these, but a table whose reach cannot be read off it defeats the
		// reason whole-path matching was chosen.
		{"chained mapping", []PathMap{
			{Path: "/a", To: "/b"},
			{Path: "/b", To: "/c"},
		}, ""},
		{"self-referential mapping", []PathMap{{Path: "/a", To: "/a"}}, ""},
	}
	for _, c := range cases {
		if err := base(c.pm, c.host).Validate(); err == nil {
			t.Errorf("%s: accepted %+v", c.name, c.pm)
		}
	}
}

// TestDefaultRoutesCarryGatewayPathMap pins the reason path_map exists: without
// it on the generated provider-native route, pointing pi's
// cloudflare-ai-gateway provider at /cloudflare/<gw> can only ever work for one
// of its three model families.
func TestDefaultRoutesCarryGatewayPathMap(t *testing.T) {
	routes := DefaultRoutes(Meta{AccountID: "ACCT", Gateways: []string{"prod", "bench"}})
	native, rest := 0, 0
	for _, r := range routes {
		switch {
		case strings.HasPrefix(r.Name, "cloudflare-rest-"):
			rest++
			if len(r.PathMap) != len(RestPathMap) {
				t.Errorf("route %q: path_map = %+v, want the REST mapping", r.Name, r.PathMap)
			}
			// /v1/messages must NOT be mapped here: RestBase already ends in
			// /ai, so the pass-through produces the correct URL. Mapping it
			// would double the /v1.
			for _, m := range r.PathMap {
				if m.Path == "/v1/messages" {
					t.Errorf("route %q must not map /v1/messages; the pass-through is already correct", r.Name)
				}
			}
			// The gateway is injected, never taken from the request, so a
			// container cannot select one here at all.
			var gotGatewayID bool
			for _, h := range r.Inject {
				if h.Header == "cf-aig-gateway-id" {
					gotGatewayID = true
					if h.Value != r.Gateway {
						t.Errorf("route %q injects gateway id %q, want %q", r.Name, h.Value, r.Gateway)
					}
				}
			}
			if !gotGatewayID {
				t.Errorf("route %q must inject cf-aig-gateway-id, or it reaches the account default gateway", r.Name)
			}
		case strings.HasPrefix(r.Name, "cloudflare-"):
			native++
			if len(r.PathMap) != len(GatewayPathMap) {
				t.Fatalf("route %q: path_map = %+v, want the gateway mapping", r.Name, r.PathMap)
			}
			// Each alias must land on the same upstream path the explicit form
			// reaches, so both spellings are interchangeable.
			for _, m := range r.PathMap {
				if !strings.HasSuffix(m.To, m.Path) {
					t.Errorf("route %q: mapping %q -> %q changes more than the provider segment", r.Name, m.Path, m.To)
				}
			}
		default:
			if len(r.PathMap) != 0 {
				t.Errorf("route %q should carry no path_map", r.Name)
			}
		}
	}
	if native != 2 || rest != 2 {
		t.Fatalf("want one provider-native and one REST route per gateway, got %d and %d", native, rest)
	}
}
