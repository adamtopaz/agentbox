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
		{Name: "anthropic", Prefix: "/anthropic",
			Upstream: "https://gateway.ai.cloudflare.com/v1/acct/gw/anthropic",
			Inject:   []Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token}"}}},
		{Name: "github-git", Prefix: "/github-git", Upstream: "https://github.com",
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
	c := Config{Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://example.com/base/"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Routes[0].Upstream != "https://example.com/base" {
		t.Fatalf("upstream not normalized: %q", c.Routes[0].Upstream)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]Config{
		"empty":            {},
		"bad name":         {Routes: []Route{{Name: "Bad_Name", Prefix: "/a", Upstream: "https://x.com"}}},
		"dup name":         {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com"}, {Name: "a", Prefix: "/b", Upstream: "https://x.com"}}},
		"bad prefix":       {Routes: []Route{{Name: "a", Prefix: "/a/b", Upstream: "https://x.com"}}},
		"no slash prefix":  {Routes: []Route{{Name: "a", Prefix: "a", Upstream: "https://x.com"}}},
		"dup prefix":       {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com"}, {Name: "b", Prefix: "/a", Upstream: "https://x.com"}}},
		"relative up":      {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "example.com"}}},
		"ftp upstream":     {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "ftp://x.com"}}},
		"query upstream":   {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com/p?q=1"}}},
		"userinfo":         {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://u:p@x.com"}}},
		"bad header":       {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X Y", Value: "v"}}}}},
		"unknown template": {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "{nope:x}"}}}}},
		"stray brace":      {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "ab}cd"}}}}},
		"quote in value":   {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: `a"b`}}}}},
		"newline in value": {Routes: []Route{{Name: "a", Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "a\nb"}}}}},
		"basic user clash": {Routes: []Route{
			{Name: "a", Prefix: "/a", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "{basic:u1:tok}"}}},
			{Name: "b", Prefix: "/b", Upstream: "https://x.com", Inject: []Header{{Header: "X", Value: "{basic:u2:tok}"}}},
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
	good := `{"routes":[{"name":"a","prefix":"/a","upstream":"https://x.com","inject":[{"header":"X","value":"{secret:tok}"}]}]}`
	if err := os.WriteFile(p, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}

	// Unknown fields fail closed.
	bad := `{"routes":[{"name":"a","prefix":"/a","upstream":"https://x.com","surprise":true}]}`
	if err := os.WriteFile(p, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestMeta(t *testing.T) {
	if err := (Meta{AccountID: "abc-123", GatewayID: "gw_1"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Meta{{}, {AccountID: "a b", GatewayID: "g"}, {AccountID: "a", GatewayID: "g/w"}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
	routes := DefaultRoutes(Meta{AccountID: "ACCT", GatewayID: "GW"})
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
	}
	if prefixes != 3 || hosts != 4 {
		t.Fatalf("day-one table = %d prefix + %d host routes, want 3 + 4", prefixes, hosts)
	}
	// One route serves every Cloudflare gateway: the gateway name is the next
	// path segment, so /cloudflare/<gw>/anthropic/v1/messages reaches
	// https://gateway.ai.cloudflare.com/v1/<acct>/<gw>/anthropic/v1/messages.
	var cf *Route
	for i, r := range routes {
		if r.Name == "cloudflare" {
			cf = &routes[i]
		}
		// /anthropic and /openai stay free for talking to those APIs directly.
		if r.Prefix == "/anthropic" || r.Prefix == "/openai" {
			t.Errorf("%q must stay reserved for direct (non-Cloudflare) API access", r.Prefix)
		}
	}
	if cf == nil {
		t.Fatal("no /cloudflare route")
	}
	if cf.Prefix != "/cloudflare" || cf.Upstream != "https://gateway.ai.cloudflare.com/v1/ACCT" {
		t.Fatalf("cloudflare route = %+v", *cf)
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
		"neither":       {Routes: []Route{{Name: "a", Upstream: "https://x.com"}}},
		"both":          {Routes: []Route{{Name: "a", Prefix: "/a", Host: "x.com", Upstream: "https://x.com"}}},
		"bad host":      {Routes: []Route{{Name: "a", Host: "not a host", Upstream: "https://x.com"}}},
		"host no dot":   {Routes: []Route{{Name: "a", Host: "localhost", Upstream: "https://x.com"}}},
		"host trailing": {Routes: []Route{{Name: "a", Host: "x.com.", Upstream: "https://x.com"}}},
		"dup host": {Routes: []Route{
			{Name: "a", Host: "x.com", Upstream: "https://x.com"},
			{Name: "b", Host: "x.com", Upstream: "https://y.com"},
		}},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	ok := Config{Routes: []Route{
		{Name: "a", Prefix: "/a", Upstream: "https://x.com"},
		{Name: "b", Host: "api.x.com", Upstream: "https://api.x.com"},
	}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Routes[0].Selector() != "/a" || ok.Routes[1].Selector() != "api.x.com" {
		t.Fatal("selectors wrong")
	}
}
