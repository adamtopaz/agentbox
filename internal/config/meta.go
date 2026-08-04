package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
)

// Meta holds the non-secret Cloudflare AI Gateway coordinates
// (/etc/agentbox/agentbox.json).
//
// Gateways is the set of AI Gateways this host may use. There is deliberately
// no default: every gateway is named explicitly, each gets its own route, and
// each carries its own credential (`cf-aig-token-<gateway>`). Cloudflare
// cannot scope a token to one gateway — any token with AI Gateway Run reaches
// them all — so separate tokens buy revocation and attribution granularity
// rather than capability isolation. The isolation that *is* enforceable
// happens here: a container is created against one gateway and its Caddy site
// carries only that gateway's route.
type Meta struct {
	AccountID string   `json:"account_id"`
	Gateways  []string `json:"gateways"`
}

// AnyGateway marks a route usable by every container, whatever gateway it was
// created against (the GitHub routes, for instance).
const AnyGateway = "*"

// GatewaySecret is the credential name for a gateway's Cloudflare token.
func GatewaySecret(gateway string) string { return "cf-aig-token-" + gateway }

// ValidGatewayName reports whether a gateway name is usable. It has to survive
// being a path segment, a route name, and part of a secret name.
func ValidGatewayName(s string) bool { return gatewayRE.MatchString(s) }

// HasGateway reports whether the named gateway is configured.
func (m Meta) HasGateway(name string) bool {
	return slices.Contains(m.Gateways, name)
}

var (
	idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	// Gateway names become path segments, route names and secret-name
	// suffixes, so they are held to the strictest of those: the route-name
	// slug rule.
	// Capped at 50 so GatewaySecret(name) stays inside credstore's 64-byte
	// credential-name limit; otherwise a gateway would validate here and then
	// be impossible to store a token for.
	gatewayRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,49}$`)
)

func (m Meta) Validate() error {
	if !idRE.MatchString(m.AccountID) {
		return fmt.Errorf("invalid account_id %q", m.AccountID)
	}
	if len(m.Gateways) == 0 {
		return errors.New("no gateways configured; list at least one in \"gateways\"")
	}
	seen := map[string]bool{}
	for _, g := range m.Gateways {
		if g == AnyGateway {
			return fmt.Errorf("%q is not a gateway name; it is the marker for a universal route", AnyGateway)
		}
		if !ValidGatewayName(g) {
			return fmt.Errorf("invalid gateway name %q (lowercase letters, digits and dashes)", g)
		}
		if seen[g] {
			return fmt.Errorf("duplicate gateway %q", g)
		}
		seen[g] = true
	}
	return nil
}

// LoadMeta reads and validates agentbox.json.
func LoadMeta(path string) (Meta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return Meta{}, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// GatewayBase is the Cloudflare AI Gateway root for an account. Everything
// after it is `<gateway-name>/<provider>/<provider path>`.
func GatewayBase(accountID string) string {
	return "https://gateway.ai.cloudflare.com/v1/" + accountID
}

// GatewayPrefix is the container-visible prefix for Cloudflare AI Gateway
// traffic. Each configured gateway gets its own route beneath it:
// `/cloudflare/<gateway>/...` maps onto
// `https://gateway.ai.cloudflare.com/v1/<account>/<gateway>/...`, carries that
// gateway's own credential, and is rendered only into the sites of containers
// created against it.
const GatewayPrefix = "/cloudflare"

// DefaultRoutes is the day-one route table (spec §4), parameterized by the
// gateway coordinates.
func DefaultRoutes(m Meta) []Route {
	ghToken := []Header{{Header: "Authorization", Value: "Bearer {secret:gh-pat}"}}
	var routes []Route

	// One route per configured gateway, each injecting that gateway's own
	// credential. The prefix is stripped and the account base prepended, so
	//   /cloudflare/<gw>/anthropic/v1/messages
	//   /cloudflare/<gw>/openai/chat/completions
	// reach the provider-native endpoints of that gateway.
	//
	// /anthropic and /openai are deliberately left unused, reserved for
	// talking to those APIs directly rather than through Cloudflare.
	for _, g := range m.Gateways {
		routes = append(routes, Route{
			Name:     "cloudflare-" + g,
			Prefix:   GatewayPrefix + "/" + g,
			Gateway:  g,
			Upstream: GatewayBase(m.AccountID) + "/" + g,
			Inject: []Header{{
				Header: "cf-aig-authorization",
				Value:  "Bearer {secret:" + GatewaySecret(g) + "}",
			}},
		})
	}

	return append(routes, []Route{
		{Name: "github-api", Gateway: AnyGateway, Prefix: "/github-api", Upstream: "https://api.github.com", Inject: ghToken},
		{Name: "github-git", Gateway: AnyGateway, Prefix: "/github-git", Upstream: "https://github.com",
			Inject: []Header{{Header: "Authorization", Value: "{basic:x-access-token:gh-pat}"}}},

		// Host routes for the `gh` CLI, which has no base-URL override but
		// does have http_unix_socket: it dials our socket in plain HTTP while
		// still addressing the real hostnames.
		{Name: "gh-api", Gateway: AnyGateway, Host: "api.github.com", Upstream: "https://api.github.com", Inject: ghToken},
		{Name: "gh-uploads", Gateway: AnyGateway, Host: "uploads.github.com", Upstream: "https://uploads.github.com", Inject: ghToken},
		// Asset downloads redirect here with a signed URL; they need no
		// credential, and must not be sent one.
		{Name: "gh-objects", Gateway: AnyGateway, Host: "objects.githubusercontent.com", Upstream: "https://objects.githubusercontent.com"},
		{Name: "gh-codeload", Gateway: AnyGateway, Host: "codeload.github.com", Upstream: "https://codeload.github.com"},
	}...)
}
