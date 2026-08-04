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

// GatewayPathMap lets one base URL — /cloudflare/<gateway> — serve all three
// of the gateway's provider APIs, by mapping the API-shape suffix a client
// appends onto the provider segment Cloudflare expects.
//
// This is for clients that accept a single base URL per *provider* but talk
// several API shapes underneath it. pi is the case in hand: its
// cloudflare-ai-gateway provider covers Anthropic, OpenAI and Workers AI
// models, its catalog gives each model a base URL ending in a different
// segment, and it offers no per-model base-URL override — so without this,
// pointing that provider at the proxy necessarily breaks two families out of
// three. Verified against pi 0.83.0 by observing the requests it emits.
//
// Each mapping is an alias, not a new capability: same upstream, same gateway,
// same injected credential, and the explicitly-addressed form keeps working
// untouched (which is what claude and codex use via ANTHROPIC_BASE_URL and
// OPENAI_BASE_URL).
var GatewayPathMap = []PathMap{
	{Path: "/v1/messages", To: "/anthropic/v1/messages"},        // api: anthropic-messages
	{Path: "/responses", To: "/openai/responses"},               // api: openai-responses
	{Path: "/chat/completions", To: "/compat/chat/completions"}, // api: openai-completions
}

// RestBase is Cloudflare's account-level AI REST API root. It is a different
// endpoint from GatewayBase, not a different spelling of it: the gateway is
// named in a `cf-aig-gateway-id` header instead of the path, auth is a plain
// `Authorization: Bearer` Cloudflare API token instead of
// `cf-aig-authorization`, and the model is named `provider/model` in the
// request body instead of being implied by a path segment.
//
// It exists here because some models are reachable only this way. Cloudflare's
// docs call this and `env.AI.run()` the "Unified Billing endpoints", and the
// newest models (claude-fable-5 at the time of writing) list only those two as
// their call paths — no gateway.ai.cloudflare.com URL. On the provider-native
// passthrough such a model gets no credential attached at all and is forwarded
// bare, so the provider answers `401 x-api-key header is required` — an error
// that reads like a proxy bug and is not one.
func RestBase(accountID string) string {
	return "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/ai"
}

// RestPrefix is the container-visible prefix for the REST API, one route per
// gateway so a container still reaches only its own.
const RestPrefix = "/cloudflare-rest"

// RestPathMap normalizes the OpenAI-shaped suffixes onto the REST API's own
// paths. `/v1/messages` needs no entry: RestBase + that suffix is already the
// correct URL, which is why the pass-through covers it.
var RestPathMap = []PathMap{
	{Path: "/chat/completions", To: "/v1/chat/completions"},
	{Path: "/responses", To: "/v1/responses"},
}

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
			PathMap:  GatewayPathMap,
			Inject: []Header{{
				Header: "cf-aig-authorization",
				Value:  "Bearer {secret:" + GatewaySecret(g) + "}",
			}},
		})
		// The REST API for the same gateway. It reuses that gateway's token:
		// both this and cf-aig-authorization take a Cloudflare API token, and
		// whether one token satisfies both depends on the permissions it was
		// minted with (`AI Gateway` / `AI Gateway Run`). If it does not, this
		// route answers 403 and wants its own secret.
		//
		// cf-aig-gateway-id is injected rather than taken from the request, so
		// a container cannot name a gateway at all here — pinning is stronger
		// on this route than on the path-addressed one, not weaker.
		routes = append(routes, Route{
			Name:     "cloudflare-rest-" + g,
			Prefix:   RestPrefix + "/" + g,
			Gateway:  g,
			Upstream: RestBase(m.AccountID),
			PathMap:  RestPathMap,
			Inject: []Header{
				{Header: "Authorization", Value: "Bearer {secret:" + GatewaySecret(g) + "}"},
				{Header: "cf-aig-gateway-id", Value: g},
			},
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
