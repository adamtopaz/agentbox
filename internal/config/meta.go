package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Meta holds the non-secret Cloudflare AI Gateway coordinates
// (/etc/agentbox/agentbox.json).
//
// GatewayID is the *default* gateway: routing does not depend on it, since
// `/cloudflare/<gateway>/...` names the gateway in the path. It is what the
// image wires agents to out of the box, so an agent that is never told
// otherwise bills to this one.
type Meta struct {
	AccountID string `json:"account_id"`
	GatewayID string `json:"gateway_id"`
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (m Meta) Validate() error {
	if !idRE.MatchString(m.AccountID) {
		return fmt.Errorf("invalid account_id %q", m.AccountID)
	}
	if !idRE.MatchString(m.GatewayID) {
		return fmt.Errorf("invalid gateway_id %q", m.GatewayID)
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
// traffic. `/cloudflare/<gateway>/...` maps straight onto
// `https://gateway.ai.cloudflare.com/v1/<account>/<gateway>/...`, so any
// number of gateways are reachable through one route with no config change —
// the gateway name is just the next path segment.
const GatewayPrefix = "/cloudflare"

// DefaultRoutes is the day-one route table (spec §4), parameterized by the
// gateway coordinates.
func DefaultRoutes(m Meta) []Route {
	aig := []Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token}"}}
	ghToken := []Header{{Header: "Authorization", Value: "Bearer {secret:gh-pat}"}}
	return []Route{
		// Path-prefix routes: agents point their base URL at 127.0.0.1:8787.
		//
		// One route covers every gateway on the account. The prefix is
		// stripped and the account base prepended, so
		//   /cloudflare/<gw>/anthropic/v1/messages
		//   /cloudflare/<gw>/openai/chat/completions
		// reach the provider-native endpoints of whichever gateway is named.
		//
		// /anthropic and /openai are deliberately left unused, reserved for
		// talking to those APIs directly rather than through Cloudflare.
		{Name: "cloudflare", Prefix: GatewayPrefix, Upstream: GatewayBase(m.AccountID), Inject: aig},
		{Name: "github-api", Prefix: "/github-api", Upstream: "https://api.github.com", Inject: ghToken},
		{Name: "github-git", Prefix: "/github-git", Upstream: "https://github.com",
			Inject: []Header{{Header: "Authorization", Value: "{basic:x-access-token:gh-pat}"}}},

		// Host routes for the `gh` CLI, which has no base-URL override but
		// does have http_unix_socket: it dials our socket in plain HTTP while
		// still addressing the real hostnames.
		{Name: "gh-api", Host: "api.github.com", Upstream: "https://api.github.com", Inject: ghToken},
		{Name: "gh-uploads", Host: "uploads.github.com", Upstream: "https://uploads.github.com", Inject: ghToken},
		// Asset downloads redirect here with a signed URL; they need no
		// credential, and must not be sent one.
		{Name: "gh-objects", Host: "objects.githubusercontent.com", Upstream: "https://objects.githubusercontent.com"},
		{Name: "gh-codeload", Host: "codeload.github.com", Upstream: "https://codeload.github.com"},
	}
}
