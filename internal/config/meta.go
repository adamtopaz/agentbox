package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Meta holds the non-secret Cloudflare AI Gateway coordinates
// (/etc/agentbox/agentbox.json).
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

// DefaultRoutes is the day-one route table (spec §4), parameterized by the
// gateway coordinates.
func DefaultRoutes(m Meta) []Route {
	gw := "https://gateway.ai.cloudflare.com/v1/" + m.AccountID + "/" + m.GatewayID
	aig := []Header{{Header: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token}"}}
	ghToken := []Header{{Header: "Authorization", Value: "Bearer {secret:gh-pat}"}}
	return []Route{
		// Path-prefix routes: agents point their base URL at 127.0.0.1:8787.
		{Name: "anthropic", Prefix: "/anthropic", Upstream: gw + "/anthropic", Inject: aig},
		{Name: "openai", Prefix: "/openai", Upstream: gw + "/openai", Inject: aig},
		{Name: "cf-gateway", Prefix: "/cf-gateway", Upstream: gw, Inject: aig},
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
