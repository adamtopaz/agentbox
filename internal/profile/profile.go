// Package profile contains optional, provider-specific compositions of the
// generic domain model. Profiles do not receive privileged access to the
// daemon; applying one is exactly equivalent to submitting its ordinary
// routes through the public control service.
package profile

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"agentbox/internal/domain"
)

var accountIDRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

// ReplaceOwned replaces routes selected by owns while preserving all other
// operator-managed routes. It is the generic merge primitive profiles use.
func ReplaceOwned(existing, generated []domain.Route, owns func(domain.Route) bool) []domain.Route {
	out := append([]domain.Route(nil), generated...)
	for _, route := range existing {
		if !owns(route) {
			out = append(out, route)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func GitHubRoutes() []domain.Route {
	bearer := []domain.HeaderValue{{Name: "Authorization", Value: "Bearer {credential:github}"}}
	return []domain.Route{
		{Name: "github-api", Scope: "*", Match: domain.Match{PathPrefix: "/github-api"}, Upstream: "https://api.github.com", StripPrefix: true, SetHeaders: bearer},
		{Name: "github-git", Scope: "*", Match: domain.Match{PathPrefix: "/github-git"}, Upstream: "https://github.com", StripPrefix: true,
			SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "Basic {basic:x-access-token:credential:github}"}}},
		{Name: "github-host-api", Scope: "*", Match: domain.Match{Host: "api.github.com"}, Upstream: "https://api.github.com", SetHeaders: bearer},
		{Name: "github-host-uploads", Scope: "*", Match: domain.Match{Host: "uploads.github.com"}, Upstream: "https://uploads.github.com", SetHeaders: bearer},
		{Name: "github-host-objects", Scope: "*", Match: domain.Match{Host: "objects.githubusercontent.com"}, Upstream: "https://objects.githubusercontent.com"},
		{Name: "github-host-codeload", Scope: "*", Match: domain.Match{Host: "codeload.github.com"}, Upstream: "https://codeload.github.com"},
	}
}

func OwnsGitHub(route domain.Route) bool { return strings.HasPrefix(route.Name, "github-") }

func CloudflareRoutes(accountID string, gateways []string) ([]domain.Route, error) {
	if !accountIDRE.MatchString(accountID) {
		return nil, fmt.Errorf("Cloudflare account ID must be 32 lowercase hexadecimal characters")
	}
	seen := map[string]bool{}
	var routes []domain.Route
	for _, gateway := range gateways {
		if gateway == domain.UniversalScope || !domain.ValidScope(gateway) {
			return nil, fmt.Errorf("invalid gateway %q", gateway)
		}
		if seen[gateway] {
			return nil, fmt.Errorf("duplicate gateway %q", gateway)
		}
		seen[gateway] = true
		routes = append(routes, domain.Route{
			Name: "cloudflare-" + gateway, Scope: gateway,
			Match: domain.Match{PathPrefix: "/cloudflare/" + gateway}, StripPrefix: true,
			Upstream: "https://gateway.ai.cloudflare.com/v1/" + accountID + "/" + gateway,
			SetHeaders: []domain.HeaderValue{{
				Name: "cf-aig-authorization", Value: "Bearer {secret:cf-aig-token-" + gateway + "}",
			}},
		})
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("at least one gateway is required")
	}
	return routes, nil
}

func OwnsCloudflare(route domain.Route) bool { return strings.HasPrefix(route.Name, "cloudflare-") }

// CloudflareContainerScript returns gateway-specific client configuration.
// It writes only non-secret URLs and dummy keys inside the container.
func CloudflareContainerScript(gateway string) (string, error) {
	if gateway == domain.UniversalScope || !domain.ValidScope(gateway) {
		return "", fmt.Errorf("invalid gateway %q", gateway)
	}
	base := "http://127.0.0.1:8787/cloudflare/" + gateway
	return `set -eu
GW=` + base + `
cat > /etc/profile.d/agentbox-cloudflare.sh <<EOF
export AGENTBOX_SCOPE=` + gateway + `
export ANTHROPIC_BASE_URL=$GW/anthropic
export OPENAI_BASE_URL=$GW/openai
export ANTHROPIC_API_KEY=agentbox-dummy
export OPENAI_API_KEY=agentbox-dummy
export GH_TOKEN=agentbox-dummy
EOF
chmod 0644 /etc/profile.d/agentbox-cloudflare.sh

touch /etc/environment
awk '/^# BEGIN agentbox-cloudflare$/{skip=1} /^# END agentbox-cloudflare$/{skip=0; next} !skip{print}' /etc/environment > /etc/environment.agentbox
{
  cat /etc/environment.agentbox
  echo '# BEGIN agentbox-cloudflare'
  echo 'AGENTBOX_SCOPE=` + gateway + `'
  echo "ANTHROPIC_BASE_URL=$GW/anthropic"
  echo "OPENAI_BASE_URL=$GW/openai"
  echo 'ANTHROPIC_API_KEY=agentbox-dummy'
  echo 'OPENAI_API_KEY=agentbox-dummy'
  echo 'GH_TOKEN=agentbox-dummy'
  echo '# END agentbox-cloudflare'
} > /etc/environment
rm -f /etc/environment.agentbox

install -d -o agent -g agent -m 0755 /home/agent/.codex /home/agent/.pi/agent
cat > /home/agent/.codex/config.toml <<EOF
model_provider = "agentbox"
[model_providers.agentbox]
name = "agentbox proxy"
base_url = "$GW/openai"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
EOF
cat > /home/agent/.pi/agent/models.json <<EOF
{
  "providers": {
    "anthropic": { "baseUrl": "$GW/anthropic" },
    "openai": { "baseUrl": "$GW/openai" },
    "cloudflare-ai-gateway": { "baseUrl": "$GW" }
  }
}
EOF
chown -R agent:agent /home/agent/.codex /home/agent/.pi
chmod 0644 /home/agent/.codex/config.toml /home/agent/.pi/agent/models.json
`, nil
}
