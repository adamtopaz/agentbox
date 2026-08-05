// Package profile composes provider-specific conveniences from Agentbox's
// generic profile, route, secret-reference, and credential-binding model.
package profile

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"agentbox/internal/domain"
)

var accountIDRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

func New(name string) (domain.Profile, error) {
	profile := domain.Profile{Name: name, Routes: []domain.Route{}, Credentials: map[string]string{}, Environment: map[string]string{}}
	ensureClientEnvironment(&profile)
	if err := domain.ValidateProfile(profile); err != nil {
		return domain.Profile{}, err
	}
	return profile, nil
}

func SetCloudflare(current domain.Profile, accountID, gateway, privateKey string) (domain.Profile, error) {
	if err := domain.ValidateProfile(current); err != nil {
		return domain.Profile{}, err
	}
	if !accountIDRE.MatchString(accountID) {
		return domain.Profile{}, fmt.Errorf("Cloudflare account ID must be 32 lowercase hexadecimal characters")
	}
	if !domain.ValidProfileName(gateway) {
		return domain.Profile{}, fmt.Errorf("invalid gateway %q", gateway)
	}
	if !domain.ValidKeyName(privateKey) {
		return domain.Profile{}, fmt.Errorf("private key must reference a valid encrypted key name")
	}
	current = clone(current)
	ensureClientEnvironment(&current)
	current.Routes = replaceOwned(current.Routes, []domain.Route{{
		Name:  "cloudflare",
		Match: domain.Match{PathPrefix: "/cloudflare/" + current.Name}, StripPrefix: true,
		Upstream:   "https://gateway.ai.cloudflare.com/v1/" + accountID + "/" + gateway,
		SetHeaders: []domain.HeaderValue{{Name: "cf-aig-authorization", Value: "Bearer {secret:" + privateKey + "}"}},
	}}, ownsCloudflare)
	return current, domain.ValidateProfile(current)
}

func UnsetCloudflare(current domain.Profile) (domain.Profile, error) {
	current = clone(current)
	ensureClientEnvironment(&current)
	current.Routes = replaceOwned(current.Routes, nil, ownsCloudflare)
	return current, domain.ValidateProfile(current)
}

func SetGitHub(current domain.Profile, source string) (domain.Profile, error) {
	if err := domain.ValidateProfile(current); err != nil {
		return domain.Profile{}, err
	}
	if !domain.ValidName(source) {
		return domain.Profile{}, fmt.Errorf("invalid credential source %q", source)
	}
	current = clone(current)
	ensureClientEnvironment(&current)
	current.Routes = replaceOwned(current.Routes, githubRoutes(), ownsGitHub)
	current.Credentials["github"] = source
	return current, domain.ValidateProfile(current)
}

func UnsetGitHub(current domain.Profile) (domain.Profile, error) {
	current = clone(current)
	ensureClientEnvironment(&current)
	current.Routes = replaceOwned(current.Routes, nil, ownsGitHub)
	delete(current.Credentials, "github")
	return current, domain.ValidateProfile(current)
}

func ensureClientEnvironment(current *domain.Profile) {
	if current.Environment == nil {
		current.Environment = map[string]string{}
	}
	base := "http://127.0.0.1:8787/cloudflare/" + current.Name
	for name, value := range map[string]string{
		"AGENTBOX_PROFILE":   current.Name,
		"ANTHROPIC_BASE_URL": base + "/anthropic",
		"OPENAI_BASE_URL":    base + "/openai",
		"ANTHROPIC_API_KEY":  "agentbox-dummy",
		"OPENAI_API_KEY":     "agentbox-dummy",
		"GH_TOKEN":           "agentbox-dummy",
	} {
		current.Environment[name] = value
	}
}

func githubRoutes() []domain.Route {
	bearer := []domain.HeaderValue{{Name: "Authorization", Value: "Bearer {credential:github}"}}
	return []domain.Route{
		{Name: "github-api", Match: domain.Match{PathPrefix: "/github-api"}, Upstream: "https://api.github.com", StripPrefix: true, SetHeaders: bearer},
		{Name: "github-git", Match: domain.Match{PathPrefix: "/github-git"}, Upstream: "https://github.com", StripPrefix: true,
			SetHeaders: []domain.HeaderValue{{Name: "Authorization", Value: "Basic {basic:x-access-token:credential:github}"}}},
		{Name: "github-host-api", Match: domain.Match{Host: "api.github.com"}, Upstream: "https://api.github.com", SetHeaders: bearer},
		{Name: "github-host-uploads", Match: domain.Match{Host: "uploads.github.com"}, Upstream: "https://uploads.github.com", SetHeaders: bearer},
		{Name: "github-host-objects", Match: domain.Match{Host: "objects.githubusercontent.com"}, Upstream: "https://objects.githubusercontent.com"},
		{Name: "github-host-codeload", Match: domain.Match{Host: "codeload.github.com"}, Upstream: "https://codeload.github.com"},
	}
}

func ownsCloudflare(route domain.Route) bool { return strings.HasPrefix(route.Name, "cloudflare") }
func ownsGitHub(route domain.Route) bool     { return strings.HasPrefix(route.Name, "github-") }

func replaceOwned(existing, generated []domain.Route, owns func(domain.Route) bool) []domain.Route {
	out := append([]domain.Route(nil), generated...)
	for _, route := range existing {
		if !owns(route) {
			out = append(out, route)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func clone(current domain.Profile) domain.Profile {
	out := current
	out.Routes = make([]domain.Route, len(current.Routes))
	for i, route := range current.Routes {
		out.Routes[i] = route
		out.Routes[i].SetHeaders = append([]domain.HeaderValue(nil), route.SetHeaders...)
	}
	out.Credentials = cloneMap(current.Credentials)
	out.Environment = cloneMap(current.Environment)
	return out
}

func cloneMap(source map[string]string) map[string]string {
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

// ContainerScript materializes only public profile settings. All secrets and
// renewable credentials remain in the daemon and are injected by routes.
func ContainerScript(current domain.Profile) (string, error) {
	if err := domain.ValidateProfile(current); err != nil {
		return "", err
	}
	keys := make([]string, 0, len(current.Environment))
	for key := range current.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var script strings.Builder
	script.WriteString("set -eu\n")
	script.WriteString("install -d -m 0755 /etc/profile.d\n")
	script.WriteString(": > /etc/profile.d/agentbox-profile.sh\n")
	for _, key := range keys {
		line := "export " + key + "=" + shellQuote(current.Environment[key])
		fmt.Fprintf(&script, "printf '%%s\\n' %s >> /etc/profile.d/agentbox-profile.sh\n", shellQuote(line))
	}
	script.WriteString("chmod 0644 /etc/profile.d/agentbox-profile.sh\n")
	script.WriteString("touch /etc/environment\n")
	script.WriteString("awk '/^# BEGIN agentbox-profile$/{skip=1} /^# END agentbox-profile$/{skip=0; next} !skip{print}' /etc/environment > /etc/environment.agentbox\n")
	script.WriteString("printf '%s\\n' '# BEGIN agentbox-profile' >> /etc/environment.agentbox\n")
	for _, key := range keys {
		line := key + "=" + strconv.Quote(current.Environment[key])
		fmt.Fprintf(&script, "printf '%%s\\n' %s >> /etc/environment.agentbox\n", shellQuote(line))
	}
	script.WriteString("printf '%s\\n' '# END agentbox-profile' >> /etc/environment.agentbox\n")
	script.WriteString("mv /etc/environment.agentbox /etc/environment\n")
	script.WriteString("chmod 0644 /etc/environment\n")

	openAIBase := current.Environment["OPENAI_BASE_URL"]
	anthropicBase := current.Environment["ANTHROPIC_BASE_URL"]
	if openAIBase != "" || anthropicBase != "" {
		script.WriteString("install -d -o agent -g agent -m 0755 /home/agent/.pi/agent\n")
		providers := map[string]map[string]string{}
		if anthropicBase != "" {
			providers["anthropic"] = map[string]string{"baseUrl": anthropicBase}
		}
		if openAIBase != "" {
			providers["openai"] = map[string]string{"baseUrl": openAIBase}
		}
		encoded, _ := json.MarshalIndent(map[string]any{"providers": providers}, "", "  ")
		fmt.Fprintf(&script, "printf '%%s\\n' %s > /home/agent/.pi/agent/models.json\n", shellQuote(string(encoded)))
		script.WriteString("chown -R agent:agent /home/agent/.pi\n")
		script.WriteString("chmod 0644 /home/agent/.pi/agent/models.json\n")
	}
	if openAIBase != "" {
		script.WriteString("install -d -o agent -g agent -m 0755 /home/agent/.codex\n")
		config := "model_provider = \"agentbox\"\n[model_providers.agentbox]\nname = \"agentbox proxy\"\nbase_url = " + strconv.Quote(openAIBase) + "\nwire_api = \"responses\"\nenv_key = \"OPENAI_API_KEY\""
		fmt.Fprintf(&script, "printf '%%s\\n' %s > /home/agent/.codex/config.toml\n", shellQuote(config))
		script.WriteString("chown -R agent:agent /home/agent/.codex\n")
		script.WriteString("chmod 0644 /home/agent/.codex/config.toml\n")
	}
	return script.String(), nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
