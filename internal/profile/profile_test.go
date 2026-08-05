package profile

import (
	"os/exec"
	"strings"
	"testing"

	"agentbox/internal/domain"
)

func TestProviderHelpersComposeGenericProfile(t *testing.T) {
	current, err := New("prod")
	if err != nil {
		t.Fatal(err)
	}
	current, err = SetCloudflare(current, "0123456789abcdef0123456789abcdef", "ff-prod", "cloudflare-api")
	if err != nil {
		t.Fatal(err)
	}
	current, err = SetGitHub(current, "github-prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Routes) != 7 || current.Credentials["github"] != "github-prod" {
		t.Fatalf("unexpected profile: %+v", current)
	}
	var cloudflare *domain.Route
	for i := range current.Routes {
		if current.Routes[i].Name == "cloudflare" {
			cloudflare = &current.Routes[i]
		}
	}
	if cloudflare == nil || cloudflare.Match.PathPrefix != "/cloudflare/prod" ||
		cloudflare.Upstream != "https://gateway.ai.cloudflare.com/v1/0123456789abcdef0123456789abcdef/ff-prod" || !cloudflare.StripPrefix {
		t.Fatalf("unexpected Cloudflare route: %+v", cloudflare)
	}
	if got := current.Environment["ANTHROPIC_BASE_URL"]; got != "http://127.0.0.1:8787/cloudflare/prod/anthropic" {
		t.Fatalf("Anthropic URL=%q", got)
	}
	if current.Environment["GH_TOKEN"] != "agentbox-dummy" {
		t.Fatal("GitHub client configuration missing")
	}
}

func TestSetCloudflareReplacesOnlyItsIntegration(t *testing.T) {
	current, _ := New("prod")
	current, _ = SetGitHub(current, "github-prod")
	current, _ = SetCloudflare(current, "0123456789abcdef0123456789abcdef", "first", "first-key")
	current, err := SetCloudflare(current, "fedcba9876543210fedcba9876543210", "second", "second-key")
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Routes) != 7 || current.Credentials["github"] != "github-prod" {
		t.Fatalf("unrelated integration changed: %+v", current)
	}
	for _, route := range current.Routes {
		if route.Name == "cloudflare" && (!strings.HasSuffix(route.Upstream, "/second") || route.SetHeaders[0].Value != "Bearer {secret:second-key}") {
			t.Fatalf("Cloudflare integration was not replaced: %+v", route)
		}
	}
}

func TestProfilesCarryIndependentProviderAssignments(t *testing.T) {
	production, _ := New("production")
	production, _ = SetCloudflare(production, "0123456789abcdef0123456789abcdef", "ff-prod", "prod-token")
	production, _ = SetGitHub(production, "github-prod")
	development, _ := New("development")
	development, _ = SetCloudflare(development, "fedcba9876543210fedcba9876543210", "ff-dev", "dev-token")
	development, _ = SetGitHub(development, "github-dev")

	if production.Credentials["github"] != "github-prod" || development.Credentials["github"] != "github-dev" {
		t.Fatalf("credential assignments crossed profiles: prod=%v dev=%v", production.Credentials, development.Credentials)
	}
	if production.Routes[0].Upstream == development.Routes[0].Upstream ||
		production.Routes[0].SetHeaders[0].Value == development.Routes[0].SetHeaders[0].Value {
		t.Fatalf("Cloudflare assignments crossed profiles: prod=%+v dev=%+v", production.Routes[0], development.Routes[0])
	}
}

func TestUnsetIntegrationsPreservesProfile(t *testing.T) {
	current, _ := New("prod")
	current, _ = SetCloudflare(current, "0123456789abcdef0123456789abcdef", "ff-prod", "cloudflare-api")
	current, _ = SetGitHub(current, "github-prod")
	current, err := UnsetCloudflare(current)
	if err != nil {
		t.Fatal(err)
	}
	if current.Environment["ANTHROPIC_BASE_URL"] == "" || len(current.Routes) != 6 {
		t.Fatalf("Cloudflare integration remains: %+v", current)
	}
	current, err = UnsetGitHub(current)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Routes) != 0 || len(current.Credentials) != 0 || current.Environment["AGENTBOX_PROFILE"] != "prod" || current.Environment["GH_TOKEN"] != "agentbox-dummy" {
		t.Fatalf("profile cleanup failed: %+v", current)
	}
}

func TestContainerScriptContainsOnlyPublicProfileConfiguration(t *testing.T) {
	current, _ := New("prod")
	current, _ = SetCloudflare(current, "0123456789abcdef0123456789abcdef", "ff-prod", "host-secret-name")
	current, _ = SetGitHub(current, "github-prod")
	script, err := ContainerScript(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "GH_TOKEN", "agentbox-dummy", "/home/agent/.codex/config.toml", "/home/agent/.pi/agent/models.json"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	for _, forbidden := range []string{"host-secret-name", "github-prod", "cf-aig-authorization"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script exposed host material/reference %q", forbidden)
		}
	}
	current.Environment["CUSTOM_VALUE"] = `spaces ' quotes $ dollars \\ slashes`
	script, err = ContainerScript(current)
	if err != nil {
		t.Fatal(err)
	}
	check := exec.Command("sh", "-n")
	check.Stdin = strings.NewReader(script)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("generated script is invalid: %v: %s", err, output)
	}
}

func TestCloudflareRequiresExplicitValidKeyReference(t *testing.T) {
	current, _ := New("prod")
	for _, privateKey := range []string{"", "Cloudflare-Key", "path/to/key"} {
		if _, err := SetCloudflare(current, "0123456789abcdef0123456789abcdef", "ff-prod", privateKey); err == nil {
			t.Fatalf("accepted invalid private key reference %q", privateKey)
		}
	}
}
