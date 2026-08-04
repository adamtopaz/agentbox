package image

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedBuilderDefinitionContainsReviewedContract(t *testing.T) {
	for _, required := range [][]byte{
		[]byte(`user.agentbox-build: "true"`),
		[]byte("cloud-init.user-data: |"),
		[]byte("#cloud-config"),
		[]byte("NODE_VERSION=24.19.0"),
		[]byte("node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"),
		[]byte("14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647"),
		[]byte(`test "$(node --version)" = "v${NODE_VERSION}"`),
		[]byte("      - fd-find"),
		[]byte("ln -sfn /usr/bin/fdfind /usr/local/bin/fd"),
		[]byte("@anthropic-ai/claude-code@2.1.220"),
		[]byte("@openai/codex@0.145.0"),
		[]byte("@earendil-works/pi-coding-agent@0.82.1"),
		[]byte("http_unix_socket: /run/agentbox.sock"),
		[]byte("GIT_EXEC_PATH=/usr/local/lib/agentbox/git-core"),
		[]byte("path: /usr/local/lib/agentbox/git-remote-https"),
		[]byte("https://github.com/*)"),
		[]byte(`"http://127.0.0.1:8787/github-git/$path"`),
		[]byte("/usr/local/lib/agentbox/git-remote-http-original"),
		[]byte("github-git-transport=helper-v1"),
	} {
		if !bytes.Contains(Definition, required) {
			t.Fatalf("embedded builder definition missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{
		[]byte("distrobuilder"), []byte("Caddy"), []byte("caddy"),
		[]byte("      - nodejs\n"), []byte("      - npm\n"),
		[]byte(`[url "http://127.0.0.1:8787/github-git/"]`),
		[]byte("insteadOf = https://github.com/"),
		[]byte("insteadOf = git@github.com:"),
		[]byte("insteadOf = ssh://git@github.com/"),
	} {
		if bytes.Contains(Definition, forbidden) {
			t.Fatalf("embedded builder definition contains obsolete %q reference", forbidden)
		}
	}
}

func TestGitHubTransportHelperRewritesOnlyExactGitHubHTTPS(t *testing.T) {
	script := embeddedWriteFile(t, "/usr/local/lib/agentbox/git-remote-https")
	const original = "original=/usr/local/lib/agentbox/git-remote-http-original"
	if strings.Count(script, original) != 1 {
		t.Fatalf("transport helper has %d original-helper assignments", strings.Count(script, original))
	}
	script = strings.Replace(script, original, "original=/bin/echo", 1)
	path := filepath.Join(t.TempDir(), "git-remote-https")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("transport helper syntax: %v: %s", err, output)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "GitHub HTTPS",
			args: []string{"origin", "https://github.com/owner/repository.git"},
			want: "origin http://127.0.0.1:8787/github-git/owner/repository.git\n",
		},
		{
			name: "other host",
			args: []string{"origin", "https://gitlab.com/owner/repository.git"},
			want: "origin https://gitlab.com/owner/repository.git\n",
		},
		{
			name: "host suffix attack",
			args: []string{"origin", "https://github.com.example/owner/repository.git"},
			want: "origin https://github.com.example/owner/repository.git\n",
		},
		{
			name: "non-HTTPS GitHub",
			args: []string{"origin", "http://github.com/owner/repository.git"},
			want: "origin http://github.com/owner/repository.git\n",
		},
		{
			name: "one-argument delegation",
			args: []string{"origin"},
			want: "origin\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := exec.Command(path, test.args...).CombinedOutput()
			if err != nil {
				t.Fatalf("run transport helper: %v: %s", err, output)
			}
			if string(output) != test.want {
				t.Fatalf("output=%q want %q", output, test.want)
			}
		})
	}
}

func embeddedWriteFile(t *testing.T, path string) string {
	t.Helper()
	definition := string(Definition)
	marker := "      - path: " + path + "\n"
	start := strings.Index(definition, marker)
	if start < 0 {
		t.Fatalf("embedded builder definition has no write_file for %s", path)
	}
	definition = definition[start+len(marker):]
	contentMarker := "        content: |\n"
	start = strings.Index(definition, contentMarker)
	if start < 0 {
		t.Fatalf("write_file for %s has no literal content", path)
	}
	definition = definition[start+len(contentMarker):]
	var content strings.Builder
	for _, line := range strings.Split(definition, "\n") {
		if line != "" && !strings.HasPrefix(line, "          ") {
			break
		}
		content.WriteString(strings.TrimPrefix(line, "          "))
		content.WriteByte('\n')
	}
	return content.String()
}
