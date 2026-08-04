package image

import (
	"bytes"
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
	} {
		if !bytes.Contains(Definition, required) {
			t.Fatalf("embedded builder definition missing %q", required)
		}
	}
	for _, forbidden := range [][]byte{[]byte("distrobuilder"), []byte("Caddy"), []byte("caddy"), []byte("      - nodejs\n"), []byte("      - npm\n")} {
		if bytes.Contains(Definition, forbidden) {
			t.Fatalf("embedded builder definition contains obsolete %q reference", forbidden)
		}
	}
}
