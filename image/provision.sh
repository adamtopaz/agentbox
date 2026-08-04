#!/usr/bin/env bash
# agentbox-base provisioning. Runs inside the build container as root, via
# `agentbox build-image`. Must stay re-runnable: guards, not assumptions.
#
# Environment provided by the builder:
#   AGENTBOX_ACCOUNT_ID  Cloudflare account ID (non-secret; may be empty)
#   AGENTBOX_BUILD_DATE  build date stamp
#
# Everything written here is a dummy value or non-secret: the host-side proxy
# strips and replaces every auth header no matter what the agent sends.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

PROXY="http://127.0.0.1:8787"
# Nothing gateway-dependent is baked in: there is no default gateway, and
# `agentbox create --gateway <name>` writes the base URLs into each container.
# An image with a gateway baked in would strand every container built from it
# the moment that choice changed.
# Same host-side proxy, reached as a unix socket (incus proxy device) for
# clients that address real hostnames instead of a base URL.
GH_SOCKET="/run/agentbox.sock"

echo "==> base packages"
apt-get update
apt-get -y full-upgrade
apt-get -y install \
    git curl wget ca-certificates gnupg build-essential \
    python3 python3-venv python3-pip pkg-config \
    sudo jq ripgrep unzip locales openssh-client

echo "==> locale"
sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
locale-gen
update-locale LANG=en_US.UTF-8

echo "==> node (NodeSource LTS, Debian fallback)"
if ! command -v node >/dev/null 2>&1; then
    if curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && apt-get install -y nodejs; then
        echo "node installed via NodeSource"
    else
        echo "WARN: NodeSource failed; falling back to Debian's nodejs/npm"
        apt-get install -y nodejs npm
    fi
fi

echo "==> gh cli (official apt repo)"
if ! command -v gh >/dev/null 2>&1; then
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /etc/apt/keyrings/githubcli-archive-keyring.gpg
    chmod 0644 /etc/apt/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list
    apt-get update
    apt-get install -y gh || echo "WARN: gh install failed; git still works through the proxy"
fi

echo "==> agent user"
id agent >/dev/null 2>&1 || useradd -m -s /bin/bash agent
install -d -o agent -g agent /home/agent/work
echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent
chmod 0440 /etc/sudoers.d/agent
visudo -c >/dev/null

echo "==> coding agents (root-owned npm globals; self-update disabled by construction)"
# pi lives under @earendil-works now (it moved from @mariozechner, whose
# @mariozechner/pi still exists but ships a `pi-pods` binary — installing it
# succeeds and leaves no `pi` command, which is how this went unnoticed).
npm install -g @anthropic-ai/claude-code @openai/codex @earendil-works/pi-coding-agent

# Verify each agent actually produced the binary it is supposed to. npm exiting
# 0 is not evidence: the wrong package installs cleanly and simply provides a
# differently-named command. Failing here beats publishing an image that is
# quietly short a tool.
missing=""
for cmd in claude codex pi; do
    command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
done
if [ -n "$missing" ]; then
    echo "ERROR: these agents installed but produced no binary:$missing" >&2
    echo "       check the package names — a package can install fine and ship a different command" >&2
    exit 1
fi

echo "==> proxy wiring: environment"
# Login shells (agentbox shell) read profile.d; PAM-less exec paths read
# /etc/environment. Both are generated from the same list below.
ENV_VARS=(
    # ANTHROPIC_BASE_URL / OPENAI_BASE_URL / CLOUDFLARE_GATEWAY_ID are written
    # per container by `agentbox create` into /etc/profile.d/agentbox-gateway.sh.
    "ANTHROPIC_API_KEY=agentbox-dummy"
    "OPENAI_API_KEY=agentbox-dummy"
    "CLOUDFLARE_ACCOUNT_ID=${AGENTBOX_ACCOUNT_ID:-}"
    "CLOUDFLARE_API_KEY=agentbox-dummy"
    "DISABLE_AUTOUPDATER=1"
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"
    "GIT_TERMINAL_PROMPT=0"
    # gh refuses to run without *a* token, and never validates it; the proxy
    # strips this and injects the real PAT host-side.
    "GH_TOKEN=agentbox-dummy"
)

{
    echo "# agentbox proxy wiring — dummies and non-secrets only"
    for kv in "${ENV_VARS[@]}"; do
        echo "export ${kv}"
    done
} > /etc/profile.d/agentbox.sh

# /etc/environment is not shell: KEY=value lines only. Managed marker block,
# replaced on re-run, never appended blindly.
touch /etc/environment
awk '/^# BEGIN agentbox$/{skip=1} /^# END agentbox$/{skip=0; next} !skip{print}' /etc/environment > /etc/environment.tmp
{
    cat /etc/environment.tmp
    echo "# BEGIN agentbox"
    for kv in "${ENV_VARS[@]}"; do
        echo "${kv}"
    done
    echo "# END agentbox"
} > /etc/environment
rm -f /etc/environment.tmp

echo "==> claude code headless preseed"
# Pre-approve the dummy key so the first headless run skips onboarding
# (exact keys verified against the installed Claude Code version, spec §10.1).
install -o agent -g agent -m 0644 /dev/stdin /home/agent/.claude.json <<'EOF'
{
  "hasCompletedOnboarding": true,
  "customApiKeyResponses": {
    "approved": ["agentbox-dummy"],
    "rejected": []
  }
}
EOF

echo "==> codex + pi dirs (configs written per container by agentbox create)"
install -d -o agent -g agent /home/agent/.codex
install -d -o agent -g agent /home/agent/.pi /home/agent/.pi/agent

echo "==> gh wiring (http_unix_socket)"
# gh has no base-URL override, but http_unix_socket makes it dial a unix
# socket in plain HTTP for every request — REST, GraphQL, and uploads —
# while still sending the real Host header. The host-side proxy matches on
# that Host and injects the PAT. No TLS, no CA, no /etc/hosts.
gh_config() {
    # $1=home dir, $2=owner
    install -d -o "$2" -g "$2" -m 0755 "$1/.config/gh"
    install -o "$2" -g "$2" -m 0644 /dev/stdin "$1/.config/gh/config.yml" <<EOF
# agentbox: route all gh traffic through the host-side credential proxy.
http_unix_socket: ${GH_SOCKET}
git_protocol: https
prompt: enabled
EOF
}
gh_config /home/agent agent
# The agent user has passwordless sudo, and \`sudo gh\` reads root's config —
# without this it would bypass the proxy and hit api.github.com directly.
gh_config /root root

echo "==> git wiring (system gitconfig)"
# --replace-all first (plain --add would accumulate, and a plain set would
# fail with "cannot overwrite multiple values" on a re-run).
git config --system --replace-all url."${PROXY}/github-git/".insteadOf "https://github.com/"
git config --system --add url."${PROXY}/github-git/".insteadOf "git@github.com:"

echo "==> image marker"
{
    echo "agentbox-base built ${AGENTBOX_BUILD_DATE:-unknown}"
    echo "node: $(node --version 2>/dev/null || echo none)"
    echo "claude: $(claude --version 2>/dev/null | head -1)"
    echo "codex: $(codex --version 2>/dev/null | head -1)"
    echo "pi: $(pi --version 2>/dev/null | head -1)"
} > /etc/agentbox-image

echo "==> provision complete"
