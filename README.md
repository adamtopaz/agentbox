# agentbox

Credential-isolating sandboxes for coding agents (Claude Code, Codex, pi) on
Incus containers. **No real credential ever exists inside a container** — not
even a pseudo-token. Agents talk to `http://127.0.0.1:8787` inside their
container; on the host, Caddy strips every auth header they send and injects
the real one, per route, before forwarding upstream (Cloudflare AI Gateway for
inference, GitHub for git). Each configured AI Gateway gets its own route
(`/cloudflare/<name>/...`) and its own credential, and a container reaches
only the gateway it was created against.

## How it works

- Each container gets a host-side unix socket, wired to `127.0.0.1:8787`
  inside via an incus proxy device. Caddy serves one site per socket, so the
  socket a request arrives on *is* the container's identity — no tokens
  between container and proxy.
- A single Go CLI (`agentbox`) renders Caddy's config from a route table
  (`/etc/agentbox/routes.json`) and per-container state files. There is no
  daemon: every mutating command runs one reconcile cycle
  (render → `caddy validate` → atomic install → `caddy reload`).
- Secrets are stored **encrypted at rest** by `systemd-creds` in
  `/etc/agentbox/secrets/<name>.cred` (root, 0600) — `agentbox add-secret`
  pipes the value straight into the encryptor, so no plaintext credential is
  ever written to disk. systemd decrypts them into the service's private
  `/run/credentials` tmpfs via `LoadCredentialEncrypted=`, and the config
  references them as `{file.*}` placeholders. The rendered Caddyfile contains
  secret *names* only (one exception to the CLI never handling values: `setup`
  decrypts, in memory, to derive the pre-encoded HTTP Basic companion git needs). A route whose secret is not
  installed serves 503 rather than proxying without credentials.
- Logs are metadata-only by construction — query strings stripped,
  request/response headers dropped, entries tagged with the container name —
  on both the access log and the error log.
- Caddy listens only on unix sockets, its admin endpoint included
  (`/run/agentbox/admin.sock`, mode 0660): that API is unauthenticated and can
  read every loaded credential, so it must not sit on localhost:2019 where any
  host user can reach it.

**Membership in group `agentbox` is a trusted role, not a reduced privilege.**
Members can edit the rendered Caddyfile and reload Caddy, which is equivalent
to reading every secret. The group exists to avoid routine `sudo`, not as a
security boundary.

What this does **not** protect: container egress is open (agents need git,
npm, docs). A compromised container can spend tokens through the proxy —
observable in the AI Gateway dashboard, bounded by gateway budgets, and
revocable per container — but cannot exfiltrate a credential that works
anywhere else.

## Install

Requirements: Debian-ish host with systemd, [Incus](https://linuxcontainers.org/incus/)
initialized, Go ≥ 1.24 to build. Caddy ≥ 2.8 is installed by `setup` from
Caddy's official apt repo if missing or too old.

```sh
make bin
sudo ./bin/agentbox setup          # prompts for Cloudflare account + gateway names
sudo agentbox add-secret cf-aig-token-prod   # one token per gateway
sudo agentbox add-secret gh-pat
sudo agentbox setup                # loads the new secrets into caddy
agentbox build-image               # bake the agentbox-base container image
```

`setup` adds you to the `agentbox` and `incus-admin` groups; log out and back
in before running container commands as a non-root user.

## Use

```sh
agentbox create --gateway prod dev   # --gateway is required; no default
agentbox shell dev         # login shell as user 'agent'; claude/codex/pi ready
agentbox list              # state vs incus vs socket — drift is visible
agentbox destroy dev

agentbox proxy status      # containers + blocked/socket state
agentbox proxy routes      # route table
agentbox proxy reload      # force a reconcile (e.g. after editing routes.json)
agentbox proxy block dev   # 403 the container's site (--hard severs connections)
agentbox proxy unblock dev
```

Inside a container, everything is pre-wired with dummy keys: `claude` and
`codex` work out of the box; `git clone https://github.com/...` is rewritten
through the proxy and authenticates with the host-side PAT; and `gh` works
unmodified via its `http_unix_socket` setting, which makes it dial
`/run/agentbox.sock` in plain HTTP while still addressing `api.github.com`.
Host-matched routes inject the PAT for the GitHub API and upload hosts, and
deliberately do not for the signed-URL asset hosts. An unmapped `Host` gets a
404, so the socket is not an open relay.

## Operations

See [docs/runbook.md](docs/runbook.md) for secrets rotation, adding routes,
revocation, logs, and disaster recovery.

## Development

```sh
make            # vet + test + build
make race       # tests under the race detector
go test ./internal/caddyfile -update   # regenerate Caddyfile goldens
sudo test/e2e.sh                       # live end-to-end (real caddy + container)
```

The Caddyfile renderer is the security-critical piece: golden-file tests pin
its output, presence tests assert every strip/redaction rule, a validate test
runs the real `caddy validate` when a caddy ≥ 2.8 is available, and
`test/e2e.sh` proves the properties against live traffic.
