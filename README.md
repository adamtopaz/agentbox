# agentbox

Agentbox runs coding agents in Incus containers without putting real API keys
in those containers. A small Go daemon owns both the reverse proxy and its live
configuration. Containers receive dummy credentials; `agentboxd` removes
credential-bearing request headers and injects an appropriate host-side static
secret or renewable credential only after a route has matched.

There is no Caddy dependency and no generated proxy configuration. Routes,
keys, and container registrations change while the daemon is running.

## Architecture

```text
operator
  agentbox CLI ── HTTP/Unix socket ──> typed application service
                                           ├── state.json (routes/containers/sources/grants)
                                           ├── AES-256-GCM key envelopes
                                           ├── expiring credential broker
                                           └── immutable runtime snapshots

container ── Incus proxy device ──> per-container Unix socket
                                      └── Go httputil.ReverseProxy ──> upstream
```

HTTP is only the current adapter for the control socket. Validation,
persistence, route/key/credential operations, and commits live in a
transport-independent application service. Provider profiles are ordinary
compositions of the same generic route model.

The per-container socket is its identity. A container has no bearer token with
which to claim another identity, and its listener sees only routes in its
concrete scope plus routes in the universal `"*"` scope.

## Requirements

- Linux host with systemd and [`systemd-creds`](https://systemd.io/CREDENTIALS/)
- [Incus](https://linuxcontainers.org/incus/), initialized for the operator
- Go 1.24 or newer to build

The image builder uses Incus's Debian 13 cloud image and a declarative
cloud-init instance configuration. Claude Code, Codex, pi, and their Node.js
runtime are deliberately pinned in [`image/agentbox.yaml`](image/agentbox.yaml).
Debian 13's Node.js 20 is too old for the pinned pi release, so the image
installs Node.js 24 LTS from an exact upstream archive with a reviewed SHA-256
checksum for each supported architecture. Debian's `fd-find` package is baked
in under the canonical `fd` command name so pi never downloads a mutable helper
on first launch.

## Install

```sh
make bin
sudo ./bin/agentbox setup
# Log out and back in after setup activates group membership, then:
agentbox image build
```

`setup` installs `agentbox` and `agentboxd`, creates the unprivileged
`agentboxd` account, generates one encrypted systemd credential for the master
key, and installs the only systemd unit in the project. It also adds
`$SUDO_USER` to `agentbox` and `incus-admin` when those groups exist. Log out
and back in after the first setup.

The image build does not require root. It gives the embedded Incus/cloud-init
configuration to a disposable `agentbox-build` instance, waits for provisioning,
verifies every pinned tool and proxy configuration, removes instance-specific
state, disables cloud-init in the baked result, and publishes it as
`agentbox-base`. Incus performs the privileged work behind its daemon boundary.
Rebuilding the same alias uses `incus publish --reuse`.

## Configure and use

GitHub is an optional profile built from ordinary routes and a renewable
credential. Give the GitHub App only the repository permissions agents need,
install it on the intended repositories, and download one App private key.
The Client ID, installation ID, repository selection, and permission subset
are non-secret configuration; only the PEM is stored as an encrypted key.

```sh
agentbox key set github-app-private-key < /path/to/app.private-key.pem

agentbox credential source github-app github-main \
  --client-id Iv1.example \
  --installation-id 12345678 \
  --private-key github-app-private-key \
  --repository-ids 111111,222222 \
  --permissions contents=write,pull_requests=write,issues=write

agentbox profile apply github

agentbox container create --scope prod --configure none work
agentbox credential grant set work github github-main
agentbox container shell work
```

Use `--repositories repo-a,repo-b` instead of numeric IDs if preferred; names
are relative to the installation account. Omit both selectors to use every
repository selected in the installation. Omit `--permissions` to inherit all
App permissions, though an explicit least-privilege subset is preferable.

On the first request, the host signs a short-lived App JWT, exchanges it for a
one-hour installation token, caches that token only in daemon memory, and
refreshes it before expiry. A grant binds the logical credential `github` to a
source for exactly one container listener. The App private key, JWT, and
installation token never enter the container. The image configures `git`
through `/github-git/` and uses GitHub CLI's supported
[`http_unix_socket`](https://cli.github.com/manual/gh_config) setting for
`/run/agentbox.sock`; `gh` and Git continue to see only dummy credentials.

Cloudflare AI Gateway is also an optional profile. Each gateway is both a route
scope and a separately named key:

```sh
agentbox key set cf-aig-token-prod
agentbox profile apply cloudflare \
  --account-id 0123456789abcdef0123456789abcdef \
  --gateways prod

agentbox container create --scope prod work
agentbox container shell work
```

Container creation registers the identity with the daemon, waits for its Unix
listener, launches the Incus instance, attaches TCP `127.0.0.1:8787` and Unix
`/run/agentbox.sock` proxy devices, then writes only non-secret client settings.

Useful live operations:

```sh
agentbox status
agentbox route list
agentbox key list
agentbox credential source list
agentbox credential grant list
agentbox container list
agentbox container block work
agentbox container block --hard work
agentbox container unblock work
agentbox container destroy work
```

## Generic routes

A route matches either an exact host or a clean path prefix. `scope` is always
explicit; use `"*"` only when every registered container should reach it.

```json
{
  "name": "example-api",
  "scope": "prod",
  "match": { "path_prefix": "/example" },
  "upstream": "https://api.example.com/v1",
  "strip_prefix": true,
  "path_map": [
    { "path": "/messages", "to": "/chat/messages" }
  ],
  "set_headers": [
    { "name": "Authorization", "value": "Bearer {secret:example-token}" }
  ]
}
```

```sh
agentbox key set example-token
agentbox route put route.json
```

Header values support durable `{secret:key-name}` references, renewable
`{credential:name}` references, and Basic forms such as
`{basic:username:key-name}` or `{basic:username:credential:name}`. Credential
names are resolved against the grant for the request's container listener. A
missing key, grant, or valid lease returns 503 before any upstream request.
Incoming authorization, cookies, forwarding headers,
Cloudflare Access headers, and the complete `cf-aig-*` family are removed;
configured headers are applied afterward. Queries are forwarded but never
logged. Ambiguous escaped paths, dot segments, repeated separators, backslashes,
and semicolons are rejected.

## Security boundaries

The daemon runs as `agentboxd`, with no capabilities and a hardened systemd
unit. `systemd-creds` protects one 32-byte master key at startup. Dynamic keys
are independently sealed with AES-256-GCM using random nonces and key-name-bound
additional data under `/var/lib/agentbox/secrets`; rotation needs no restart.
Renewable leases exist only in daemon memory, are never returned by the control
API, and are cleared on source/key changes and shutdown.

Membership in group `agentbox` is a trusted secret-management role. A member
cannot list plaintext through the API, but can set a route that sends a stored
key to an upstream they control, which is equivalent access. Root on the
running host can also reach daemon memory. Encryption at rest protects copied
or offline storage; it is not a defense against a compromised running host,
and full-disk encryption remains valuable.

Container egress is intentionally not restricted. A compromised agent can use
the routes assigned to its scope and spend against them, but it cannot recover
a reusable upstream credential from agentbox. Apply upstream budgets and
revocation controls as a second boundary.

Proxy logs contain method, status, container, route, and duration—not URLs,
queries, headers, or bodies. Upstream services may have their own logging.

See [`docs/runbook.md`](docs/runbook.md) for operations, recovery, control API,
and image maintenance.

## Development

```sh
make                 # vet, tests, both binaries
make race
test/e2e.sh          # local daemon + real Unix sockets + local upstream
# Full image validation provisions and publishes a disposable test alias:
agentbox image build --alias agentbox-test
```

The Go module currently has no third-party dependencies.
