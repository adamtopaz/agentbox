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
                                           ├── state.json (profiles/routes/containers/sources)
                                           ├── AES-256-GCM key envelopes
                                           ├── expiring credential broker
                                           └── immutable runtime snapshots

container ── Incus proxy device ──> per-container Unix socket
                                      └── Go httputil.ReverseProxy ──> upstream
```

HTTP is only the current adapter for the control socket. Validation,
persistence, profile/route/key/credential operations, and commits live in a
transport-independent application service. Provider integrations are ordinary
compositions of the same generic profile, route, key-reference, and credential
binding model.

The per-container socket is its identity. A container has no bearer token with
which to claim another identity. Each container names exactly one reusable
profile, and its listener sees only the routes and credential bindings in that
profile.

## Requirements

- Linux host with systemd and [`systemd-creds`](https://systemd.io/CREDENTIALS/)
- [Incus](https://linuxcontainers.org/incus/), initialized for the operator
- Go 1.26.5 or newer to build (the patch-level floor prevents binaries from
  embedding a standard library with known, already-fixed security defects)

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
make setup
# Log out and back in after setup activates group membership, then:
agentbox image build
```

`make setup` builds both binaries as the current user, then runs the privileged
`agentbox setup` installation step through `sudo`. The installer installs
`agentbox` and `agentboxd`, creates the unprivileged
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

Create a named profile first. Provider helpers then assign ordinary routes,
public client settings, encrypted-key references, and renewable credential
bindings to that profile atomically:

```sh
agentbox profile create production
```

GitHub support is built from ordinary routes and a renewable credential. Give
the GitHub App only the repository permissions agents need,
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

agentbox profile set github production --source github-main

agentbox container create --profile production work
agentbox container shell work
```

Use `--repositories repo-a,repo-b` instead of numeric IDs if preferred; names
are relative to the installation account. Omit both selectors to use every
repository selected in the installation. Omit `--permissions` to inherit all
App permissions, though an explicit least-privilege subset is preferable.

On the first request, the host signs a short-lived App JWT, exchanges it for a
one-hour installation token, caches that token only in daemon memory, and
refreshes it before expiry. The profile binds the logical credential `github`
to the selected source; every container using that profile receives the same
policy without receiving the credential itself. The App private key, JWT, and
installation token never enter the container. The image configures `git`
with canonical `https://github.com/...` remotes while a GitHub-only HTTPS
transport helper routes clone, fetch, and push through `/github-git/`. This
keeps checkout-aware `gh` commands working without exposing the proxy URL in
repository metadata. GitHub CLI API calls use its supported
[`http_unix_socket`](https://cli.github.com/manual/gh_config) setting for
`/run/agentbox.sock`; `gh` and Git continue to see only dummy credentials.

Cloudflare AI Gateway is also an optional profile. Key-store names are arbitrary;
the profile explicitly names the entry containing its API token:

```sh
agentbox key set cloudflare-production
agentbox profile set cloudflare production \
  --account-id 0123456789abcdef0123456789abcdef \
  --gateway ff-prod \
  --private-key cloudflare-production

agentbox container create --profile production work
agentbox container shell work
```

AI inference uses Cloudflare AI Gateway's provider-native paths: `/anthropic`
for Anthropic and `/openai` for OpenAI. Agentbox creates one transparent route
inside the named profile. It removes container-supplied authentication headers, injects
`cf-aig-authorization`, and otherwise leaves the provider
request alone. In particular, methods, provider path suffixes, queries, bodies,
model names, system blocks, messages, and provider feature headers are not
translated or normalized.

This deliberately favors provider compatibility over Cloudflare's unified REST
model catalog. In current testing, Anthropic's Opus, Sonnet, and Haiku models
work through the provider-native endpoint, while Fable 5 is not available there
under the tested Cloudflare Unified Billing configuration. Agentbox does not
rewrite Fable requests into Cloudflare REST requests as a workaround.

Container creation registers the identity with the daemon, waits for its Unix
listener, launches the Incus instance, attaches TCP `127.0.0.1:8787` and Unix
`/run/agentbox.sock` proxy devices, then writes only non-secret client settings.
New containers default to 4 CPUs, 8 GiB of memory, 2,048 processes, and a
50 GiB root disk. Override those safeguards with `--cpus`, `--memory`,
`--processes`, and `--disk` when a workload needs different limits. To omit
all Agentbox per-instance limits, use `--no-resource-limits`; limits inherited
from the Incus profile still apply. The opt-out cannot be combined with the
individual resource flags.

Create as many independent policies as needed. For example, `development` and
`production` can reference different Cloudflare gateway tokens and different
GitHub App sources; container creation needs only the chosen profile name.
Changing a profile updates routing and renewable credential access immediately
for all of its existing containers. Standard client URLs are based on the
stable profile name and are installed at container creation, so changing an
assigned gateway, key, or GitHub source does not require recreating containers.

Useful live operations:

```sh
agentbox status
agentbox profile list
agentbox profile show production
agentbox route list production
agentbox key list
agentbox credential source list
agentbox container list
agentbox container block work
agentbox container block --hard work
agentbox container unblock work
agentbox container destroy work
```

## Generic routes

A route matches either an exact host or a clean path prefix. Routes are owned
by the profile in which they are stored; low-level route operations are
available for integrations that do not yet have a convenience helper.

```json
{
  "name": "example-api",
  "match": { "path_prefix": "/example" },
  "upstream": "https://api.example.com/v1",
  "strip_prefix": true,
  "set_headers": [
    { "name": "Authorization", "value": "Bearer {secret:example-token}" }
  ]
}
```

```sh
agentbox key set example-token
agentbox route put production route.json
```

Header values support durable `{secret:key-name}` references, renewable
`{credential:name}` references, and Basic forms such as
`{basic:username:key-name}` or `{basic:username:credential:name}`. Credential
names are resolved against the binding in the request container's profile.
Credential and profile commands likewise take explicit references to key-store
entries; key names carry no provider-specific meaning. A missing key, profile
binding, or valid lease returns 503 before any upstream request.
Routes intentionally have no body, query, or provider-path transformation
features. For a path route, `strip_prefix` removes only Agentbox's local routing
namespace; the remaining provider-visible path suffix and raw query are joined
to the configured upstream without rewriting. The request body is streamed
unchanged and is never parsed by Agentbox.
Routes that inject a secret or credential must use HTTPS; literal loopback IP
HTTP upstreams are permitted for host-local services. `localhost` is not
accepted because resolving a name is weaker than verifying a loopback address.
Incoming authorization, cookies, forwarding headers, Cloudflare Access
credentials, and `cf-aig-authorization` are removed; configured headers are
applied afterward. Other provider and gateway headers are preserved. Queries
are forwarded but never logged. Ambiguous escaped paths, dot segments, repeated
separators, backslashes, and semicolons are rejected.

## Security boundaries

The daemon runs as `agentboxd`, with no capabilities and a hardened systemd
unit. Startup completes only after the control and data listeners are ready;
the unit also bounds file descriptors and OS tasks. Each container listener
accepts at most 128 simultaneous connections, and upstream connection, TLS,
and response-header work is bounded without imposing a timeout on streamed
response bodies. `systemd-creds` protects one 32-byte master key at startup.
Dynamic keys are independently sealed with AES-256-GCM using random nonces and
key-name-bound additional data under `/var/lib/agentbox/secrets`; rotation
needs no restart.
Renewable leases exist only in daemon memory, are never returned by the control
API, and are cleared on source/key changes and shutdown.

Membership in group `agentbox` is a trusted secret-management role. A member
cannot list plaintext through the API, but can set a route that sends a stored
key to an upstream they control, which is equivalent access. Root on the
running host can also reach daemon memory. Encryption at rest protects copied
or offline storage; it is not a defense against a compromised running host,
and full-disk encryption remains valuable.

Container egress is intentionally not restricted. A compromised agent can use
the routes assigned to its profile and spend against them, but it cannot recover
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
