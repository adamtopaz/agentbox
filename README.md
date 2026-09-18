# agentbox

Agentbox runs coding agents in Incus containers or directly on the main host
without putting real API keys in those processes. A small Go daemon owns both
the reverse proxy and its live configuration. Agents receive short-lived or
dummy credentials; `agentboxd` removes
credential-bearing request headers and injects an appropriate host-side static
secret or renewable credential only after a route has matched.

There is no Caddy dependency and no generated proxy configuration. Routes,
keys, and container registrations change while the daemon is running.

## Architecture

```text
administrator (explicit sudo) ── root-only admin socket ──> typed application service
                                           ├── state.json (profiles/routes/containers/sources)
                                           ├── AES-256-GCM key envelopes
                                           ├── expiring credential broker
                                           └── immutable runtime snapshots

container ── Incus proxy device ──> per-container Unix socket
                                      └── Go httputil.ReverseProxy ──> upstream

regular user ── group-protected user socket ──> UID-authorized host session
host coding agent ── authenticated loopback bridge ──> UID-protected Unix socket ──> upstream
```

HTTP is only the current adapter for the control socket. Validation,
persistence, profile/route/key/credential operations, and commits live in a
transport-independent application service. Provider integrations are ordinary
compositions of the same generic profile, route, key-reference, and credential
binding model.

Container lifecycle and container sockets are administrator-only. Each
container names exactly one reusable profile, and its listener sees only the
routes and credential bindings in that profile. Host-session listeners are
separate and verify the connecting Unix UID, so another `agentbox` group member
cannot claim the session by discovering its socket name.

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
# Log out and back in after setup activates host-user group membership, then:
sudo agentbox image build
```

`make setup` builds both binaries as the current user, then runs the privileged
`agentbox setup` installation step through `sudo`. The installer installs
`agentbox` and `agentboxd`, creates the unprivileged
`agentboxd` account, generates one encrypted systemd credential for the master
key, and installs the only systemd unit in the project. It adds `$SUDO_USER` to
the `agentbox` host-access group; it does not grant Incus administration.
Administrative Agentbox and Incus operations use explicit `sudo`, keeping that
authority out of coding-agent processes. Log out and back in after setup.

Upgrading from state version 3 preserves profiles, routes, credentials, and
containers but creates no implicit user grants. Because restarting `agentboxd`
revokes all in-memory host sessions, finish any active `agentbox host` work
before installing the new binaries, then grant the intended profiles with
`sudo agentbox user grant USER PROFILE`.

Older Agentbox installers added the initial operator to `incus-admin`. The new
installer does not remove existing group memberships. On an upgraded host,
remove users from `incus-admin` separately if they should have host-only access,
then have them log out and back in. Keep Incus privilege only for accounts that
are intentionally allowed to administer Incus outside Agentbox as well.

Image building is an administrator operation invoked with explicit elevation.
It gives the embedded Incus/cloud-init configuration to a disposable
`agentbox-build` instance, waits for provisioning, verifies every pinned tool
and proxy configuration, removes instance-specific state, disables cloud-init
in the baked result, and publishes it as `agentbox-base`. Incus performs the
container work behind its daemon boundary. Rebuilding the same alias uses
`incus publish --reuse`.

## Configure and use

Create a named profile first. Provider helpers then assign ordinary routes,
public client settings, encrypted-key references, and renewable credential
bindings to that profile atomically:

```sh
sudo agentbox profile create production
```

GitHub support is built from ordinary routes and a renewable credential. Give
the GitHub App only the repository permissions agents need,
install it on the intended repositories, and download one App private key.
The Client ID, installation ID, repository selection, and permission subset
are non-secret configuration; only the PEM is stored as an encrypted key.

```sh
sudo agentbox key set github-app-private-key < /path/to/app.private-key.pem

sudo agentbox credential source github-app github-main \
  --client-id Iv1.example \
  --installation-id 12345678 \
  --private-key github-app-private-key \
  --repository-ids 111111,222222 \
  --permissions contents=write,pull_requests=write,issues=write

sudo agentbox profile set github production --source github-main

sudo agentbox container create --profile production work
sudo agentbox container shell work
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
sudo agentbox key set cloudflare-production
sudo agentbox profile set cloudflare production \
  --account-id 0123456789abcdef0123456789abcdef \
  --gateway ff-prod \
  --private-key cloudflare-production

sudo agentbox container create --profile production work
sudo agentbox container shell work
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
sudo agentbox status
sudo agentbox profile list
sudo agentbox profile show production
sudo agentbox route list production
sudo agentbox key list
sudo agentbox credential source list
sudo agentbox container list
sudo agentbox container block work
sudo agentbox container block --hard work
sudo agentbox container unblock work
sudo agentbox container destroy work
```

## Run coding agents directly on the host

An administrator must first grant a profile to the user's Unix account:

```sh
sudo usermod -aG agentbox alice
sudo agentbox user grant alice production
```

The user must start a new login session after first being added to the group.

That user can then run Claude Code, Codex, or Pi without Incus access:

```sh
agentbox host profiles
agentbox host claude --profile production
agentbox host codex --profile production
agentbox host pi --profile production
# Separate Agentbox flags from agent arguments with `--`:
agentbox host claude --profile production -- -p "inspect this repository"
agentbox host codex --profile production -- exec "inspect this repository"
agentbox host pi --profile production -- -p "inspect this repository"
# Run any other program with the same session and environment:
agentbox host run --profile production -- python3 my_agent.py
```

The command creates a non-persistent host identity in `agentboxd`, starts an
authenticated random-port loopback bridge, and launches the selected agent.
Codex receives per-run custom-provider arguments. Claude Code receives a
session-only gateway token. Pi receives a temporary configuration that merges
its existing providers and credentials while overriding the built-in OpenAI and
Anthropic providers. Agentbox does not replace or edit the user's persistent
agent configuration. On normal exit or a handled signal, the bridge, temporary
files, and daemon identity are removed; a daemon restart also revokes all host
identities because they are never written to `state.json`. A `SIGTERM` sent to
`agentbox` is relayed to the launched process, while Ctrl-C reaches it directly
from the terminal; a process killed by a signal yields exit status 128 plus the
signal number.

`host run` launches an arbitrary program through the same session and performs
no agent-specific configuration. It sets only the variables described below and
does not remove or remap other credentials the program may prefer, so use the
named launchers for Claude Code, Codex, and Pi. The session lasts exactly as
long as the program.

Within the launched process, `OPENAI_BASE_URL` and `ANTHROPIC_BASE_URL` use the
selected Agentbox profile. `AGENTBOX_PROXY_URL` and `AGENTBOX_PROXY_TOKEN` name
the bridge and its session token directly, so a program can reach any route in
the profile even when the profile environment provides no base URL for it. The
bridge accepts the token as `Authorization: Bearer`, `Authorization: token`,
HTTP Basic with the token as the password, or `X-Api-Key`. `OPENAI_API_KEY`
and `GH_TOKEN` carry the same token, as does `ANTHROPIC_API_KEY` except under
`host claude`, which removes it and supplies `ANTHROPIC_AUTH_TOKEN` instead.
GitHub CLI API traffic uses the session's protected Unix socket. A temporary
Git HTTPS transport helper sends only canonical
`https://github.com/...` clone/fetch/push operations through `/github-git/`, so
repository remotes remain unchanged; other Git HTTPS hosts are delegated to
Git's normal helper. As in the container image, GitHub SSH remotes are not
rewritten. Direct `curl`, MCP-server, connector/app, web-search, SSH, and other
unrecognized network traffic is outside this routing mechanism.

The host user must belong to `agentbox`, have an explicit grant for the selected
profile, and have the selected agent or program and `git` installed. The user
API returns only assigned profile names and public launch environment—not
routes, key names, or credential-source bindings. Use `--claude-bin`, `--codex-bin`, `--pi-bin`,
or `--git-bin` when an executable is not on `PATH`.

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
sudo agentbox key set example-token
sudo agentbox route put production route.json
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

Membership in `agentbox` permits only assigned-profile host sessions. Routes,
profiles, grants, keys, credential sources, image management, and containers use
a separate root-authenticated API and explicit elevation. A root process can set
a route that sends a stored key to an upstream it controls, which is equivalent
to plaintext access; root can also reach daemon memory. Encryption at rest
protects copied or offline storage, not a compromised running host.

A profile granted to regular users may inject credential material only into
HTTPS upstreams. Agentbox cannot prevent a trusted upstream from reflecting an
injected credential in its response, so administrators must grant only profiles
whose upstream behavior they trust.

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
sudo agentbox image build --alias agentbox-test
```

The Go module currently has no third-party dependencies.
