# Agentbox runbook

## Service health

```sh
agentbox status
systemctl status agentboxd
journalctl -u agentboxd
```

Production paths are:

| Purpose | Path |
|---|---|
| Control socket | `/run/agentbox/control.sock` |
| Container listeners | `/run/agentbox/containers/<name>.sock` |
| Non-secret state | `/var/lib/agentbox/state.json` |
| Encrypted key envelopes | `/var/lib/agentbox/secrets/<name>.json` |
| Encrypted master credential | `/etc/agentbox/master-key.cred` |
| Unit | `/etc/systemd/system/agentboxd.service` |

The sockets are group-accessible to `agentbox`; their directories grant the
group traverse but not replace permission. The state and encrypted key
directories belong to the unprivileged service account.

## Keys

Add or rotate a key without restarting the daemon:

```sh
agentbox key set <name>
# or
printf '%s' "$VALUE" | agentbox key set <name>
```

The CLI never puts the value in argv. Interactive input is hidden; piped input
has one trailing newline removed. The API never returns key values.

```sh
agentbox key list
agentbox key delete <name>
```

Deletion is refused while any route or credential source references the key.
Remove or replace those references first. Missing keys are permitted in route
and credential-source definitions so an operator can stage configuration, but
requests fail closed with 503 before dialing upstream.

Each envelope is AES-256-GCM ciphertext with a fresh nonce. The key name is
authenticated as additional data, so renaming an envelope cannot retarget its
contents. An invalid envelope, wrong master key, or authentication failure
prevents daemon startup instead of silently dropping keys.

## Renewable credentials

A credential source describes how to issue request material without exposing
provider details to routes. A profile binds logical credential names to
sources, and every container using that profile inherits the binding:

```text
route template {credential:github}
             ↓
container work → profile production + logical name github
             ↓
profile binding to source github-main
             ↓
github-app provider → expiring lease
```

List the live, non-secret configuration:

```sh
agentbox credential source list
agentbox credential source list --json
agentbox profile show production
```

Generic JSON sources can be submitted with `credential source put`. The
GitHub-specific CLI adapter constructs the same generic source after validating
its flags:

```sh
agentbox key set github-app-private-key < /path/to/app.private-key.pem

agentbox credential source github-app github-main \
  --client-id Iv1.example \
  --installation-id 12345678 \
  --private-key github-app-private-key \
  --repository-ids 111111,222222 \
  --permissions contents=write,pull_requests=write,issues=write

agentbox profile create production
agentbox profile set github production --source github-main
```

The Client ID is shown on the GitHub App settings page. The installation ID is
the numeric component of the installation's Configure URL (and is also
available from GitHub's App installation API). It is not the App ID.

`--repositories repo-a,repo-b` is an alternative to numeric IDs; repository
names are relative to the installation account. The two selectors are mutually
exclusive and GitHub permits at most 500. Omitting both gives the token access
to every repository selected in that installation. Omitting permissions gives
the token all permissions granted to the installation. Neither option can
expand beyond the App installation's repository selection or permissions.

One source represents one GitHub installation and one requested repository/
permission subset. Create additional sources for narrower profiles or for
installations under other accounts. One token cannot span installations.

Sources and profile bindings update while the daemon is running:

```sh
agentbox profile set github <profile> --source <source>
agentbox profile unset github <profile>
agentbox credential source delete <source>
```

Source deletion is refused while a profile references it. Updating a source or
rotating one of its encrypted keys invalidates the cached lease immediately.

The broker obtains at most one lease concurrently for a source, caches it only
in daemon memory, and refreshes five minutes before expiry. During that refresh,
concurrent requests may continue using the still-valid old lease. A temporary
refresh failure also falls back to the old lease until its exact expiry; after
that the proxy returns 503. Failed issuance is retried no more than once every
15 seconds to avoid an upstream outage or invalid configuration creating a
token-mint storm. Leases are never persisted, returned by the control API, or
logged.

The `github-app` provider uses the App Client ID as the JWT issuer, signs RS256
with the encrypted PEM, and calls only GitHub's fixed installation-token
endpoint with a direct, time-limited HTTP client. Redirects are rejected and
upstream error bodies are never included in errors or logs. Token strings are
opaque; no prefix or fixed-length assumption is made.

## Routes

List or export routes:

```sh
agentbox route list <profile>
agentbox route list --json <profile> > routes.json
```

Create or replace one named route:

```sh
agentbox route put <profile> route.json
```

Atomically replace one profile's entire route collection:

```sh
agentbox route replace <profile> routes.json
```

Delete one:

```sh
agentbox route delete <profile> <name>
```

All input is strict JSON: unknown fields, duplicate names/selectors, invalid
URLs, unsafe paths, forbidden transport headers, malformed templates, and
ambiguous matches are rejected before state changes. A commit validates and
compiles a new immutable snapshot, atomically persists state, publishes the
snapshot, and reconciles listeners. A listener failure rolls state back.

A route that renders `{secret:...}` or `{credential:...}` material must use an
HTTPS upstream. Plain HTTP is accepted for material only when the upstream host
is a literal loopback IP such as `127.0.0.1` or `::1`; `localhost` and other
DNS names are deliberately not trusted as proof of a local transport.

Matching order is exact-host routes, then longest path prefix within the
container's selected profile. Agentbox routes do not transform request bodies, raw
queries, or provider-visible path suffixes. `strip_prefix` removes only the
local Agentbox routing namespace before joining the suffix to the upstream base
path. Bodies remain streaming and are never parsed by the proxy.

State version 3 introduces reusable profiles and migrates version-2 scopes into
profiles. Legacy per-container grants are migrated only when every container in
a scope has the same bindings; a conflicting scope fails startup rather than
broadening access. Version-1 transforming routes remain omitted during
migration because Agentbox is an authentication proxy.

## Profiles

A profile is the reusable policy selected when a container is created. It owns
generic routes, public container environment, and logical credential bindings.
Provider-specific commands are convenience adapters that atomically compose
those generic fields:

```sh
agentbox profile create production
agentbox profile set cloudflare production \
  --account-id <32-hex-id> --gateway ff-prod \
  --private-key <stored-key-name>
agentbox profile set github production --source github-main
```

Inspect or remove assignments without exposing any secret values:

```sh
agentbox profile list
agentbox profile show production
agentbox profile unset github production
agentbox profile unset cloudflare production
agentbox profile delete production
```

Deletion is refused while a container uses the profile. `profile put` accepts
the strict generic JSON form for integrations that do not yet have a helper.

Multiple profiles can reference different Cloudflare gateways, encrypted keys,
and GitHub App sources. Reapplying one integration replaces only that
integration inside the selected profile and preserves its other routes and
bindings. Avoid the reserved `github-*` and `cloudflare*` route names for
operator-owned routes.

The GitHub profile has path routes for Git HTTPS/API and exact-host routes for
GitHub CLI. `api.github.com` and `uploads.github.com` receive the container
profile's bound `github` credential;
`objects.githubusercontent.com` and `codeload.github.com` are pass-through so
credentials are not attached to signed asset downloads. Unmapped hosts return
404. GitHub CLI uses its supported `http_unix_socket` setting; no TLS
interception, DNS override, or fake CA is involved. The container retains its
dummy `GH_TOKEN`; Agentbox strips it before injecting the installation token.

Git repositories retain canonical `https://github.com/OWNER/REPOSITORY.git`
remote URLs. A GitHub-only `git-remote-https` transport helper changes only the
live clone/fetch/push destination to the container's `/github-git/` route, then
delegates the Git wire protocol to the distro's original HTTP helper. This lets
`gh` infer the repository from the current checkout. Other HTTPS Git hosts are
delegated unchanged, and SSH GitHub URLs are intentionally not translated.
The helper contains no credential and never receives an installation token.

Every container using a GitHub-enabled profile receives the same GitHub policy.
GitHub operations are attributed to the App installation. Commands that require
a human-user-only API endpoint may not work; validate the exact `gh` operations
and App permissions used by agents.

The Cloudflare integration creates one provider-native route in the selected
profile. `--private-key` explicitly references the arbitrary key-store entry
containing that gateway's Cloudflare token; no key name is derived from a
gateway or provider name. The container uses
`/cloudflare/<profile>/anthropic/...` and
`/cloudflare/<profile>/openai/...`; after removing that local namespace, Agentbox
forwards the exact suffix to Cloudflare AI Gateway's corresponding provider
endpoint. It strips dummy/provider credentials and incoming
`cf-aig-authorization`, then injects only the host-side value. It does not alter
model names, JSON structure, system blocks, messages, feature headers, or query
parameters. The container receives only loopback URLs and dummy keys.

Provider-native routing means the provider endpoint, rather than Cloudflare's
unified REST schema, decides model availability. Opus, Sonnet, and Haiku worked
in the current Anthropic tests. Fable 5 returned a provider-key requirement
under the tested Unified Billing configuration, so it is intentionally not
shimmed through the REST API.

## Containers

```sh
agentbox container create --profile production <name>
agentbox container list
agentbox container shell <name>
agentbox container destroy <name>
```

Use an empty profile for a generic container with no provider integrations,
and `--image <alias>` to select another image. The profile determines route and
credential visibility and is persisted independently of Incus. New instances have
safe resource defaults: 4 CPUs, 8 GiB memory, 2,048 processes, and a 50 GiB
root disk. Adjust them at creation time when needed:

```sh
agentbox container create --profile production \
  --cpus 8 --memory 16GiB --processes 4096 --disk 100GiB <name>
```

To let the Incus profile and host determine available capacity without adding
Agentbox per-instance limits, use the explicit opt-out:

```sh
agentbox container create --profile production \
  --no-resource-limits <name>
```

`--no-resource-limits` cannot be combined with `--cpus`, `--memory`,
`--processes`, or `--disk`. Incus profile-level limits, if any, still apply.

These limits are stored by Incus and do not apply retroactively to existing
containers. Use `incus config set` and `incus config device override`, or
recreate an old container, to bring it under the same limits.

`container list` deliberately exposes drift: a missing Incus instance, missing
daemon socket, or tagged but unregistered Incus instance is shown instead of
being repaired implicitly.

Soft containment changes the live snapshot so new requests return 403:

```sh
agentbox container block <name>
agentbox container unblock <name>
```

Hard containment first blocks the identity, then removes both Incus proxy
devices to sever existing connections:

```sh
agentbox container block --hard <name>
```

Unblock re-adds missing managed devices. Destroy refuses to delete an existing
Incus instance unless it carries `user.agentbox=true`.

## Control protocol

The current wire adapter is HTTP/1.1 over `/run/agentbox/control.sock`:

| Method | Path | Operation |
|---|---|---|
| `GET` | `/v1/health` | daemon counts/status |
| `GET` | `/v1/profiles` | list reusable profiles |
| `PUT`, `DELETE` | `/v1/profiles/{name}` | atomically upsert or delete a profile |
| `GET`, `PUT` | `/v1/profiles/{profile}/routes` | list or replace one profile's routes |
| `PUT`, `DELETE` | `/v1/profiles/{profile}/routes/{name}` | upsert or delete one profile route |
| `GET` | `/v1/keys` | list key metadata |
| `PUT`, `DELETE` | `/v1/keys/{name}` | set raw value or delete key |
| `GET` | `/v1/credential-sources` | list non-secret source configuration |
| `PUT`, `DELETE` | `/v1/credential-sources/{name}` | upsert or delete a source |
| `GET`, `POST` | `/v1/containers` | list or register identities |
| `PATCH`, `DELETE` | `/v1/containers/{name}` | block/unblock or unregister |

The protocol is not the domain boundary. Handlers call a typed application
service that contains all mutation and validation semantics; another local
transport can be added without duplicating route, key, or credential logic.

There is no bearer authentication on this local API. Authorization is the
kernel-enforced owner/group/mode on the Unix socket. Linux peer credentials are
recorded in control logs for attribution. Members of `agentbox` are trusted
because arbitrary route management can redirect injected keys and credentials.

The systemd unit uses `Type=notify`, so setup/restart is not considered
successful until state, encrypted keys, the control listener, and all persisted
container listeners have loaded. The unit bounds file descriptors and OS tasks;
the data plane separately caps each container listener at 128 simultaneous
connections. Dial, TLS handshake, response-header time, and response-header
size are bounded, while response bodies remain streamable without a global
request timeout.

## Master key and recovery

`agentbox setup` generates a random 32-byte master key, asks `systemd-creds` to
encrypt it using the host's available TPM/host-key mechanism, verifies a
decrypt round trip, then installs only the ciphertext. systemd exposes the
plaintext in the service's private credential directory at startup. Dynamic
key envelopes are handled by agentbox itself, which is why they can change
without unit regeneration or a daemon restart.

Back up these together:

- `/var/lib/agentbox/state.json`
- `/var/lib/agentbox/secrets/`
- `/etc/agentbox/master-key.cred`

The encrypted systemd credential is host-bound. A same-host restore can
recover the set; moving to another host normally cannot. For migration, keep
the non-secret state, run setup on the destination to create a new master key,
and re-enter every dynamic key. Loss of the master credential has the same
recovery procedure. Do not copy ciphertext aside and assume it is a portable
backup.

Neither this encryption nor systemd's private credential delivery protects
against root on a running host. Use full-disk encryption for the broader
offline-disk threat and upstream rotation after a suspected compromise.

## Image maintenance

The disposable builder instance is defined in
[`../image/agentbox.yaml`](../image/agentbox.yaml) and embedded into the CLI.
It is an Incus instance configuration whose `cloud-init.user-data` installs
packages, creates the agent user, writes proxy configuration, and installs the
pinned coding agents.

Build and publish it through your existing Incus access—no `sudo` or separate
image-builder installation is required:

```sh
agentbox image build
```

The command refuses to touch an existing `agentbox-build` instance unless it
carries `user.agentbox-build=true`. It removes a stale owned builder, initializes
`images:debian/13/cloud`, waits for `cloud-init status --wait`, independently
verifies binaries/configuration, removes cloud-init seed/log/machine state,
disables cloud-init in the final filesystem, stops the builder, and publishes
the result with `incus publish --reuse`. The builder is deleted on both success
and failure.

`--alias` selects the output image alias. `--source` selects another
cloud-init-enabled base image. `--keep-builder` retains the stopped builder on
success—or its current state on failure—for diagnosis:

```sh
agentbox image build --alias agentbox-test --keep-builder
incus delete --force agentbox-build   # when finished inspecting it
```

The image pins Node.js 24 LTS from the official nodejs.org binary distribution
because Debian 13's Node.js 20 cannot run the pinned pi release. Downloads are
accepted only for the architectures and SHA-256 checksums recorded in the
cloud-init definition; an unreviewed architecture fails closed.
The Debian `fd-find` package is exposed as `/usr/local/bin/fd`, which prevents
pi from downloading a per-user helper during first startup.

Update Node.js, Claude Code, Codex, and pi by changing their exact versions and
checksums in the cloud-init `runcmd`, the independent verification script, and
`/etc/agentbox-image` marker, then build and
launch a fresh container to smoke-test each binary. Existing containers do not
change when an image alias is rebuilt.

## Logs and incident response

`agentboxd` emits structured logs to stderr/journald. Proxy request entries
contain container, route, method, status, and duration only. Control entries
contain method, API path, duration, and Linux UID/GID/PID where available.
Queries, request/response headers, bodies, and key values are never logged by
agentbox. Remember that an upstream such as Cloudflare AI Gateway may log
request and response bodies independently.

For suspected container compromise:

1. `agentbox container block --hard <name>`.
2. Rotate every key reachable from that container's profile.
3. Review daemon metadata and upstream audit/billing logs.
4. Destroy and recreate the container.

For suspected host compromise, rotate all upstream credentials after restoring
the host; ciphertext-at-rest does not change that response.
