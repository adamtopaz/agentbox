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

Deletion is refused while any route references the key. Remove or replace
those routes first. Missing keys are permitted in route definitions so an
operator can stage configuration, but requests to such a route fail closed
with 503 before dialing upstream.

Each envelope is AES-256-GCM ciphertext with a fresh nonce. The key name is
authenticated as additional data, so renaming an envelope cannot retarget its
contents. An invalid envelope, wrong master key, or authentication failure
prevents daemon startup instead of silently dropping keys.

## Routes

List or export routes:

```sh
agentbox route list
agentbox route list --json > routes.json
```

Create or replace one named route:

```sh
agentbox route put route.json
```

Atomically replace the entire route collection:

```sh
agentbox route replace routes.json
```

Delete one:

```sh
agentbox route delete <name>
```

All input is strict JSON: unknown fields, duplicate names/selectors, invalid
URLs, unsafe paths, forbidden transport headers, malformed templates, and
ambiguous matches are rejected before state changes. A commit validates and
compiles a new immutable snapshot, atomically persists state, publishes the
snapshot, and reconciles listeners. A listener failure rolls state back.

Matching order is exact-host routes, then longest path prefix. For otherwise
equivalent selectors, a route in the container's concrete scope wins over the
universal `"*"` route. `path_map` entries match exact post-strip paths and do
not cascade.

Provider helpers are optional route generators:

```sh
agentbox profile apply github
agentbox profile apply cloudflare --account-id <32-hex-id> --gateways prod,test
```

Applying a profile replaces the routes it owns (`github-*` or `cloudflare-*`)
and preserves all others. Avoid those prefixes for operator-owned routes.

The GitHub profile has path routes for Git HTTPS/API and exact-host routes for
GitHub CLI. `api.github.com` and `uploads.github.com` receive the PAT;
`objects.githubusercontent.com` and `codeload.github.com` are pass-through so
credentials are not attached to signed asset downloads. Unmapped hosts return
404. GitHub CLI uses its supported `http_unix_socket` setting; no TLS
interception, DNS override, or fake CA is involved.

The Cloudflare profile creates only the provider-native AI Gateway route for
each named scope. It intentionally does not preserve the old, unverified
Cloudflare REST route.

## Containers

```sh
agentbox container create --scope prod <name>
agentbox container list
agentbox container shell <name>
agentbox container destroy <name>
```

Use `--configure none` for a generic container with no Cloudflare client
settings, and `--image <alias>` to select another image. The scope determines
route visibility and is persisted independently of Incus.

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
| `GET`, `PUT` | `/v1/routes` | list or replace all routes |
| `PUT`, `DELETE` | `/v1/routes/{name}` | upsert or delete one route |
| `GET` | `/v1/keys` | list key metadata |
| `PUT`, `DELETE` | `/v1/keys/{name}` | set raw value or delete key |
| `GET`, `POST` | `/v1/containers` | list or register identities |
| `PATCH`, `DELETE` | `/v1/containers/{name}` | block/unblock or unregister |

The protocol is not the domain boundary. Handlers call a typed application
service that contains all mutation and validation semantics; another local
transport can be added without duplicating route or key logic.

There is no bearer authentication on this local API. Authorization is the
kernel-enforced owner/group/mode on the Unix socket. Linux peer credentials are
recorded in control logs for attribution. Members of `agentbox` are trusted
because arbitrary route management can redirect injected keys.

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
2. Rotate every key reachable from that container's scope.
3. Review daemon metadata and upstream audit/billing logs.
4. Destroy and recreate the container.

For suspected host compromise, rotate all upstream credentials after restoring
the host; ciphertext-at-rest does not change that response.
