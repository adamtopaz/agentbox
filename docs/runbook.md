# agentbox runbook

Operator procedures. Everything here is generic to any agentbox deployment.

## Add or rotate a secret

```sh
sudo agentbox add-secret <name>   # value read without echo, encrypted at rest
sudo agentbox setup               # loads it into caddy; derives .basic companions
```

`add-secret` pipes the value directly into `systemd-creds`, so it never lands
on disk in plaintext, never appears in argv or shell history, and is not
echoed to your terminal. Piping works too (`... | sudo agentbox add-secret x`).
Rotation is the same command again.

`setup` is idempotent; re-running it is the standard way to pick up secret
changes (systemd credentials are loaded at caddy start, so setup restarts
caddy). Secrets used in `{basic:USER:NAME}` templates get a pre-encoded
`<name>.basic` companion — rotating the source requires the `setup` re-run to
regenerate it.

Until a referenced secret is both installed **and** loaded into Caddy, its
routes serve `503 credential not installed` — deliberately, so a missing
credential can never turn into an unauthenticated upstream call. Two files
decide this: `/etc/agentbox/secrets.installed` (names only, written by setup)
and the `LoadCredentialEncrypted=` lines in
`/etc/systemd/system/caddy.service.d/agentbox.conf`. A secret must appear in
both, which is why installing a secret requires re-running `setup` (it
regenerates the drop-in and restarts caddy) and not just `proxy reload`.

### What encryption at rest does and does not protect

Ciphertext lives in `/etc/agentbox/secrets/<name>.cred`, encrypted by
`systemd-creds`. On a host with a TPM the key is sealed to the hardware; with
no TPM, systemd falls back to a host key at `/var/lib/systemd/credential.secret`.

It protects the secrets when the **disk is read outside the running system** —
a stolen or decommissioned drive, a backup, a copied snapshot. Note that with
a host key rather than a TPM, key and ciphertext sit on the same disk, so that
protection only holds if the two are separated (e.g. a backup covering `/etc`
but not `/var/lib/systemd`). Full-disk encryption is the stronger answer there.

It does **not** protect against root on the running host. Caddy needs the
plaintext at request time and must start unattended, so the key is necessarily
reachable by the machine. No scheme changes that. Membership in group
`agentbox` is likewise root-equivalent with respect to these secrets.

Because the ciphertext is bound to this host, a `.cred` file restored onto a
different machine will not decrypt — re-add the secret there.

Two caveats worth knowing. Migrating a previously-plaintext secret *unlinks*
the cleartext file rather than shredding it, so the old bytes may persist in
free blocks until the volume is re-provisioned — against a stolen-disk threat
the guarantee only fully holds behind full-disk encryption. And credentials
written before this feature landed were sealed with systemd's default PCR
policy; on a host with a TPM, re-add them (`agentbox add-secret <name>`) so
they are re-sealed without one, or a firmware or Secure Boot change can make
them permanently undecryptable.

## Add a route

Edit `/etc/agentbox/routes.json`. A route selects on **either** a path prefix
(stripped before proxying; this is what agents reach at `127.0.0.1:8787`) or a
Host header (path untouched; this is how `gh` and anything else that dials
`/run/agentbox.sock` is served):

```json
{
  "name": "anthropic-direct",
  "gateway": "*",
  "prefix": "/anthropic",
  "upstream": "https://api.anthropic.com",
  "inject": [{ "header": "x-api-key", "value": "{secret:anthropic-key}" }]
},
{
  "name": "gitlab-prod-only",
  "gateway": "prod",
  "host": "gitlab.com",
  "upstream": "https://gitlab.com",
  "inject": [{ "header": "Authorization", "value": "Bearer {secret:gitlab-token}" }]
}
```

**`gateway` is required on every route.** Use `"*"` for a route any container
may use, or a gateway name to restrict it to containers created against that
gateway. It is mandatory rather than defaulting to universal on purpose: a
route that forgot it would silently be reachable from every container,
dissolving the pinning boundary instead of being rejected by it.

Routes named `cloudflare-<gateway>` are generated — `setup` reconciles them
against `agentbox.json` on every run and will overwrite your edits. Everything
else you add is preserved untouched. A prefix that contains another
(`/cloudflare` alongside `/cloudflare/prod`) is refused, because the shorter
one would shadow the longer and serve it with the wrong credential.

Only add an injecting host route for a host that should receive that
credential. Redirect targets that carry signed URLs (asset/CDN hosts) should
be pass-through — no `inject` — so the token is not sent somewhere it was
never scoped for.

Then `agentbox proxy reload`. If the route references a new secret, add it with
`sudo agentbox add-secret <name>` and re-run `sudo agentbox setup` first (the
drop-in must know the name). Validation fails closed: a broken routes.json never replaces the
live config.

## Cloudflare AI Gateway: using more than one

List every gateway in `/etc/agentbox/agentbox.json`; there is no default.

```json
{ "account_id": "…", "gateways": ["prod", "experiments"] }
```

Each gets its own route and its own credential, named `cf-aig-token-<gateway>`:

```sh
sudo agentbox add-secret cf-aig-token-prod
sudo agentbox add-secret cf-aig-token-experiments
sudo agentbox setup
```

A container is created against exactly one, and **its Caddy site carries only
that gateway's route** — another gateway is not merely unauthorized for it, it
returns 404 because it does not exist on that socket:

```sh
agentbox create --gateway prod dev
agentbox create --gateway experiments bench
agentbox list          # the GATEWAY column shows which
```

Inside the container, `agentbox create` writes
`/etc/profile.d/agentbox-gateway.sh` with `ANTHROPIC_BASE_URL`,
`OPENAI_BASE_URL` and `AGENTBOX_GATEWAY`, and regenerates Codex's config. The
image itself is gateway-agnostic, so changing gateways needs no rebuild — but
an existing container keeps the gateway it was created with. Recreate it to
move it (containers are designed to be cheap to recreate).

This *is* an enforceable boundary, and it is the only one available: Cloudflare
cannot scope a token to one gateway — any token with `AI Gateway Run` reaches
every gateway on the account, including ones holding provider keys via Bring
Your Own Keys. Separate tokens therefore buy revocation and attribution
granularity; the proxy is what stops a container spending against a gateway
that is not its own.

Adding or removing a gateway: edit `gateways`, `add-secret
cf-aig-token-<name>` for a new one, then `sudo agentbox setup` — it reconciles
the generated `cloudflare-*` routes to match, adding and removing as needed,
and leaves your own routes alone. Existing containers keep the gateway they
were created with; if that gateway is removed, reconcile warns that the
container can now reach none.

Upgrading from the single-gateway format: `setup` migrates
`{account_id, gateway_id}` to a one-entry `gateways` list, keeping the account
id. The old shared `cf-aig-token` stops being referenced — add
`cf-aig-token-<gateway>`, then revoke the old token in Cloudflare and delete
its ciphertext.

## Revoke / contain a container

| Action | Effect |
|---|---|
| `agentbox proxy block <name>` | new requests get 403; in-flight requests drain (bounded by the 10s reload grace period) |
| `agentbox proxy block --hard <name>` | additionally removes the incus proxy device — existing connections sever instantly at the kernel |
| `agentbox destroy <name>` | deletes the container entirely (device goes with it) |
| Cloudflare dashboard | revoke/rotate the gateway token, set budgets |

`agentbox proxy unblock <name>` restores routes and re-adds the device.

## Logs

- Proxy logs: `journalctl -u caddy`. Metadata only by construction — no query
  strings, no headers, no bodies, on both the access log and the error log;
  each access entry carries `"container":"<name>"`.
- **Privacy note:** Cloudflare AI Gateway logs request/response *bodies* by
  default on the gateway side. If agent prompts/code are sensitive, disable or
  limit gateway logging in the Cloudflare dashboard. Host-side logs stay
  metadata-only regardless.

## Rebuild the base image

```sh
agentbox build-image            # agent versions are image properties; rebuild to bump
incus image list agentbox-base  # verify
```

Existing containers keep their old image; recreate them to pick up the new
one. Iterate on the provision script with
`agentbox build-image --provision image/provision.sh --keep-build`.

## Host reboot

Nothing to do. The rendered Caddyfile is persistent (`/var/lib/agentbox/Caddyfile`),
`caddy.service` starts on its own, tmpfiles.d recreates `/run/agentbox`, Caddy
re-binds the sockets, and containers have `boot.autostart=true`. Manual
container start/stop is plain `incus start|stop <name>`.

## Disaster recovery

- **Caddy down:** agents get connection refused; containers and their work
  are unaffected. `systemctl restart caddy`.
- **Rendered config rejected:** the previous config stays live; the bad
  candidate is kept at `/var/lib/agentbox/Caddyfile.rejected`. Fix
  routes.json, `agentbox proxy reload`.
- **State drift** (e.g. a container deleted behind agentbox's back):
  `agentbox list` shows it (`MISSING!` / `untracked`). Clean up with
  `agentbox destroy <name>` (tolerates missing instances) or by removing the
  state file in `/var/lib/agentbox/containers.d/` and running
  `agentbox proxy reload`.
- **Full rebuild:** `sudo agentbox setup && agentbox build-image`, reinstall
  secrets, recreate containers. Nothing else is stateful.
- **Permission denied on the state dir or incus:** you are not in the
  `agentbox` and `incus-admin` groups yet, or have not re-logged in since
  `setup` added you (`id -nG` to check).

## GitHub inside containers

Three independent paths, all credential-free inside the container:

- **git** — `https://github.com/...` and `git@github.com:` are rewritten to
  the `/github-git` route by the system gitconfig.
- **gh** — the image sets `http_unix_socket: /run/agentbox.sock` in
  `~/.config/gh/config.yml`, so every gh request (REST, GraphQL, uploads)
  goes over the proxy socket in plain HTTP with its real `Host:` header, and
  the host routes inject the PAT. `GH_TOKEN` is a dummy; gh never validates
  it. If gh reports a connection error, check `agentbox list` for the
  container's socket and that its `agentbox-socket` device exists
  (`incus config device list <name>`).
- **curl** — `curl http://127.0.0.1:8787/github-api/user` for one-off REST
  calls.

Only the hosts in the route table are reachable through the socket; anything
else gets a 404. `gh release download` and similar commands follow redirects
to asset hosts — `objects.githubusercontent.com` and `codeload.github.com` are
mapped as pass-through (no credential, since those URLs are already signed).
If a download 404s at the proxy, the redirect went somewhere unmapped; add a
pass-through host route for it rather than an injecting one.
