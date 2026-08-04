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

Any route whose name begins with `cloudflare-` is treated as generated: `setup`
reconciles those against `agentbox.json` on every run, overwriting edits and
**deleting ones it did not generate**. Do not name your own routes
`cloudflare-*`. Everything else you add is preserved untouched.

A prefix that contains another (`/cloudflare` alongside `/cloudflare/prod`) is
refused, because the shorter one would shadow the longer and serve it with the
wrong credential.

### path_map: one base URL, several upstream paths

A prefix route may carry `path_map`, which aliases whole request paths onto
other upstream paths:

```json
{
  "name": "cloudflare-prod",
  "gateway": "prod",
  "prefix": "/cloudflare/prod",
  "upstream": "https://gateway.ai.cloudflare.com/v1/<acct>/prod",
  "path_map": [
    { "path": "/v1/messages", "to": "/anthropic/v1/messages" },
    { "path": "/responses", "to": "/openai/responses" }
  ]
}
```

It exists for clients that accept a single base URL per provider but speak
several API shapes underneath it — see the pi notes below. `path` matches the
whole path left after the prefix is stripped (not a prefix, not a pattern), and
`to` replaces it, still relative to the upstream's own path. Anything unmatched
falls through to the route's normal pass-through behaviour, so a target
addressed explicitly keeps working alongside its alias.

Whole-path matching is deliberate: a finite set means what a mapping can reach
is decidable by reading it. Wildcards, regexes, `..`, Caddy placeholders, and a
`to` that is another entry's `path` are all rejected. A mapping grants no
authority the route did not already have — same upstream, same injected
credential, same gateway restriction, and the fail-closed 503 still applies when
the credential is missing.

Two details worth knowing before relying on it:

- Matching is **not byte-exact**. Caddy's `path` matcher is case-insensitive and
  sees the cleaned, percent-decoded path, so `/V1/Messages`, `//v1/messages` and
  `/v1%2Fmessages` all hit a mapping written `/v1/messages`. This changes which
  spellings reach the mapped target, never which target they reach.
- The alias is additive for *targets*, not for *sources*. Once `/v1/messages` is
  mapped, it can no longer reach `<upstream>/v1/messages` — that spelling now
  goes to the mapped target instead. Only map paths that are not themselves
  meaningful on the upstream.

Only add an injecting host route for a host that should receive that
credential. Redirect targets that carry signed URLs (asset/CDN hosts) should
be pass-through — no `inject` — so the token is not sent somewhere it was
never scoped for.

Then `agentbox proxy reload`. If the route references a new secret, add it with
`sudo agentbox add-secret <name>` and re-run `sudo agentbox setup` first (the
drop-in must know the name). Validation fails closed: a broken routes.json never replaces the
live config.

## Two Cloudflare endpoints per gateway

Each configured gateway gets **two** generated routes, because Cloudflare serves
its models on two different endpoints and not every model is on both:

| Route | Container-visible | Upstream | Auth injected |
|---|---|---|---|
| `cloudflare-<gw>` | `/cloudflare/<gw>/…` | `gateway.ai.cloudflare.com/v1/<acct>/<gw>/…` | `cf-aig-authorization` |
| `cloudflare-rest-<gw>` | `/cloudflare-rest/<gw>/…` | `api.cloudflare.com/client/v4/accounts/<acct>/ai/…` | `Authorization` + `cf-aig-gateway-id` |

The first is the **provider-native passthrough**: the provider is a path segment
(`/anthropic`, `/openai`, `/compat`) and the model is named the provider's own
way. This is what `claude`, `codex` and `pi` use.

The second is Cloudflare's **REST API**, which Cloudflare's docs group with
`env.AI.run()` as the "Unified Billing endpoints". Here the gateway is a header
rather than a path segment — injected by the proxy, so a container cannot select
a gateway at all on this route — and the model is named `provider/model` in the
request **body**:

```sh
incus exec <container> -- su - agent -c 'curl -sS -X POST \
  http://127.0.0.1:8787/cloudflare-rest/<gw>/v1/messages \
  -H "content-type: application/json" \
  -d "{\"model\":\"anthropic/claude-fable-5\",\"max_tokens\":64,
       \"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"'
```

**Why both exist:** the newest models are served only on the REST endpoint. On
the provider-native passthrough they get no credential attached and are
forwarded bare, so the provider answers `401 x-api-key header is required` —
see the 401 note above. Confirmed 2026-08-04 with `claude-fable-5`.

**What the REST route cannot do:** because the model name lives in the body and
agentbox never rewrites bodies, a client that sends bare model ids cannot reach
these models through it. That includes `claude`, `codex` and `pi` as wired.
Today the REST route is for `curl` and for anything you can hand a full
`provider/model` string.

Both routes reuse the same `cf-aig-token-<gw>` secret. They need different
*permissions* on it, though: the passthrough needs `AI Gateway Run`, and the
REST API is documented as needing `AI Gateway`. If the REST route answers 403
while the passthrough works, mint a token with both and re-add the secret.

## Cloudflare AI Gateway: using more than one

List every gateway in `/etc/agentbox/agentbox.json`; there is no default.

```json
{ "account_id": "…", "gateways": ["prod", "experiments"] }
```

Each gets its own routes (both of the above) and its own credential, named
`cf-aig-token-<gateway>`:

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

## Agents in the image

`claude` and `codex` are wired through the proxy and verified working.
Provisioning fails the build if any agent installs without producing its
binary — npm exiting 0 does not prove the command exists, as a package can
install cleanly and ship a differently-named one.

In pi, all three providers are proxied — `anthropic`, `openai`, and
`cloudflare-ai-gateway` (`pi --model cloudflare-ai-gateway/claude-opus-5`).

`pi` is routed by `~/.pi/agent/models.json`, written per container by
`agentbox create`. pi honours no `*_BASE_URL` environment variable — it
resolves a provider's endpoint as extension > models.json > built-in — so
without that file it talks to Anthropic, OpenAI and Cloudflare directly. That
fails closed (the container holds only dummy keys) but bypasses the proxy, so
if you see pi reporting 401 from a provider, check that file exists and names
the container's gateway.

The `cloudflare-ai-gateway` provider needs one extra thing, and it is why
`path_map` exists. A provider-level `baseUrl` replaces each model's catalog URL
wholesale, and those URLs end in *different* provider segments depending on the
model — `/anthropic`, `/openai` or `/compat`. pi offers no per-model override
(`modelOverrides` covers `name, reasoning, thinkingLevelMap, input, cost,
contextWindow, maxTokens, headers, compat` — not `baseUrl`), so one base URL
would necessarily break two families out of three. What saves it is that pi
appends a distinct suffix per API shape, so the segment is recoverable from the
path: the generated gateway route maps `/v1/messages` → `/anthropic/v1/messages`,
`/responses` → `/openai/responses`, `/chat/completions` →
`/compat/chat/completions`. Verified against pi 0.83.0.

Two known rough edges, both upstream of agentbox:

- A few Workers AI models carry a `maxTokens` in pi's catalog above what the
  model accepts (`glm-5.2` says 262144, the model caps at 256000), so pi's
  first request is rejected with `max_completion_tokens is too large`. Fix it
  per model in `~/.pi/agent/models.json` with `modelOverrides` — `maxTokens`
  *is* an overridable field.
- pi's catalog marks these models as reachable via `/compat`, which Cloudflare
  documents as deprecated in favour of its REST API
  (`api.cloudflare.com/client/v4/accounts/<id>/ai/...`). That API is not usable
  here: it identifies the model as `provider/model` in the request *body*, and
  agentbox never rewrites bodies. If Cloudflare retires `/compat`, the Workers
  AI models stop working; the Anthropic and OpenAI families are unaffected.

### A 401 through the gateway usually means "unknown model", not "bad credential"

Cloudflare AI Gateway attaches your stored provider key only for models in
**its** catalog. For a model it does not recognize it forwards the request bare,
and the provider answers `401 x-api-key header is required` — an error that
reads like the proxy failed to inject a credential when in fact it did.
Confirmed 2026-08-04: `claude-fable-5` and an invented `claude-bogus-99` return
byte-identical 401s, while `claude-opus-5` and `claude-sonnet-5` return 200 over
the same route with the same injected token.

So before suspecting agentbox, try a known-good model on the same route:

```sh
incus exec <container> -- su - agent -c 'curl -sS -X POST \
  http://127.0.0.1:8787/cloudflare/<gw>/anthropic/v1/messages \
  -H "content-type: application/json" -H "anthropic-version: 2023-06-01" \
  -d "{\"model\":\"claude-opus-5\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"'
```

If that returns 200, injection is fine and the other model simply is not
available through the gateway. Note that pi's catalog can list models
Cloudflare's does not carry, so a model appearing in `pi --list-models` is not
evidence the gateway can serve it. Reaching such a model means going to the
provider directly rather than through Cloudflare — what the reserved
`/anthropic` and `/openai` prefixes are for, which needs that provider's own
API key as a secret.

The mapping's left-hand side (the suffix pi appends) follows from the model's
`api` field and is stable; its right-hand side is the provider segment from pi's
**remote** catalog, which pi refreshes from `pi.dev`. So a catalog change can
make a `to` stale. Both failure modes are loud rather than silent: a stale `to`
gets `400 Invalid provider` from Cloudflare, and a new API shape pi has not been
mapped for falls through to pass-through and gets the same. If that happens,
re-derive the mapping from the catalog:

```sh
incus exec <container> -- su - agent -c \
  'jq -r ".[\"cloudflare-ai-gateway\"].models | .[] | \"\(.api)  \(.baseUrl)\"" \
     ~/.pi/agent/models-store.json | sort -u'
```

Check what an image actually shipped:

```sh
incus exec <container> -- cat /etc/agentbox-image
```

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
