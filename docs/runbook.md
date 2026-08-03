# agentbox runbook

Operator procedures. Everything here is generic to any agentbox deployment.

## Add or rotate a secret

```sh
sudo install -m 600 /dev/stdin /etc/agentbox/secrets/<name>   # paste value, ^D
sudo agentbox setup        # regenerates LoadCredential drop-in + .basic companions
```

`setup` is idempotent; re-running it is the standard way to pick up secret
changes (systemd credentials are loaded at caddy start, so setup restarts
caddy). Secrets used in `{basic:USER:NAME}` templates get a pre-encoded
`<name>.basic` companion — rotating the source requires the `setup` re-run to
regenerate it.

Until a referenced secret is both installed **and** loaded into Caddy, its
routes serve `503 credential not installed` — deliberately, so a missing
credential can never turn into an unauthenticated upstream call. Two files
decide this: `/etc/agentbox/secrets.installed` (names only, written by setup)
and the `LoadCredential=` lines in
`/etc/systemd/system/caddy.service.d/agentbox.conf`. A secret must appear in
both, which is why installing a secret requires re-running `setup` (it
regenerates the drop-in and restarts caddy) and not just `proxy reload`.

## Add a route

Edit `/etc/agentbox/routes.json`. A route selects on **either** a path prefix
(stripped before proxying; this is what agents reach at `127.0.0.1:8787`) or a
Host header (path untouched; this is how `gh` and anything else that dials
`/run/agentbox.sock` is served):

```json
{
  "name": "groq",
  "prefix": "/groq",
  "upstream": "https://gateway.ai.cloudflare.com/v1/<ACCT>/<GW>/groq",
  "inject": [
    { "header": "cf-aig-authorization", "value": "Bearer {secret:cf-aig-token}" }
  ]
},
{
  "name": "gitlab-api",
  "host": "gitlab.com",
  "upstream": "https://gitlab.com",
  "inject": [{ "header": "Authorization", "value": "Bearer {secret:gitlab-token}" }]
}
```

Only add an injecting host route for a host that should receive that
credential. Redirect targets that carry signed URLs (asset/CDN hosts) should
be pass-through — no `inject` — so the token is not sent somewhere it was
never scoped for.

Then `agentbox proxy reload`. If the route references a new secret, install it
and re-run `sudo agentbox setup` first (the LoadCredential drop-in must know
the name). Validation fails closed: a broken routes.json never replaces the
live config.

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
