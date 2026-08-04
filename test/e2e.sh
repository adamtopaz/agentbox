#!/usr/bin/env bash
# agentbox end-to-end test: proves the security properties of the data plane
# AND the control plane against a real caddy and a real container, without
# touching production state. Run as root: sudo test/e2e.sh
#
# It drives the real `agentbox` CLI (create / list / proxy block / unblock /
# destroy) pointed at temp directories and a private caddy instance, so the
# same code paths an operator uses are the ones under test. Only the routes,
# state dir, run dir and caddy instance are private; the container is real and
# is wired by `agentbox create` exactly as in production.
#
# Requires: root, caddy >= 2.8 in PATH (or $CADDY), incus, the agentbox-base
# image, go.

set -euo pipefail

CONTAINER=agentbox-e2e

say()  { echo -e "\033[1m== $*\033[0m"; }
die()  { echo "e2e: FAIL: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root"
command -v incus >/dev/null || die "incus not found"
command -v go >/dev/null || die "go not found"
CADDY=${CADDY:-caddy}
command -v "$CADDY" >/dev/null || die "caddy not found"
"$CADDY" version | grep -qE '^v?2\.([89]|[1-9][0-9])' || die "caddy >= 2.8 required (got: $($CADDY version))"
incus image info agentbox-base >/dev/null 2>&1 || die "agentbox-base image missing (run: agentbox build-image)"

cd "$(dirname "$0")/.."
W=$(mktemp -d /tmp/agentbox-e2e.XXXXXX)
mkdir -p "$W/state/containers.d" "$W/run/containers" "$W/creds"
ADMIN="unix/$W/admin.sock|0660"

CADDY_PID=""
ECHO_PID=""
cleanup() {
    set +e
    # shellcheck disable=SC2086
    "$W/agentbox" destroy $FLAGS "$CONTAINER" >/dev/null 2>&1
    [ -n "$CADDY_PID" ] && kill "$CADDY_PID" 2>/dev/null
    [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null
    incus delete --force "$CONTAINER" 2>/dev/null
    rm -rf "$W"
}
FLAGS=""
trap cleanup EXIT

say "build"
go build -o "$W/agentbox" ./cmd/agentbox

# Every CLI invocation is scoped to the temp instance. Go's flag package stops
# parsing at the first non-flag argument, so the flags must precede positional
# ones — hence the subcommand-aware wrapper rather than a plain append.
FLAGS="--routes $W/routes.json --state-dir $W/state --run-dir $W/run
       --caddyfile $W/Caddyfile --credentials-dir $W/creds
       --secrets-manifest $W/secrets.installed --caddy-dropin $W/dropin.conf
       --caddy-bin $CADDY --caddy-admin $ADMIN"
# shellcheck disable=SC2086  # word splitting of FLAGS is intended
abx() {
    local cmd=$1; shift
    if [ "$cmd" = proxy ]; then
        local sub=$1; shift
        "$W/agentbox" proxy "$sub" $FLAGS "$@"
    else
        "$W/agentbox" "$cmd" $FLAGS "$@"
    fi
}

say "test fixtures (dummy secret material only)"
printf 'e2e-dummy-secret' > "$W/creds/e2e-token"
# Distinct per-gateway values: with one shared value the pinning assertion
# below could only ever catch a 404, never "got the other gateway's token".
printf 'token-for-mine' > "$W/creds/e2e-token-mine"
printf 'token-for-other' > "$W/creds/e2e-token-other"
printf '# names only\ne2e-token\ne2e-token-mine\ne2e-token-other\n' > "$W/secrets.installed"
{
  echo '[Service]'
  for n in e2e-token e2e-token-mine e2e-token-other; do
    printf 'LoadCredentialEncrypted=%s:%s/creds/%s\n' "$n" "$W" "$n"
  done
} > "$W/dropin.conf"

"$W/agentbox" debug-echo --listen 127.0.0.1:0 > "$W/echo.out" 2>&1 &
ECHO_PID=$!
sleep 0.5
UPSTREAM_PORT=$(grep -oP 'LISTEN 127.0.0.1:\K[0-9]+' "$W/echo.out" || true)
[ -n "$UPSTREAM_PORT" ] || die "echo upstream did not start: $(cat "$W/echo.out")"

# The injected headers deliberately collide with the strip list — Caddy
# applies header deletes after sets inside reverse_proxy regardless of
# Caddyfile order, so a route injecting Authorization or cf-aig-* is exactly
# the case that would silently forward an unauthenticated request.
cat > "$W/routes.json" <<EOF
{"routes":[
 {"name":"echo","gateway":"*","prefix":"/echo","upstream":"http://127.0.0.1:${UPSTREAM_PORT}","inject":[
   {"header":"Authorization","value":"Bearer {secret:e2e-token}"},
   {"header":"cf-aig-authorization","value":"Bearer {secret:e2e-token}"}]},
 {"name":"nocred","gateway":"*","prefix":"/nocred","upstream":"http://127.0.0.1:${UPSTREAM_PORT}","inject":[
   {"header":"X-Absent","value":"{secret:not-installed}"}]},
 {"name":"hostroute","gateway":"*","host":"api.example.test","upstream":"http://127.0.0.1:${UPSTREAM_PORT}","inject":[
   {"header":"Authorization","value":"Bearer {secret:e2e-token}"}]},
 {"name":"gw-mine","prefix":"/cloudflare/mine","gateway":"mine","upstream":"http://127.0.0.1:${UPSTREAM_PORT}/v1/ACCT/mine","inject":[
   {"header":"cf-aig-authorization","value":"Bearer {secret:e2e-token-mine}"}]},
 {"name":"gw-other","prefix":"/cloudflare/other","gateway":"other","upstream":"http://127.0.0.1:${UPSTREAM_PORT}/v1/ACCT/other","inject":[
   {"header":"cf-aig-authorization","value":"Bearer {secret:e2e-token-other}"}]}
]}
EOF

say "render config, start private caddy"
abx proxy reload >/dev/null
grep -q "admin unix/$W/admin.sock" "$W/Caddyfile" || die "test config must use the test admin socket"
"$CADDY" run --config "$W/Caddyfile" --adapter caddyfile > "$W/caddy.log" 2>&1 &
CADDY_PID=$!
for _ in $(seq 1 20); do [ -S "$W/admin.sock" ] && break; sleep 0.2; done
[ -S "$W/admin.sock" ] || die "caddy did not start: $(tail -3 "$W/caddy.log")"

say "control plane: agentbox create (the real path — state, reconcile, incus, devices)"
incus delete --force "$CONTAINER" 2>/dev/null || true
abx create --gateway mine "$CONTAINER" || die "agentbox create failed"
incus config device get "$CONTAINER" agentbox-proxy connect >/dev/null || die "tcp proxy device missing"
incus config device get "$CONTAINER" agentbox-socket connect >/dev/null || die "unix proxy device missing"
abx list | grep -q "^${CONTAINER}.*Running.*present" \
    || die "list should show the container Running with a live socket:
$(abx list)"
sleep 2

ccurl() { incus exec "$CONTAINER" -- curl -s --max-time 10 "$@"; }

say "assert: container credentials replaced by injected ones, path + query intact"
RESP=$(ccurl "http://127.0.0.1:8787/echo/v1/messages?a=1&k=QUERYSECRET" \
    -H 'Authorization: Bearer container-fake' \
    -H 'x-api-key: container-fake' \
    -H 'Cookie: c=1' \
    -H 'cf-aig-authorization: spoofed' \
    -H 'cf-aig-collect-log: false' \
    -H 'X-Forwarded-For: 6.6.6.6')
python3 - "$RESP" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
h = {k.lower(): v for k, v in d["headers"].items()}
assert d["path"] == "/v1/messages", d
assert d["query"] == "a=1&k=QUERYSECRET", d
# Injected credentials must ARRIVE.
assert h.get("authorization") == "Bearer e2e-dummy-secret", h
assert h.get("cf-aig-authorization") == "Bearer e2e-dummy-secret", h
# Everything the container sent must be gone — including the non-auth members
# of the cf-aig-* family, which are upstream controls (cf-aig-collect-log
# would let a container switch off the gateway logging it is audited by).
assert "container-fake" not in json.dumps(h), h
assert "spoofed" not in json.dumps(h), h
assert "cf-aig-collect-log" not in h, h
for bad in ("x-api-key", "cookie", "x-forwarded-for"):
    assert bad not in h, (bad, h)
print("   ok")
PYEOF

say "assert: host routes over the unix socket (the gh path)"
HOSTRESP=$(ccurl --unix-socket /run/agentbox.sock \
    -H 'Authorization: token container-fake' 'http://api.example.test/v1/thing')
python3 - "$HOSTRESP" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
h = {k.lower(): v for k, v in d["headers"].items()}
assert d["path"] == "/v1/thing", d          # host routes must not rewrite the path
assert h.get("authorization") == "Bearer e2e-dummy-secret", h
print("   ok")
PYEOF
[ "$(ccurl -o /dev/null -w '%{http_code}' --unix-socket /run/agentbox.sock \
    http://evil.example.test/x)" = 404 ] || die "unmapped Host was proxied — open relay"
echo "   ok (unmapped host -> 404)"
if incus exec "$CONTAINER" -- sh -c 'command -v gh' >/dev/null 2>&1; then
    GHSOCK=$(incus exec "$CONTAINER" -- su - agent -c 'gh config get http_unix_socket' | tr -d '\r\n')
    [ "$GHSOCK" = /run/agentbox.sock ] || die "gh not wired to the proxy socket (got '$GHSOCK')"
    echo "   ok (gh wired to $GHSOCK)"
fi

say "assert: the container reaches only the gateway it was created with"
MINE=$(ccurl "http://127.0.0.1:8787/cloudflare/mine/anthropic/v1/messages")
python3 - "$MINE" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
h = {k.lower(): v for k, v in d["headers"].items()}
assert d["path"] == "/v1/ACCT/mine/anthropic/v1/messages", d
assert h.get("cf-aig-authorization") == "Bearer token-for-mine", h
assert "token-for-other" not in json.dumps(h), h
print("   ok (its own gateway, its own credential — not the other's)")
PYEOF
# The other gateway's route is configured, but must not exist on this socket.
[ "$(ccurl -o /dev/null -w '%{http_code}' "http://127.0.0.1:8787/cloudflare/other/anthropic/v1/messages")" = 404 ] \
    || die "container reached a gateway it was not created against"
echo "   ok (another gateway -> 404, not merely unauthorized)"

say "assert: uninstalled credential fails closed (503, no upstream call)"
[ "$(ccurl -o /dev/null -w '%{http_code}' "http://127.0.0.1:8787/nocred/x")" = 503 ] \
    || die "route with a missing secret must 503, not proxy unauthenticated"
echo "   ok"

say "assert: unknown route -> 404, bare prefix -> 308, dot segments -> 404"
[ "$(ccurl -o /dev/null -w '%{http_code}' "http://127.0.0.1:8787/nope/x")" = 404 ] || die "unknown route"
[ "$(ccurl -o /dev/null -w '%{http_code}' "http://127.0.0.1:8787/echo")" = 308 ] || die "bare prefix"
for p in '/echo/../x' '/echo/a/%2e%2e/b' '/echo/a/..%2fb' '/echo/a/%252e%252e/b' '/echo/a/..\/b' '/echo/a/..;/b'; do
    [ "$(ccurl -o /dev/null -w '%{http_code}' --path-as-is "http://127.0.0.1:8787${p}")" = 404 ] \
        || die "dot segment not rejected: $p"
done
[ "$(ccurl -o /dev/null -w '%{http_code}' "http://127.0.0.1:8787/echo/a..b")" = 200 ] \
    || die "legitimate path containing dots was rejected"
echo "   ok"

say "assert: SSE streams incrementally"
TIMES=$(ccurl -N "http://127.0.0.1:8787/echo/sse" | grep -oP 'data: event-\d \K\d+')
python3 - $TIMES <<'PYEOF'
import sys
ts = [int(x) for x in sys.argv[1:]]
assert len(ts) == 3, ts
spread = ts[-1] - ts[0]
assert spread >= 600, f"events not spread out ({spread}ms): buffered, not streamed?"
print(f"   ok ({spread}ms spread)")
PYEOF

say "control plane: agentbox proxy block / unblock"
abx proxy block "$CONTAINER" >/dev/null
sleep 0.5
[ "$(ccurl -o /dev/null -w '%{http_code}' "http://127.0.0.1:8787/echo/x")" = 403 ] || die "block"
abx list | grep -q "^${CONTAINER}.*true" || die "list should report the container blocked"
abx proxy unblock "$CONTAINER" >/dev/null
sleep 0.5
[ "$(ccurl -o /dev/null -w '%{http_code}' "http://127.0.0.1:8787/echo/x")" = 200 ] || die "unblock"
echo "   ok"

say "control plane: block --hard severs the devices"
abx proxy block --hard "$CONTAINER" >/dev/null
for dev in agentbox-proxy agentbox-socket; do
    incus config device get "$CONTAINER" "$dev" connect >/dev/null 2>&1 \
        && die "--hard left device $dev attached"
done
abx proxy unblock "$CONTAINER" >/dev/null
incus config device get "$CONTAINER" agentbox-proxy connect >/dev/null || die "unblock did not restore the tcp device"
incus config device get "$CONTAINER" agentbox-socket connect >/dev/null || die "unblock did not restore the unix device"
echo "   ok"

say "control plane: destroy refuses containers it does not own"
if abx destroy definitely-not-ours >/dev/null 2>&1; then
    die "destroy accepted an unknown container"
fi
echo "   ok"

say "assert: log redaction on the success path"
sleep 0.5
for leak in QUERYSECRET container-fake e2e-dummy-secret; do
    grep -q "$leak" "$W/caddy.log" && die "leaked into caddy access log: $leak"
done
grep -q "\"container\":\"${CONTAINER}\"" "$W/caddy.log" || die "container tag missing from access log"
echo "   ok"

# The error logger is separate from the site access logs and logs the full URI
# and request headers unless the global default logger is filtered too.
say "assert: log redaction on the failure path (upstream down -> 502)"
kill "$ECHO_PID" 2>/dev/null; ECHO_PID=""
sleep 0.3
ccurl -o /dev/null "http://127.0.0.1:8787/echo/x?k=ERRQUERY" \
    -H 'x-api-key: ERRAPIKEY' -H 'Authorization: Bearer ERRAUTH' || true
sleep 0.5
for leak in ERRQUERY ERRAPIKEY ERRAUTH e2e-dummy-secret; do
    grep -q "$leak" "$W/caddy.log" && die "leaked into caddy error log: $leak"
done
echo "   ok"

say "control plane: agentbox destroy, then leftover check"
abx destroy "$CONTAINER" >/dev/null || die "destroy failed"
[ -e "$W/state/containers.d/${CONTAINER}.json" ] && die "state file survived destroy"
incus info "$CONTAINER" >/dev/null 2>&1 && die "container survived destroy"
cleanup
trap - EXIT
[ -d "$W" ] && die "temp dir left behind"
echo "e2e: PASS"
