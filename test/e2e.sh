#!/usr/bin/env bash
# Host-local end-to-end test: real agentboxd, control/data Unix sockets, CLI,
# encryption, dynamic updates, and a local upstream. No root, Incus, Caddy, or
# network access is required.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/agentbox-e2e.XXXXXX")
DAEMON_PID=
UPSTREAM_PID=

cleanup() {
    if [[ -n "$DAEMON_PID" ]]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    if [[ -n "$UPSTREAM_PID" ]]; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf -- "$WORK"
}
trap cleanup EXIT

fail() { echo "e2e: FAIL: $*" >&2; exit 1; }
wait_for() {
    local path=$1
    for _ in {1..100}; do
        [[ -e "$path" ]] && return 0
        sleep 0.05
    done
    fail "timed out waiting for $path"
}

make -C "$ROOT" bin >/dev/null
command -v curl >/dev/null || fail "curl is required"
command -v python3 >/dev/null || fail "python3 is required"

cat > "$WORK/upstream.py" <<'PY'
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def respond(self, body=None):
        response = {
            "path": self.path.split("?", 1)[0],
            "query": self.path.split("?", 1)[1] if "?" in self.path else "",
            "headers": dict(self.headers.items()),
        }
        if body is not None:
            response["body_text"] = body.decode()
            response["body"] = json.loads(body)
        payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.respond()

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        self.respond(self.rfile.read(length))

    def log_message(self, *_):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(server.server_port, flush=True)
server.serve_forever()
PY

python3 "$WORK/upstream.py" >"$WORK/upstream.port" 2>"$WORK/upstream.log" &
UPSTREAM_PID=$!
wait_for "$WORK/upstream.port"
for _ in {1..100}; do
    [[ -s "$WORK/upstream.port" ]] && break
    sleep 0.05
done
PORT=$(tr -d '\r\n' < "$WORK/upstream.port")
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "upstream did not report a port"

dd if=/dev/urandom of="$WORK/master.key" bs=32 count=1 status=none
"$ROOT/bin/agentboxd" \
    --state "$WORK/state.json" \
    --secrets "$WORK/secrets" \
    --control-socket "$WORK/control.sock" \
    --container-sockets "$WORK/containers" \
    --master-key-file "$WORK/master.key" \
    --log-format json 2>"$WORK/daemon.log" &
DAEMON_PID=$!
wait_for "$WORK/control.sock"

abx() { "$ROOT/bin/agentbox" --socket "$WORK/control.sock" "$@"; }
control() {
    curl --silent --show-error --fail-with-body --unix-socket "$WORK/control.sock" "$@"
}
proxy() {
    curl --silent --show-error --unix-socket "$WORK/containers/dev.sock" "$@"
}

printf '%s' real-one | abx key set token
cat > "$WORK/plaintext-secret-route.json" <<'EOF'
{
  "name": "plaintext-secret",
  "scope": "test",
  "match": {"path_prefix": "/plaintext"},
  "upstream": "http://example.invalid",
  "set_headers": [
    {"name": "Authorization", "value": "Bearer {secret:token}"}
  ]
}
EOF
if abx route put "$WORK/plaintext-secret-route.json" >/dev/null 2>&1; then
    fail "secret-bearing remote plaintext route was accepted"
fi
cat > "$WORK/path-route.json" <<EOF
{
  "name": "echo",
  "scope": "test",
  "match": {"path_prefix": "/echo"},
  "upstream": "http://127.0.0.1:${PORT}/base",
  "strip_prefix": true,
  "set_headers": [
    {"name": "Authorization", "value": "Bearer {secret:token}"}
  ]
}
EOF
abx route put "$WORK/path-route.json"
control -H 'content-type: application/json' -d '{"name":"dev","scope":"test"}' \
    http://agentbox/v1/containers >/dev/null
wait_for "$WORK/containers/dev.sock"

RESPONSE=$(proxy -H 'Authorization: Bearer container-fake' \
    -H 'Cookie: private=1' -H 'Cf-Aig-Collect-Log: false' \
    'http://agentbox/echo/messages?value=QUERYSECRET')
python3 - "$RESPONSE" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
h = {k.lower(): v for k, v in d["headers"].items()}
assert d["path"] == "/base/messages", d
assert d["query"] == "value=QUERYSECRET", d
assert h.get("authorization") == "Bearer real-one", h
assert "cookie" not in h, h
assert h.get("cf-aig-collect-log") == "false", h
assert "container-fake" not in json.dumps(h), h
PY

cat > "$WORK/transparent-route.json" <<EOF
{
  "name": "transparent",
  "scope": "test",
  "match": {"path_prefix": "/transparent"},
  "upstream": "http://127.0.0.1:${PORT}",
  "strip_prefix": true
}
EOF
abx route put "$WORK/transparent-route.json"
PAYLOAD='{"model": "claude-opus-5", "system": [{"text":"rules","cache_control":{"type":"ephemeral"}}], "messages":[{"role":"system","content":"more rules"},{"role":"user","content":"say ok"}], "context_management":{"edits":[]}}'
RESPONSE=$(proxy -H 'content-type: application/json; charset=utf-8' \
    -H 'anthropic-beta: context-management-2025-06-27' \
    --data-binary "$PAYLOAD" \
    'http://agentbox/transparent/anthropic/v1/messages?beta=true')
python3 - "$RESPONSE" "$PAYLOAD" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
assert d["path"] == "/anthropic/v1/messages", d
assert d["query"] == "beta=true", d
assert d["body_text"] == sys.argv[2], d
h = {k.lower(): v for k, v in d["headers"].items()}
assert h.get("content-type") == "application/json; charset=utf-8", h
assert h.get("anthropic-beta") == "context-management-2025-06-27", h
PY

# Key rotation is live and does not restart or rewrite routes.
printf '%s' real-two | abx key set token
RESPONSE=$(proxy 'http://agentbox/echo/rotated')
python3 - "$RESPONSE" <<'PY'
import json, sys
h = {k.lower(): v for k, v in json.loads(sys.argv[1])["headers"].items()}
assert h.get("authorization") == "Bearer real-two", h
PY

# Host matching is the transport used by GitHub CLI's http_unix_socket.
cat > "$WORK/host-route.json" <<EOF
{
  "name": "host-echo",
  "scope": "test",
  "match": {"host": "api.example.test"},
  "upstream": "http://127.0.0.1:${PORT}",
  "set_headers": [
    {"name": "Authorization", "value": "Bearer {secret:token}"}
  ]
}
EOF
abx route put "$WORK/host-route.json"
RESPONSE=$(proxy -H 'Host: api.example.test' 'http://agentbox/host/path')
python3 - "$RESPONSE" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
assert d["path"] == "/host/path", d
PY
[[ $(proxy -o /dev/null -w '%{http_code}' -H 'Host: unknown.example' http://agentbox/x) == 404 ]] \
    || fail "unmapped host did not fail closed"

cat > "$WORK/missing-route.json" <<EOF
{
  "name": "missing",
  "scope": "test",
  "match": {"path_prefix": "/missing"},
  "upstream": "http://127.0.0.1:${PORT}",
  "set_headers": [
    {"name": "Authorization", "value": "{secret:not-installed}"}
  ]
}
EOF
abx route put "$WORK/missing-route.json"
[[ $(proxy -o /dev/null -w '%{http_code}' http://agentbox/missing/x) == 503 ]] \
    || fail "missing key did not return 503"

# Renewable credentials are configured and granted independently. A missing
# GitHub App private key fails before any network request and never forwards
# the container's dummy Authorization header.
abx credential source github-app github-test \
    --client-id Iv1.test \
    --installation-id 123 \
    --private-key github-app-private-key \
    --repository-ids 42 \
    --permissions contents=write,pull_requests=write
abx credential grant set dev github github-test
abx profile apply github >/dev/null
[[ $(proxy -o /dev/null -w '%{http_code}' -H 'Host: api.github.com' \
    -H 'Authorization: Bearer agentbox-dummy' http://agentbox/repos/example/repo) == 503 ]] \
    || fail "unavailable renewable credential did not fail closed"
abx credential source list | grep -q 'github-test.*github-app' \
    || fail "credential source is not listed"
abx credential grant list | grep -q 'dev.*github.*github-test' \
    || fail "credential grant is not listed"

abx container block dev >/dev/null
[[ $(proxy -o /dev/null -w '%{http_code}' http://agentbox/echo/x) == 403 ]] \
    || fail "live block did not return 403"
control -X PATCH -H 'content-type: application/json' -d '{"blocked":false}' \
    http://agentbox/v1/containers/dev >/dev/null
[[ $(proxy -o /dev/null -w '%{http_code}' http://agentbox/echo/x) == 200 ]] \
    || fail "live unblock did not restore the route"

abx status | grep -q '10 routes, 1 keys, 1 containers, 1 credential sources, 1 credential grants' \
    || fail "health counts are wrong"
for leak in QUERYSECRET container-fake real-one real-two; do
    if grep -Fq "$leak" "$WORK/daemon.log"; then
        fail "daemon log leaked $leak"
    fi
done

echo "e2e: PASS"
