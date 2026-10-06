#!/usr/bin/env bash
#
# Starts a throwaway teddycloud server on the given ports, waits for it to
# answer on the HTTP port, runs the given command, and always stops the
# server afterwards - regardless of whether the command succeeds.
#
# The server runs in a sandbox: a copy of a template base directory (--base_path),
# so tests never touch the dev config/data/certs. The sandbox path is exported
# as TC_SANDBOX and removed afterwards. Ports given as 0 are picked free; the
# ports and TEDDYCLOUD_BASE_URL are exported to the command.
#
# Usage:
#   with_server.sh <http_port> <https_web_port> <https_api_port> <ready_timeout_seconds> -- <command...>
#
# Exists so integration tests under tests/py/ don't each duplicate the
# same start/wait/cleanup logic in the Makefile.
set -euo pipefail

usage() {
    echo "Usage: $0 <http_port> <https_web_port> <https_api_port> <ready_timeout_seconds> -- <command...>" >&2
    exit 1
}

[ "$#" -ge 5 ] || usage
HTTP_PORT="$1"
HTTPS_WEB_PORT="$2"
HTTPS_API_PORT="$3"
READY_TIMEOUT="$4"
shift 4
[ "$1" = "--" ] || usage
shift

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin/teddycloud"

# a port of 0 means: pick a free one (so tests don't collide with whatever runs on the dev machine)
free_port() {
    python3 -c '
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
'
}
[ "$HTTP_PORT" != 0 ] || HTTP_PORT="$(free_port)"
[ "$HTTPS_WEB_PORT" != 0 ] || HTTPS_WEB_PORT="$(free_port)"
[ "$HTTPS_API_PORT" != 0 ] || HTTPS_API_PORT="$(free_port)"
export TC_HTTP_PORT="$HTTP_PORT" TC_HTTPS_WEB_PORT="$HTTPS_WEB_PORT" TC_HTTPS_API_PORT="$HTTPS_API_PORT"
export TEDDYCLOUD_BASE_URL="http://127.0.0.1:$HTTP_PORT" TEDDYCLOUD_HTTPS_API_PORT="$HTTPS_API_PORT"

for port in "$HTTP_PORT" "$HTTPS_WEB_PORT" "$HTTPS_API_PORT"; do
    if ! python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.2)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) else 1)
' "$port"; then
        echo "[ERR] Test port $port is already in use. Free it first, e.g.:" >&2
        echo "        ps -ef | awk '/teddycloud/ && !/awk/ {print}'" >&2
        echo "        kill <PID>" >&2
        exit 1
    fi
done

tmp_log="$(mktemp /tmp/teddycloud_test_XXXXXX.log)"
PORT_SETTINGS="core.server.http_port=$HTTP_PORT,core.server.https_web_port=$HTTPS_WEB_PORT,core.server.https_api_port=$HTTPS_API_PORT"

# Generating the server certificates takes minutes, hence the template is
# created once and reused. It is regenerated when the certificate code changes
# (stamp in .complete), or delete the directory. CI caches it with the same key.
TEMPLATE="${TC_TEST_TEMPLATE:-$REPO_ROOT/bin/test-template}"
WEB_UI="$REPO_ROOT/data/www/web"
# bump the layout number when the template directory structure below changes
TEMPLATE_LAYOUT=2
TEMPLATE_STAMP="$( (echo "$TEMPLATE_LAYOUT"; cat "$REPO_ROOT/src/cert.c" "$REPO_ROOT/include/cert.h") | sha256sum | cut -d' ' -f1)"
srv_pid=
LINEBUF=; command -v stdbuf >/dev/null && LINEBUF="stdbuf -oL -eL" # the log is otherwise lost when the server is killed
SANDBOX=

wait_ready() { # <pid> <timeout_seconds> [any]  (any: every HTTP answer counts, not only 200)
    local deadline=$(($(date +%s) + $2)) code
    while [ "$(date +%s)" -lt "$deadline" ]; do
        kill -0 "$1" >/dev/null 2>&1 || return 1
        code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/web/" || true)
        [ "$code" = "200" ] && return 0
        [ "${3:-}" = any ] && [ "$code" != "000" ] && return 0
        sleep 0.2
    done
    return 1
}

start_server() { # <base dir>
    (cd "$1" && exec $LINEBUF "$BIN" --base_path "$1" --config-set "$PORT_SETTINGS") >"$tmp_log" 2>&1 &
    srv_pid=$!
}

stop_server() {
    if [ -n "$srv_pid" ]; then
        kill "$srv_pid" >/dev/null 2>&1 || true
        wait "$srv_pid" 2>/dev/null || true # the server may write config on shutdown
        srv_pid=
    fi
}

fail_log() {
    echo "[ERR] $1. Log:" >&2
    sed -n '1,140p' "$tmp_log" >&2
    exit 1
}

cleanup() {
    stop_server
    [ -n "$SANDBOX" ] && rm -rf "$SANDBOX"
    rm -f "$tmp_log"
}
trap cleanup EXIT INT TERM

if [ "$(cat "$TEMPLATE/.complete" 2>/dev/null)" != "$TEMPLATE_STAMP" ]; then
    echo "[INFO] Creating test template in $TEMPLATE (generates certificates, takes a while)..." >&2
    rm -rf "$TEMPLATE"
    mkdir -p "$TEMPLATE/config" "$TEMPLATE/data/www" "$TEMPLATE/data/content/default" "$TEMPLATE/data/firmware" "$TEMPLATE/data/cache" "$TEMPLATE/data/library" "$TEMPLATE/certs/server" "$TEMPLATE/certs/client" "$TEMPLATE/certs/server_tb2" "$TEMPLATE/certs/client/tb2"
    start_server "$TEMPLATE"
    if ! wait_ready "$srv_pid" 900 any; then
        stop_server
        rm -rf "$TEMPLATE"
        fail_log "Template server did not become ready"
    fi
    stop_server
    echo "$TEMPLATE_STAMP" >"$TEMPLATE/.complete"
fi

SANDBOX="$(mktemp -d /tmp/teddycloud_sandbox_XXXXXX)"
cp -a "$TEMPLATE/." "$SANDBOX/"
rm -f "$SANDBOX/.complete"
# the web UI is a symlink, so the template stays relocatable (and cacheable)
[ -d "$WEB_UI" ] && ln -s "$WEB_UI" "$SANDBOX/data/www/web"
export TC_SANDBOX="$SANDBOX" TC_TEMPLATE="$TEMPLATE" # TC_TEMPLATE: tests may cache things signed by the template CA (box certs) there

start_server "$SANDBOX"

if ! wait_ready "$srv_pid" "$READY_TIMEOUT"; then
    fail_log "Test server did not become ready on port $HTTP_PORT within ${READY_TIMEOUT}s"
fi

rc=0
"$@" || rc=$?
if [ "$rc" -ne 0 ]; then
    stop_server # the log is buffered until the server exits
    echo "[ERR] Test command failed ($rc). Server log, last lines:" >&2
    tail -n 80 "$tmp_log" >&2
fi
exit "$rc"
