#!/usr/bin/env bash
#
# Starts a throwaway teddycloud server on the given ports, waits for it to
# answer on the HTTP port, runs the given command, and always stops the
# server afterwards - regardless of whether the command succeeds.
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
"$BIN" --config-set "core.server.http_port=$HTTP_PORT,core.server.https_web_port=$HTTPS_WEB_PORT,core.server.https_api_port=$HTTPS_API_PORT" \
    >"$tmp_log" 2>&1 &
srv_pid=$!

cleanup() {
    kill "$srv_pid" >/dev/null 2>&1 || true
    rm -f "$tmp_log"
}
trap cleanup EXIT INT TERM

ready=0
deadline=$(($(date +%s) + READY_TIMEOUT))
while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$srv_pid" >/dev/null 2>&1; then
        echo "[ERR] Test server exited during startup. Log:" >&2
        sed -n '1,140p' "$tmp_log" >&2
        exit 1
    fi
    http_code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/web/" || true)
    if [ "$http_code" = "200" ]; then
        ready=1
        break
    fi
    sleep 0.2
done

if [ "$ready" != "1" ]; then
    echo "[ERR] Test server did not become ready on port $HTTP_PORT within ${READY_TIMEOUT}s. Log:" >&2
    sed -n '1,140p' "$tmp_log" >&2
    exit 1
fi

"$@"
