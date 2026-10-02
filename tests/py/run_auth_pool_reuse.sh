#!/usr/bin/env bash
#
# Generates a box client certificate signed by the running test server's own
# CA and runs the pooled-connection auth regression test with it. Meant to be
# run through with_server.sh, which provides the server and the ports.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cert_dir="$(mktemp -d)"
trap 'rm -rf "$cert_dir"' EXIT INT TERM

"$REPO_ROOT/bin/teddycloud" --generate-client-cert deadbeef0001 --destination "$cert_dir" >/dev/null
openssl x509 -inform der -in "$cert_dir/client.der" -outform pem -out "$cert_dir/client.pem"
openssl rsa -inform der -in "$cert_dir/private.der" -outform pem -out "$cert_dir/private.pem" 2>/dev/null

TEDDYCLOUD_CLIENT_CERT="$cert_dir/client.pem" \
TEDDYCLOUD_CLIENT_KEY="$cert_dir/private.pem" \
    python3 "$REPO_ROOT/tests/py/test_auth_pool_reuse.py"
