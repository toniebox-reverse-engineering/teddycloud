#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace

mkdir -p /teddycloud/certs/server /teddycloud/certs/server_tb2 /teddycloud/certs/client
cd /teddycloud

# PUID/PGID support: if set and non-zero, drop privileges to that user before
# running teddycloud. When unset or 0, behavior is unchanged (runs as root).
#
# This pairs with `setcap 'cap_net_bind_service=+ep'` on /usr/local/bin/teddycloud
# in the Dockerfile so the non-root user can still bind ports 80/443.
RUN_AS=()
if [ -n "${PUID:-}" ] && [ -n "${PGID:-}" ] && [ "${PUID}" != "0" ] && [ "${PGID}" != "0" ]; then
  # Pick whichever drop-privs helper is installed: gosu (Debian/Ubuntu) or
  # su-exec (Alpine). Both have the same calling convention (`<helper> user cmd...`).
  if command -v gosu >/dev/null 2>&1; then
    DROP_PRIVS="gosu"
  elif command -v su-exec >/dev/null 2>&1; then
    DROP_PRIVS="su-exec"
  else
    echo "PUID/PGID set but neither gosu nor su-exec is installed; cannot drop privileges." >&2
    exit 1
  fi

  # Create or reconcile the teddy group/user with the requested ids. The
  # `|| ... ||  true` chain handles re-runs (user/group already exists at the
  # right ids) without failing the entrypoint.
  groupadd -g "${PGID}" teddy 2>/dev/null \
    || groupmod -o -g "${PGID}" teddy 2>/dev/null \
    || true
  useradd -u "${PUID}" -g "${PGID}" -M -s /bin/bash teddy 2>/dev/null \
    || usermod -o -u "${PUID}" -g "${PGID}" teddy 2>/dev/null \
    || true

  echo "Adjusting /teddycloud ownership to ${PUID}:${PGID}..."
  chown -R "${PUID}:${PGID}" /teddycloud

  RUN_AS=("${DROP_PRIVS}" "teddy")
  echo "Will run teddycloud as ${PUID}:${PGID} via ${DROP_PRIVS}"
fi

if [ -n "${DOCKER_TEST:-}" ]; then
  echo "Running teddycloud --docker-test..."
  LSAN_OPTIONS=detect_leaks=0 "${RUN_AS[@]}" teddycloud --docker-test
else
  # teddycloud requests an in-place restart by exiting with RETURNCODE_USER_RESTART
  # (-2 in the source), which the shell receives as the unsigned 8-bit code 254.
  # Restart the process on that code; for any other exit code, leave the loop and
  # let Docker's restart policy (if configured) decide what happens next.
  readonly RESTART_CODE=254
  while true
  do
    # Disable errexit only around the long-running process: a non-zero exit (a
    # crash, or a user-requested restart/quit) must NOT abort the loop before we
    # have inspected the exit code below.
    set +o errexit
    if [ -n "${STRACE:-}" ]; then
      echo "Running teddycloud with strace..."
      "${RUN_AS[@]}" strace -t -T teddycloud
    else
      echo "Running teddycloud..."
      "${RUN_AS[@]}" teddycloud
    fi
    retVal=$?
    set -o errexit
    echo "teddycloud exited with code $retVal"
    if [ "$retVal" -ne "$RESTART_CODE" ]; then
      exit "$retVal"
    fi
    echo "Restarting teddycloud..."
  done
fi
