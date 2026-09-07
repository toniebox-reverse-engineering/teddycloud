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

  # Resolve the requested ids to an account. Reuse whatever already owns them --
  # the ubuntu base image ships `ubuntu` at 1000:1000, and 1000 is the most
  # common PUID/PGID value -- and only create teddy when they are free. Both
  # steps are best-effort: the privilege drop below names the numeric uid:gid,
  # which gosu and su-exec accept with no passwd entry at all.
  if ! getent group "${PGID}" >/dev/null 2>&1; then
    groupadd -o -g "${PGID}" teddy \
      || echo "groupadd -g ${PGID} teddy failed; using the numeric gid" >&2
  fi
  if ! getent passwd "${PUID}" >/dev/null 2>&1; then
    useradd -o -u "${PUID}" -g "${PGID}" -M -s /bin/bash teddy \
      || echo "useradd -u ${PUID} teddy failed; using the numeric uid" >&2
  fi

  echo "Adjusting /teddycloud ownership to ${PUID}:${PGID}..."
  chown -R "${PUID}:${PGID}" /teddycloud

  run_user="$(getent passwd "${PUID}" | cut -d: -f1 || true)"
  run_group="$(getent group "${PGID}" | cut -d: -f1 || true)"
  RUN_AS=("${DROP_PRIVS}" "${PUID}:${PGID}")
  echo "Will run teddycloud as ${PUID}:${PGID} (${run_user:-no passwd entry}:${run_group:-no group entry}) via ${DROP_PRIVS}"
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
