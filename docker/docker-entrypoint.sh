#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace


if [ -n "$DOCKER_TEST" ]; then
  cd /teddycloud
  LSAN_OPTIONS=detect_leaks=0 teddycloud DOCKER_TEST
else
  while true
  do
    curl -f https://raw.githubusercontent.com/toniebox-reverse-engineering/tonies-json/release/tonies.json -o /teddycloud/config/tonies.json || true
    cd /teddycloud
    teddycloud
    retVal=$?
    if [ $retVal -ne -2 ]; then
        exit $retVal
    fi
  done
fi