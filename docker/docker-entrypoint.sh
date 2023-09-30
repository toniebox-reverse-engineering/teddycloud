#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace

curl -f https://gt-blog.de/JSON/tonies.json?source=teddyCloud-docker -o /teddycloud/config/tonies.json || true

while true
do
  cd /teddycloud
  teddycloud
  retVal=$?
  if [ $retVal -ne -2 ]; then
      exit $retVal
  fi
done
