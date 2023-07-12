#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace

cd /teddycloud/

if [ ! -f "/teddycloud/certs/server/ca.der" ]; then
  echo "Creating certs..."
  faketime '2015-11-04 00:00:00' gencerts.sh
  if [ ! -f "/teddycloud/certs/server/ca.der" ]; then
    echo "Error during certs creation"
    exit
  fi
fi

while true
do
  teddycloud
  retVal=$?
  if [ $retVal -ne -2 ]; then
      exit $retVal
  fi
done