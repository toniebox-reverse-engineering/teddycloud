#!/bin/bash
# Setup dev-sandbox/run/ with test data. Called from Makefile.
set -e
cd "$(dirname "$0")/.."
SRC=dev-sandbox
DST=dev-sandbox/run
CONTRIB=contrib

echo "[ DEV    ] Setup $DST/"
mkdir -p "$DST"/{config,data/content,data/library,data/www/custom_img,data/firmware,data/cache,certs/server,certs/client}

cp -r "$SRC"/config/. "$DST"/config/
cp -r "$SRC"/content/. "$DST"/data/content/
cp -r "$SRC"/library/. "$DST"/data/library/
cp -r "$SRC/certs/server/." "$DST/certs/server/"
cp -r "$SRC/custom_img/." "$DST/data/www/custom_img/"

# Copy contrib/data/www (symlink web on Linux for live updates)
if [ -d "$CONTRIB/data/www" ]; then
  for item in "$CONTRIB"/data/www/*; do
    name=$(basename "$item")
    if [ "$name" = "web" ]; then
      rm -rf "$DST/data/www/web"
      ln -sf ../../../../$CONTRIB/data/www/web "$DST/data/www/web"
    else
      cp -r "$item" "$DST/data/www/"
    fi
  done
fi

echo "[ OK     ] Dev sandbox ready"
