#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <host>"
  exit 1
fi

host="$1"
path="/v1/content/"

for language in $(seq -w 0 3); do
  for content in $(seq -w 0 24); do
    language_hex=$(printf "%08x" "${language#0}")
    content_hex=$(printf "%08x" "${content#0}")
    url="$host$path$language_hex$content_hex"
    echo "Triggering download for URL: $url"
    curl "$url"
  done
done