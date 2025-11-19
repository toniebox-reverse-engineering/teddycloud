#!/bin/bash
set -e

MP3_URL="https://download.samplelib.com/mp3/sample-15s.mp3"
MP3_FILE="sample-15s.mp3"
PCM_FILE="input.raw"

# Download MP3 if it doesn't exist
if [ ! -f "$MP3_FILE" ]; then
    echo "Downloading $MP3_FILE..."
    if command -v wget >/dev/null 2>&1; then
        wget -q "$MP3_URL" -O "$MP3_FILE"
    elif command -v curl >/dev/null 2>&1; then
        curl -s "$MP3_URL" -o "$MP3_FILE"
    else
        echo "Error: Neither wget nor curl found."
        exit 1
    fi
else
    echo "$MP3_FILE already exists."
fi

# Convert to PCM (s16le, 48000Hz, mono)
echo "Converting to $PCM_FILE..."
if command -v ffmpeg >/dev/null 2>&1; then
    ffmpeg -y -i "$MP3_FILE" -f s16le -acodec pcm_s16le -ar 48000 -ac 2 "$PCM_FILE"
    echo "Done! Created $PCM_FILE"
else
    echo "Error: ffmpeg not found. Please install ffmpeg."
    exit 1
fi
