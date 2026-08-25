# Development Sandbox

Mock data for local TeddyCloud development. Start a local server to see behavior and try out features.

**Source** for `dev-sandbox/run/` (gitignored).

## Contents

- **20 tonies**: All custom (custom_001 … custom_020), each with custom audio
- **20 models**: custom_001 … custom_020 in `tonies.custom.json`
- **20 TAF files**: `library/audio_001.taf` … `audio_020.taf`
    - The `audio_id` and `hash` in `tonies.custom.json` must match the TAF header. The hash is the **SHA1 of the audio content** (bytes after the header), not the file hash.

- **20 images**: `custom_img/custom_001.png` … `custom_020.png`
- **1 Toniebox**: Mock box "Test Toniebox" (shows in Tonieboxes list)


## Usage

### Outside the Devcontainer

When working outside the devcontainer and you don't want to install build tools (make, gcc, npm) on the host. Uses Docker Compose with bind mounts for `run/certs`, `run/config`, `run/data/content`, etc. (web comes from the image). Builds local image.

**Initial setup:** Run the setup script. No make or build tools required – it only copies files.

```bash
./dev-sandbox/setup.sh
cd dev-sandbox
docker compose build --no-cache
docker compose up -d
# Open http://localhost:8080 (ports 8080/8443/8444 for rootless Docker)
```

**After code changes:** One container (backend + frontend). Web is built in-container via `make web` before `make zip`.

```bash
docker compose -f ./dev-sandbox/docker-compose.yaml up --build
```

- **Access:** http://localhost:8080

### In Devcontainer

When working inside the devcontainer: Make uses all build tools (gcc, npm, protobuf-c). Uses Docker if available (bind mounts `run/certs`, `run/config`, `run/data/content`, etc., builds local image), otherwise runs `bin/teddycloud` natively with `--base_path dev-sandbox/run/`.

**Initial setup:** Run `make dev-sandbox-setup` once to create `run/` (config, content, library, certs, custom_img). Or `make dev-sandbox-up` does auto-setup on first run.

```bash
make dev-sandbox-setup   # First time only
make dev-sandbox-up      # Start
# Open http://localhost
make dev-sandbox-restart # Rebuild and restart
make dev-sandbox-down
```

Server certificates are generated once on first run (or when missing) and reused. No RSA regeneration on each start.

After code changes: `make dev-sandbox-restart`. To reset: `make dev-sandbox-setup`.
