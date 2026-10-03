# Architecture

TeddyCloud is a single C server process that stands in between a Toniebox and
the manufacturer's cloud, and between a browser and that same data. This
document describes how the pieces in `src/` fit together.

## Startup (`src/main.c`)

`main()` first checks for one-shot CLI subcommands (certificate generation,
ESP32 firmware patching, ffmpeg encode tests, cloud URL tests, TAF
encode tests). If none match, it starts the server:

1. `settings_init()` locates and loads `config.ini` / `config.overlay.ini`.
2. `toniebox_state_init()` sets up the in-memory box-state tracker.
3. `platform_init()` brings up the CycloneTCP stack.
4. `tls_init()` loads or generates the CA and server/box certificates.
5. `mqtt_init()` connects the outbound MQTT client (if configured).
6. `server_init()` creates the HTTP(S) listeners and then runs the main
   loop until shutdown.

There is no explicit thread spawning in `main.c` — CycloneTCP's
`platform_init()` and the HTTP server contexts own their own worker
threads. `server_init()`'s own loop (`osDelayTask(250)`) drives the
recurring housekeeping: `mqtt_server_task()`, `settings_loop()`,
periodic sanity checks, `mutex_manager_loop()`, and connection/online
bookkeeping.

## HTTP/HTTPS listeners (`server.c`, `tls_adapter.c`, `cert.c`)

`server_init()` starts three CycloneTCP `HttpServerContext` listeners:

| Listener | Default port | Audience | TLS |
|---|---|---|---|
| HTTP | `core.server.http_port` (80) | Web UI | none |
| HTTPS "web" | `core.server.https_web_port` (8443) | Web UI (browser) | server certificate |
| HTTPS "API" | `core.server.https_api_port` (443) | Toniebox | SNI-selected box certificate + client-cert auth |

The box-facing listener is the interesting one: `httpServerSelectBoxCertificate`
picks the TB1 or TB2 certificate based on whether the ClientHello carries an
SNI hostname (see [box-https-sni.md](./box-https-sni.md)), and the box
authenticates itself with its own client certificate.

Both listeners funnel every request through `httpServerRequestCallback()`
(`server.c`), which walks a single data-driven table, `request_paths[]`
(URI prefix + HTTP method + `SERTY_WEB` / `SERTY_API` / `SERTY_BOTH` flag
→ handler function). The same function also does box user-agent
sniffing/box-generation detection and security-mitigation checks before
falling back to serving a static file from `core.wwwdir`, or a 404.

Handlers are split by concern:

- `handler_api.c` — browser-facing REST API (settings, file/content
  management, tonies.json editing, ESP32 tools, SSE).
- `handler_cloud.c` — the Toniebox cloud protocol itself: `/v1`, `/v2`,
  `/v3` endpoints for time, OTA, claim, content, freshness-check, log,
  cloud-reset.
- `handler_reverse.c` — transparent proxy/passthrough to the real Tonie
  cloud for anything not served locally.
- `handler_rtnl.c` — the box's real-time notification/log protocol.
- `handler_sse.c` — server-sent events that push live state to the web UI.

## Tonie / TAF content model

A "Tonie audio file" (`.taf`) is TeddyCloud's on-disk container: Ogg-Opus
audio (`toniefile.c`/`.h`, via `libopus`) wrapped in a protobuf header
(`proto/toniebox.pb.taf-header.proto`) carrying chapter/track offsets, an
`audio_id`, and a SHA1 integrity hash. `.tap` playlist files
(`tonie_audio_playlist.c`) are an alternative content source that points at
one or more other files instead of embedding audio directly.

Per-content metadata lives in each item's `content.json`
(`contentJson.c`): the `nocloud` flag, the `source` (a local TAF/TAP path
or a stream URL — see [webradio-streaming.md](./webradio-streaming.md)),
and cloud claim/auth info. `toniesJson.c` manages the separate
`tonies.json` / `tonieboxes.json` catalog (the community-maintained
mapping from audio IDs to titles and cover art, with per-install custom
overrides). `cache.c` is a simple on-disk cache, keyed by URL hash, for
content fetched through the reverse-proxy path.

## Toniebox protocol

`handler_cloud.c` implements the endpoints the box actually calls:

- `handleCloudFreshnessCheck` — parses a `TonieFreshnessCheckRequest`
  protobuf, checks a `freshnessCache` of UIDs, and reports back which tags
  changed.
- `handleCloudContentV1`/`V2` — serve TAF content, either from local
  storage/library or passed through/streamed from the source, depending on
  `content.json`.
- `handleCloudOTA` / V3 variants — firmware update delivery.
- `handleCloudClaim`, `handleCloudLog`, `handleCloudReset`.

`cloud_request.c` is the matching outbound HTTPS client used to reach the
real Tonie cloud for passthrough/OTA. `esp32.c` handles the
community ESP32 firmware specifically (patching hostnames/certificates
into a firmware dump, FAT partition extraction/injection). Live box
state (tag placed/removed, knock, tilt, playback) is tracked in
`toniebox_state.c` and feeds both MQTT and SSE. `pcap_dump.c`/`pcaplog.c`
can record raw box traffic to pcap files for debugging.

## MQTT and Home Assistant

`mqtt.c` is the outbound MQTT client that publishes box/server events
under a configurable topic prefix; `mqtt_server.c` is an embedded MQTT
broker so local clients can subscribe without running an external one.
`home_assistant.c` builds Home Assistant MQTT-discovery messages
(`homeassistant/<type>/<id>/<entity>/config`) so box state (tag, playback,
battery, ...) shows up as HA entities automatically.

## Settings

`settings.c` declares configuration as a macro-based option table
(`OPTION_STRING`/`OPTION_UNSIGNED`/`OPTION_BOOL`/...), each entry binding a
dotted key (e.g. `core.server.http_port`) to a field in `settings_t`, a
default, a validation range, and a UI visibility tier. On top of the
global defaults, `overlay_settings_init()` supports per-box overlays (by
client-certificate common name, up to `MAX_OVERLAYS`), so each Toniebox
can have its own settings. Code reads/writes settings through the
generic `settings_get_*`/`settings_set_*` helpers rather than touching
`settings_t` directly.

## Directory layout

Git submodules (third-party, see `.gitmodules`): `cJSON`, `teddycloud_web`,
`cyclone/*` (CycloneTCP/TLS/Crypto), `opus`, `ogg`, `emsdk`. `fat/` is a
vendored FatFs library used for ESP32 FAT image extraction.

First-party:

- `src/` — the server itself (see above).
- `proto/` — hand-maintained `.proto` definitions, compiled to `*_pb-c.h/c`.
- `config/` — runtime configuration and data, not source.
- `contrib/` — build-time assets, including `contrib/data/` which is the
  template tree copied into the runtime `data/` directory (web UI,
  library, firmware, content skeletons).
- `docker/` — Docker Compose files and entrypoint for container deployment.
- `dev-sandbox/` — a local dev Compose environment with sample
  certs/content/library for testing without real hardware (see
  [dev-sandbox/README.md](../dev-sandbox/README.md)).

## Web frontend

The actual frontend source lives in the `teddycloud_web` submodule, not in
this repository. The `Makefile` builds it (npm) and copies the build
output into `contrib/data/www/web`, which then gets copied into the
runtime `data/www/` directory. At request time, `web.c` and
`httpServerWebRequestCallback()` serve static files straight from
`core.wwwdir`: `/` and `index.shtm` redirect to the web UI at `/web`,
`/web` is rewritten to `/web/index.html`, and anything else is resolved
relative to `wwwdir` or answered with a 404. `contrib/data/www` also
ships `plugins/` and `custom_img/` alongside the built SPA.

See the [README](../README.md#contribution-workflow-teddycloud--teddycloud_web)
for the contribution workflow between this repository and `teddycloud_web`.

## Testing

Tests live under `tests/`, split by what they need to exercise:

- `tests/c/` — pure C unit tests for logic that doesn't need a running
  server (e.g. `os_ext.c` helpers). Plain `assert()`-based: a small
  `test_runner.c` main registers each `test_*.c` file's entry point in a
  table and calls it; a failed assertion aborts with a file/line and a
  non-zero exit code, which is enough for `make` to fail the build.
  Run with `make test_c`.
- `tests/py/` — HTTP-level integration tests that talk to a real running
  `teddycloud` server (e.g. `test_tonies_custom_json_api.py`).
  `tests/py/with_server.sh` is the shared harness: it starts the server on
  a given set of ports, waits for it to answer, runs the given command,
  and always stops the server afterwards - so each test's Makefile target
  is a few lines instead of duplicating the start/wait/cleanup logic. Run
  a single suite with e.g. `make test_api_custom_json_with_server`.

`make test` runs both: the C unit tests, then the Python integration
suite against a throwaway server instance.
