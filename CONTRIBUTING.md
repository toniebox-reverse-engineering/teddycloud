# Contributing to TeddyCloud

Thanks for your interest in improving TeddyCloud! This is a short, practical guide
to contributing code and documentation. It's meant as a starting point — if a
maintainer suggests a different convention, follow that.

## Where things live

TeddyCloud spans two repositories:

- **[teddycloud](https://github.com/toniebox-reverse-engineering/teddycloud)** — the C server (HTTP/HTTPS, the Toniebox cloud protocol, the admin/REST API).
- **[teddycloud_web](https://github.com/toniebox-reverse-engineering/teddycloud_web)** — the React/TypeScript web frontend, included here as the `teddycloud_web` git submodule.

Frontend changes go to `teddycloud_web`; everything else goes here.

## Before you start

- For anything non-trivial, **open an issue first** so the approach can be discussed before you invest time.
- Search existing issues and pull requests so you don't duplicate work in flight.
- For questions and general discussion, use GitHub Discussions / the project's community channels (linked from the [documentation site](https://toniebox-reverse-engineering.github.io/docs/tools/teddycloud/)).

## Pull requests

- **Target the `develop` branch, not `master`.** `master` holds stable releases only; PRs opened against it will be redirected to `develop`, where active development merges.
- Keep each PR focused on a single logical change — it's much easier to review and, if needed, to revert.
- Reference the issue it addresses (e.g. `Fixes #123`).
- Make sure the project still builds and your change is clean under the sanitizers (see below).

## Building

A full build needs the submodules:

```bash
git clone --recurse-submodules https://github.com/toniebox-reverse-engineering/teddycloud.git
# …or in an existing clone:
git submodule update --init --recursive
```

The build is a single hand-written `Makefile`:

```bash
make            # full build: dependency check + submodules + web frontend + binary
make build      # just the server binary -> bin/teddycloud
```

Building inside **Docker** (see the `Dockerfile*` files and the README) is the most
reproducible option and is the recommended path on macOS. Linux debug builds compile
with **AddressSanitizer + UBSan** enabled by default — please verify your change is
clean under them.

## Vendored / third-party code

TeddyCloud vendors the Oryx Embedded **CycloneTCP / CycloneSSL / CycloneCrypto** stack
under `cyclone/` (git submodules) plus a few other libraries (cJSON, opus, ogg, FatFs).

**Don't edit the vendored submodule sources directly.** Where TeddyCloud needs to change
vendored behaviour, it keeps a *patched copy* under `src/cyclone/…` and the `Makefile`
compiles that instead of the submodule original (the `-Isrc/cyclone/…` include path takes
precedence). If you must change a vendored file, add or extend the copy there rather than
modifying the submodule.

## Code style

- **Blend in** with the surrounding code. The repo ships a `.vscode/` configuration with
  `editor.formatOnSave` enabled — letting your editor auto-format on save keeps diffs
  consistent with the existing style.
- In `teddycloud_web`, run `npm run format` (Prettier) before committing.
- Avoid reformatting unrelated lines in the same PR; keep the diff limited to your change.

## Handy conventions

- Logging uses the `TRACE_ERROR/WARNING/INFO/DEBUG/VERBOSE(...)` macros; log lines end with `\r\n`.
- Functions return `error_t` / `int_t` codes (`NO_ERROR`, `ERROR_*`); use the cyclone
  wrappers for memory and strings (`osAllocMem`/`osFreeMem`, `osStrcmp`, `osMemcpy`, …).
- The HTTP server is multi-threaded — guard shared state with the `mutex_lock(MUTEX_*)` /
  `mutex_unlock(MUTEX_*)` helpers from `mutex_manager.c`.

Thanks for contributing! 🧸
