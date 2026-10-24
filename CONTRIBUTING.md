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

## Testing

```bash
make test      # C unit tests + Python integration tests against a throwaway server
make test_c    # just the C unit tests (tests/c/)
```

New pure logic (no running server needed) gets a C test under `tests/c/`; new
HTTP-level behavior gets a Python test under `tests/py/`, using
`tests/py/with_server.sh` to start/stop the throwaway server instead of
duplicating that in the Makefile. See [docs/architecture.md](docs/architecture.md#testing)
for how these fit together.

## Vendored / third-party code

TeddyCloud vendors the Oryx Embedded **CycloneTCP / CycloneSSL / CycloneCrypto** stack
under `cyclone/` (git submodules) plus a few other libraries (cJSON, opus, ogg, FatFs).

**Don't edit the vendored submodule sources directly, and avoid patching them at all** - every
patched line has to be re-ported on each Cyclone update. In order of preference:

1. **TeddyCloud code outside the vendored tree.** Wrapper headers found first through `-Iinclude`
   (`include/debug.h`), the configuration macros (`include/os_port_config.h`, `net_config.h`,
   `tls_config.h`), and the hooks Cyclone offers (`HTTP_*_HOOK`, `*_CONTEXT_PRIVATE`,
   `HTTP_*_PRIVATE_HEADER_FIELDS`; see `include/http_ext.h`).
2. **Replace a weak Cyclone function** with your own strong definition. Cyclone's version is renamed
   with a per-object `-D` in the `Makefile`, which also works with MSVC (no weak symbols), see
   `tlsParseCertificateList` and `mpiCheckProbablePrime`.
3. **Only if neither works, a minimal patched copy** under `src/cyclone/...` (the `-Isrc/cyclone/...`
   include path takes precedence). Copy the file unmodified from the submodule, then make the change
   on the copy; don't run the auto-formatter on it. Keep the copy identical to upstream except for the
   patch, and don't keep unmodified copies of headers: they would shadow the newer ones after an update.
   Today these are about 60 lines in 5 files, the rest is the RTNL `*binary` hook, musl casts and
   pcap logging.

Updating Cyclone: move the four submodules to the new tag, adapt the source lists and include paths in
the `Makefile`, port the TeddyCloud code to the changed APIs, re-port the remaining patches onto the new
files and run `make test` plus the complete Docker matrix (`publish_docker_matrix_all.yml` with
`dry_run=true` and `full_matrix=true`; dry runs and pull requests are otherwise fast and skip the emulated Alpine builds).

## Releases and release candidates

A release is a tag `tc_vX.Y.Z`: it builds the zips, a draft GitHub release and the Docker images
`X.Y.Z`, `X.Y`, `X` and `latest`.

A **release candidate** has its own tag prefix `rc_` and so never touches the release machinery. Tag a
commit that is on `develop`:

    git fetch origin
    git tag rc_v0.7.1 origin/develop          # the first candidate of 0.7.1
    git push origin rc_v0.7.1
    # further candidates of the same version: rc_v0.7.1-1, rc_v0.7.1-2 (or rc_v0.7.1-rc1, ...)

It publishes **Docker images only** (no GitHub release): `rc` (the newest candidate of anything),
`rc0.7.1` (the newest candidate of 0.7.1) and, for a suffixed tag, the exact `rc0.7.1-1` (or
`rc0.7.1-rc1`) plus the git tag name. `latest`, `0`, `0.7` and `0.7.1` never move, a check in the
workflow fails the run before pushing if they would. The binary reports `v0.7.1-rc` / `v0.7.1-rc1`.
An `rc_` tag whose commit is not reachable from `develop` is refused. Candidate runs are queued one
at a time (the `rc` tags move), so don't re-run an old candidate. Nothing is merged to `master`.

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
