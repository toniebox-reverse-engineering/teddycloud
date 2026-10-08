# teddycloud open issue triage — 2026-09-30

70 open issues, checked against `develop` + full comment threads, cross-referenced against all
170 PRs (open/merged/closed) in the repo. Legend:

- **Validity**: valid / invalid / already-fixed / unclear / duplicate
- **Complexity**: easy / medium / complex (implementation effort, not issue-writing effort)
- **Usefulness**: high / medium / low / niche

Checkboxes are for you to tick as you action each one — nothing here is applied yet.

---

## 0. PR status across both repos

Only **5 PRs are currently open** in `teddycloud`: #462, #471 (release), #477, #482, #484.
`teddycloud_web` (the companion frontend repo) has **5 more**: #326–#330. Cross-checked
every issue against GitHub's PR-linking metadata plus manual reading where linking wasn't
automatic (a plain pasted URL in a comment, e.g., doesn't create a GitHub cross-reference).

**Update:** `teddycloud_web` PR #317 ("track listened status for library files") is now
**merged** — its conflicts against `develop` (in `CHANGELOG.md`, `FileBrowser.tsx`,
`Columns.tsx`) were resolved and a real bug found in review (missing `encodeURIComponent`
on file paths in `TeddyCloudApi.ts`'s `apiPostFileSetListened` and in
`useAssignNextEpisode.ts`) was fixed before it landed on `develop` at commit `6310d2c`.

### Ready to merge right now (approved + green CI + no conflicts)

| Repo | PR | Title | Status |
|---|---|---|---|
| teddycloud_web | [#330](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/330) | feat: add optional web UI login with multiple users | **APPROVED** by henryk86, CI green, clean merge. Frontend half of #85. |
| teddycloud_web | [#329](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/329) | feat: download TAF tracks as OGG files | Went CHANGES_REQUESTED → **APPROVED** (latest review), CI green, clean merge. Frontend half of #169/#331 — coordinate with backend #484 (see below), which isn't merged yet. |

Nothing in `teddycloud` (backend) has an approving review yet — see the per-PR table below.

### teddycloud (backend) open PRs — none formally approved

| PR | Title | Review | CI / merge state |
|---|---|---|---|
| [#484](https://github.com/toniebox-reverse-engineering/teddycloud/pull/484) | feat: export selected TAF tracks as Ogg or Zip | No reviews yet | CI all green, mergeStateStatus CLEAN — closest to ready, just needs someone to look and approve |
| [#482](https://github.com/toniebox-reverse-engineering/teddycloud/pull/482) | feat: add optional web UI login with cookie sessions | Active back-and-forth (14 COMMENTED reviews from henryk86/ditschi), no approval yet | CI all green — still under discussion, not resolved |
| [#462](https://github.com/toniebox-reverse-engineering/teddycloud/pull/462) | Feature/rabbit hole tap playlist | No reviews, still **draft** | 2 CI failures (`build-windows-amd64`, `ubuntuAsanTest/ppc64le`) alongside passing reruns — flaky or unresolved, and it's a draft so not merge-eligible regardless |
| [#477](https://github.com/toniebox-reverse-engineering/teddycloud/pull/477) | fix(server): clear authenticated on every pooled connection reuse | No reviews | **Merge conflicts** (CONFLICTING/DIRTY), needs a rebase before anyone can review it properly |
| [#471](https://github.com/toniebox-reverse-engineering/teddycloud/pull/471) | Next Version | No reviews | Automated release-prep PR, not a normal review target |

### teddycloud_web (frontend) open PRs — full list

| PR | Title | Review | CI / merge state |
|---|---|---|---|
| [#330](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/330) | feat: add optional web UI login with multiple users | **APPROVED** | Clean, green — ready (see above) |
| [#329](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/329) | feat: download TAF tracks as OGG files | **APPROVED** (after an earlier changes-requested round) | Clean, green — ready pending backend #484 |
| [#328](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/328) | chore: update dependencies, add translation check | No reviews | Clean, green — low-risk chore, just unreviewed |
| [#327](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/327) | feature: List view for Tonies | **CHANGES_REQUESTED** (twice) | UNSTABLE — maintainer wants it to reuse the antd design system, not a bespoke list component |
| [#326](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/326) | Support serving the web UI under a runtime URL prefix | No formal review yet; maintainer's "feels like this could break everything" comment predates the changelog entry that's already in the diff | No CI has run at all (`gh pr checks` reports none — needs a maintainer to approve the workflow run for this external contributor). Fixes issue #245. **Code review: sound.** Single source of truth (`src/utils/basePath.ts`), a regex anchored on `/web` as a path segment so it can't false-match a prefix like `/webapp`, `withBase()` is idempotent, and it's applied consistently at every root-absolute URL call site (~20 files: API config, router basename, i18n, RTNL EventSource, audio/image URLs, plugin iframes, WASM encoder, cert download). Favicon/manifest hrefs are untouched but fine — Vite auto-rewrites those via `base: "./"` at build time. Blocked only on CI being triggered and a review/approval, not on a code issue. |

### Merged just now (this session)

| PR | Title | Note |
|---|---|---|
| [teddycloud_web #317](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/317) MERGED | feat: track listened status for library files | From a fork (`pladux/teddycloud_web`), had merge conflicts against `develop` and an `encodeURIComponent` bug — both fixed, then pushed directly to `develop` (commit `6310d2c`). Backend counterpart PR #467 (`teddycloud`) was already merged earlier. |

### Already fixed by a *merged* PR (issue should just be closed)

| Issue | Merged PR | Note |
|---|---|---|
| [#419](https://github.com/toniebox-reverse-engineering/teddycloud/issues/419) core.wwwdir/pluginsdir configurable | [#444](https://github.com/toniebox-reverse-engineering/teddycloud/pull/444) MERGED | Done — abandoned attempt #443 was superseded by this one |
| [#407](https://github.com/toniebox-reverse-engineering/teddycloud/issues/407) Stream started twice | [#479](https://github.com/toniebox-reverse-engineering/teddycloud/pull/479) MERGED | perf: skip encoding for range requests that force a box restart |
| [#311](https://github.com/toniebox-reverse-engineering/teddycloud/issues/311) Ubuntu AARCH64 build fails | [#461](https://github.com/toniebox-reverse-engineering/teddycloud/pull/461) MERGED | Native arm64 runners |
| [#131](https://github.com/toniebox-reverse-engineering/teddycloud/issues/131) MQTT event when Tonie removed | [#321](https://github.com/toniebox-reverse-engineering/teddycloud/pull/321) MERGED | Verified in current code: `src/handler_rtnl.c:348` calls `tbs_tag_removed()` → `src/toniebox_state.c:42` fires `mqtt_sendBoxEvent("TagInvalid", "", ...)` (CC3200/ESP32 scope per the PR title; TB2 coverage unconfirmed). Issue just needs the reporter to confirm and close. |
| [#483](https://github.com/toniebox-reverse-engineering/teddycloud/issues/483) CC3235 → TB2 | direct commit `0b6673f` (no PR, pushed straight to develop) | Fixed by us today |

### Open PR pending merge — don't start new work, review/merge instead

| Issue | Open PR | Note |
|---|---|---|
| [#169](https://github.com/toniebox-reverse-engineering/teddycloud/issues/169) `/web` download doesn't split TAF into per-track OGG | [#484](https://github.com/toniebox-reverse-engineering/teddycloud/pull/484) OPEN | PR body says "Closes #169" directly. Companion frontend PR [teddycloud_web#329](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/329) also open. |
| [#331](https://github.com/toniebox-reverse-engineering/teddycloud/issues/331) Enhance TAF download to OGG w/ chapters | [#484](https://github.com/toniebox-reverse-engineering/teddycloud/pull/484) OPEN | SciLor linked this PR in a comment on #331, but it's **not merged yet** — GitHub didn't auto-link it since the PR's own "Closes" keyword only names #169. |
| [#85](https://github.com/toniebox-reverse-engineering/teddycloud/issues/85) Real web UI auth | [#482](https://github.com/toniebox-reverse-engineering/teddycloud/pull/482) OPEN | Optional login w/ cookie sessions, exactly what's requested. Companion frontend PR [teddycloud_web#330](https://github.com/toniebox-reverse-engineering/teddycloud_web/pull/330) also open. Author's own note: they no longer personally need this (switched to Authelia+Traefik) but left it open for review. |
| [#262](https://github.com/toniebox-reverse-engineering/teddycloud/issues/262) TAP times out / box shuts down mid-encode | [#462](https://github.com/toniebox-reverse-engineering/teddycloud/pull/462) OPEN | A commenter on the issue explicitly confirms: "#462 reworks this path... That is the writer side; it does not clear the reader's EOF indicator, so the two changes would be complementary rather than alternatives" — i.e. #462 helps but may not fully close this alone (related to a separate PR #478, already merged, for the EOF/stall issue). |

### Abandoned/closed PRs that attempted a fix but didn't land (worth reviving, not reinventing)

| Issue | Closed PR | Note |
|---|---|---|
| [#417](https://github.com/toniebox-reverse-engineering/teddycloud/issues/417) Preencode TAF after TAP creation | [#460](https://github.com/toniebox-reverse-engineering/teddycloud/pull/460) CLOSED | "Keep TAP generation alive after client disconnect" — closed unmerged |
| [#262](https://github.com/toniebox-reverse-engineering/teddycloud/issues/262) (also) | [#460](https://github.com/toniebox-reverse-engineering/teddycloud/pull/460) CLOSED | Same abandoned PR touches this too |

### Tangentially related merged PRs (didn't fully close the issue, worth a quick look before starting fresh)

| Issue | Related merged PR | Note |
|---|---|---|
| [#342](https://github.com/toniebox-reverse-engineering/teddycloud/issues/342) Addon/plugin folder structure | [#220](https://github.com/toniebox-reverse-engineering/teddycloud/pull/220) MERGED | Early partial groundwork ("prepared feature teddycloud plugins"); upload/delete + full spec still open |
| [#283](https://github.com/toniebox-reverse-engineering/teddycloud/issues/283) Custom Tonies caching fails on paths | [#426](https://github.com/toniebox-reverse-engineering/teddycloud/pull/426) MERGED | "Feature/custom model editor" — uncertain overlap, worth checking if it already covers the relative-path case before implementing |
| [#430](https://github.com/toniebox-reverse-engineering/teddycloud/issues/430) / [#194](https://github.com/toniebox-reverse-engineering/teddycloud/issues/194) | [#439](https://github.com/toniebox-reverse-engineering/teddycloud/pull/439) MERGED | "Enhance condition for valid tonieInfo check" — tangential, doesn't fully resolve either |
| [#406](https://github.com/toniebox-reverse-engineering/teddycloud/issues/406) API to detect Tonie removed | [#321](https://github.com/toniebox-reverse-engineering/teddycloud/pull/321) MERGED | The MQTT *event* on removal exists (see #131 above) but the explicit ask here — a queryable REST status — is still not implemented |

### Checked, no related PR found at all

#384 (iOS Safari upload — PR #456 fixed a *Firefox* truncation bug, different root cause), #473 (boot loop — only a documented uid workaround exists, no PR fix), #405 (TB2 support — in progress via `teddycloud_web` repo, no teddycloud-side PR yet), #338, #383, #367, #120, #445, #303, #271, #270, #189, #172, #165, #164, #163, #89, #50, #27, #22, and everything in sections 4–7 below not mentioned above (#245 has a PR — see `teddycloud_web` #326 above).

---

## 1. Close now — already fixed (5)

- [ ] [#483](https://github.com/toniebox-reverse-engineering/teddycloud/issues/483) CC3235 detected as box generation TB2 — fixed by us today, commit `0b6673f`
- [ ] [#407](https://github.com/toniebox-reverse-engineering/teddycloud/issues/407) Stream started twice — merged PR #479
- [ ] [#311](https://github.com/toniebox-reverse-engineering/teddycloud/issues/311) Ubuntu AARCH64 build fails (ASan allocator) — merged PR #461
- [ ] [#419](https://github.com/toniebox-reverse-engineering/teddycloud/issues/419) Make `core.wwwdir`/`pluginsdir` configurable — merged PR #444
- [ ] [#131](https://github.com/toniebox-reverse-engineering/teddycloud/issues/131) MQTT event when Tonie removed — merged PR #321, verified working in current `src/toniebox_state.c`

## 2. Close now — invalid / wontfix (5)

- [ ] [#430](https://github.com/toniebox-reverse-engineering/teddycloud/issues/430) Switch identity to RUID-based mapping — already RUID-based; real gap (MQTT uses audio-id) is tracked separately in #194
- [ ] [#409](https://github.com/toniebox-reverse-engineering/teddycloud/issues/409) Expected end of current Tonie via MQTT — box doesn't report playback position, infeasible
- [ ] [#334](https://github.com/toniebox-reverse-engineering/teddycloud/issues/334) Time-based disabling of Toniebox — no trigger mechanism exists while box is idle
- [ ] [#186](https://github.com/toniebox-reverse-engineering/teddycloud/issues/186) HA: static picture when nothing playing — it's a question, not a bug; workaround exists
- [ ] [#174](https://github.com/toniebox-reverse-engineering/teddycloud/issues/174) MP3→TAF chapter encoding — explicitly labeled wontfix by maintainers already

## 3. Review the open PR — pending merge, don't reimplement (4)

- [ ] [#169](https://github.com/toniebox-reverse-engineering/teddycloud/issues/169) Split TAF download into per-track OGG — PR #484 (+ frontend #329)
- [ ] [#331](https://github.com/toniebox-reverse-engineering/teddycloud/issues/331) Enhance TAF download to OGG w/ chapters — PR #484
- [ ] [#85](https://github.com/toniebox-reverse-engineering/teddycloud/issues/85) Real web UI auth — PR #482 (+ frontend #330)
- [ ] [#262](https://github.com/toniebox-reverse-engineering/teddycloud/issues/262) TAP times out mid-encode — PR #462 (may need a follow-up per commenter)

## 4. Ping the reporter — need more info / can't confirm (8)

- [ ] [#403](https://github.com/toniebox-reverse-engineering/teddycloud/issues/403) Error downloading a TAF — single report, no repro, no logs
- [ ] [#384](https://github.com/toniebox-reverse-engineering/teddycloud/issues/384) iOS Safari upload doesn't work — partially fixed, Safari-specific part unreproduced (no Mac); not the same bug as the merged Firefox fix in #456
- [ ] [#348](https://github.com/toniebox-reverse-engineering/teddycloud/issues/348) Cloud settings not shown/forwarded via MQTT — no repro on current develop
- [ ] [#308](https://github.com/toniebox-reverse-engineering/teddycloud/issues/308) Service fails to start sporadically after reboot — no root cause, may be stale (one user says it stopped)
- [ ] [#138](https://github.com/toniebox-reverse-engineering/teddycloud/issues/138) 2048 vs 4096-bit certs — collaborator claims fixed in develop, SciLor disputes it
- [ ] [#124](https://github.com/toniebox-reverse-engineering/teddycloud/issues/124) Extract ESP32 client certs via web UI — maintainer asked "fixed in develop, or should this be added?" — unanswered
- [ ] [#88](https://github.com/toniebox-reverse-engineering/teddycloud/issues/88) Initial WLAN setup fails ("Ant" error) — "partly implemented" per maintainer, thread trailed off
- [ ] [#77](https://github.com/toniebox-reverse-engineering/teddycloud/issues/77) Slow/unstable initial box connection — no diagnosis confirmed, likely RTNL timing issue

## 5. Quick wins — valid + easy, no PR yet (15)

Sorted by usefulness, high first.

| # | Title | Usefulness | Note |
|---|---|---|---|
| [473](https://github.com/toniebox-reverse-engineering/teddycloud/issues/473) | Boot loop after 0.7.0 update (Docker, DXP2800) | high | Regression from PR #442 (gosu uid switch fails w/o "teddy" passwd entry); no fix PR exists, only a documented workaround |
| [338](https://github.com/toniebox-reverse-engineering/teddycloud/issues/338) | Redownload TAF button on corruption | high | Corruption already detected & logged, just missing a UI/API trigger to redownload |
| [406](https://github.com/toniebox-reverse-engineering/teddycloud/issues/406) | API to detect Tonie removed from box | medium | MQTT event for this already exists (#131/PR #321); this issue wants a queryable REST endpoint specifically |
| [383](https://github.com/toniebox-reverse-engineering/teddycloud/issues/383) | Store structured settings as JSON via API | medium | Maintainer already agreed on the approach |
| [367](https://github.com/toniebox-reverse-engineering/teddycloud/issues/367) | Add `isOriginalTonie` flag to getTagIndex | medium | Maintainer confirmed it's needed |
| [120](https://github.com/toniebox-reverse-engineering/teddycloud/issues/120) | tonies.json auto-update never runs periodically | medium | Only called once at startup — one-line timer bug |
| [380](https://github.com/toniebox-reverse-engineering/teddycloud/issues/380) | HA: no content picture for radio stream source | low | |
| [296](https://github.com/toniebox-reverse-engineering/teddycloud/issues/296) | Library name as ContentTitle (MQTT) | niche | |
| [277](https://github.com/toniebox-reverse-engineering/teddycloud/issues/277) | HA MQTT discovery range restricted to INT32 | low | Preventive, not an active bug yet |
| [268](https://github.com/toniebox-reverse-engineering/teddycloud/issues/268) | Download Boxine CA cert from teddyCloud | low | |
| [264](https://github.com/toniebox-reverse-engineering/teddycloud/issues/264) | Docker tags don't follow semver | low | Pure CI/release workflow change |
| [233](https://github.com/toniebox-reverse-engineering/teddycloud/issues/233) | Different "unknown" icon per content type | low | Mockups provided, pure frontend |
| [231](https://github.com/toniebox-reverse-engineering/teddycloud/issues/231) | `--cloud-test` crashes (null deref) | niche | One-line null-check guard, confirmed root cause |
| [104](https://github.com/toniebox-reverse-engineering/teddycloud/issues/104) | Lower/uppercase content dirs | low | |
| [48](https://github.com/toniebox-reverse-engineering/teddycloud/issues/48) | Add screenshots/gifs/YouTube to README | low | Docs only |

## 6. Valid, medium effort, no PR yet (17)

| # | Title | Usefulness |
|---|---|---|
| [445](https://github.com/toniebox-reverse-engineering/teddycloud/issues/445) | Plugin settings via `/api/settings` (plugin.* namespace) | medium |
| [417](https://github.com/toniebox-reverse-engineering/teddycloud/issues/417) | Preencode TAF directly after TAP creation | medium — see abandoned PR #460 above |
| [342](https://github.com/toniebox-reverse-engineering/teddycloud/issues/342) | Addon/plugin folder structure | medium — partial groundwork in PR #220 |
| [335](https://github.com/toniebox-reverse-engineering/teddycloud/issues/335) | Show TAF encoding percentage | low |
| [303](https://github.com/toniebox-reverse-engineering/teddycloud/issues/303) | Detect TAF encoder (Original/Creative/TeddyCloud/etc) | medium |
| [283](https://github.com/toniebox-reverse-engineering/teddycloud/issues/283) | Custom Tonies caching fails on relative/space paths | medium — check PR #426 overlap first |
| [271](https://github.com/toniebox-reverse-engineering/teddycloud/issues/271) | Overlay config via MQTT | medium |
| [270](https://github.com/toniebox-reverse-engineering/teddycloud/issues/270) | ESP32 hostname flash: no UI feedback on failure | medium |
| [189](https://github.com/toniebox-reverse-engineering/teddycloud/issues/189) | Search API for taf/tap files | medium — labeled "prio" |
| [172](https://github.com/toniebox-reverse-engineering/teddycloud/issues/172) | "Report unknown Tonie" feature parity w/ old UI | medium |
| [165](https://github.com/toniebox-reverse-engineering/teddycloud/issues/165) | Cache-to-library source-value not set | medium — fix exists but disabled due to mutex deadlock risk |
| [164](https://github.com/toniebox-reverse-engineering/teddycloud/issues/164) | Mark settings as box-specific | medium |
| [163](https://github.com/toniebox-reverse-engineering/teddycloud/issues/163) | Persist toniebox internals to file | low |
| [89](https://github.com/toniebox-reverse-engineering/teddycloud/issues/89) | Combine/split tracks (99-track TAF limit) | medium |
| [50](https://github.com/toniebox-reverse-engineering/teddycloud/issues/50) | HASS/MQTT online status for device | medium |
| [27](https://github.com/toniebox-reverse-engineering/teddycloud/issues/27) | Decode info from `/v1/log` endpoint | low |
| [22](https://github.com/toniebox-reverse-engineering/teddycloud/issues/22) | Enhance RTNL decoder (RTNL2 func-codes undecoded) | medium |

## 7. Valid, complex — bigger projects, no PR yet (11)

Ranked, best value-for-effort first.

| # | Title | Usefulness | Why it matters |
|---|---|---|---|
| [310](https://github.com/toniebox-reverse-engineering/teddycloud/issues/310) | Boxine comms deadlock / slow freshnessCheck | **high** | Core reliability issue, still reported unresolved (Dec 2025) |
| [405](https://github.com/toniebox-reverse-engineering/teddycloud/issues/405) | Toniebox 2 support | high | Actively in progress already (web UI PR merged there, cert extraction still WIP), no teddycloud-side PR |
| [245](https://github.com/toniebox-reverse-engineering/teddycloud/issues/245) | Support URL path prefix (reverse-proxy deployments) | medium | **Has an open PR:** `teddycloud_web` #326 — not merge-ready yet (needs changelog entry, maintainer wants more confidence it won't break the default path) |
| [378](https://github.com/toniebox-reverse-engineering/teddycloud/issues/378) | Expand tonie.json with API data from Tonies account | medium | Prototype exists, but full auth flow + crowdsourcing is a big scope |
| [267](https://github.com/toniebox-reverse-engineering/teddycloud/issues/267) | Cache TAF header for on-the-fly conversions | medium | Avoids re-encoding; needs persistent header cache |
| [210](https://github.com/toniebox-reverse-engineering/teddycloud/issues/210) | Freshnesscheck API (mark stale content) | medium | Maintainer's own proposal, scope still undefined |
| [188](https://github.com/toniebox-reverse-engineering/teddycloud/issues/188) | Metadata (series/episode/image) on custom TAFs | medium | Unresolved protobuf/firmware-compat concerns, needs a design decision first |
| [182](https://github.com/toniebox-reverse-engineering/teddycloud/issues/182) | MQTT removed-event not firing after long playtime | medium | Possibly tied to 90-min Kreativtonie limit, needs investigation |
| [159](https://github.com/toniebox-reverse-engineering/teddycloud/issues/159) | Library vs. Boxine-defined creative Tonies collide | medium | Real UX gap, partial mitigations exist (#156/#157) |
| [157](https://github.com/toniebox-reverse-engineering/teddycloud/issues/157) | Tagging/labeling + grouping of tonies/tags | medium | Needs backend + web UI schema work |

## 8. Valid, complex, niche — low priority (7)

- [ ] [#437](https://github.com/toniebox-reverse-engineering/teddycloud/issues/437) Enhance CC3200 flashing process — large multi-step feature, niche box type
- [ ] [#388](https://github.com/toniebox-reverse-engineering/teddycloud/issues/388) Multiple TAFs per Tonie w/ random playback
- [ ] [#363](https://github.com/toniebox-reverse-engineering/teddycloud/issues/363) Fetch ARD Audiothek — community scripts already solve this outside teddyCloud
- [ ] [#194](https://github.com/toniebox-reverse-engineering/teddycloud/issues/194) MQTT missing image/title for webstream Tonies — audio_id churns per placement, no fix proposed
- [ ] [#125](https://github.com/toniebox-reverse-engineering/teddycloud/issues/125) RTP streaming to Toniecloud — speculative, no design consensus, dead since 2024
- [ ] [#105](https://github.com/toniebox-reverse-engineering/teddycloud/issues/105) Cycle through TAF files — needs box-orientation detection hack

---

## Summary counts

| Bucket | Count |
|---|---|
| Close — already fixed (merged PR or direct commit) | 5 |
| Close — invalid/wontfix | 5 |
| Review open PR, don't reimplement | 4 |
| Needs reporter follow-up | 8 |
| Quick wins (easy + valid, no PR) | 15 |
| Medium effort, valid, no PR | 17 |
| Complex, valid, worth doing, no PR | 10 |
| Complex, valid, niche/low priority | 6 |
| **Total** | **70** |

Note: #262 and #406 each appear in two sections above (once for the PR/related-work note, once in their
priority bucket) since they have partial coverage but aren't fully resolved — not double-counted in the
total.
