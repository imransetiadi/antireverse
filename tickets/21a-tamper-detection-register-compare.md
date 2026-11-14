---
title: "Ticket 21a — Tamper detection: integrity marker, report and comparison"
aliases: [Ticket 21a]
project: anti-reverse
doc: TICKET
slice: 21
version: 0.1.0
status: done
updated: 2026-11-14
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[QASUITE]]"
---

# 21a: Tamper detection — register and compare

**What to build:** A registered Build carries an integrity marker. An attestation may report the hashes a browser observed for that Build's protected files. The API compares them with the registered Build and opens a High "Tampered Build" Incident on a mismatch. This slice ends at the API and the Console: the Guard collector that sends real reports from browsers is 21b.

**Why this and not a self-check:** a check inside the bundle cannot honestly lower W4 Tamper, because the stand-in already stubs the classic `--integrity` wrapper and so can any attacker (D-099). The RRS stays 24, and `transform.integrity` is not touched.

**Status:** done on 2026-11-14. The Guard collector is 21b.

**Blocked by:** nothing.

## Decisions (D-100)

| Fork | Choice | Decided by |
|---|---|---|
| How Guard learns the Build and files | A planted marker under `globalThis[Symbol.for("ar.build")]` with the Build id and up to 32 file paths; identifiers only, never hashes | Jev 0.78 |
| When the report travels | An optional field on `/v1/attest`; 21b brings the first re-attest forward once | Jev 0.81 |
| What the signal affects | Detection and Incident only; token, verdict and Shield unchanged; SDD amended | Jev 0.97 |
| File id on the wire, scope, storage, grouping, caps, origin | The designer's set (below) | Jev 1.0 |
| Threshold and severity | One mismatch opens a High Incident | Owner |
| Never-matched Builds | A Build is armed by its first fully matching report; before that, no Incident | Owner, against Jev's pick of a verify CLI (0.61 at confidence 0.53) |
| Marker default | On with `--register`; `--no-integrity-marker` turns it off | Owner, against Jev's pick of no flag (0.51 at confidence 0.41) |

The designer's set:
- **Wire:** a file is named by its index into `manifest.integrity.files`.
- **Storage:** two nullable columns on `detections` (`artifact_path`, `observed_sha256`) and one on `builds` (`integrity_first_match_at`); no new table.
- **Grouping:** one Incident per App, Environment and Build.
- **Origin:** the page's canonical, non-local `Origin` is stored on a mismatch Detection.
- **Caps (changed by the reviews, D-101):** per Build, 20 new file-and-hash pairs an hour, 50 in any rolling 24 hours, and 600 mismatching reports an hour. The lifetime cap and the per-App-Environment cap were dropped.

## Acceptance criteria

Harden

- [x] With `--register`, Harden plants one marker statement in the existing planting step. It pushes `{ b: <Build id>, f: [<artifact paths>] }` under `globalThis[Symbol.for("ar.build")]`, inside try/catch, with HTML-safe literals.
- [x] `f` holds at most 32 paths: the planted file first, then the largest protected JS artifacts.
- [x] The marker never fails a build. If it does not fit the size budget it is planted with fewer files or none, and the CLI report and the Manifest say so.
- [x] `--no-integrity-marker` turns it off.
- [x] The Manifest gains optional `integrity: { files: string[] }` (at most 32, each one of `artifacts[].path`); the API validates it.
- [x] The bytes on disk equal the Manifest's sha256 for fixtures with a BOM, CRLF and non-ASCII text.
- [x] `transform.integrity` is unchanged, and the stand-in RRS baseline stays 24.

Protocol and API

- [x] `AttestRequestSchema` gains optional `integrity: { build, files: [{ i, h }], skipped }` within the 4 KB body cap. An old API ignores it; an old Guard sends none. `tamper.integrity_mismatch` cannot be asserted by a client.
- [x] The attest handler adds no awaited I/O. A recorder judges the report after the response, only for handshakes that passed the nonce, the key binding and the App limiter.
- [x] The recorder:
  - drops reports with a missing, non-canonical or local `Origin`;
  - looks the Build up by App and Build id through a definer function, with caches and lookup buckets;
  - arms the Build on its first fully matching report;
  - treats a hash that equals the same path in another recent Build of the App Environment as stale, never a Detection;
  - applies the caps;
  - records a Detection (rule `tampered-build`, High, threshold 1, window 3600 s) with the file path, the observed hash, the origin and the reporter's network prefix.
- [x] One Incident per App, Environment and Build; one alert when it opens.
- [x] An unarmed Build, an unknown Build and a Build of another App or Organization open nothing.
- [x] Token claims, verdict, usage metering and SLO-01 classification are unchanged.
- [x] Export, purge and retention catalog tests stay green.

Console

- [x] The Incident list and detail show "Tampered Build": Build, file, registered and observed hash, origin as plain text, reports and networks. There is no containment bar, and a note says why.

Quality

- [x] An HTTP end-to-end test: `harden --register`, then attest with hand-built reports.
  - a match opens nothing and arms the Build;
  - a one-byte mismatch opens exactly one Incident and sends one alert;
  - a mixed deploy of two Builds opens none;
  - a forged flood stays within the caps.
- [x] `npm run verify` passes, and the release gate's runnable checks still pass.

## Proof

| Criteria | Proven by |
|---|---|
| Marker statement, file list, degrading, flag, Manifest field, byte-exact hashes | `packages/harden/test/marker.test.ts`, `cli-marker.test.ts`; `packages/protocol/test/integrity.test.ts` |
| Request field, hand-off without awaited I/O, token and SLO-01 unchanged | `apps/api/test/integrity.test.ts` |
| Recorder: arming, stale Builds, caps, grouping, alert, what a report cannot reach | `apps/api/test/integrity.test.ts`, `integrity-review.test.ts`, `integrity-db.test.ts`, `data-pending.test.ts` |
| Console | `apps/console/test/tamper-components.test.tsx`, `stub-tamper.test.ts` |
| End to end | `tests/e2e/tamper-detection.http.test.ts`: a match arms and opens nothing; one byte changed opens one Incident with one alert; a mixed deploy opens none; a forged flood stops at 20 Detections. Disabling the comparison fails 5 of its 9 tests |
| Quality | `npm run gate:release` on 2026-11-14: verify 8,350 tests in 323 files, Playwright 26/26, matrices, stand-in RRS 24 on both profiles, bench and load smoke all pass; verdict `blocked`, exit 2 (lines that cannot be checked yet) |

**Independent reviews:** two, each reproducing what it reported. All findings were fixed test-first.

- **First review** (1 HIGH, 3 MEDIUM, 4 LOW):
  - The stale check ran before every cap, so forged reports stalled the API (another visitor's attestation went from 1 ms to 941 ms).
  - The lifetime cap blinded a Build for good.
  - Matching reports used up the report budget.
  - One App's flood dropped other Organizations' reports.
  - The armed flag could lag in the cache; one report wrote 32 log lines; the request role could disarm a Build.
- **Second review, of the rewritten recorder** (2 MEDIUM, 3 LOW):
  - Stale-only reports used up the report budget.
  - About 50 Apps could hold the global lookup budget empty.
  - The stale map missed paths no recent marker lists.
  - Evicting a Build's state reset its caps.
  - A report in flight during a purge logged an error.

**Jev:** its verification of the final gate claims came back unverified at low confidence (one claim verified at 0.67); the claims rest on the gate log quoted above. Jev was unreachable when the cap was redesigned; asked afterwards, it picked the rolling window at 0.51 with confidence 0.41, and the owner confirmed it (D-101).

## Honest limits

- **Nothing in the field sends reports until 21b.** The Console pages were checked by component tests and the stub, not in a browser.
- **It catches non-adaptive tampering only.** A tampered bundle can strip the marker, strip Guard, or report the registered hashes.
- **Blind spot of arming:** an origin compromised before it ever served clean files never arms.
- **Forged reports can suppress as well as forge.** Anyone with the public App id can report false mismatches for an armed Build, and can also spend that Build's limits so that real reports are not recorded. The limits are per Build. When a limit dropped a distinct hash, the open Incident says so.
- **An old Build that is still served is reported as tampered.** A file is stale only when its hash is the registered one for the same path in one of the newest 20 Builds or a Build registered in the last 30 days.
- **A downgrade reads as stale.** Serving a recent older Build's file is never a Detection.
- **The origin on a Detection can be wrong.** A Detection is recorded once per Build, file and hash per hour, so the first report fixes the origin, and a forged report can name a made-up one.
- **The hourly caps are per API process** and reset on a restart; the repeat window and the daily cap are kept in the database.
- **Registered output is no longer byte-identical across runs with one seed,** because the marker carries the Build id. It is identical with `--no-integrity-marker`.
