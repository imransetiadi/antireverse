---
title: "Ticket 21b — Tamper detection: Guard's integrity collector"
aliases: [Ticket 21b]
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

# 21b: Guard's integrity collector

**What to build:** Guard reads the integrity marker Harden planted (21a), hashes the Build's protected files it can read in the browser, and sends the report with an attestation. With 21a this closes the loop: a file changed after Harden opens a "Tampered Build" Incident from a real browser (QASUITE TC-GRD-002).

**Status:** done on 2026-11-14.

**Blocked by:** 21a (done). Design decisions D-100 and D-101 apply; none is re-opened here.

## Acceptance criteria

Collector

- [x] **When it runs:** only after the first Attestation Token exists, in idle time. The first handshake's body carries no report, and the first token is not delayed.
- [x] **What it reads:** the marker registry under `globalThis[Symbol.for("ar.build")]`, read lazily, so load order does not matter. A missing, malformed or hostile registry is ignored without throwing.
- [x] **Which files it fetches (as built, D-102):** only same-origin URLs the browser loaded as a script.
  - A `<script>` counts only with an empty, JavaScript or `module` type, and, where Resource Timing works, only with an entry for its URL.
  - The Build's base is taken only from URLs that end like exactly one listed path. Exactly one base must result, or the Build is skipped.
  - Each file is the script at exactly base + path. A URL two Builds would name is used by neither.
  - No other URL is ever fetched.
- [x] **How it hashes:** one file at a time, `fetch(url, { cache: "force-cache", credentials: "same-origin" })`, then `arrayBuffer()`, then SHA-256 with `crypto.subtle`, as canonical base64url.
- [x] **Budgets:**
  - skipped entirely when `navigator.connection.saveData` is set;
  - a file over 2 MB is skipped (checked from Resource Timing before fetching, and from the response);
  - about 5 s of wall time overall; what is not done by then is skipped.
- [x] **Failures:** a failed, blocked (CSP) or opaque fetch counts as `skipped`. Nothing throws into the page.
- [x] **What is sent:** `{ build, files: [{ i, h }], skipped }` within the protocol's limits, on `/v1/attest`. No URL, path or content leaves the browser. A report with no hashed file is not sent.
- [x] **When it is sent:** the first re-attest is brought forward once, about 30 s after the first token and only while the tab is visible. A first-party memo keeps a device from reporting the same Build more than once in 24 hours.
- [x] **Opt-out:** `createGuard({ integrity: false })`.
- [x] **Several markers:** when more than one Build registered (two bundles on a page), the report covers one Build per attestation; say which and why.

Budgets and privacy

- [x] Guard stays within 35 KB gzip (PB-05), and the new synchronous work stays within PB-06. Both are measured in a test.
- [x] A network capture in the browser test shows the attest body holds only the reviewed fields.

End to end

- [x] **Playwright:** the storefront fixture bundle is hardened and registered with Guard on the page, then served twice.
  - Untouched: the Build becomes armed and no Incident opens.
  - One byte changed in a protected file on disk: within 60 s the Console shows a High "Tampered Build" Incident with the Build, the file and both hashes.
- [x] `docs/guard.md` explains what is hashed, what leaves the browser, the CSP need (`connect-src 'self'`), cross-origin scripts (skipped), the opt-out and the limits.
- [x] `npm run verify` passes, and the release gate's runnable checks still pass.

## Out of scope

Cross-origin scripts with CORS, the `verify --url` deploy check, and any change to the token, verdict or Shield.

## Proof

| Criteria | Proven by |
|---|---|
| Collector: timing, registry, matching, hashing, budgets, failures, wire content, early re-attest, memo, opt-out, several markers | `packages/guard/test/integrity.test.ts` (306 Guard tests in all) |
| Size and synchronous cost | `packages/guard/test/package.test.ts`: 19.8 KB gzip for all Guard sources against 35 KB (JS as shipped about 17 KB; 10.2 KB before this slice). `plan()` takes 2–3 ms on a large page and about 10 ms on a hostile one, on a desktop |
| End to end in a browser | `tests/e2e/tamper-guard.e2e.ts`: the untouched Build becomes watched with no Incident; one byte changed opens a High "Tampered Build" Incident in the Console about 30 s after page load. Every request to the shop origin is logged and matched exactly, and every attest body is checked key by key |
| Quality | `npm run gate:release` on 2026-11-14: verify 8,466 tests in 324 files, Playwright 27/27, matrices, stand-in RRS 24, bench and load smoke all pass; verdict `blocked`, exit 2 |

**Independent reviews:** two, each reproducing what it reported. All findings were fixed test-first.

- **First review** (1 HIGH, 2 MEDIUM, 9 LOW):
  - Suffix matching hashed the wrong file, which would open a false High Incident.
  - The 2 MB cap did not bound the download.
  - Guard fetched URLs the browser never loaded, with the user's credentials.
  - `stop()` did not stop a running collection; two Guards both reported; the early re-attest went out from a hidden tab.
- **Second review, of the rewrite** (3 MEDIUM, 7 LOW, one test gap):
  - "Most files wins" still picked another directory.
  - A 200 answer that was not the script (a SPA fallback page) was hashed.
  - Two Apps on one page reported the Build under the wrong App.
  - A chunk that was not a `Uint8Array` was hashed as zeros; a listener stayed after `stop()`; the monotonic budget check was untested.

**Not independently reviewed:** the fixes after the second review, including the final base rule (D-102). They are covered by the slice's own tests and the gate only.

## Honest limits

- **Coverage is partial by design.** A Build is skipped when its base is ambiguous, when the page gives no Resource Timing entries (Firefox `resistFingerprinting`, Tor Browser, pages that clear the buffer), or when its scripts come from another origin.
- **What is hashed is what a refetch receives,** not the bytes that ran. With `no-store` scripts that is the server's current answer.
- **The file indexes reveal which chunks a visitor loaded,** and they travel with the device identifier.
- **The 24 h memo is per App and Build,** so a partial first report is not completed that day. Without usable storage, every page view of 30 s hashes again.
- **Non-Chromium browsers may report fewer files;** the browser test runs Chromium only.
- **PB-06 was measured on a desktop,** not on a throttled phone profile.
- **A script already on the page can suppress detection** (for example by making the base ambiguous). It cannot make Guard report a wrong file.
