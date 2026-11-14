---
title: "Ticket 21b — Tamper detection: Guard's integrity collector"
aliases: [Ticket 21b]
project: anti-reverse
doc: TICKET
slice: 21
version: 0.1.0
status: done
updated: 2026-11-15
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
- [x] **Which files it fetches (as built, D-103):** only same-origin URLs the browser loaded as a script.
  - A `<script>` counts only with an empty, JavaScript or `module` type, and, where Resource Timing works, only with an entry for its URL.
  - **Anchor by content.** Candidates for the first listed file (the file Harden planted the marker in) are the loaded scripts whose path ends like it, at most 4. A candidate qualifies only if its bytes hold the marker's literal `b:"<Build id>",f:[`.
  - Exactly one candidate must qualify, and every candidate must be examinable. Otherwise nothing is sent for the Build.
  - Every other file is the single loaded script at exactly base + path whose query string equals the anchor's.
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
| Collector: timing, registry, anchoring, hashing, budgets, failures, wire content, early re-attest, memo, opt-out, several markers | `packages/guard/test/integrity.test.ts` (349 Guard tests in all), including a seeded differential test against a plain reference (5 seeds × 4,000 pages) |
| The marker's literal survives a minifier | A test builds a real marker statement, minifies it with esbuild and finds the needle in both forms |
| Size and synchronous cost | `packages/guard/test/package.test.ts`: 21.4 KB gzip for all Guard sources against 35 KB (JS as shipped about 19 KB; 10.2 KB before this slice). `plan()` takes about 2 ms on a large page and under 10 ms on hostile ones, on a desktop |
| End to end in a browser | `tests/e2e/tamper-guard.e2e.ts`: the untouched Build becomes watched with no Incident; one byte changed opens a High "Tampered Build" Incident in the Console about 30 s after page load. Every request to the shop origin is logged and matched exactly, and every attest body is checked key by key |
| Quality | `npm run gate:release` on 2026-11-15: verify 8,509 tests in 324 files, Playwright 27/27, matrices, stand-in RRS 24, bench and load smoke all pass; verdict `blocked`, exit 2 |

**Independent reviews:** four, each reproducing what it reported. All findings were fixed test-first.

- **First** (1 HIGH, 2 MEDIUM, 9 LOW): suffix matching hashed the wrong file; the 2 MB cap did not bound the download; Guard fetched URLs the browser never loaded.
- **Second** (3 MEDIUM, 7 LOW): "most files wins" still picked another directory; a 200 answer that was not the script was hashed; two Apps on one page reported under the wrong App.
- **Third, of commit 86e3a7c** (1 HIGH, 2 MEDIUM, 5 LOW): the name-based rule was still unsound. A foreign same-origin script with a listed name was hashed as the Build's file whenever the Build's own files were not visible (CDN origin, imported module, lazy load after a full buffer, inlined bundle, 500 padded tags). Name-based inference was dropped for the content anchor (D-103).
- **Fourth, of the content anchor** (1 MEDIUM, 1 LOW–MEDIUM, 2 LOW): no false mismatch on honest origins in its own ground-truth fuzz (30,000 pages, 20,208 hashes, all correct). Two cases remained on unusual origins and were closed by failing closed, matching the marker's literal instead of the bare id, and the query rule.

**Not independently reviewed:** the fixes after the fourth review (fail closed, the literal needle, the query rule). They are covered by the slice's tests and the gate only. Commit 86e3a7c, which was pushed before the third review, carried the unsound name-based rule.

## Honest limits

- **A wrong file can still be reported on one kind of origin:** one with an endpoint that serves the whole planted file at a URL ending like the first file's path (a combining handler), on a page where the true file is not a counted script.
- **Coverage is partial by design.** Nothing is sent when the Build is on another origin, inlined, or has its marker stripped; when a candidate cannot be examined; when two copies qualify; or when the page gives no Resource Timing entries (Firefox `resistFingerprinting`, Tor Browser, pages that clear the buffer).
- **A script already on the page can suppress detection** (a fifth namesake, a second copy). The earlier claim that it "cannot make Guard report a wrong file" was wrong for commit 86e3a7c and is now true only up to the first limit above.
- **A minifier run after Harden keeps the marker.** A minified copy is reported with its own hash, so such a Build is never watched; serving raw and minified copies of a watched Build opens an Incident.
- **What is hashed is what a refetch receives,** not the bytes that ran.
- **The file indexes reveal which chunks a visitor loaded,** and they travel with the device identifier.
- **The 24 h memo is per App and Build,** so a partial first report is not completed that day. Without usable storage, every page view of 30 s hashes again.
- **Two Builds on one page that share file names** lose those files from their reports.
- **Non-Chromium browsers may report fewer files;** the browser test runs Chromium only.
- **PB-06 was measured on a desktop,** not on a throttled phone profile.
