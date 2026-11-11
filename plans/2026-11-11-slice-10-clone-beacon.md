---
title: "Plan — Slice 10 Clone Beacon"
aliases: [Plan 10]
project: anti-reverse
doc: PLAN
slice: 10
version: 0.1.0
status: done
updated: 2026-11-11
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# Slice 10 — Clone Beacon Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** A protected bundle served from an origin its developer did not allow raises a High "Clone detected" Incident naming the origin and the Build.

**Architecture:** Harden plants an opt-in beacon statement (like Canaries) carrying the allowed origins, a per-Build token and the report URL. In a browser on a foreign, non-local origin it calls `navigator.sendBeacon` once. A public API endpoint validates and rate-limits reports, then records a Detection that opens or joins a `clone-origin` Incident grouped by origin; slice-06 alerts fire. The Console shows the beacon on the Build and the origin on the Incident. No new dependency.

**Spec:** [tickets/10-clone-beacon.md](../tickets/10-clone-beacon.md). Background: [SDD.md](../SDD.md) §8 (Origin lock and Clone Beacon), §9 (`origin.unauthorized`); [SECURITY.md](../SECURITY.md) TA-04, O2; [PERFORMANCE.md](../PERFORMANCE.md) (Clone Beacon events never shed); MEMORY D-032, D-033, D-039, D-043. Earlier plans and amendments still bind (slice 05 determinism, budget gate, equivalence; slice 06 detector, grouping, alerts, per-Organization bounds; slice 07 planting, scoped derivation, exit codes; slice 09 Incident detail).

## Global Constraints (additions)

- **Identifiers:** beacon token `bcn_<24 hex>`.
- **Origins:** canonical `scheme://host[:port]` — scheme `http` or `https`; host lower case (IDN as punycode); IPv6 in brackets; port omitted when default; no path, query, fragment or userinfo; ≤ 255 characters. `--origin` repeatable, 1–20, duplicates refused (exit 2). `--origin` requires `--register` (exit 2 otherwise).
- **Local origins (never reported, client and server):** host `localhost` or ending in `.localhost`, `.local`, `.test`, `.internal`; IPv4 loopback 127/8, private 10/8, 172.16/12, 192.168/16, link-local 169.254/16; IPv6 `::1`, `fc00::/7`, `fe80::/10`; any non-http(s) origin, and `null`.
- **Token:** `deriveBeaconToken(seed, { appId, version })` — HMAC-SHA256 with key `antireverse/beacon/v1/<seed>` over `<appId>\n<version>\nbeacon`, `bcn_` + first 24 hex. Deterministic; distinct per App and version.
- **Beacon statement** (planted as plain text after transforms, into the same file selection as Canaries — the first protected file that fits the budget; planting counts toward the budget; if it fits nowhere the harden fails, D-043): a self-contained IIFE wrapped in `try/catch` that does nothing unless `typeof location`, `typeof navigator` and `navigator.sendBeacon` exist; reads `location.origin`; returns if it is in the embedded list or local; otherwise calls `navigator.sendBeacon("<endpoint>/v1/beacon", JSON.stringify({ t: "<token>", o: location.origin }))` once. No global binding, no other side effect, no timers, no listeners. Size ≤ 600 bytes before gzip for 20 origins of typical length.
- **Manifest (optional fields, format stays 1):** `beacon: { token, origins: string[] }`. Build responses show `beacon: { origins }` and whether it is on — the token is not returned (it is in the public bundle, but responses stay minimal, as for Canaries).
- **Endpoint `POST /v1/beacon`:** public, no key; accepts `text/plain` or `application/json`; reads at most 1,024 bytes (more → still 204, dropped); **always 204** with no body and `Cache-Control: no-store`; no CORS headers needed (sendBeacon is no-cors). A report counts only when: body parses to `{ t, o }`; `t` names a registered Build's beacon; `o` is canonical, not local, not in that Build's origins; the `Origin` request header equals `o`. The reporter's address is reduced to its /24 or /48 at once; the full address is never stored or logged.
- **Limits (per Build, in memory, per API process):** ≤ 20 distinct new origins per hour and ≤ 600 reports per hour counted; one Detection per (Build, origin) per hour; drops are counted in a metric/log line with ids only. Per-Organization bounds of the detector (D-037) still apply.
- **Detection rule:** `clone-origin` — title "Clone detected", severity `high`, threshold 1. Detection carries `origin`, `build_id`, `ip_prefix` (the reporter's, nullable). Incident gains `origin` (nullable for other rules); `ip_prefix` becomes nullable (null for `clone-origin`). Grouping: same App, Environment, rule and origin while open or acknowledged. A new Incident alerts (slice 06). Incident detail for a clone: Detections as the timeline (each with time and reporter prefix), no Events evidence, no Actors, no containment.
- **Budgets:** report → Incident ≤ 60 s (expected ~1 s); Harden size budget includes the beacon.

## Review Focus

1. **No visitor traffic on allowed or local origins**, the beacon never throws and is inert outside a browser; equivalence still passes. *(harden)*
2. **The endpoint reveals nothing** (always 204, timing roughly equal) and **forgery is bounded** (Origin header check, per-Build limits, one Detection per origin per hour). *(API)*
3. **Privacy:** only the reporter's prefix is stored; no full address, no page path, no cookies. *(API)*
4. **Tenancy:** a token only ever opens Incidents for its own Build's Organization, App and Environment. *(API)*
5. **Determinism** of the beacon given seed, App and version. *(harden, protocol)*

## Contracts

- **P1 Protocol:** `beacon.ts` (isomorphic): `BEACON_LIMITS = { originsMax: 20, bodyBytesMax: 1024, newOriginsPerHour: 20, reportsPerHour: 600 }`, `OriginSchema` (canonical), `canonicalOrigin(text) → string | null`, `isLocalOrigin(origin) → boolean`, `BeaconTokenSchema`, `BeaconReportSchema { t, o }`, `ManifestBeaconSchema { token, origins }`, `BuildBeaconSchema { origins }`. Manifest gains optional `beacon`; Build response `beacon` without token. `DETECTION_RULES` gains `clone-origin`. Incident `origin` nullable; Incident and Detection `ip_prefix` nullable where needed; Detection gains `origin`. Server entry: `deriveBeaconToken(seed, scope)` with known answers. `ID_PATTERNS.bcn`.
- **P2 Harden:** `--origin` flags and validation; `src/beacon.ts` `beaconStatement(token, origins, endpoint)` and planting beside Canaries; report and `--json` additions; Manifest `beacon`.
- **P3 API:** migration `0010_beacon.sql` (build beacons: token → build, origins; incidents/detections `origin` column, `ip_prefix` nullable for `clone-origin` with checks); `POST /v1/beacon` (public route outside auth); limiter; detector path for `clone-origin` (may record the Detection directly from the route through the detector's write path — keep grouping, retry_join and alerts shared); Build and Incident responses.
- **P4 Console:** Build detail Clone Beacon fact (On · N origins / Off) and the origins list; Incident page for `clone-origin`: facts Origin, Build link, reporter prefixes in the timeline; containment bar replaced by a note ("Containment does not apply to a clone. Take the copy down at its host."); Incidents list shows the origin for clone Incidents.

## Tasks

Order: Task 1 (protocol) → Tasks 2–4 in parallel (Harden ‖ API ‖ Console) → Task 5 (e2e) → Task 6 (review, docs).

1. **Protocol** — failing tests first: canonical origin cases (case, default ports, IPv6, IDN, paths refused), local origins table, schemas, token known answers, nullable fields round-trip and old Incidents parse, rule table, entrypoints.
2. **Harden** — failing tests first: flags (missing --register, >20, duplicates, non-canonical → exit 2); beacon statement executed in a fake browser context (a `vm` context with stubbed `location`/`navigator`): allowed origin → no call; local origin → no call; foreign origin → exactly one sendBeacon with the right URL and body; missing APIs → no throw; outside a browser → no-op; equivalence passes across seeds; determinism; budget with Canaries + beacon; Manifest and report.
3. **API** — failing tests first per Review Focus 2–4: always 204 (valid, unknown token, malformed, oversize, wrong method content-types); counted only with matching Origin header; local and allowed origins ignored; limits; one Detection per origin per hour; Incident grouping by origin; alert payload has origin and build_id; prefix-only storage; tenancy; Build response has origins but no token.
4. **Console** — failing tests first: Build Clone Beacon fact; clone Incident facts and Build link; no containment bar for clone Incidents; list shows origin; copy pins; build.
5. **End to end** — HTTP: harden a copy of the reference bundle with `--origin http://shop.example:<port> --register`; POST reports as a browser would (Origin header) from an allowed, a local and a foreign origin → only the foreign one opens one High Incident naming the Build, and a signed alert; forged flood bounded by the limits. Browser: Chromium with `--host-resolver-rules` mapping `shop.example` and `clone.example` to 127.0.0.1; serve the protected bundle from both names; the allowed name sends no beacon request; the clone name produces the Incident in the Console.
6. **Review and docs.**

## Residual risks known up front

- A cloner who edits the bundle can remove the beacon; it catches wholesale copies.
- Limits are per API process (in memory).
- A customer's Content-Security-Policy `connect-src` must allow the API origin, or the browser drops the report.

## Deliberately not in this slice

Origin lock · Console-managed allowed origins · takedown workflow · Watermark · Guard-attested reports.

## Amendments

- **A1 — Protocol as built (Jev: accept_but_unspecified_local, 0.72).** Incident and Detection carry a required, nullable `origin` (canonical when set); Detection does not carry `build_id` (the Incident does); `canonicalOrigin` uses the global WHATWG `URL` (IDN → punycode, browser-identical `location.origin`; it normalises odd IPv4 spellings and port zeros rather than refusing them); no schema refine ties `clone-origin` to its fields (the API enforces it); `0.0.0.0` and `[::]` count as local origins; the beacon token pattern lives in `beacon.ts`, not `ID_PATTERNS` (derived values stay out, like the actor hash). Token known answer: seed 1, `app_0123456789abcdef01234567`, `1.0.0` → `bcn_a5dd35b17f47a81a0532f99e`.
- **A2 — Console as built (Jev: accept_all, 0.95).** The Build's Markers section shows **Clone Beacon** (On · N origins, with the origins as plain text, or Off with a one-line explanation). A clone Incident shows its origin as plain monospace text with a Copy button — never a link — and links the Build; its timeline lists each report's network (or "Unknown network"); Actors, Evidence and Blocks are hidden and the containment bar is replaced by "Containment does not apply to a clone. Take the copy down at its host." The Incidents list shows the origin under the title. With a null `ip_prefix` the containment bar offers no network block.
- **A3 — Harden as built.** Beacon and Canaries are planted together, in one step, into the first protected file whose budget holds both (never split). The client-side local check is one regular expression over the browser's host, pinned against the protocol's `isLocalOrigin` over ~12,000 origins with no mismatch. The statement is ≤ 600 bytes apart from the embedded origins (1,111 bytes raw / 488 gzip with 20 origins) — the plan's "≤ 600 bytes with 20 origins" was not achievable with the local check. `--endpoint` must be a plain http(s) URL (no credentials, query or fragment) when `--origin` is given. `--json` includes the token (it is public in the bundle). Origins keep the given order.
- **A4 — Enlarge the reference app (owner's decision 2026-11-11; Jev split 0.56/0.41).** The demo bundle was too small to hold Canaries plus the beacon within the 35% per-file budget, so D-043 failed the harden. A realistic-size module is added to `apps/range/web` (its own check still passes) so the reference app demonstrates both; the per-file budget and D-043 are unchanged.
- **A5 — API as built (Jev: reasons_and_negative_cache, 0.82).** `POST /v1/beacon` judges reports after answering 204 (no database work before the response); bodies over 1,024 bytes are dropped (drained up to 16 KiB, then `Connection: close`); the reporter's address comes from the socket only (X-Forwarded-For is not trusted) and is reduced to its prefix at once; hourly windows are fixed per Build; a second Build reporting the same origin joins the open Incident (which keeps the first Build's id); tokens resolve through a SECURITY DEFINER lookup and every write is scoped to the token's Organization; tracking is bounded (10,000 Builds, 1,000 per Organization, 1,000 in flight). Added: conflict reasons `beacon-token-taken` and `containment-not-applicable`, and a bounded negative cache for unknown tokens (cleared when that token is registered).
- **A6 — Review fixes (Jev: fix_all_as_proposed, 0.94).** F1 (MEDIUM) an anonymous flood of made-up tokens could make every tenant's genuine reports drop: per-reporter-prefix lookup cap and a global bucket for unknown-token lookups before the database, a positive token cache, and a per-Organization in-flight cap. F2 (MEDIUM) the owner's own site opened as `shop.example.` reported itself: one trailing dot is ignored when comparing origins, on the client and the server. F3 (MEDIUM) forgery scaled with the number of Builds: a cap of 20 new origins per App and Environment per hour on top of the per-Build cap. F4 (LOW) another Organization could register a victim's token first and capture its reports: the report carries the App id (`{a, t, o}`) and tokens are unique per App. F5 (LOW) a failed registration left a written bundle with an unregistered token: Harden registers before writing `--out`. F6 (LOW) `<` in a developer-supplied endpoint could break out of an inlined script: every embedded string escapes `<`, `>` and `&`, and such endpoints are refused.
- **A7 — Beacon guards kept (Jev: restore_guards, 0.94).** The statement checks `typeof location`, `typeof navigator` and `navigator.sendBeacon` before touching them, so outside a browser it returns without throwing; the size target is ≤ 700 bytes apart from the embedded origins. Allowed origins given with a trailing dot are embedded without it. Signature: `beaconStatement(appId, token, origins, endpoint)`.
- **A8 — API review fixes as built.** Reports are `{a, t, o}`; tokens are unique per App (migration 0011, lookup `beacon_lookup_token(app_id, token)`); before any lookup: unknown-token cache, known-token cache, global pending cap, 60 lookups per minute per reporter prefix, a global bucket of 50 lookups per second (burst 200); after it, 100 in flight per Organization; 20 new origins per App and Environment per hour across its Builds. Clone Incidents are stored and grouped by the origin without a trailing host dot (Jev: group_dotless, 1.0), so both spellings of one site are one Incident.
