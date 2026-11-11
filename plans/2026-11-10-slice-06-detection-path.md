---
title: "Plan — Slice 06 Detection path"
aliases: [Plan 06]
project: anti-reverse
doc: PLAN
slice: 6
version: 0.1.0
status: done
updated: 2026-11-10
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

# Slice 06 — Detection Path Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: a decision with real alternatives goes through Jev (report it if you cannot reach Jev; do not guess).

**Goal:** Events matching a managed rule become Detections, grouped into Incidents; a new Incident alerts the Organization's webhook and Slack channels; analysts triage Incidents in the Console.

**Architecture:** The protocol gains Detection, Incident and AlertChannel schemas and the managed rule table. In the API, a **Detector** subscribes to the existing in-process event bus (after commit), keeps bounded sliding windows in memory, and writes Detections and Incidents through tenant-scoped transactions. A **Notifier** delivers alerts asynchronously with retries, an SSRF guard and HMAC signatures. The Console adds an Incidents list, an Incident page and alert-channel settings. No new dependency anywhere.

**Spec:** [tickets/06-detection-path.md](../tickets/06-detection-path.md). Background: [SDD.md](../SDD.md) §5.3, §7 (webhook signature), §11; [SECURITY.md](../SECURITY.md) TP-05, TP-17, SC-TEL-*, SC-INF-04; [PERFORMANCE.md](../PERFORMANCE.md) PB-14, PB-18; [UIUX.md](../UIUX.md) §4.2 (severity tokens), §7 (SCR-04, SCR-05), §8, §10, §11. Earlier plans' constraints and amendments still bind.

## Global Constraints (additions)

- **Identifiers:** Incident `inc_<24 hex>`, Detection `dtc_<24 hex>`, alert channel `chn_<24 hex>`, delivery `dlv_<24 hex>`.
- **Managed rules (constants in the protocol):**

| Rule key | Title | Counts | Threshold | Window | Severity |
|---|---|---|---|---|---|
| `blocked-burst` | Blocked burst | Events with `decision.action = "block"` and `decision.mode = "enforce"` | 20 | 300 s | high |
| `failed-signin-burst` | Failed sign-in burst | Events with `request.status` 401 or 403 | 30 | 300 s | medium |

  Counting key: (Organization, App, Environment, rule, `actor.ip_prefix`). Events with `ip_prefix: null` are not counted.
- **Detector:** runs on the bus after commit; never on the ingest path; a detector error is logged (without data) and swallowed. Sliding window of timestamps per key; when the count reaches the threshold a Detection is recorded and **that key's window is cleared** (one Detection per threshold crossing). Bounded memory: at most 10,000 keys (evict the least recently updated) and at most `threshold` timestamps per key. The clock is injectable.
- **Grouping:** a Detection joins an Incident with the same (App, Environment, rule, `ip_prefix`) whose status is `open` or `acknowledged`; otherwise a new Incident opens with status `open`. A `resolved` Incident is never reopened. Only a *newly opened* Incident triggers alerts.
- **Incident status transitions:** `open → acknowledged`, `open → resolved`, `acknowledged → resolved`. Anything else is 409 `conflict`.
- **Evidence:** an Incident page shows up to 20 Events from its network prefix, App and Environment within its time span, newest first, as stored (the Event allowlist).
- **Alert channels:** kinds `webhook` and `slack`; name 1–80 characters; URL ≤ 2,048 characters; at most 10 channels per Organization. The full URL is stored but **never returned** (a Slack URL is itself a secret): responses show only `host` and the last 4 characters. A webhook channel gets a signing secret `whsec_<43 base64url>` shown once at creation, stored for signing, never returned again.
- **Delivery:** asynchronous in-process queue; at most 3 attempts with backoff 1,000 / 2,000 / 4,000 ms (injectable); request timeout 5,000 ms; redirects are **not** followed; response bodies are not read beyond 4 KB; every attempt is recorded (`delivered` for 2xx, else `failed`, with status code or null). A failing channel never blocks others.
- **Webhook payload:** `{ "type": "incident.opened", "incident": Incident, "console_url": "<AR_CONSOLE_URL>/incidents/<id>" }`, `content-type: application/json`, header `AR-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`.
- **Slack payload:** `{ "text": "<severity word> — <title> on <App name> (<environment>): <console_url>" }`.
- **SSRF guard (send time, every attempt):** URL must be `https:`; resolve the host with `dns.lookup(host, { all: true })`; refuse if **any** resolved address is loopback (127.0.0.0/8, ::1), unspecified, private (10/8, 172.16/12, 192.168/16, fc00::/7), link-local (169.254/16, fe80::/10, which covers 169.254.169.254 metadata), CGNAT 100.64/10, or IPv4-mapped forms of these; connect to the vetted address. `AR_ALLOW_PRIVATE_ALERT_URLS=1` (read by `startApi`, injectable as an option) allows `http:` and these addresses — for local development and tests only. The same checks run when a channel is created (fast feedback) **and** at send time (DNS rebinding).
- **Secrets:** the signing secret and channel URLs never appear in a log line, an error, a delivery record or a response after creation.
- **`AR_CONSOLE_URL`:** default `http://127.0.0.1:3000`, used only to build links in alerts.
- **Budgets:** PB-14 event → Detection ≤ 10 s; PB-18 Incident → alert delivered ≤ 60 s.

## Review Focus

1. **Detector correctness** — exactly one Detection per threshold crossing; counts never cross keys (Organization, App, Environment, rule, prefix); null prefixes ignored; events of another Organization never count toward this one. *(API)*
2. **Grouping** — repeated bursts from one prefix join one open Incident; after resolve, the next burst opens a new Incident and alerts again; acknowledged still groups and does not re-alert. *(API)*
3. **SSRF** — `http://127.0.0.1`, `https://10.0.0.5`, `https://169.254.169.254`, `https://[::1]`, `https://[::ffff:127.0.0.1]`, a hostname resolving to a private address, a redirect to a private address: all refused without the flag. *(API)*
4. **Secrets** — the signing secret is shown once and never again; a channel URL is never returned or logged; deliveries record no secret. *(API, Console)*
5. **Tenancy** — another Organization cannot list, read or change Incidents, or list, test or delete channels; a Shield key gets 403. *(API)*

## Contracts

### P1 — Protocol (`packages/protocol/src/incidents.ts`, isomorphic)

```ts
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
export const INCIDENT_STATUSES = ["open", "acknowledged", "resolved"] as const
export const ALERT_CHANNEL_KINDS = ["webhook", "slack"] as const
export const DETECTION_RULES = [
  { key: "blocked-burst", title: "Blocked burst", severity: "high", threshold: 20, window_s: 300 },
  { key: "failed-signin-burst", title: "Failed sign-in burst", severity: "medium", threshold: 30, window_s: 300 },
] as const
export const INCIDENT_LIMITS = { listed: 50, detectionsListed: 100, evidence: 20, channelsMax: 10, urlMax: 2048, nameMax: 80 } as const

DetectionSchema = { id, rule, app_id, environment, ip_prefix, count, window_start, window_end, detected_at }
IncidentSchema  = { id, app_id, environment, rule, severity, title, status, ip_prefix,
                    first_seen, last_seen, detection_count, created_at, updated_at }
ListIncidentsResponseSchema   = { incidents: Incident[] }                 // newest first by last_seen, ≤ 50
IncidentDetailResponseSchema  = { incident, detections: Detection[], evidence: StoredEvent[] }
UpdateIncidentRequestSchema   = { status: "acknowledged" | "resolved" }
AlertChannelSchema            = { id, kind, name, host, url_last4, active, created_at }
CreateAlertChannelRequestSchema  = { kind, name, url }
CreateAlertChannelResponseSchema = { channel, signing_secret?: string }   // webhook only, shown once
ListAlertChannelsResponseSchema  = { channels: AlertChannel[] }
AlertDeliverySchema           = { id, channel_id, incident_id: string|null, attempt, outcome: "delivered"|"failed", status_code: int|null, at }
TestAlertChannelResponseSchema   = { delivery: AlertDelivery }
WebhookAlertPayloadSchema     = { type: "incident.opened" | "test", incident: Incident|null, console_url: string|null }
export function signWebhookBody(secret: string, t: number, body: string): string   // server entry: hex HMAC-SHA256 of `${t}.${body}`
export function verifyWebhookSignature(secret, header, body, nowS, toleranceS = 300): boolean   // server entry, for receivers and tests
```

Server entry: `newId("inc" | "dtc" | "chn" | "dlv")`, `generateSigningSecret()` → `whsec_<43 base64url>`, `signWebhookBody`, `verifyWebhookSignature` (constant-time compare, tolerance).

### P2 — API

| Method and path | Key | Success | Notes |
|---|---|---|---|
| `GET /v1/incidents?app_id=&status=` | admin | 200 `ListIncidentsResponse` | Filters optional; 400 on a bad status |
| `GET /v1/incidents/:incidentId` | admin | 200 `IncidentDetailResponse` | 404 outside the Organization |
| `PATCH /v1/incidents/:incidentId` | admin | 200 `{ incident }` | Allowed transitions only, else 409 |
| `GET /v1/alert-channels` | admin | 200 `ListAlertChannelsResponse` | — |
| `POST /v1/alert-channels` | admin | 201 `CreateAlertChannelResponse` | SSRF check; 400 with `errors[].path = "url"` when refused; 409 over 10 channels |
| `DELETE /v1/alert-channels/:channelId` | admin | 204 | 404 outside the Organization |
| `POST /v1/alert-channels/:channelId/test` | admin | 200 `TestAlertChannelResponse` | Sends one `type: "test"` alert synchronously (one attempt), returns the delivery |

Migration `apps/api/migrations/0006_incidents.sql`: `detections`, `incidents`, `alert_channels` (url, signing_secret), `alert_deliveries`; each tenant-scoped with row-level security like every tenant table; grants follow the existing pattern (incidents need UPDATE for status/last_seen; detections and deliveries are append-only).

Modules: `src/detect/detector.ts` (`createDetector({ db, bus, notifier, now, logger, maxKeys })` → `{ start(): () => void }` — subscribes to all Events on the bus; the bus needs an "all events" subscription if it only supports per-App filters: add `subscribeAll` to the bus), `src/detect/rules.ts` (rule matching from `DETECTION_RULES`), `src/notify/notifier.ts` (`createNotifier({ db, now, fetch, resolve, allowPrivate, consoleUrl, backoffMs, logger })` → `{ incidentOpened(incident, orgId): void; test(channel, orgId): Promise<AlertDelivery>; drain(): Promise<void> }`), `src/notify/ssrf.ts` (`checkDestination(url, { resolve, allowPrivate })` → `{ ok: true; address } | { ok: false; reason }`), stores and routes. `startApi` wires Detector and Notifier and reads `AR_ALLOW_PRIVATE_ALERT_URLS` and `AR_CONSOLE_URL`; `StartApiOptions` gains `allowPrivateAlertUrls?`, `consoleUrl?`, `alertBackoffMs?`. `close()` drains the notifier queue (bounded wait) before closing the database.

### P3 — Console

- Shell navigation gains **Incidents** (top level) and **Alerts** (settings).
- `/incidents?status=` list: severity badge (shape + word + colour), title, App name, status, last-seen; filter by status (links); empty state.
- `/incidents/[incidentId]`: header with severity and title; status with actions **Acknowledge** (when open) and **Resolve** (when open or acknowledged; resolve asks for a one-step confirmation); facts (App, Environment, network prefix, first/last seen, Detection count); timeline of Detections; evidence table of Events (reuse the live-feed row component/format).
- `/settings/alerts`: channel list (kind, name, host…last4, created); add form (kind select, name, URL); on webhook creation show the signing secret once with `KeyReveal`; **Send test** per channel showing the delivery outcome; **Remove** with confirmation.
- Copy in the catalog; tokens only; severity never by colour alone.

## Tasks

Order: Task 1 → (Task 2 ‖ Task 3) → Task 4 → Task 5.

### Task 1: Protocol (P1)
Failing tests first: schemas, constants, id prefixes, `generateSigningSecret` format, `signWebhookBody` known-answer vector, `verifyWebhookSignature` (valid, wrong secret, tampered body, outside tolerance, malformed header, constant-time path), unknown keys stripped, entrypoint export lists. Then implement; protocol checks + whole-repo test run.

### Task 2: API (P2)
Failing tests first, covering Review Focus 1–5: detector counting and one-Detection-per-crossing (injected clock), window expiry, key isolation, null prefix, bounded keys; grouping and status transitions; incidents routes and tenancy; channel CRUD, URL never returned, secret once; SSRF table (inject `resolve`), redirect not followed; delivery retries with backoff (injected), attempt records, no secret in records or logs; signature verifies with the protocol's `verifyWebhookSignature`; a detector error never fails ingest; `close()` drains. Then a curl smoke test with a local receiver and the flag on.

### Task 3: Console (P3)
Failing tests first: API client calls, list/detail rendering, status actions (acknowledge, resolve with confirmation), alert channel form with secret shown once, test-send outcome, remove with confirmation, nav entries, copy pins. Then implement; console checks + `next build`.

### Task 4: End to end
HTTP: Org + App + Enforce Rule on `/api/admin/**`; webhook channel to a local receiver (flag on); 20 blocked requests through Shield → Incident open within 10 s → one alert received within 60 s whose signature verifies; a second burst joins the same Incident (no second alert); acknowledge; resolve; a third burst opens a new Incident and alerts again; another Organization sees nothing. Browser: the Incident appears in the Console list; open it, acknowledge, resolve.

### Task 5: Docs, memory, review
README, ticket proof, MEMORY.md, PRD slice table; `npm run verify`, `npm run e2e`, `npm run bench`; independent review; fixes test-first; Jev-verify completion claims.

## Deliberately not in this slice

Email and PagerDuty; custom rules and editable thresholds; Playbooks and automatic containment; Canary/Clone Beacon detections; anomaly baselines; AI summaries; SIEM export; stream-processor detector.

## Amendments

- **A1 — several `v1` signatures (Jev: accept_multiple_v1, confidence 0.7).** `verifyWebhookSignature` accepts one to eight `v1` values and passes when any matches, so a later zero-downtime secret rotation does not break receivers built today. A duplicate `t`, a malformed `v1` or a ninth `v1` rejects the header; every candidate is compared in constant time without early exit. The sender still sends one `v1`. Proven by `packages/protocol/test/webhooks.test.ts` ("several v1 values (secret rotation)"); protocol 333 tests green.
- **A2 — Incidents list order (Jev: newest_first_fix_uiux, 0.74).** Newest first by last seen, as the ticket says; UIUX SCR-04 amended to match (it said severity-sorted). Re-sorting a capped page would hide newer Incidents.
- **A3 — Console defaults (Jev: accept_all, 0.83).** After a refused URL the field is left empty (never echo a URL); the Console accepts `http:` and the API decides (dev flag); removing an already-removed channel counts as removed; status tag outline solid/dashed/dotted plus the word; confirmations post the object's id.
- **A4 — Detection window clock (Jev: arrival_time, 0.57; confirmed by the owner on 2026-11-11).** The window runs on the server's arrival clock, so a client clock cannot hide a burst; the Detection records min/max Event `ts` for display. Confirmed by the owner.
- **A5 — Concurrent first crossing (Jev: retry_join, 1.0).** On a unique violation (23505) the detector retries its transaction once, so the Detection joins the Incident that won the race; no second alert.
- **A6 — API defaults (Jev: accept_all, 0.93).** Backoff base doubles with at most 3 attempts (waits 1 s, 2 s — the 4 s step in this plan never applies); delivery records have no foreign key and survive channel removal; SSRF block list wider than listed (0/8, multicast, 240/4, fec0::/10, ff00::/8, 64:ff9b::/96, IPv4-compatible) and unresolvable hosts refused at creation; an Event can count toward both rules; notifier queue cap 1,000, drain ≤10 s; a failed test send is a 200 carrying a failed delivery; malformed `app_id` → 400, PATCH to the same status → 409; detector also exposes `flush()` and `trackedKeys()`; connections pinned to the vetted address; Slack text `High — Blocked burst on <App> (env): <url>` with `& < >` escaped.
- **A7 — Shield blocks are not failed sign-ins (Jev: exclude_shield_blocks, 1.0).** The e2e showed one blocked attack of 40 requests opening two Incidents, because Shield answers its own enforced blocks with 403. `failed-signin-burst` now counts 401/403 responses that are not an enforced block (a Monitor-mode block still counts — Shield did not answer it). Supersedes the "an Event can count toward both rules" part of A6.
- **A8 — Review fixes (Jev: fix_all_now, 0.98).** F1 per-Organization detector window bound (1,000) under the global cap, eviction from the Organization holding the most windows; F2 per-Organization alert queue cap (100), global safety cap 10,000; F3 the attempt timeout covers the DNS lookup, and channel creation bounds its lookup (5 s); F4 SSRF also refuses embedded IPv4 in ::ffff:0:0/96, 2002::/16, 64:ff9b:1::/48 and the special-purpose ranges 100::/64, 2001:db8::/32, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24; F5 evidence filtered by the rule's own condition (defined once in rules.ts).
- **A9 — e2e Console build folder (Jev: dist_dir_env, 1.0).** `next.config.ts` reads `AR_NEXT_DIST_DIR`; the browser e2e builds its Console into `.next/e2e`, so it runs the current code while a developer's dev server runs. `tsconfig.json` lists the `.next/e2e` type folders so Next does not rewrite it.
