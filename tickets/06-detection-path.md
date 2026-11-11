---
title: "Ticket 06 — Detection path"
aliases: [Ticket 06]
project: anti-reverse
doc: TICKET
slice: 6
version: 0.1.0
status: done
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# 06: Detection path

**What to build:** Events that match a managed detection rule become Detections; related Detections are grouped into an Incident; a new Incident raises an alert to the Organization's alert channels (signed webhook or Slack). An analyst sees Incidents in the Console, opens one to read its timeline and evidence, and acknowledges or resolves it.

**Blocked by:** 01 (done). Uses the Decisions of 02 (done) as detection input.

**Status:** done on 2026-11-10 — plan in [plans/2026-11-10-slice-06-detection-path.md](../plans/2026-11-10-slice-06-detection-path.md)

## Acceptance criteria

Detection

- [x] Two managed rules run on every App: **Blocked burst** (at least 20 enforced blocks from one network prefix within 5 minutes → High) and **Failed sign-in burst** (at least 30 responses with status 401 or 403 from one network prefix within 5 minutes → Medium; Shield's own enforced blocks do not count — plan amendment A7). Thresholds are constants in this slice.
- [x] A Detection is recorded within 10 s of the Event that completes it (PB-14), with the rule, the App, the Environment, the actor network prefix, the count and the window.
- [x] Detections of the same rule, App and network prefix while an Incident for them is open join that Incident instead of opening a new one; a resolved Incident is never reopened — a new one starts.
- [x] The detector runs after the Events are committed, never on the ingest request path; ingest latency is unchanged, and a detector failure never fails ingest.

Incidents

- [x] An Incident has a severity, a title, a status (`open`, `acknowledged`, `resolved`), first-seen and last-seen times, its Detections as a timeline, and a sample of the Events behind them (route, Decision, status, time — never more than the Event allowlist already holds).
- [x] The Console lists Incidents newest first with severity (word + shape, never colour alone), title, App, status and last-seen; an Incident page shows the timeline and evidence and lets an admin acknowledge or resolve it.
- [x] Incidents belong to an Organization: another Organization can neither list, read nor change them.

Alerts

- [x] An Organization can add, list, test and remove alert channels of two kinds: **webhook** (a URL; a signing secret shown once at creation) and **Slack** (an incoming-webhook URL).
- [x] When an Incident opens, every active channel of its Organization receives one alert within 60 s (PB-18). Webhook alerts carry `AR-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "t.body">`; Slack alerts carry a readable message with severity, title, App and a link to the Incident.
- [x] Delivery is asynchronous with retries (up to 3 attempts with backoff); a failing channel never blocks detection or other channels; each attempt is recorded with its status code, never with the secret.
- [x] Alert destinations are protected against server-side request forgery: `https` only, and the resolved address must not be loopback, private, link-local or a cloud metadata address — checked at send time, not only at save time. A flag `AR_ALLOW_PRIVATE_ALERT_URLS=1` allows `http` and loopback for local development and tests only.
- [x] Alert bodies contain no key, no signing secret and no data outside the Event allowlist.

Quality

- [x] The Incidents list, Incident page and alert-channel settings use the tokens, vocabulary and states of UIUX.md.
- [x] `npm run verify` passes; an end-to-end test drives a burst of blocked requests through Shield, sees the Incident open in the Console, and receives a correctly signed webhook alert.

## Decisions taken with Jev

- Detector on the in-process event bus after commit, behind an interface (0.98).
- Webhook and Slack now; email waits for the owner to choose a provider (0.72).
- Server-side request forgery protection with a local-development flag (1.0).
- Receivers accept several `v1` signatures (0.7); Incidents listed newest first (0.74); window on the server's arrival clock (0.57; confirmed by the owner on 2026-11-11); retry once on a concurrent first crossing (1.0); Shield blocks are not failed sign-ins (1.0); fix all review findings now (0.98). Full list: plan amendments A1–A9.

## Proof

| Criteria | Proven by |
|---|---|
| Rules, Detection ≤10 s, grouping, never reopen, detector off the ingest path | `apps/api/test/detector.test.ts`, `incidents.test.ts`, `detection-server.test.ts`; `tests/e2e/detection.http.test.ts` (real requests through Shield: Incident ~0.2 s after the burst) |
| Incidents, Console list and page, tenancy | `incidents.test.ts`, `incidents-db.test.ts` (RLS and grants); `apps/console/test/incidents-*.test.*`; `detection.http.test.ts` tenancy case; `tests/e2e/detection.e2e.ts` (acknowledge, resolve with confirmation) |
| Alert channels, signed webhook, Slack, retries, delivery records | `alert-channels.test.ts`, `notifier.test.ts`; `packages/protocol/test/webhooks.test.ts`; `detection.http.test.ts` and `detection.e2e.ts` (signature verified with the secret the Console showed once) |
| SSRF protection | `apps/api/test/ssrf.test.ts` (96 cases), checked before every attempt with the connection pinned; review checked TLS against the host name |
| No key, secret or out-of-allowlist data in alerts | `notifier.test.ts` log and delivery checks; `detection.http.test.ts` body-key and leak assertions |
| Quality | `npm run verify` — 2,081 tests, type-check, lint · `npm run e2e` — 6 journeys · `npm run bench` — worst p99 6.17 µs |

An independent review reproduced F1 (one Organization could evict another's detector windows), F2 (one Organization's stuck channels could drop others' alerts), F3 (the DNS lookup was outside the attempt timeout), F4 (SSRF block-list gaps) and F5 (evidence not matching the rule) — all MEDIUM or LOW, all fixed test-first. The end-to-end test found one blocked attack raising two Incidents; fixed (A7). Completion claims Jev-verified (`jev_verify`): the specific claims verified at 0.91–1.0; the two compound claims (repository green, findings fixed) came back for review and were confirmed directly from the command output.

## Open for the owner

- **Email alerts** need a delivery provider (an account and credentials). Which provider, if any, is the owner's choice; until then email is not offered.

## Out of scope — later slices

Custom detection rules · editable thresholds · Playbooks and automatic containment (09) · Canary and Clone Beacon detections (07, 10) · PagerDuty and email · anomaly baselines · AI triage summaries · SIEM export · moving the detector to stream processors.
