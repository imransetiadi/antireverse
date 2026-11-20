---
title: "Ticket 18g — Synthetic probes for enforcement propagation and event freshness"
aliases: [Ticket 18g]
project: anti-reverse
doc: TICKET
slice: 18
version: 0.1.0
status: done
updated: 2026-11-20
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PERFORMANCE]]"
  - "[[OPERATION]]"
  - "[[QASUITE]]"
---

# 18g: Synthetic probes

**What to build:** Once a minute the API runs the two probes of OPERATION §7 against itself, over the path a customer's data takes: it publishes a marked block and times its enforcement by a real Shield (PB-15, SLO-06), and it times how long the marked Event of the blocked request takes to become readable (PB-13, SLO-04). The results go into the SLO buckets of slice 18d, so attainment, error budget, burn alerts, `/v1/ops/slo`, `/metrics` and the operator dashboard show them like every other SLO. Off by default.

**Out of scope:** per-region probes, probes from outside the API process, automatic rollback after a deploy (there is no deploy pipeline here), and SLO-08 (see below).

**Blocked by:** nothing. Chosen as the next slice by Jev at 0.82, confidence 0.79 (D-115).

**Status:** done on 2026-11-20. One independent review (no HIGH, 2 MEDIUM, 4 LOW), all fixed: see Review. The fixes are not independently reviewed. Plan: [plans/2026-11-20-slice-18g-synthetic-probes.md](../plans/2026-11-20-slice-18g-synthetic-probes.md).

## The slice title and SLO-08

The slice was handed over as "probes for SLO-06 and SLO-08". The specification says otherwise:

- OPERATION §7 names two probes: "emit a marked event and time its appearance; publish a marked block and time its enforcement". OPERATION §5 calls them "synthetic probes for PB-13 and PB-15".
- PB-13 belongs to **SLO-04** (Event freshness) and PB-15 to **SLO-06** (Enforcement propagation).
- **SLO-08** is "Console page loads meeting PB-19", and PB-19 is Core Web Vitals (LCP, INP, CLS). A server-side probe cannot measure any of the three; that needs a browser.

So this slice measures SLO-06 and adds end-to-end samples to SLO-04. SLO-08 stays "not measured", with a sharper reason. Whether to build browser measurement for SLO-08 (a real-user beacon or a headless run) is an open scope question for the owner.

## Design

```
            ┌────────────────────────── API process ──────────────────────────┐
            │  prober (timer, one cycle at a time)                            │
            │    │ 1. PUT /v1/apps/:app/policies/production   (admin key)     │
            │    │      one enforced block Rule on /airverse-probe/<nonce>    │
            │    ▼                                                            │
  HTTP on   │  API routes ── signed bundle ──► probe Shield (shield-node)     │
  the API's │                 GET /v1/policy-bundle, polled every 5 s         │
  own       │    │ 2. GET /airverse-probe/<nonce> on the probe's loopback     │
  listening │    │      server, behind that Shield ──► 403   = enforcement    │
  socket    │    │ 3. Shield emits the Event (route = the Rule's path)        │
            │    │      POST /v1/events (Shield key, 1 s flush)               │
            │    ▼ 4. GET /v1/apps/:app/events (admin key) until the route    │
            │         appears                                = freshness      │
            └─────────────────────────────────────────────────────────────────┘
```

Everything between the prober and the API goes over HTTP to the API's listening address with real keys: authentication, validation, the audit entry of the publish, bundle signing, signature verification in Shield, the Shield's own poller and emitter, ingest, storage and the read route the Console uses. Nothing is read from or written to the database in place of a request, and the probe never calls `refreshPolicy()` or `flush()` on its Shield: it waits for the SDK's own timers, as a customer's Shield does.

## Decisions

Every decision went through Jev (`jev_decide`, model jev-1.14.0, 2026-11-20). "Contradicted" lists the requirements Jev judged the chosen candidate to miss.

| # | Decision | Chosen | Jev | Contradicted |
|---|---|---|---|---|
| 1 | Where the prober runs | In the API process on a timer, with a real Shield and a loopback server, talking to the API over HTTP only | 0.66, confidence 0.60 | "Can record a failure while the API process itself is down" — true, and accepted: see Honest limits |
| 2 | Which SLO each leg feeds | Block leg → SLO-06; Event leg → SLO-04 as extra end-to-end samples; SLO-08 stays not measured and the conflict goes to the owner | 0.95, confidence 0.94 | none |
| 3 | The marked block and the marked Event | Each cycle publishes, in the probe's own App, one enforced block Rule on the literal path `/airverse-probe/<fresh nonce>`. The blocked request's Event carries that path as its route (Shield records the Rule's pattern), so it is recognised without any change to the Event schema | 1.00, confidence 1.00 | none |
| 4 | The probe's Organization and keys | One system Organization registered in the owner-only table `system_organizations` (migration 0043). Found or created at the first cycle; at every start its old keys are revoked and fresh admin and Shield keys are made, whose plaintext lives in memory only | 0.92, confidence 0.91 | none ("no pile-up across restarts" judged unknown; a test proves it) |
| 5 | What a failed probe is, and alerting | SLO-06: good when the 403 arrives within 30 s; bad when later, at the 60 s timeout, or when the publish fails. SLO-04: good within 5 s, bad later or at the 30 s timeout; **not counted** when the block leg failed (there is no marked Event then). Alerts through the existing burn rules only; every failure is a warning in the log and shows in a probe status on the operator report | 0.97, confidence 0.96 | none |
| 6 | Switch and interval | `AR_PROBES=1` turns the prober on; unset, empty or `0` is off; anything else stops the start, naming the variable. The interval is one minute; only tests change it, through `startApi` options | 0.98, confidence 0.98 | none |
| 7 | Growth of the probe's own data | The probe Organization keeps Events 7 days (the retention job of 18c removes them). Policy versions and audit entries stay append-only and their growth is documented | 0.75, confidence 0.71 | "Cannot delete or alter a real tenant's rows" — **disagreed**: the only write is `event_retention_days = 7` on the registered probe Organization's own row, inside that Organization's tenant transaction, and the sweep is the existing per-Organization job |

Not sent to Jev: keys, tokens, identifiers or any tenant data.

Chosen without Jev, as there was no real alternative:

- Enforcement is watched with `shield.decide()` (the Shield's public decision over the bundle it has applied) every 100 ms, and confirmed with one real HTTP request through the Shield's middleware. The time is taken at the 403 of that request. Polling with real requests instead would write some 50 Events a cycle into the probe Organization for no better measurement.
- The clock of every latency is monotonic (`performance.now()`), injected in tests.
- A cycle that is cut by shutdown records nothing: stopping is not a failure.

## Acceptance criteria

Probe runner

- [x] **One cycle** publishes the marked block through the admin route, times its enforcement at the probe's Shield, then times the marked Event's appearance through the Events route, on a monotonic clock.
- [x] **SLO-06** gets one sample per cycle: good within 30 s; bad when later, on the 60 s timeout or when the publish fails.
- [x] **SLO-04** gets one sample per cycle whose block was enforced: good within 5 s; bad when later or on the 30 s timeout. Not counted, and logged as skipped, when the block leg failed.
- [x] **Failures are never swallowed:** each is a warning in the log (leg, outcome, a reason code or milliseconds, the class of an error and never its text; no key) and shows in the probe status.
- [x] **No overlap:** the next cycle is scheduled only when the one before has ended.
- [x] **Clean stop:** `close()` stops the timer, cuts the cycle in flight without recording it, closes the Shield and the loopback server, and the API then closes as before.

Isolation

- [x] The probe uses a **registered system Organization** of its own; restarting does not create another one, and old keys stop working.
- [x] **No tenant sees probe data:** another Organization's Events, usage, Policy and bundle are unchanged by probe cycles; the marked Rule is in the probe App's bundle only.
- [x] **No key** of the probe is written to the log or to a file. The probe's own log lines name no Organization; the API's request log names the Organization of every request, the probe's like a tenant's.

Reporting

- [x] `GET /v1/ops/slo` reports SLO-06 as measured while probes are on (attainment, budget, burn, p95 against 30 s and p99 against 60 s, alerts) and as not measured, with the reason, while they are off. It carries a `probes` status: `null` when off; otherwise interval, runs, failures, consecutive failures, the last run's time and both legs' outcome and latency.
- [x] `GET /metrics` includes SLO-06 while probes are on.
- [x] **Operator dashboard:** a "Synthetic probes" section above the SLO panels shows that status, or that probes are off and how to turn them on. Its text says what the number is: measured inside this API instance against one local Shield, not per region and not on customers' Shields.
- [x] **Burn alerts** for SLO-06 fire through the existing rules, naming RB-04.

Configuration

- [x] `AR_PROBES=1` turns the prober on; off by default; an invalid value stops the start naming the variable and not the value.

Quality

- [x] The api, console, protocol, gate and e2e Vitest projects pass; `npx tsc -b` and `npx biome check` on the changed files pass.
- [x] The release gate's performance criterion stays not checkable, with a reason that names PB-13 and PB-15 precisely.

## As built

| Part | Where |
|---|---|
| Catalog: `probe` per SLO; SLO-06 with PB-15's bounds (good within 30 s, p95 30 s, p99 60 s); `PROBES_VARIABLE`, `PROBE_PATH_PREFIX`, `PROBE_BOUNDS`; `ProbeLegSchema`, `ProbeStatusSchema`; `SloReportSchema.probes` | `packages/protocol/src/slo.ts` |
| The switch `AR_PROBES` | `apps/api/src/probe/settings.ts` |
| The registry `system_organizations` (owner only, no key) | `apps/api/migrations/0043_probes.sql`, `apps/api/src/stores/system-organizations.ts` |
| The probe's Organization, App and keys | `apps/api/src/probe/tenant.ts` |
| The cycle, its samples, status, schedule and stop | `apps/api/src/probe/runner.ts` |
| The real transport: `fetch` to the API, a Shield of `@antireverse/shield-node`, a loopback server behind its middleware | `apps/api/src/probe/transport.ts` (the API now depends on `@antireverse/shield-node`) |
| SLO-06 measured, alerted on and in `/metrics` while a prober is attached; `probes` in the report | `apps/api/src/slo/service.ts` |
| `StartApiOptions.probes`, `RunningApi.probes`; started after the jobs, stopped first on close | `apps/api/src/server.ts`, `main.ts`, `index.ts` |
| "Synthetic probes" section on `/ops` | `apps/console/src/features/ops/probe-status.tsx`, `app/ops/page.tsx`, `lib/messages/en.ts`; the stand-in API answers `probes: null` (`scripts/stub-ops.mjs`) |
| Release gate: the performance criterion's gap names PB-13 and PB-15 as timed in process only; no check added | `tools/gate/src/catalog.ts` |
| Docs | `README.md` (Operator SLO dashboard → Synthetic probes; Configuration), `PRD.md` row 18 |

Details that differ from the first design:

- **A probe that is given up is recorded just past its bound** (60,001 ms, 30,001 ms), not at it. The histogram's buckets are inclusive, so a sample at exactly 60 s would show the p99 target of 60 s as met by a probe that never saw the block.
- **A failed set-up is not an SLI sample, up to three times in a row.** If the probe's Organization, Shield or loopback server cannot be made, nothing of the path was exercised: the run counts as failed in the status and the log, and the next cycle sets up again. From the fourth failure in a row each cycle is a bad SLO-06 sample (D-117, see Review). A refused publish is a bad SLO-06 sample.
- **A start is never failed by the probe.** Set-up happens in the first cycle, 5 s after the start.
- **OPERATION.md is unchanged.** It describes the target (per region, automatic rollback); this ticket's Honest limits say what is built.

## Proof

| Criterion | Proven by | Seen failing, then passing |
|---|---|---|
| Catalog, bounds, status schema | `packages/protocol/test/slo.test.ts` | 4 failed (no `probe`, no `probes`) → 11 passed |
| One cycle; SLO-06 and SLO-04 samples; bounds at 30 s, 60 s, 5 s, 30 s; skipped leg not counted; failures logged; set-up failure | `apps/api/test/probe-runner.test.ts` (scripted transport, manual clock, no sleeps) | written before the code but first run after it (14 passed); then checked by mutation: taking any answer for a 403, recording after a stop and allowing overlap fail 4 tests. The "just past the bound" change: 3 failed → 14 passed |
| No overlap; clean stop | `probe-runner.test.ts` ("the probe schedule"), `probe-server.test.ts` ("closes while a cycle is in flight") | as above; the server test failed (`api.probes` undefined) → passed |
| System Organization: one, registered, restart-safe, old keys revoked, registry closed to the request role | `apps/api/test/probe-tenant.test.ts`, `probe-server.test.ts` ("keeps one probe Organization across restarts") | module missing → 4 passed; server test failed → passed. A fifth test (a tenant's keys survive the probe's key rotation) was added with the explicit `organization_id` predicate of the revocation: it also passes by row-level security alone, so it was never seen failing |
| The real path and isolation: a real cycle over HTTP with a real Shield; rows only in the probe Organization; a tenant's Events, usage and bundle untouched; a tenant's own Rule on the probe's prefix changes nothing; no key in the log | `apps/api/test/probe-server.test.ts` | 5 failed before the server was wired → 5 passed (run 3 times) |
| Report, metrics, burn alert naming RB-04, off without a prober | `apps/api/test/probe-slo.test.ts`, `probe-server.test.ts` | written after `attachProbes` existed: **not test-first** |
| `AR_PROBES` | `apps/api/test/probe-settings.test.ts`, `probe-server.test.ts` ("refuses to start") | module missing → passed; the server test failed (start succeeded) → passed |
| Dashboard | `apps/console/test/ops-probes.test.tsx`, `stub-ops.test.ts` | import missing, and the stub refused by the schema (no `probes`) → 8 and 5 passed |
| Gate | `tools/gate/test/catalog.test.ts` | 1 failed (reason did not name PB-13 and PB-15) → 10 passed |

Final run after the review fixes (2026-11-20): protocol 2,101 tests in 43 files · api 2,170 in 131 · console 1,829 in 92 · gate 116 in 11 · e2e 253 in 29, all passing; `npx tsc -b` clean; `npx biome check` clean on the changed files. Not run by the worker: the release gate and Playwright. The dashboard section was not looked at in a browser.

**Jev gate** (`jev_gate`, 2026-11-20, on the source of the runner, the transport, the tenant and the server wiring, with the probe tests' output): all 8 completion claims **verified**, none contradicted; 3 stand on their own (no overlap 0.95, clean stop 0.94, monotonic clock 0.99) and 5 are below its 0.8 confidence line. Its patch review **escalated**: safe to apply 0.36, composite 0.66, limited by "correctness" of the runner at confidence 0.02 and by the test gap — the tests were given as output, not as code. So this slice needs the independent review of Rule 2 before it counts as reviewed.

## Review

One independent review on 2026-11-20, reproducing what it reported: no HIGH; tenant isolation held. All findings fixed test-first, tests in `apps/api/test/probe-review-*.test.ts`.

| # | Finding | Fix |
|---|---|---|
| F1 MEDIUM | The probe's Organization was provisioned again at every set-up attempt: a transport that could not be opened made a new pair of keys each minute (20 key rows after 10 cycles, 2,880 a day), while SLO-06 showed "measured", total 0, alerts ok | Provisioned once per process, only the transport is opened again (`probe/connect.ts`). At provisioning the rows of the Organization's earlier keys are deleted, as the owner and for the registered Organization only; nothing refers to a key row (audit entries and Policy versions keep the id as text), so the table holds the current pair and nothing else |
| D-117 (Jev 0.99, confidence 0.99; decided by the coordinator) | A prober that cannot be set up was invisible to the burn rules | Up to three failed set-ups in a row record nothing; each further one is a bad SLO-06 sample at the give-up bound. The log (`reason=setup setup_failures=N counted=bad`) and the status (`setup_failures`) name the cause; the indicator of SLO-06 and the Console say so |
| F2 MEDIUM, D-116 (Jev 0.92, confidence 0.90; decided by the coordinator) | The probe's own requests filled SLO-02, -03, -05, -07 and a second, in-process SLO-04 sample | A request with a key of a system Organization feeds no request SLI; its Events feed no in-process SLO-04 sample. The set of system Organizations is held in memory (loaded at start, extended at provisioning before the first request): no database read per request. **The Detector does not look at a system Organization's Events** — chosen over "detect but never alert": no Detection, Incident or alert exists for it, and SLO-05 gets nothing from it. The probe no longer fetches `GET /v1/signing-key` (a keyless request cannot be told apart from a tenant's): the key is handed over as configuration |
| F3 LOW | An SLO-06 alert firing when probes were switched off stayed in `slo_alerts` for ever and came back as "firing" with empty windows | Without a prober, the firing rules of a probe-fed SLO are resolved at the next evaluation with the normal transition (stored, logged, sent). With one, a rule whose long window holds no sample is resolved. **Scoped to probe-fed SLOs** (Jev 0.99, confidence 0.99, none contradicted): traffic-fed SLOs keep D-094, where an empty window is no evidence |
| F4 LOW | A cycle cut during the Event leg had already recorded its SLO-06 sample | Both samples are recorded together when the cycle has ended |
| F5 LOW | A logger or clock that threw after the cycle rejected the run and lost it from the status | The status is updated first by plain assignments; the clock, each sample and each log line are contained one by one; the timer path has a catch |
| F6 LOW | Growth understated (1 MB a day; measured about 3 MB a day, 1.1 GB a year) | Figure corrected here and in the README. Jev (0.90, confidence 0.88, none contradicted): document and keep rotation of the probe Organization as a follow-up; no rotation in this slice |

Also asked: `@antireverse/shield-node` lists `@antireverse/protocol` as a devDependency only. That is right and was left: every import of the protocol in Shield is `import type` (erased; Shield has no run-time dependency by contract C3), so the API consuming Shield at run time needs nothing more.

Test-first exceptions of the review fixes:

- `createProbeConnect` (F1) was written before its unit test first ran (the file had to exist for the other tests of that file to be seen failing); the server test of F1 was seen failing.
- The timer-path test of F5 passed before the fix: a sink that throws inside the cycle was already contained. The two other F5 tests were seen failing (`promise rejected "Error: logger down"`, `"Error: no clock"`).
- The server test of F1 and D-117 first failed because the test-only option `probes.open` did not exist, not by reproducing the 20 key rows; the restart test failed on the rows (6 instead of 2).

**Jev on the fixes** (`jev_verify`, six claims with the review tests' assertions as evidence): 5 verified (cut cycle 0.99, set-up rule 0.98, key rows 0.98, the 40 cycles 0.95, stale alerts 0.65 and below its confidence line), none contradicted, 1 judged unsupported ("a tenant's requests and Events are still counted") — disagreed: the same test asserts the tenant's totals (SLO-02 1, SLO-03 1, SLO-04 42, SLO-07 2). The fixes are not independently reviewed.

Limits of the fixes:

- A system Organization's Events are invisible to the Detector whoever sends them. Only the probe holds its keys, and they exist in memory only.
- `setup_failures` and the three-cycle grace are per process: a restart starts them at zero.
- An SLO-06 alert is resolved at the first evaluation after a start without probes: up to a minute after the start.

## Honest limits

- **One instance, one process, one Shield.** The probe runs inside the API it measures, against a Shield in the same process over the loopback interface. It is not a per-region measurement, it does not show that *every* Shield enforced the block (PB-15's wording), and it includes no network between a customer's Shield and the cloud.
- **When the API is down, nothing is recorded.** An in-process prober stops with the API. Outages of the whole API show in SLO-01, -02, -03 and -07 only after it is back, and not at all in SLO-04 or SLO-06 (Jev's contradicted requirement of decision 1). An outside prober needs an authenticated route to submit samples; not built.
- **Propagation is poll-bound.** Shield polls every 5 s (plus up to 25 % jitter); there is no push channel in this product, so the measured enforcement latency is mostly the wait for the next poll.
- **A rule, not a Containment.** The marked block is a Policy Rule. A Containment (the "manual action" of PB-15) can only be created from an Incident; it travels in the same signed bundle over the same poll, but its creation route is not exercised by the probe.
- **SLO-04 mixes two kinds of sample.** The in-process feed judges every Event from receipt to the live bus; the probe adds one sample a minute from the blocked request to readable through the API (Shield's 1 s flush included). Under traffic the probe sample is a small share of the total, so a failing probe moves SLO-04 slowly; the probe status shows it at once.
- **Slow to page.** With a 95 % objective and one sample a minute, a total enforcement outage pages after about 43 failed minutes (fast rule) — that is the burn arithmetic of OPERATION §7. The probe status and the log show the first failure.
- **SLO-08 is still not measured.** It needs Core Web Vitals from a browser.
- **The probe Organization grows.** While probes are on it gains about 1,440 Policy versions, 1,440 audit entries and 1,440 Events a day. Events go after 7 days; versions and audit entries are never pruned: about 3 MB a day, 1.1 GB a year (measured by the reviewer: about 1.5 KB per audit entry and 0.6 KB per Policy version). Rotating the probe Organization is a follow-up (Review, F6).
- **Key rotation at start is not audited.** The probe Organization's creation and its App's are audit entries by the system actor; the fresh keys of each start, and the removal of the rows of the keys before them, are not (there is no audit action for a key alone).
- **The probe's own traffic is counted nowhere else.** Its publish, bundle fetches, ingest and reads feed no request SLI, its Events no in-process SLO-04 sample, and the Detector does not look at them (D-116). The cost: a fault that only the probe's requests would have met (say, a slow bundle route on an instance with no tenant traffic) shows in SLO-06 or SLO-04 only, not in SLO-03.
- **The Shield's public key is handed to the probe directly**, as a customer configures it once; `GET /v1/signing-key` is not part of what the probe exercises.
- **Up to three minutes of a probe that cannot be set up record nothing** (D-117); the status and the log show the first.
- **Counters of the probe status** (runs, failures) are per process: a restart starts them at zero. The SLO buckets persist.
