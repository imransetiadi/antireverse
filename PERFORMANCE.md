---
title: "Anti Reverse — Performance"
aliases: [PERFORMANCE]
project: anti-reverse
doc: PERFORMANCE
version: 0.1.0
status: approved
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - spec/performance
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[OPERATION]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"
  - "[[MEMORY]]"
---

# Anti Reverse — Performance

**This document is the single source of truth for every performance number.** Other documents quote these budgets; if a figure differs elsewhere, this one wins. All targets are design targets set before the first measurement and are re-baselined after the first load test (§14).

---

## 1. Principles

1. **A protection that slows the product is a defect.** Budgets are release gates, not aspirations.
2. **Measure where the customer feels it** — inside their request path, on their users' devices, in their CI — not only in our cloud.
3. **Nothing of ours on the hot path.** Shield decides locally; everything else is asynchronous.
4. **Pay for protection only where it is needed.** Profiles and protection maps keep heavy transforms off hot code.
5. **Degrade in a fixed order** (§13). Enforcement and security-critical events are shed last.
6. **Percentiles, not averages.** Every latency target names its percentile.

## 2. Budget summary

| ID | Budget | Target |
|---|---|---|
| PB-01 | Shield added latency, attested and signed route | p50 ≤ 0.5 ms · p99 ≤ 1.5 ms |
| PB-02 | Shield added latency, route without attestation | p50 ≤ 0.1 ms · p99 ≤ 0.5 ms |
| PB-03 | Shield added latency with shared counters (Redis, same zone) | p99 ≤ 4 ms |
| PB-04 | Shield footprint | ≤ 40 MB resident memory · ≤ 3 % of one core per 1,000 requests/s |
| PB-05 | Guard (web) transfer size | ≤ 35 KB gzip in MVP; ≤ 60 KB with the WASM core, lazy-loaded |
| PB-06 | Guard main-thread cost | ≤ 50 ms total on a mid-tier phone profile; no single task > 25 ms; zero render blocking |
| PB-07 | Guard effect on Core Web Vitals | LCP change ≤ 50 ms · INP change ≤ 10 ms · CLS change 0 (all p75) |
| PB-08 | Attestation round trip seen by the client | p95 ≤ 250 ms; never blocks the first request |
| PB-09 | Request signing cost on the client | ≤ 3 ms at p75 for bodies up to 100 KB |
| PB-10 | Harden runtime overhead | `light` ≤ 5 % · `balanced` ≤ 15 % · `maximum` ≤ 50 % on protected code only |
| PB-11 | Harden size overhead (gzip) | `light` ≤ 10 % · `balanced` ≤ 35 % · `maximum` ≤ 80 % on protected modules |
| PB-12 | Harden build time | ≤ 45 s per 5 MB of input JavaScript on a 4-vCPU runner (`balanced`) |
| PB-13 | Event to visible in Console | p95 ≤ 5 s · p99 ≤ 30 s |
| PB-14 | Event to Detection | p95 ≤ 10 s |
| PB-15 | Detection or manual action to enforcement on every Shield | p95 ≤ 30 s · p99 ≤ 60 s |
| PB-16 | Policy publish to applied | p95 ≤ 15 s |
| PB-17 | Canary use to Incident | p95 ≤ 60 s |
| PB-18 | Alert delivery after Incident creation | p95 ≤ 60 s |
| PB-19 | Console Core Web Vitals | LCP ≤ 2.0 s · INP ≤ 200 ms · CLS ≤ 0.1 (p75) |
| PB-20 | Console queries | 24-hour window p95 ≤ 1.5 s · 30-day window p95 ≤ 4 s · search over 7 days p95 ≤ 3 s |
| PB-21 | Control API | Reads p95 ≤ 200 ms · writes p95 ≤ 500 ms |
| PB-22 | Reverse Assessment, tier T1 | Result ≤ 30 min p95 after upload; queue wait ≤ 5 min p95 |

## 3. Service level objectives

Window: rolling 30 days. Allowed downtime shown for a 30-day month.

| ID | Service | Indicator | Objective | Allowed |
|---|---|---|---|---|
| SLO-01 | Attestation | Valid requests answered successfully; server time p95 ≤ 50 ms, p99 ≤ 120 ms | 99.99 % | 4.3 min |
| SLO-02 | Ingest | Batches acknowledged; acknowledgement p99 ≤ 150 ms | 99.95 % | 21.6 min |
| SLO-03 | Policy distribution | Bundle and key-set fetches served | 99.99 % | 4.3 min |
| SLO-04 | Event freshness | Events queryable within PB-13 | 99 % of events | — |
| SLO-05 | Detection latency | Detections within PB-14 | 95 % | — |
| SLO-06 | Enforcement propagation | Actions applied within PB-15 | 95 % in 30 s, 99 % in 60 s | — |
| SLO-07 | Control API | Successful responses within PB-21 | 99.9 % | 43.2 min |
| SLO-08 | Console | Successful page loads meeting PB-19 | 99.9 % | 43.2 min |
| SLO-09 | Alert delivery | Alerts delivered within PB-18 | 99 % | — |
| SLO-10 | Prove | Assessments completing within PB-22 | 95 % | — |

**Why the tiers differ.** Attestation and policy distribution are the only cloud services a customer's protection depends on in near real time, so they get four nines and multi-region active-active. Even so, their failure is absorbed: Shield keeps its last bundle and applies an attestation grace period (SDD §18).

**Error-budget policy.** At 50 % of a service's monthly budget consumed, reliability work takes priority over features for that service. At 100 %, feature releases to that service stop until the budget recovers.

## 4. Shield

Budget allocation for PB-01 (p99, attested and signed route):

| Step | Budget | Lever |
|---|---|---|
| Normalise request, match route | 0.05 ms | Precompiled route tree |
| Verify Attestation Token | 0.15 ms cold · 0.01 ms warm | Verified-token cache keyed by token identifier until expiry |
| Verify request signature | 0.30 ms | Native elliptic-curve verification; body hash streamed |
| Replay check | 0.02 ms | In-memory nonce window per instance; shared store optional |
| Evaluate rules | 0.05 ms | Rules compiled to a decision tree at bundle load |
| Update counters | 0.01 ms memory · ≤ 2.5 ms shared | Local token bucket; pipelined shared-store calls |
| Enqueue event | 0.02 ms | Lock-free ring buffer; batch flush off-thread |
| Margin | 0.90 ms | Garbage collection and scheduling noise |

Rules:

- No synchronous network or disk I/O in `decide`. Bundle refresh, list deltas and event flush run on background timers.
- Bounded memory: event buffer capped (default 10,000 events); on overflow, drop sampled `allow` events first and count the drops.
- **Burst collapsing.** When one rule fires for one key more than a threshold per second, Shield emits one aggregate event per second with a count — an attack flood must not become an event flood.
- Cold start: first bundle load ≤ 200 ms and never blocks the host application's start.
- Push channel reconnects use jittered exponential backoff to avoid a reconnect storm.

## 5. Guard

| Aspect | Rule |
|---|---|
| Loading | Bundled with the application, deferred; initialisation runs in idle time in small tasks |
| First request | Never waits for attestation; requests sent before a token exists are marked `pending` and judged by policy grace |
| Network | Handshake: two requests, ≤ 4 KB up and ≤ 3 KB down. Re-attestation about every 4 minutes while visible; paused in background tabs. Signal reports batched, at most one request per 30 s; final flush with a beacon on page hide |
| Memory | ≤ 5 MB |
| Timers | None while the page is hidden |
| Collectors | Each collector has its own time budget and is skipped when it overruns |

## 6. Harden

| Metric | How measured | Gate |
|---|---|---|
| Runtime overhead (PB-10) | Benchmark suite of the reference app and a library corpus, protected vs original, same device profile | CI fails when a profile exceeds its budget |
| Script evaluation time | Parse and compile time on a throttled profile | ≤ 15 % increase on `balanced` |
| Size (PB-11) | Gzip and Brotli sizes per chunk | Reported per Build; CI fails over budget |
| Build time (PB-12) | Wall-clock on the standard runner | Tracked per release |

Levers: per-path protection maps; automatic exclusion of code marked hot by a profile run; pass-level cost accounting in the protection report so developers see what each pass costs.

## 7. Pipeline latency

Allocation for PB-13 (event to visible, p95 ≤ 5 s):

| Stage | Budget |
|---|---|
| Shield batch flush interval | ≤ 1.0 s |
| Network and Ingest acknowledgement | ≤ 0.3 s |
| Event log to stream processors | ≤ 0.5 s |
| Enrichment and write to the analytics store | ≤ 1.5 s |
| Console subscription delivery | ≤ 0.5 s |
| Margin | 1.2 s |

PB-15 (action to enforcement, p95 ≤ 30 s): decision recorded ≤ 1 s → signed delta produced ≤ 2 s → pushed over open channels ≤ 5 s → applied by Shield ≤ 1 s; instances without an open channel pick it up at the next 30-second poll.

## 8. Console

- Server-render the frame; stream data regions; skeletons reserve final dimensions so layout never shifts.
- The live feed is a virtualised list; at most one render per 250 ms regardless of event rate; a "paused" state when the analyst scrolls.
- Charts update at most once per second and read from one-minute rollups for any window over one hour.
- Queries never scan raw events for windows over 24 hours.
- Route-level code splitting; the analytics and graph libraries load only on screens that use them.
- Budgets are enforced by a lab check in CI and by real-user monitoring in production.

## 9. Prove

| Aspect | Target |
|---|---|
| Sandbox start | ≤ 60 s |
| Queue wait | ≤ 5 min p95 (PB-22) |
| Tier ceilings | T1 15 min · T2 2 h · T3 8 h, enforced by the orchestrator |
| Concurrency | Per-tenant limit by plan; global limit by sandbox capacity and model-provider rate limits |
| Model usage | Stable prompt prefix so caching applies; batch processing for normalisation and reports; cache hit rate monitored |
| Cost guard | Spend ceiling per Assessment and Campaign; a run that reaches it stops and reports what was completed |

## 10. Capacity model

Planning assumptions for the MVP region (to be replaced by measurements):

| Quantity | Assumption |
|---|---|
| Protected requests | 2 billion per month ≈ 770 per second average, 10× peak |
| Event ratio | Non-`allow` decisions 2 % + sampled `allow` 5 % + Guard reports ≈ 8–10 % of requests |
| Event rate | ≈ 80 per second average; design point **20,000 per second sustained, 100,000 burst** |
| Event size | ≈ 600 bytes on the wire; ≈ 70 bytes stored after columnar compression |
| Storage | `events/s × 86,400 × retention days × 70 bytes`; at 80/s and 30 days ≈ 15 GB |
| Attestation | One handshake per session plus refresh every ~4 minutes of active use |
| Push channels | One long-lived connection per Shield instance |

Scaling rules:

- Ingest and Attestation are stateless and scale horizontally on request rate.
- The event log is partitioned by tenant; a tenant exceeding its quota is throttled at Ingest with an explicit response, never by slowing other tenants.
- Stream processors scale on consumer lag.
- The analytics store scales by adding shards; tenants above a size threshold move to dedicated tables.
- Per-tenant quotas by plan: events per second, rule count, list size, concurrent Prove runs, API rate.

## 11. Cost efficiency

Tracked from the first deployment; targets are set after the first load test rather than guessed.

| Unit metric | Main levers |
|---|---|
| Infrastructure cost per million protected requests | `allow` sampling, rollups at the edge, burst collapsing |
| Storage cost per tenant per month | Retention by plan, cold archive in columnar files, time-to-live on raw events |
| Model cost per Assessment and per Incident summary | Prompt caching, batch processing, smaller model for high-volume tasks, ceilings |
| Sandbox cost per Assessment | Tier chosen by trigger: T1 on every Build, T2 nightly, T3 before release |

## 12. Measurement

| What | Tool class | Where |
|---|---|---|
| Shield micro-benchmarks per step | Benchmark harness with statistical comparison | CI on every change to Shield |
| Shield in a real server | Load generator against the reference app with and without Shield | Nightly |
| Guard lab metrics | Automated browser audits on throttled device profiles | CI |
| Guard field metrics | Real-user monitoring through the customer's own page (opt-in, aggregated) | Production |
| Harden overhead | Benchmark corpus, protected vs original | CI |
| Cloud services | Tracing, metrics and SLO dashboards | Production |
| End-to-end latency | Synthetic probes that emit a marked event and time its appearance, and a marked block and time its enforcement | Every minute, every region |
| Console | Lab audits in CI and real-user monitoring | CI and production |

## 13. Degradation order

Under overload, shed in this order and stop as soon as the system is healthy:

1. Sampled `allow` events.
2. Rollup granularity (one minute → five minutes).
3. Low-confidence Guard signals.
4. AI summaries and report generation.
5. Search over raw events (dashboards stay on rollups).

**Never shed:** decisions of enforced rules, Canary and Clone Beacon events, audit events, policy and list distribution.

## 14. Load and stress test plan

| Scenario | Purpose | Pass condition |
|---|---|---|
| Steady state at design point | Baseline | All SLOs met for 2 h |
| 10× burst for 15 min | Elasticity | No data loss in never-shed classes; recovery ≤ 10 min |
| Single-tenant attack flood | Isolation | Other tenants' freshness and latency unchanged; burst collapsing engaged |
| Event-log partition loss | Resilience | No acknowledged event lost; lag recovers |
| Slow analytics store | Backpressure | Degradation order followed; alerts fire |
| Policy storm (1,000 publishes per minute) | Distribution | PB-16 holds; no Shield applies a stale bundle after a newer one |
| Push-channel reconnect storm after an edge restart | Thundering herd | Reconnects spread by jitter; no cascading failure |
| Attestation regional failover | Availability | Clients fail over within the grace period; no enforcement gap |
| Prove queue saturation | Fairness | Per-tenant limits hold; queue wait reported accurately |
| Cold start of every service | Recovery | Time to healthy within each service's target |

Load tests run against staging sized as a known fraction of production, weekly at design point and before every release that changes a hot path.

## 15. Regression gates in CI

- Shield: fail on a statistically significant regression above 5 % in any step benchmark, or any budget breach.
- Guard: fail when size exceeds PB-05 or lab metrics exceed PB-06.
- Harden: fail when a profile exceeds PB-10 or PB-11 on the corpus.
- Console: fail when lab metrics exceed PB-19 on the key routes.
- Any accepted regression needs a recorded reason in the decision log.

## 16. Open items

1. Replace the capacity assumptions with design-partner traffic profiles.
2. Decide the approximate global rate-limit design that avoids requiring the customer's Redis (SDD §19).
3. Set unit-cost targets after the first load test.
4. Define mobile budgets (battery, start-up, binary size) with Phase 2.
