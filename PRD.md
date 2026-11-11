---
title: "Anti Reverse — Product Requirements Document"
aliases: [PRD]
project: anti-reverse
doc: PRD
version: 0.1.0
status: approved
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - spec/prd
related:
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[OPERATION]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"
  - "[[MEMORY]]"
---

# Anti Reverse — Product Requirements Document (PRD)

> **One line.** Anti Reverse is a SaaS platform that makes a digital product expensive to reverse engineer, tamper with, clone and attack — and proves it on every release by attacking the product itself, with authorization, using AI agents.

| Item | Value |
|---|---|
| Product form | Multi-tenant SaaS (cloud control plane) with small components that run inside the customer's build, app and backend |
| Protects | SaaS products, websites, web apps, APIs, mobile apps, desktop software, and paid digital products (templates, plugins, scripts) |
| Default language | English (`en`). The product is i18n-ready from the first commit; Bahasa Indonesia (`id`) is the proposed first additional locale |
| Status | v0.1.0 — **approved by the owner on 2026-11-10**, together with the calls in §17; the questions in §17 remain open. Build started with slice 01 ([ticket](tickets/01-walking-skeleton.md)) |
| Doc set | [SDD](SDD.md) · [SECURITY](SECURITY.md) · [PERFORMANCE](PERFORMANCE.md) · [OPERATION](OPERATION.md) · [QASUITE](QASUITE.md) · [UIUX](UIUX.md) · [MEMORY](MEMORY.md) |
| Vocabulary | Every capitalised term (App, Build, Guard, Shield, Canary, RRS …) is defined once in [MEMORY.md § Language](MEMORY.md#3-language-glossary) |

---

## 1. Problem statement

*Written from the customer's side.*

I ship a digital product. Whatever reaches my customer's device — a JavaScript bundle, an APK, a desktop binary, an API contract — an attacker can read, modify and replay.

1. **Reverse engineering became cheap.** AI agents now drive decompilers, bundle analyzers and traffic capture. They can explain how a shipped feature works, show the evidence, and rebuild it in hours. Competitors clone features; attackers map my API and find the logic I assumed was hidden.
2. **My API is called by things that are not my app.** Scripts replay captured requests. Bots stuff credentials, scrape content, create fake accounts and brute-force coupons.
3. **My site and app get cloned.** Phishing mirrors of my frontend steal my customers' credentials. Repackaged apps ship with the paywall removed or malware added.
4. **I find out late.** Nothing tells me that a client was tampered with, that a build shipped a source map or a secret, or that someone is probing my endpoints.
5. **I cannot measure my protection.** Obfuscators and "shields" claim strength without evidence. A pentest is a yearly snapshot. I do not know whether last night's release made things worse.
6. **The tools are fragmented.** Obfuscator + WAF + bot manager + app shielding + pentest vendor means five contracts, five consoles and no shared context — priced for enterprises, not for a ten-person team.

## 2. Solution

One platform that closes the loop: **Harden → Guard → Shield → Radar → Prove**, operated from one **Console**.

| Module | What the customer gets | Where it runs |
|---|---|---|
| **Harden** | Build-time protection: obfuscation, string and asset encryption, integrity self-checks, per-build diversity, leak scanning (source maps, secrets), planted Canaries and Watermarks | The customer's CI (local-first — source never leaves) |
| **Guard** | In-app runtime protection: detects debugging, hooking, tampering, automation and unauthorized origins; produces a short-lived Attestation Token; signs requests | Inside the shipped client (web first, then Android, iOS, desktop) |
| **Shield** | Request-path enforcement: verifies attestation and signatures, rate-limits, stops bots, credential stuffing, scraping and enumeration; decides `allow / monitor / challenge / throttle / block / deceive` | Inside the customer's backend (library first, proxy and edge later) |
| **Radar** | Telemetry, detection, Incidents, alerts and automated Playbooks; correlates client integrity with server behaviour | Anti Reverse cloud |
| **Prove** | Continuous adversarial validation: a **Reverse Resistance Score (RRS)** for every Build, and autonomous Pentest Campaigns against Verified Targets; CI gates on both | Anti Reverse cloud, in isolated sandboxes |
| **Console** | Onboarding, policy editing with simulation, live threat feed, incidents, findings, reports, API and integrations | Anti Reverse cloud |

What is different: **evidence**. Every Build gets a score produced by an actual attack attempt, every policy change can be replayed against yesterday's traffic before it is enforced, and every block has a reason a human can read.

## 3. Why now

- Agent-driven reverse engineering is a commodity. Open-source toolkits connect coding agents to native decompilers, JavaScript/Electron bundle analysis, Android tooling and browser/network capture, and return evidence-backed explanations of shipped software.
- Autonomous penetration-testing systems chain reconnaissance and exploitation tools inside sandboxes without a human operator.
- Defenders can point the same automation at their own products. A protection product that does not measure itself against these agents is guessing.

## 4. Users

| Persona | Context | Needs from Anti Reverse |
|---|---|---|
| **Builder** — founder or lead developer, team of 1–10 | No security staff; ships weekly | Protection in minutes, safe defaults, plain-language alerts, predictable price |
| **AppSec engineer** — product security at a scale-up | Owns client and API security for several teams | Policy control, evidence for every decision, CI gates, API and SIEM export |
| **On-call analyst / SRE** | Receives the 02:00 alert | A calm incident view, one-click containment, instant rollback |
| **Engineering leader / CTO** | Accountable for risk and velocity | Trend of RRS and incidents, proof for customers and auditors, no performance tax |
| **Risk and compliance officer** | Answers security questionnaires | Reports mapped to recognised frameworks, audit trail, data-handling facts |

**Anti-persona — the Adversary** (who we design against):

| Tier | Description | Product stance |
|---|---|---|
| A1 Opportunist | Runs public tools and AI agents with default settings | Stop outright |
| A2 Skilled individual | Experienced reverse engineer or competitor's developer | Make it cost days, detect the attempt |
| A3 Organised abuse | Bot operators, fraud rings, scraping businesses | Raise unit cost above their margin, detect and contain |
| A4 Determined and funded | Targeted, patient, custom tooling | Detect, slow down, limit blast radius — never claim prevention |

## 5. Goals, non-goals, anti-goals

### Goals

| ID | Goal | Measured by |
|---|---|---|
| G1 | Protection in minutes | Signup → first protected request ≤ 15 min (p50) |
| G2 | Measurable resistance | Reference app: RRS ≥ 70 on `balanced`, ≥ 85 on `maximum`, unprotected baseline ≤ 30 |
| G3 | Detect and act fast | ≥ 95 % recall on the labeled attack replay suite at ≤ 0.1 % false positives; Canary use detected ≤ 60 s; block propagated ≤ 30 s |
| G4 | Stay out of the way | Budgets in [PERFORMANCE.md](PERFORMANCE.md): Shield p99 ≤ 1.5 ms, Guard ≤ 35 KB gzip, zero render blocking |
| G5 | Safe by default | Monitor-first, fail-open, one-click rollback; zero customer outages caused by Anti Reverse |
| G6 | A platform worth trusting | Tenant isolation, signed bundles/tokens/releases, full audit trail, source code never leaves customer CI |
| G7 | One console, English first | English default, i18n-ready, WCAG 2.2 AA |

### Non-goals

- A CDN or a network-layer DDoS scrubbing service. Anti Reverse complements Cloudflare, AWS WAF, Vercel Firewall and similar.
- An antivirus, EDR or SIEM. It exports to SIEMs.
- A source-code scanner (SAST). It integrates with existing ones. (Known-vulnerability matching of dependencies is in scope since 2026-11-11 — see §9.7 Exposure; D-059.)
- DRM for audio/video streams.
- A general reverse-engineering or pentest-for-hire service. Prove only touches assets the tenant has proven it owns.

### Anti-goals — failure even if it "works"

- **Security theater.** A protection that does not move RRS or detection outcomes does not ship.
- **Breaking the customer's product.** A false block, a slow page or a failed build is worse than no protection.
- **Becoming the attack vector.** A compromised SDK release or a leaky telemetry pipeline would harm every customer at once.
- **Becoming an attack tool.** Prove must be unusable against third parties.
- **Surveillance creep.** No end-user personal data beyond what a decision needs.
- **Fear-based UX.** No scare copy, no alarm fatigue, no "unhackable" claims.

## 6. Approaches considered

| | Approach | Trade-off | Verdict |
|---|---|---|---|
| A | **Obfuscation-first toolkit** (CLI only) | Fast to build; no runtime visibility, no proof, a commodity market | Rejected as the product; kept as the Harden module |
| B | **Edge-only shield** (reverse proxy bot manager) | Strong network position; blind to client integrity, competes with CDNs, requires re-routing traffic and becomes a single point of failure | Deferred to Phase 2 as an optional Shield deployment mode |
| C | **Closed-loop platform**: local-first hardening + in-app Guard + in-path Shield library + SaaS control plane with Radar and Prove | More surface to build; unique value is the evidence loop and the client-plus-server correlation; adoption needs `npm install`, not a DNS change | **Chosen** — delivered as thin vertical slices, Web + API first |

## 7. Scope and phases

| Phase | Theme | In scope | Indicative window |
|---|---|---|---|
| 0 | Foundations | Tenancy and identity, Console shell, event pipeline skeleton, reference target `ar-range` | Weeks 0–4 |
| 1 | **MVP — Web + API** | Harden (web), Guard (web), Shield (Node), Radar core, Prove (Reverse Assessment for web Builds, Pentest beta), Console, billing | Weeks 5–16 |
| 2 | Mobile and depth | Harden/Guard for Android and iOS with platform attestation, Guard WASM core, Shield proxy/edge mode and Go/Python/Java SDKs, anomaly detection, SSO/SCIM, SIEM export, MCP server, self-hosted Prove runner | Months 5–8 |
| 3 | Desktop, native, licensing | Electron and native hardening, code virtualization, licensing and entitlements, leak-tracing portal, shared threat intelligence, private data plane and BYOK | Months 9–12 |

Windows are planning assumptions, not commitments; team size is an open question (§17).

## 8. User stories

**Onboarding and administration**

1. As a Builder, I want to sign up and create an Organization without talking to sales, so that I can evaluate today.
2. As a Builder, I want a guided setup that ends with my first protected request on screen, so that I know it works.
3. As a Builder, I want copy-paste snippets for my framework, so that I do not read protocol docs.
4. As an Org Owner, I want to invite members with roles, so that developers and analysts see only what they need.
5. As an Org Owner, I want passkeys and MFA enforced, so that a stolen password cannot change my policies.
6. As an AppSec engineer, I want SSO and SCIM, so that access follows our identity provider.
7. As an Org Owner, I want an immutable audit log of every change, so that I can answer "who changed this policy?".
8. As a Builder, I want to register an App with Surfaces and Environments, so that staging and production are separated.
9. As a Developer, I want CI to authenticate with short-lived federated tokens, so that no long-lived secret sits in my pipeline.
10. As a Billing admin, I want usage and plan limits visible, so that invoices never surprise me.
11. As a user in Indonesia, I want the Console in Bahasa Indonesia once available, so that my whole team can use it.

**Harden**

12. As a Developer, I want to add one plugin to my bundler, so that every production build is hardened automatically.
13. As a Developer, I want to choose a Protection Profile per path, so that hot code stays fast and sensitive code gets maximum protection.
14. As a Developer, I want my source code and unprotected build to stay in my CI, so that using Anti Reverse does not create a new leak.
15. As a Developer, I want the build to fail when a source map, secret or internal URL is about to ship, so that leaks are caught before release.
16. As a Developer, I want each Build to differ structurally from the last, so that a deobfuscation script written for one build breaks on the next.
17. As an AppSec engineer, I want Canaries planted in each Build, so that anyone using extracted strings identifies themselves.
18. As an AppSec engineer, I want each Build watermarked, so that a leaked or cloned copy can be traced to its origin.
19. As a Developer, I want the hardened build verified against my own test command, so that protection never changes behaviour.
20. As a Developer, I want a protection report per Build, so that I can see what was transformed and what it cost in size and speed.
21. As a mobile developer, I want the same workflow for Android and iOS, so that I do not learn a second tool.

**Guard**

22. As a Developer, I want Guard to load asynchronously and never block rendering, so that my Core Web Vitals do not regress.
23. As an AppSec engineer, I want to know when a client is debugged, hooked, tampered with or automated, so that I can respond.
24. As an AppSec engineer, I want Guard to start in report-only mode, so that I can observe before reacting.
25. As a Developer, I want protected API calls signed automatically, so that a request copied into a script is rejected.
26. As a privacy lead, I want Guard to collect no personal data by default, so that adding it does not change our privacy posture.
27. As an on-call analyst, I want a remote kill switch for Guard, so that I can disable it within minutes if it misbehaves.
28. As a Builder, I want to be told when my frontend is being served from a domain I do not own, so that I can take down a phishing clone.

**Shield**

29. As a Developer, I want Shield as middleware in my framework, so that I do not re-route production traffic through a third party.
30. As an SRE, I want Shield to decide locally with no network call per request, so that Anti Reverse cannot add latency or an outage to my API.
31. As an AppSec engineer, I want rules that combine client attestation with request behaviour, so that a clean IP with a tampered client is still stopped.
32. As a Builder, I want sensible managed rules for login, signup and password reset, so that credential stuffing is handled on day one.
33. As an AppSec engineer, I want rate limits keyed by IP, device, session, account or API key, so that limits match how abuse actually happens.
34. As an AppSec engineer, I want to import my OpenAPI document, so that calls to undocumented routes or parameters are flagged.
35. As an AppSec engineer, I want every rule to run in monitor mode first, so that I see what it would do.
36. As an SRE, I want to choose fail-open or fail-closed per route, so that payments can be strict while the marketing page stays available.
37. As an AppSec engineer, I want a `deceive` action that serves plausible decoy responses, so that scrapers waste their budget.
38. As a platform engineer, I want Shield available as a proxy or edge function later, so that non-Node services are covered.

**Radar**

39. As an on-call analyst, I want a live feed of security events with filters, so that I can see what is happening now.
40. As an on-call analyst, I want related detections grouped into one Incident with a timeline, so that I triage a story, not a thousand rows.
41. As an on-call analyst, I want alerts in Slack, email, webhook and PagerDuty, so that incidents reach me where I work.
42. As an on-call analyst, I want one-click containment from an Incident, so that I can block an Actor for an hour without editing a policy.
43. As an AppSec engineer, I want automated Playbooks with guardrails, so that containment happens in seconds but can never block everyone.
44. As an AppSec engineer, I want to write custom detection rules, so that business-specific abuse is covered.
45. As an analyst, I want an AI-written summary of an Incident labeled as AI-generated, so that I can understand it quickly and still verify it.
46. As an engineering leader, I want a weekly summary and an executive report, so that I can show the trend.
47. As a compliance officer, I want reports mapped to recognised frameworks, so that questionnaires take minutes.
48. As an AppSec engineer, I want events exported to my SIEM, so that Anti Reverse fits our existing operations.

**Prove**

49. As an AppSec engineer, I want every Build scored by a real reverse-engineering attempt, so that I know how resistant it is.
50. As a Developer, I want the score to come with evidence of what was recovered, so that I know what to fix.
51. As a Developer, I want CI to fail when RRS drops below our threshold, so that a regression never reaches production.
52. As an AppSec engineer, I want to verify ownership of a domain before any test runs, so that tests are always authorized.
53. As an AppSec engineer, I want to define Rules of Engagement — scope, windows, intensity, exclusions — so that tests are safe.
54. As an AppSec engineer, I want autonomous Pentest Campaigns against my staging environment, so that weaknesses are found between yearly pentests.
55. As an on-call analyst, I want to stop any Campaign instantly, so that a test never becomes an incident.
56. As a Developer, I want Findings with reproduction steps, severity and a fix suggestion, so that I can act.
57. As an AppSec engineer, I want Findings retested automatically after a fix, so that "fixed" is verified.
58. As an engineering leader, I want RRS and open Findings trended per App, so that I can see whether we are getting safer.

**Integration**

59. As a platform engineer, I want a public REST API and signed webhooks, so that I can automate everything in the Console.
60. As a developer using a coding agent, I want an Anti Reverse MCP server, so that my agent can read Findings and RRS evidence and propose fixes.
61. As an Org Owner, I want to export or delete my data, so that I stay in control of it.

## 9. Functional requirements

Priority: **M** = must for MVP, **S** = should for MVP, **P2 / P3** = later phase. Each requirement is verified by the suite named in [QASUITE.md § Traceability](QASUITE.md#11-traceability).

### 9.1 Harden

| ID | Requirement | Pri |
|---|---|---|
| FR-HRD-01 | CLI plus plugins for Vite, Webpack, Rollup, esbuild and Next.js | M |
| FR-HRD-02 | Protection Profiles `light`, `balanced`, `maximum`, assignable per path (protection map) | M |
| FR-HRD-03 | Transform set v1: identifier mangling, string encryption, control-flow flattening, opaque predicates, bounded dead-code injection, integrity self-checks | M |
| FR-HRD-04 | Per-build diversity: every Build is structurally different for the same source | M |
| FR-HRD-05 | Leak scan that fails the build: source maps, secrets, debug artifacts, internal URLs | M |
| FR-HRD-06 | Canaries: decoy strings, endpoints and keys unique to the Build | M |
| FR-HRD-07 | Watermark: recoverable per-Build identifier | S |
| FR-HRD-08 | Origin lock and Clone Beacon | M |
| FR-HRD-09 | Signed Build Manifest (hashes, profile, transform report) bound to the CI identity | M |
| FR-HRD-10 | Local-first: source and unprotected artifacts never leave the customer's CI | M |
| FR-HRD-11 | Equivalence check: run the customer's test command against the protected Build | S |
| FR-HRD-12 | Android hardening | P2 |
| FR-HRD-13 | iOS hardening | P2 |
| FR-HRD-14 | Electron and desktop hardening (fuses, archive integrity, bytecode) | P3 |
| FR-HRD-15 | Code virtualization for selected functions | P3 |

### 9.2 Guard

| ID | Requirement | Pri |
|---|---|---|
| FR-GRD-01 | Web runtime with async loader inside the budgets of PERFORMANCE.md | M |
| FR-GRD-02 | Signals v1: debugger/devtools, integrity mismatch, automation/headless, native-API hooking, environment inconsistency, origin mismatch | M |
| FR-GRD-03 | Attestation handshake issuing an Attestation Token (TTL ≤ 5 min) bound to a session key | M |
| FR-GRD-04 | Request signing with a non-extractable key, timestamp and nonce | M |
| FR-GRD-05 | Configurable reactions: report-only (default), degrade, custom callback | S |
| FR-GRD-06 | Privacy by default: no personal data, consent hooks, documented signal list | M |
| FR-GRD-07 | Signed remote configuration and kill switch | M |
| FR-GRD-08 | Android runtime with platform attestation | P2 |
| FR-GRD-09 | iOS runtime with platform attestation | P2 |
| FR-GRD-10 | WASM core shared across platforms | P2 |
| FR-GRD-11 | Desktop runtime | P3 |

### 9.3 Shield

| ID | Requirement | Pri |
|---|---|---|
| FR-SHD-01 | Node middleware for Express, Fastify, Next.js and Hono | M |
| FR-SHD-02 | Local decision engine fed by a signed Policy Bundle; no network call on the request path | M |
| FR-SHD-03 | Attestation Token and request-signature verification with replay protection | M |
| FR-SHD-04 | Rate limiting and throttling keyed by IP, device, session, account or API key; in-memory and Redis adapters | M |
| FR-SHD-05 | Bot and automation rules | M |
| FR-SHD-06 | Managed rules for credential stuffing and enumeration on authentication routes | M |
| FR-SHD-07 | Positive API model from an imported OpenAPI document; unknown-route and unknown-parameter detection | S |
| FR-SHD-08 | Decisions: `allow`, `monitor`, `challenge`, `throttle`, `block` (M); `deceive` (S) | M/S |
| FR-SHD-09 | Monitor mode by default, per-rule enforce, percentage rollout | M |
| FR-SHD-10 | Fail-open default, fail-closed selectable per route | M |
| FR-SHD-11 | Dynamic lists pushed from Radar and applied within 30 s | M |
| FR-SHD-12 | Asynchronous, batched, sampled event emission | M |
| FR-SHD-13 | Reverse-proxy and edge modes; Go, Python and Java SDKs | P2 |
| FR-SHD-14 | Baseline injection heuristics (SQL injection, XSS, SSRF, path traversal) | S |

### 9.4 Radar

| ID | Requirement | Pri |
|---|---|---|
| FR-RDR-01 | Authenticated, schema-validated, batched Ingest API | M |
| FR-RDR-02 | Live event stream and search | M |
| FR-RDR-03 | Streaming detection with managed and custom rules | M |
| FR-RDR-04 | Actor risk scoring | S |
| FR-RDR-05 | Incidents: grouping, status, assignment, timeline, notes | M |
| FR-RDR-06 | Alerts by email, Slack and signed webhook (M); PagerDuty (S) | M/S |
| FR-RDR-07 | Playbooks with guardrails (blast-radius caps, approval for broad actions) | S |
| FR-RDR-08 | Canary and Clone Beacon events raise a high-severity Incident | M |
| FR-RDR-09 | Weekly summary, executive report, framework-mapped export | S |
| FR-RDR-10 | SIEM export | P2 |
| FR-RDR-11 | AI triage summary, always labeled as AI-generated | S |
| FR-RDR-12 | Anomaly baselines | P2 |

### 9.5 Prove

| ID | Requirement | Pri |
|---|---|---|
| FR-PRV-01 | Verified Targets by DNS record or well-known file, re-verified during Campaigns | M |
| FR-PRV-02 | Rules of Engagement captured, signed by an Owner and enforced technically | M |
| FR-PRV-03 | Reverse Assessment of web Builds producing an RRS with evidence | M |
| FR-PRV-04 | Objective catalog and Budget Tiers T1–T3 | M |
| FR-PRV-05 | CI gate on minimum RRS and on new High or Critical Findings | M |
| FR-PRV-06 | Pentest Campaigns against Verified Targets through a replaceable pentest engine | S (beta) |
| FR-PRV-07 | Findings: normalised, de-duplicated, severity-rated, mapped, with workflow and retest | M |
| FR-PRV-08 | Kill switch, intensity levels, schedules, start/finish notifications | M |
| FR-PRV-09 | Proof of Ownership: only Builds with a tenant-signed manifest are assessed | M |
| FR-PRV-10 | Reverse Assessments for mobile, desktop and native Builds | P2/P3 |
| FR-PRV-11 | Trend and Build-to-Build diff | S |
| FR-PRV-12 | Self-hosted Prove runner | P2 |

### 9.6 Console and platform

| ID | Requirement | Pri |
|---|---|---|
| FR-CON-01 | Organizations, members, roles (Owner, Admin, Security Analyst, Developer, Billing, Viewer) | M |
| FR-CON-02 | Sign-in with passkeys/MFA and social login (M); SAML/OIDC SSO and SCIM (P2) | M/P2 |
| FR-CON-03 | App, Surface and Environment registration; onboarding wizard | M |
| FR-CON-04 | Policy editor with simulation against the last 24 h of events | M |
| FR-CON-05 | Scoped API keys and federated CI tokens | M |
| FR-CON-06 | Immutable audit log | M |
| FR-CON-07 | Public REST API and signed webhooks (M); Terraform provider (P2) | M/P2 |
| FR-CON-08 | Usage metering, plans and billing | M for GA |
| FR-CON-09 | i18n framework with English default (M); Bahasa Indonesia locale (S) | M/S |
| FR-CON-10 | In-product documentation and quickstarts | M |
| FR-CON-11 | Data controls: retention, export, deletion | M |
| FR-CON-12 | MCP server exposing Findings, RRS evidence and assessment triggers to coding agents | P2 |

### 9.7 Exposure (added 2026-11-11, owner's request)

| ID | Requirement | Pri |
|---|---|---|
| FR-EXP-01 | Component inventory of the shipped bundle (from Harden in CI) and of the running server (from Shield at start): package names and versions only | M |
| FR-EXP-02 | Match components against a locally synced vulnerability database (OSV: GHSA, npm, CVE aliases); the component list never leaves Anti Reverse | M |
| FR-EXP-03 | Findings with advisory and CVE ids, severity, affected and fixed versions, where found, status and expiring ignores; auto-fixed when the version disappears | M |
| FR-EXP-04 | New Critical or High findings open an Incident and alert; CI gate fails a build at or above a chosen severity | M |
| FR-EXP-05 | Virtual patches: signed Shield rules for advisories with a known request-level exploit pattern, active only where the vulnerable version runs, monitor first | S |
| FR-EXP-06 | Unknown-vulnerability discovery through Prove Pentest Campaigns, Findings in the same model | S |

## 10. Non-functional requirements (headline)

[PERFORMANCE.md](PERFORMANCE.md) and [SECURITY.md](SECURITY.md) are the sources of truth; if a number here differs, they win.

| Area | Requirement |
|---|---|
| Latency | Shield adds p99 ≤ 1.5 ms per request with in-memory counters |
| Client weight | Guard (web) ≤ 35 KB gzip, async, no render blocking |
| Hardening cost | Runtime overhead ≤ 5 % (`light`), ≤ 15 % (`balanced`), ≤ 50 % on protected code only (`maximum`) |
| Availability | Ingest 99.95 %, Attestation 99.99 %, Control API and Console 99.9 % |
| Speed of response | Event visible ≤ 5 s, detection ≤ 10 s, enforcement propagation ≤ 30 s (all p95) |
| Safety | Fail-open by default; monitor-first; every enforcement change reversible in one action |
| Security | Tenant isolation, signed bundles/tokens/releases, least privilege, audit trail |
| Privacy | Data minimisation, pseudonymous Actors, configurable retention, regional storage |
| Accessibility | WCAG 2.2 AA |
| Compatibility | Evergreen browsers (last 2 major versions), Node.js LTS lines; matrix in QASUITE.md |

## 11. Success metrics

| Type | Metric | Target at MVP exit |
|---|---|---|
| North star | **Protected Apps in Enforce** — Apps with at least one enforced rule and a current Build at RRS ≥ 70 | Tracked weekly; design-partner goal: 10 |
| Activation | Time to first protected request | ≤ 15 min p50 |
| Activation | Share of Apps reaching enforce mode within 14 days | ≥ 40 % |
| Efficacy | RRS uplift on the reference app, `balanced` vs unprotected | ≥ +40 points |
| Efficacy | Detection recall / false-positive rate on the replay suite | ≥ 95 % / ≤ 0.1 % |
| Efficacy | Canary time-to-detect | ≤ 60 s p95 |
| Trust | Customer-impacting incidents caused by Anti Reverse | 0 |
| Trust | Rule rollbacks due to false positives per 100 enforced rules | ≤ 2 per month |
| Reliability | SLO attainment | All SLOs met for 30 consecutive days before GA |

## 12. Packaging hypothesis

Dimensions to meter: Apps, protected monthly requests, monthly active Guard devices, Prove sandbox minutes, event retention, seats. Tiers: **Free** (one App, short retention, community support) → **Pro** → **Business** (SSO, longer retention, Pentest Campaigns) → **Enterprise** (private data plane, BYOK, custom retention, support SLA). Prices are deliberately undefined until design-partner interviews (§17, Q4).

## 13. Implementation decisions

Detailed design lives in [SDD.md](SDD.md). The decisions that shape the product:

- **Six deep modules** — Harden, Guard, Shield, Radar, Prove, Console — each with a small interface and one external seam for tests.
- **Local-first hardening.** Transforms run in the customer's CI. Only a signed Build Manifest and, opt-in, the already-public protected artifact are uploaded.
- **Shield decides locally.** Policies ship as signed Policy Bundles; the request path makes no call to Anti Reverse. Shield fails open unless a route is marked fail-closed.
- **Client signals are evidence, never proof.** Guard reports; only the server decides.
- **Monitor before enforce.** New rules observe first; the Console shows what they would have done.
- **Prove is gated by ownership.** Reverse Assessments accept only Builds whose manifest was signed by the tenant's CI identity; Pentest Campaigns run only against Verified Targets under signed Rules of Engagement.
- **Adversary Agents run in ephemeral, single-tenant sandboxes** with an egress allowlist; their output is treated as untrusted data.
- **RRS is empirical and relative.** It measures resistance against a stated agent, model and budget, and is never presented as a guarantee.
- **External engines sit behind interfaces.** The reverse-engineering toolbelt and the pentest engine are adapters that can be replaced.
- **English default with i18n from day one**; dark-first console design system specified in [UIUX.md](UIUX.md).

## 14. Testing decisions

- A good test exercises **external behaviour through a module's interface** — a protected bundle behaves like the original; a replayed request is rejected; a Canary raises an Incident — and never asserts on internal structure.
- **Highest seam first.** The primary seams are: the Harden CLI (input bundle → protected bundle + manifest), the Shield `decide(request, context)` function, the Ingest API, the detection engine (events in → detections out) and the Prove scorer (evidence in → RRS out).
- **Red-green-refactor** for every behaviour; a regression test is only accepted after it has been seen to fail.
- **The reference target `ar-range`** — a deliberately vulnerable demo product — is the shared fixture for end-to-end, resistance, detection and pentest suites.
- **Efficacy is a test, not a claim**: RRS thresholds and detection recall/false-positive targets are release gates.
- Suites, cases, gates and the traceability matrix are specified in [QASUITE.md](QASUITE.md).

## 15. Out of scope for MVP

Mobile and desktop Surfaces; proxy/edge Shield; SSO/SCIM; SIEM export; licensing and entitlements; code virtualization; anomaly detection by machine learning; shared threat-intelligence network; private data plane; Terraform provider; MCP server; any locale beyond English (Bahasa Indonesia is a "should").

## 16. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Hardening breaks customer code | Medium | High | Equivalence check, differential test suite, per-path profiles, instant opt-out per file |
| False positives block real users | Medium | High | Monitor-first, simulation, percentage rollout, guardrailed Playbooks, global safe-mode switch |
| The SDK becomes a supply-chain target | Low | Critical | Signed releases with provenance, two-person release, kill switch, minimal dependencies (SECURITY.md) |
| Prove is abused against third parties | Medium | Critical | Proof of Ownership, Verified Targets, Rules of Engagement, egress allowlists, abuse monitoring |
| A capable attacker bypasses Guard | High (over time) | Medium | Server-side decisions, per-build diversity, rapid signal updates, honest positioning |
| RRS is over-trusted | Medium | Medium | State scope and limits wherever the score appears; periodic human red-team calibration |
| LLM providers decline security workloads | Medium | Medium | Explicit handling of refusals as "not attempted", deterministic fallbacks, provider-verified access, self-hosted model option |
| Licence terms of embedded engines | Medium | Medium | Engines behind adapters; legal review before GA; build from source at pinned versions |
| Event volume cost | Medium | Medium | Sampling of benign events, rollups at the edge, per-tenant quotas |
| Privacy regulation exposure | Low | High | Data minimisation, regional storage, documented signal list, deletion tooling |

## 17. Calls made on your behalf and open questions

**Calls I made** (correct any of them and the documents will be updated):

| # | Call | Reason |
|---|---|---|
| C1 | Web + API first, mobile second, desktop third | Fastest path to a complete loop; the web toolchain needs no app-store cycle |
| C2 | Shield ships as a library before a proxy | No traffic re-routing, no new single point of failure |
| C3 | Hardening is local-first | Removes the biggest trust objection: "you want my source code?" |
| C4 | TypeScript monorepo, PostgreSQL + ClickHouse + Kafka-compatible log, AWS as primary cloud | One language across SDKs and services; proven building blocks (details in SDD §16) |
| C5 | Pentest Campaigns are a beta in MVP, limited to staging targets | Highest legal and operational risk; needs design-partner feedback |
| C6 | Dark-first console; signal green and alert red; restrained visual effects | Matches analyst workflows and enterprise credibility (UIUX.md) |
| C7 | Bahasa Indonesia is the first additional locale | Inferred from the language of the request; English remains the default |

**Questions only you can answer** (most important first):

1. **First customer segment** — small product teams (self-serve) or security teams at larger companies (sales-assisted)? This changes onboarding, pricing and the compliance roadmap.
2. **Team and timeline** — how many engineers, and is the 16-week MVP window realistic for you?
3. **Hosted offensive testing** — are you comfortable operating Pentest Campaigns as part of the SaaS at launch, or should Prove start with Reverse Assessments only?
4. **Pricing model** — usage-based, per-App, or seat-based?
5. **Data residency** — which region first (for example Jakarta or Singapore), and is in-country storage a requirement for your target customers?
6. **AI providers** — may protected artifacts and test transcripts be processed by a third-party model provider, or must a self-hosted model be supported from the start?
7. **SDK source** — open-source the SDKs for trust and auditability, or keep them closed?

## 18. Delivery plan — tracer-bullet slices

Each slice cuts through every layer and is demoable on its own. "Blocked by" lists the slices that must finish first.

| # | Slice — what works end to end | Blocked by |
|---|---|---|
| 01 | Walking skeleton: create Org and App → Shield in monitor mode emits an event → it appears in the Console live feed — **done 2026-11-10** | — |
| 02 | Policy path: edit a rule → signed Policy Bundle → Shield blocks a test route → the decision is visible — **done 2026-11-10** | 01 |
| 03 | Attestation path: Guard obtains an Attestation Token → Shield verifies it → verdict shown per request — **done 2026-11-11** | 01 |
| 04 | Signed requests: a replayed request from a script is rejected — **done 2026-11-11** | 03 |
| 05 | Harden path: `ar-range` bundle protected on `balanced` → Build Manifest in Console → app tests still pass — **done 2026-11-10** | 01 |
| 06 | Detection path: rule match → Incident → Slack/email/webhook alert — **done 2026-11-10** (Slack and signed webhook; email waits for a provider) | 01 |
| 07 | Leak scan and Canaries: a planted secret fails the build; Canary use raises an Incident within 60 s — **done 2026-11-11** | 05, 06 |
| 08 | Abuse rules: rate limiting and credential-stuffing protection on the login route | 02 |
| 09 | Containment: block an Actor from an Incident → enforced on all Shields within 30 s — **done 2026-11-11** | 02, 06 |
| 10 | Clone Beacon: protected bundle served from an unauthorized origin raises an Incident — **done 2026-11-11** | 05, 06 |
| 11 | Policy simulation: replay the last 24 h against a draft rule | 02, 06 |
| 12 | Reverse Assessment v1: Build → sandboxed assessment → RRS with evidence on the Build page | 05 |
| 13 | CI gate: pipeline fails when RRS is under threshold | 12 |
| 14 | Verified Target and Rules of Engagement flow | 01 |
| 15 | Pentest Campaign (beta) against `ar-range` staging → Findings with retest | 14 |
| 16 | Onboarding wizard and docs reaching G1 | 02, 03, 05 |
| 17 | Usage metering, plan limits, billing | 01 |
| 18 | GA hardening: audit log, data controls, SLO dashboards, all release gates green | all |
| 19 | Exposure step 1: component inventory (build and runtime) → CVE Findings with fix versions → Incident, alert and CI gate — **done 2026-11-11** | 05, 06 |
| 20 | Exposure step 2: virtual patches for known-exploit CVEs, active only where the vulnerable version runs | 19, 02 |

## 19. References and how they are used

| Reference | Role in this project |
|---|---|
| [obra/superpowers](https://github.com/obra/superpowers) | Development methodology: design before build, approval gate, bite-sized plans, red-green TDD, evidence before completion claims |
| [mattpocock/skills](https://github.com/mattpocock/skills) | Spec structure of this PRD (problem, solution, long user-story list, implementation and testing decisions), tracer-bullet tickets with blocking edges, shared-language glossary, lightweight decision records, deep-module design |
| [nextlevelbuilder/ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) | Design-system reasoning for a cybersecurity product: pattern, style, palette, typography, charts, priority-ordered UX rules ([UIUX.md](UIUX.md)) |
| [rohitg00/agentmemory](https://github.com/rohitg00/agentmemory) | Memory discipline for the agents that build Anti Reverse: recall before work, save decisions with reasons, lessons from corrections ([MEMORY.md](MEMORY.md)) |
| [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) | Autonomous pentest engine behind Prove's Pentest Campaigns and the QA pentest suite |
| [morluto/rea](https://github.com/morluto/rea) | Reverse-engineering toolbelt for the Adversary Agent that produces RRS; also the reference adversary Harden and Guard are designed against |
| [Obsidian](https://obsidian.md/) | The document set is a plain-Markdown vault: properties, links and a hub note, readable offline and in Git |
