---
title: "Airverse — Security"
aliases: [SECURITY]
project: anti-reverse
doc: SECURITY
version: 0.1.0
status: approved
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - spec/security
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[PERFORMANCE]]"
  - "[[OPERATION]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"
  - "[[MEMORY]]"
---

# Airverse — Security

Airverse is a security product, an attractive target, and a holder of offensive capability. This document covers all three: the threats it defends customers against (§4), the threats to the platform itself (§5), and the misuse of the platform as a weapon (§6). Architecture is in [SDD.md](SDD.md); verification of every control is in [QASUITE.md](QASUITE.md); response procedures are in [OPERATION.md](OPERATION.md).

---

## 1. Security objectives

| # | Objective |
|---|---|
| O1 | Raise an attacker's cost to understand, modify, clone or abuse a protected product, and make every attempt observable. |
| O2 | Never make a customer less safe: no new leak, no new outage path, no new privileged third-party code in their product without integrity guarantees. |
| O3 | Keep tenants isolated from each other in every store, cache, queue and sandbox. |
| O4 | Make offensive capability unusable outside ownership-verified scope. |
| O5 | Collect the minimum data a decision needs and keep it only as long as it is useful. |
| O6 | Be auditable: every security-relevant action has an actor, a time and a reason. |

## 2. Stated limits

Customers must be able to rely on what follows being true.

- **Client code can always be read eventually.** Harden raises cost and breaks tooling reuse; it does not create secrecy. Secrets that must stay secret belong on the server.
- **Guard can be bypassed by a sufficiently skilled attacker.** That is why Guard only reports and Shield decides, and why Radar looks for the bypass itself.
- **An attacker can drive a genuine client.** Request signing stops scripts, not humans or full-browser automation; behaviour rules and rate limits cover that gap.
- **RRS is empirical and relative.** It measures resistance against a stated agent, model and budget. It is not a certification.
- **Airverse is not a volumetric DDoS service, a WAF replacement, an EDR, or a substitute for secure server-side design.**
- **Protection through obscurity alone is a recognised weakness.** Every obscurity measure here is paired with detection or server-side enforcement.

## 3. Assets and trust boundaries

Trust zones Z0–Z8 are defined in SDD §3. Assets ranked by impact if compromised:

| Rank | Asset | Why it matters |
|---|---|---|
| 1 | SDK release pipeline and signing keys | A malicious Guard or Shield release reaches every customer |
| 2 | Policy and attestation signing keys | Forged bundles disable protection; forged tokens impersonate trusted clients |
| 3 | Prove sandboxes and their egress | Offensive tooling pointed at the wrong target, or used as a pivot |
| 4 | Tenant data: events, Findings, evidence, policies | Reveals each customer's weaknesses and traffic |
| 5 | Console identities and API keys | Policy tampering, protection shutdown |
| 6 | Control plane availability | Loss of visibility and updates (enforcement continues locally) |

## 4. Threat model A — attacks on customer products

What Airverse defends against, which module answers, and how the answer is measured.

| ID | Threat | Typical technique | Modules | Reference taxonomy | Measured by |
|---|---|---|---|---|---|
| TA-01 | Static reverse engineering of shipped code | Bundle analysis, decompilation, string extraction, source-map recovery | Harden, Prove | MASVS-RESILIENCE-3; CWE-540 | RRS OBJ-W1, OBJ-W3 |
| TA-02 | Dynamic analysis | Debugger, instrumentation and hooking frameworks, emulators | Guard, Radar | MASVS-RESILIENCE-4 | Signal recall suite |
| TA-03 | Tampering and repackaging | Patching checks out, removing paywalls, injecting code | Harden, Guard, Shield | MASVS-RESILIENCE-2; CWE-353 | RRS OBJ-W4 |
| TA-04 | Cloning and phishing mirrors | Copying the frontend to another origin | Harden (origin lock), Radar (Clone Beacon) | ATT&CK T1566 | Clone Beacon test |
| TA-05 | Secret extraction | Harvesting keys, tokens and internal URLs from builds | Harden (leak scan, Canaries) | CWE-798 | RRS OBJ-W2; Canary time-to-detect |
| TA-06 | Scripted API abuse and replay | Replaying captured requests outside the app | Guard (signing), Shield | CWE-294; API2:2023 | RRS OBJ-W5; replay suite |
| TA-07 | Credential stuffing and account takeover | High-volume login attempts with breached pairs | Shield, Radar | OAT-008; ATT&CK T1110.004; CWE-307 | Replay suite recall |
| TA-08 | Scraping and data harvesting | Systematic traversal of pages or endpoints | Shield (`throttle`, `deceive`), Radar | OAT-011 | Replay suite recall |
| TA-09 | Enumeration and object-level probing | Walking identifiers to reach other users' objects | Shield, Radar | API1:2023; CWE-639 | Replay suite recall |
| TA-10 | Automated business-logic abuse | Fake accounts, coupon and gift-card guessing, inventory hoarding | Shield, Radar | OAT-019, OAT-002, OAT-021; API6:2023 | Custom-rule tests |
| TA-11 | Exploitation of common web weaknesses | Injection, SSRF, path traversal | Shield heuristics, Prove (Pentest) | API7:2023; ATT&CK T1190 | Pentest Findings |
| TA-12 | Undocumented and forgotten endpoints | Calls to routes outside the contract | Shield (positive API model) | API9:2023 | Unknown-route tests |
| TA-13 | Application-layer resource exhaustion | Expensive endpoints called at volume | Shield rate limits | API4:2023; OAT-015 | Load tests |
| TA-14 | AI-agent-assisted reconnaissance and reverse engineering | Agents driving the techniques above at machine speed | All; Prove uses the same class of agent | — | RRS trend per Build |
| TA-15 | Licence bypass and piracy (Phase 3) | Key sharing, patched licence checks | Harden, Guard, Shield | MASVS-RESILIENCE-2 | Phase 3 suite |

Taxonomy keys: OWASP MASVS, OWASP API Security Top 10 (2023), OWASP Automated Threats (OAT), MITRE ATT&CK, CWE.

## 5. Threat model B — attacks on the Airverse platform

STRIDE letters: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege. Control identifiers refer to §7.

| ID | Threat | STRIDE | Impact | Controls |
|---|---|---|---|---|
| TP-01 | Cross-tenant data access through a query, cache or object-path flaw | I, E | Critical | SC-ISO-01…04, SC-SDL-05 |
| TP-02 | Theft or misuse of signing keys | S, T | Critical | SC-KEY-02, SC-KEY-03, SC-IAM-06, SC-LOG-02 |
| TP-03 | Malicious or compromised SDK release | T, E | Critical | SC-SUP-01…05 |
| TP-04 | Forged or replayed Attestation Token; Guard emulation | S | High | SC-KEY-01, short TTL, key binding, challenge programs, SC-TEL-02 |
| TP-05 | Event forgery or poisoning to frame a victim or hide an attack | T, R | High | SC-TEL-01…03 |
| TP-06 | Policy tampering through a compromised Console account | T, E | High | SC-IAM-01, SC-IAM-03, SC-LOG-01, rollout guardrails |
| TP-07 | Sandbox escape or pivot from Prove | E, I | Critical | SC-ISO-05, SC-INF-04, SC-SUP-06 |
| TP-08 | Prompt injection of Adversary Agents by artifact or target content | T, E | High | SC-AI-01, SC-AI-02 |
| TP-09 | Use of Prove against a third party | S | Critical | SC-USE-01…08 |
| TP-10 | Over-collection or leakage of personal data in telemetry | I | High | §8, SC-LOG-03, SC-AI-03 |
| TP-11 | Denial of service against Ingest, Attestation or the control plane | D | Medium (enforcement continues locally) | SC-INF-02, fail-open design, quotas |
| TP-12 | Insider misuse of production access | I, T | High | SC-IAM-06, SC-LOG-01 |
| TP-13 | Abuse of kill switches or safe mode to disable protection | T, D | High | SC-IAM-03 (step-up and dual approval), SC-LOG-02 |
| TP-14 | Tenant data exposed to model providers beyond intent | I | Medium | SC-AI-03 |
| TP-15 | Vulnerable dependency or base image | T, E | Medium | SC-SUP-03, SC-SDL-03, SC-INF-03 |
| TP-16 | Console account takeover | S | High | SC-IAM-01, SC-IAM-05 |
| TP-17 | Webhook forgery, or server-side request forgery through customer-supplied URLs | S, T | Medium | Signed webhooks, destination validation, egress proxy |
| TP-18 | Compromise of the content delivery path for bundles, key sets or Guard assets | T | High | SC-KEY-03, SC-SUP-04 |

## 6. Threat model C — misuse of Airverse

Prove contains a reverse-engineering toolbelt and an autonomous pentest engine. Both are dual-use. The design assumes someone will try to rent them.

| Misuse | Why it is blocked |
|---|---|
| Upload a competitor's app and ask for it to be reverse engineered | Reverse Assessments accept only Builds whose manifest was signed by the tenant's own CI identity and whose artifact carries that tenant's planted markers (SC-USE-01) |
| Point a Pentest Campaign at someone else's site | Campaigns run only against Verified Targets; ownership is re-proven before each run; sandbox egress is an allowlist of exactly those hosts (SC-USE-02, SC-USE-03) |
| Use a verified domain to attack a shared platform behind it | Targets resolving to shared hosting or third-party SaaS go to manual review; provider testing policies are respected (SC-USE-05) |
| Create throwaway accounts to run attacks | Pentest Campaigns require a paid plan, a verified business identity and an account-age threshold (SC-USE-04) |
| Extract tooling or exploits from the platform | Evidence stays in tenant scope; no public sharing; sandboxes are destroyed after each run (SC-USE-07) |
| Use Guard to track end users across sites | Device identifiers are random, first-party and resettable; no cross-site fingerprint exists to misuse (§8) |
| Use blocking features to censor or discriminate | Acceptable Use Policy; geographic and network rules are audited like any other policy change |

## 7. Control catalog

### Identity and access

| ID | Control |
|---|---|
| SC-IAM-01 | Passkeys or MFA are mandatory for Owner and Admin roles; phishing-resistant methods are the default. |
| SC-IAM-02 | SAML/OIDC single sign-on and SCIM provisioning (Phase 2). |
| SC-IAM-03 | Least-privilege roles scoped to Apps. Sensitive actions — promoting a rule to enforce, starting a Campaign, rotating keys, using a kill switch, deleting data — require step-up authentication, are audited, and can require a second approver. |
| SC-IAM-04 | API keys are scoped, expiring, stored hashed and identifiable by prefix. CI authenticates with short-lived federated identity tokens. |
| SC-IAM-05 | Sessions are short-lived and rotated; unusual sign-in location or device triggers re-authentication. |
| SC-IAM-06 | Staff reach production only through just-in-time, time-boxed, approved and recorded sessions with hardware-backed authentication. No standing access to tenant data. Break-glass is documented and alarmed. |

### Tenant isolation

| ID | Control |
|---|---|
| SC-ISO-01 | Row-level security on every tenant table; no service role can bypass it; a cross-tenant access matrix runs in CI. |
| SC-ISO-02 | Analytics queries pass through a service that injects the tenant predicate; row policies are the backstop. |
| SC-ISO-03 | Envelope encryption with a data key per tenant; customer-managed keys for Enterprise. |
| SC-ISO-04 | Caches, log partitions, rate limits and quotas are namespaced per tenant. |
| SC-ISO-05 | One sandbox per Assessment or Campaign, never reused, in a cloud account with no route to the core. |

### Cryptography and keys

| ID | Control |
|---|---|
| SC-KEY-01 | Ed25519 for bundles, tokens and remote configuration; ECDSA P-256 for client session keys; AES-256-GCM at rest; HKDF-SHA-256 for derivation; HMAC-SHA-256 for webhooks and pseudonymisation; TLS 1.3 in transit. |
| SC-KEY-02 | Signing keys live in a managed key service backed by hardware, are never exported, and are separated by purpose and environment. Attestation keys rotate daily with overlap; bundle-signing keys quarterly; emergency rotation is rehearsed. |
| SC-KEY-03 | SDKs embed a root verification key. Key sets served over the CDN are themselves signed by that root, so a compromised delivery path cannot introduce keys. |
| SC-KEY-04 | Secrets are held in a secret manager, rotated, and scanned for in code, images and logs. |
| SC-KEY-05 | Each tenant has its own pseudonymisation key; identifiers hashed for one tenant cannot be correlated with another's. |

### SDK and engine supply chain

| ID | Control |
|---|---|
| SC-SUP-01 | Releases are built by a protected pipeline, signed, and published with provenance attestations; two people approve every release; no long-lived publishing credentials. |
| SC-SUP-02 | SDK builds are reproducible; every release ships a software bill of materials. |
| SC-SUP-03 | Guard and Shield cores target zero runtime dependencies; everything else is pinned, reviewed on update and installed with scripts disabled. |
| SC-SUP-04 | Guard is bundled into the customer's build by default, so no third-party script loads at runtime. Any CDN-delivered asset is version-pinned with subresource integrity. |
| SC-SUP-05 | SDK versions roll out in rings (internal → design partners → everyone) with a kill switch and a yank procedure. |
| SC-SUP-06 | Third-party engines are pinned by commit, built from source, scanned, and executed only inside sandboxes. |

### Secure development lifecycle

| ID | Control |
|---|---|
| SC-SDL-01 | Any change that touches a trust boundary updates the threat model in its design document. |
| SC-SDL-02 | Every change is reviewed; cryptography, authorization, parsers and sandbox code require a security reviewer. |
| SC-SDL-03 | Static analysis, dependency, secret, infrastructure-as-code and container scanning run on every pull request. |
| SC-SDL-04 | Parsers are fuzzed continuously: policy language, tokens, event schema, bundle analysis. |
| SC-SDL-05 | Test-first development; every security defect gets a regression test that was seen to fail. |
| SC-SDL-06 | Dogfooding: the Console and public site run Guard and Shield; our own Builds must pass the RRS gate; our staging is under continuous Pentest Campaigns. |
| SC-SDL-07 | Independent penetration test yearly, internal red team quarterly, bug bounty after general availability. |

### Infrastructure

| ID | Control |
|---|---|
| SC-INF-01 | Separate cloud accounts per environment and function; private data stores; no public buckets. |
| SC-INF-02 | Edge services enforce rate limits, size limits and schema validation behind CDN-level DDoS protection. |
| SC-INF-03 | Immutable, minimal images; patch deadlines by severity; changes only through infrastructure as code. |
| SC-INF-04 | Prove egress passes an allowlisting proxy; cloud metadata endpoints and private address ranges are denied. |
| SC-INF-05 | Encrypted backups with restore tests on a schedule. |

### Logging, audit and telemetry integrity

| ID | Control |
|---|---|
| SC-LOG-01 | Append-only, hash-chained audit log of administrative and security-relevant actions, visible to the tenant and exportable. |
| SC-LOG-02 | Platform security monitoring: authentication anomalies, privilege changes, signing-key use, mass policy changes, kill-switch use. |
| SC-LOG-03 | Logs carry no secrets and no personal data; fields are allowlisted. |
| SC-TEL-01 | Shield events are authenticated with a per-Environment key; Guard reports are bound to an attestation session; all input is schema-validated and rate-limited. |
| SC-TEL-02 | Automated blocking never rests on client-originated signals alone when the action can affect another Actor; server-observed corroboration is required. |
| SC-TEL-03 | Per-source caps, outlier rejection and human approval for broad actions limit poisoning. |

### AI

| ID | Control |
|---|---|
| SC-AI-01 | Content from artifacts, targets and events is delimited and treated as data. Agents have a tool allowlist, no credentials and schema-validated outputs. |
| SC-AI-02 | Prompt-injection evaluations run in CI with hostile artifacts and hostile target responses. |
| SC-AI-03 | Prompts are minimised and redacted; provider retention terms are recorded per model; tenants can opt out of third-party processing. |
| SC-AI-04 | Step, time and spend ceilings on every agent run; kill switch; refusals recorded as "not attempted". |
| SC-AI-05 | Findings are published as *unverified* until an automated retest reproduces them. |

### Responsible use of Prove

| ID | Control |
|---|---|
| SC-USE-01 | Proof of Ownership for every assessed artifact. |
| SC-USE-02 | Verified Targets with re-verification every 24 h and before each Campaign. |
| SC-USE-03 | Signed Rules of Engagement enforced by the egress allowlist. |
| SC-USE-04 | Eligibility checks: paid plan, verified business identity, account age. |
| SC-USE-05 | Manual review for shared or third-party infrastructure; hosting-provider testing policies respected. |
| SC-USE-06 | Global and per-tenant kill switches; intensity and rate caps. |
| SC-USE-07 | Evidence confined to tenant scope; no public links; sandboxes destroyed after use. |
| SC-USE-08 | Acceptable Use Policy with suspension for violations and a defined process for lawful requests. |

## 8. Privacy and data protection

**Roles.** For telemetry about a customer's end users, the customer is the controller and Airverse the processor; a data-processing agreement and a public sub-processor list apply. For Console accounts, Airverse is the controller.

| Data | Examples | Collected? | Default retention | Notes |
|---|---|---|---|---|
| Source code, unprotected builds | — | **Never** | — | Stay in the customer's CI |
| Build Manifest | Hashes, sizes, profile, costs | Yes | Life of the Build + 13 months | No code |
| Protected artifact | The bundle that ships publicly | Opt-in | Assessment + 30 days | Needed for Prove |
| Guard reports | Signal identifiers, random device identifier, Build | Yes | 30 days | No personal data by design |
| Request metadata | Method, route template, status, latency, network, country | Yes | By plan (7 days to 13 months) | No bodies, no query strings |
| Account reference | Customer's user identifier | Hashed in Shield before sending | Same as events | Airverse never receives the raw value |
| Evidence bundles | Assessment and Campaign output | Yes | 13 months | Tenant-scoped encryption |
| Console account | Name, email, authentication log | Yes | Account lifetime | — |
| Model prompts and outputs | Agent transcripts | Yes, as evidence | 13 months | Subject to provider terms; opt-out available |

**IP addresses.** Default *privacy mode*: Shield sends the address truncated to a prefix (IPv4 /24, IPv6 /48) plus a keyed hash made with the tenant's pseudonymisation key. Counting and blocking use the keyed hash, which Shield recomputes locally for each request — so individual addresses can be blocked without Airverse storing them. *Network mode* (opt-in) sends full addresses, kept at most 7 days in the hot store and then truncated.

**Other rules.**

- Guard's identifier is random, first-party and resettable. It is storage used for security purposes; customers should reflect it in their privacy notices, and local legal review is recommended.
- Regional storage is selectable per Organization; events do not leave the chosen region except as aggregated, non-personal metrics.
- Deletion and access requests: the customer supplies an identifier, it is hashed with the tenant key, and matching records are exported or erased. Tooling is in the Console and API.
- Regulations considered in the design: GDPR, and Indonesia's Personal Data Protection Law (Law No. 27 of 2022). This document is engineering guidance, not legal advice.

## 9. Secure development workflow

Every change follows the same path, the one the methodology references in PRD §19 prescribe:

1. **Design before code** — intent, non-goals, approaches, threat-model delta; approved by a human.
2. **Plan in small tasks** — each with its own test cycle.
3. **Red, green, refactor** — a failing test first; a security fix is only accepted with a regression test that was seen to fail.
4. **Two-axis review** — does it follow our standards, and does it implement the specification.
5. **Evidence before "done"** — the verification command is run and its output read before anything is called complete.
6. **Security gate** — §12 checklist before release.

## 10. Vulnerability management and disclosure

| Severity | Platform fix target | SDK fix target |
|---|---|---|
| Critical | 7 days | Emergency release within 72 h, plus kill switch if needed |
| High | 30 days | 14 days |
| Medium | 90 days | Next scheduled release |
| Low | Best effort | Best effort |

- A `security.txt` file, a dedicated reporting address and a published policy with safe-harbour language.
- Acknowledgement within 2 business days, triage within 5.
- Coordinated disclosure; advisories for every SDK vulnerability with affected versions and upgrade path.
- Severity scored with CVSS v4.0; Findings from Prove use the same scale.

## 11. Security incident response

Platform security incidents use the incident process in OPERATION.md §8 with these additions: evidence preservation before remediation; tenant notification without undue delay and within contractual and legal deadlines; a public post-incident report for anything affecting SDK integrity. Runbooks: signing-key compromise (RB-06), malicious or faulty SDK release (RB-05), suspected sandbox escape (RB-09), suspected cross-tenant exposure (RB-10).

## 12. Release security gate

A release ships only when every line is true:

- [ ] Threat model updated for every changed trust boundary.
- [ ] No open Critical or High vulnerability in code, dependencies or images.
- [ ] Cross-tenant matrix, authorization matrix and privacy schema tests pass.
- [ ] SDK artifacts are reproducible, signed and carry provenance and a bill of materials.
- [ ] Our own Builds pass the RRS gate; no new High Finding from the staging Pentest Campaign.
- [ ] Prompt-injection evaluations pass.
- [ ] Kill switches and rollback were exercised in staging for this release.
- [ ] Audit events exist for every new administrative action.

## 13. Compliance roadmap

| Target | Proposed timing | Notes |
|---|---|---|
| Public security page, sub-processor list, data-processing agreement | At general availability | — |
| SOC 2 Type I, then Type II | Within 6 and 15 months of general availability | Controls here are written to map to the trust criteria |
| ISO/IEC 27001 | After SOC 2 Type II | — |
| Framework mappings in reports | MVP ("should") | MASVS-RESILIENCE, OWASP API Top 10, OWASP Automated Threats |
| Secure development alignment | Ongoing | NIST SSDF practices; SLSA build provenance for SDKs |

Timings are proposals pending your decision on the first customer segment (PRD §17, Q1).

## 14. Residual risks

| Risk | Why it remains | Stance |
|---|---|---|
| A skilled attacker defeats Guard for one Build | The client is under their control | Detect, diversify the next Build, never rely on Guard alone |
| A zero-day in an isolation layer | No isolation is perfect | Separate account, no credentials in sandboxes, short lifetimes |
| An owner misuses a legitimately verified target | Ownership is not intent | Rules of Engagement, audit, Acceptable Use Policy |
| Model behaviour changes between versions | Providers update models | Pin versions, re-baseline RRS on change, show the configuration with every score |
| False confidence from a high RRS | A score invites over-trust | Scope statement next to every score; human red-team calibration |
