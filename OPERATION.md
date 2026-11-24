---
title: "Airverse — Operation"
aliases: [OPERATION]
project: anti-reverse
doc: OPERATION
version: 0.1.0
status: approved
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - spec/operation
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"
  - "[[MEMORY]]"
---

# Airverse — Operation

How Airverse is built, released, run and recovered — by the team operating the cloud, and by customers operating the parts that live in their environment. Targets come from [PERFORMANCE.md](PERFORMANCE.md); controls from [SECURITY.md](SECURITY.md).

---

## 1. Operating model

| Part | Runs in | Operated by | If it fails |
|---|---|---|---|
| Harden CLI and plugins | Customer CI | Customer | Build fails loudly; `--skip` flag ships unprotected with a recorded warning |
| Guard | Customer's shipped client | Customer deploys; Airverse can disable remotely | Application continues without Guard |
| Shield | Customer backend | Customer | Fail-open by default; local environment switch disables it |
| Edge: Attestation, Ingest, Policy CDN | Airverse cloud, multi-region | Airverse | Shield keeps last bundle; attestation grace period |
| Control plane, Radar, Console | Airverse cloud | Airverse | Enforcement continues locally; visibility and updates pause |
| Prove sandboxes | Isolated Airverse account | Airverse | Assessments queue or report `inconclusive` |

**First rule of operation:** the customer's product stays up. Every procedure below prefers a temporary loss of protection to a loss of availability, unless the customer marked a route fail-closed.

## 2. Environments

| Environment | Purpose | Data | Change path |
|---|---|---|---|
| Local | Development with all services in containers and the reference target `ar-range` | Synthetic | — |
| Preview | Per-pull-request deployment of Console and API | Synthetic | Automatic, destroyed on merge |
| Staging | Production-shaped; continuous Pentest Campaigns and nightly suites run here | Synthetic | Automatic from main |
| Production | Customers | Real | Progressive delivery (§5) |
| Prove (isolated) | Sandboxes only; no route to core | Tenant artifacts in transit | Automated image pipeline |

Production data never leaves production. Tests use synthetic data only.

## 3. Infrastructure

- Topology, accounts and regions: SDD §17.
- Everything is defined as code and changed only through reviewed pull requests; console changes in the cloud provider are alarmed.
- Images are minimal and immutable; a rebuild, not a patch-in-place, delivers every fix.
- Secrets come from the secret manager at start; none in images, repositories or CI variables beyond federated identity.

## 4. Development workflow

Applies to humans and coding agents alike. It is the methodology of the references in PRD §19, written as our own rules.

| Step | Rule | Evidence required |
|---|---|---|
| 1 Design | No code before an approved design: intent, goals, non-goals, anti-goals, approaches, threat-model delta | Design document approved by a human |
| 2 Slice | Work is cut into tracer-bullet tickets — thin, end-to-end, demoable — each declaring what blocks it | Ticket list with blocking edges |
| 3 Plan | Each ticket gets a plan of small tasks, every task with its own test cycle and exact interfaces | Plan linked to the spec |
| 4 Build | Red, green, refactor. Start in an isolated branch or worktree | A test seen failing, then passing |
| 5 Review | Two independent passes: standards, and conformance to the specification | Review record; critical issues block |
| 6 Verify | Run the proving command and read its output before saying "done" | Fresh command output |
| 7 Merge | Pull request states the change, before/after evidence, and a merge-danger call: one-way or two-way door, and blast radius | Completed template |
| 8 Remember | Decisions with reasons and lessons from corrections are saved when they happen (MEMORY.md §6) | Decision or lesson entry |

Branching is trunk-based with short-lived branches. Wide mechanical refactors use expand → migrate in batches → contract so main stays green.

## 5. Continuous integration and delivery

| Stage | Runs | Blocks on |
|---|---|---|
| Pull request | Formatting, types, unit, contract, integration for touched modules, security scans, hot-path benchmarks, tenant and authorization matrices | Any failure |
| Main | Build once, sign, produce bill of materials, deploy to staging | Build or signing failure |
| Staging | End-to-end, detection replay, equivalence corpus, resistance smoke test, accessibility checks | Any failure |
| Production canary | 1 % → 10 % → 50 % → 100 % with automated analysis at each step | SLO burn, error rate, **block-rate anomaly**, latency regression |
| Post-deploy | Synthetic probes for PB-13 and PB-15, SLO dashboards | Automatic rollback when probes fail |

Rules:

- **One artifact** moves through all environments; nothing is rebuilt for production.
- **Database changes** are backward-compatible with the previous release: expand, migrate, then contract in a later release.
- **Behaviour changes** ship behind flags; flags have owners and expiry dates.
- **Policy-affecting changes** (rule engine, bundle format, managed rule packs) additionally replay 24 hours of staging traffic and compare decisions before and after; any unexplained difference blocks the release.
- **Rollback** is one command and is rehearsed for every release (SECURITY.md §12).
- Services deploy on demand, typically daily. Freeze windows apply when a service has exhausted its error budget.

## 6. SDK release management

| Topic | Rule |
|---|---|
| Channels | `canary` (every merge), `beta` (weekly), `stable` (every two weeks) |
| Versioning | Semantic versioning; breaking changes only in a major, with a migration guide |
| Rollout rings | Internal dogfood → design partners → all customers |
| Support window | Each stable minor is supported for 12 months |
| Protocol compatibility | The cloud accepts the current and previous protocol major for at least 18 months after a new major |
| Deprecation | Notice in the Console and by email at least 90 days ahead; the Console flags Apps on outdated SDKs |
| Integrity | Signed, reproducible, provenance-attested releases with a bill of materials (SC-SUP-01, SC-SUP-02) |
| Emergency | Kill switch, yank, advisory — runbook RB-05 |
| Managed rule packs | Versioned like code; new rules always arrive in monitor mode |

## 7. Observability

- **Signals:** traces, metrics and structured logs through one open standard. Logs carry tenant and request identifiers and no personal data.
- **Dashboards:** one per SLO (PERFORMANCE.md §3), one per service (rate, errors, duration, saturation), one for the pipeline (lag at every stage), one for Prove (queue, sandbox count, spend), one for SDK adoption by version.
- **Product-safety metrics**, watched as closely as uptime: global and per-tenant block rate, challenge rate, rule rollback count, Guard verdict mix, Shield fail-open count, event-drop count.
- **Synthetic probes** every minute per region: emit a marked event and time its appearance; publish a marked block and time its enforcement.
- **Alerting on error-budget burn:** page at 14.4× burn over 1 hour (confirmed over 5 minutes) and at 6× over 6 hours (confirmed over 30 minutes); open a ticket at 1× over 3 days.
- Every alert links to a runbook. An alert without a runbook is a defect.

## 8. Incident management

| Severity | Definition | Response |
|---|---|---|
| SEV1 | Customer traffic wrongly blocked at scale; SDK integrity problem; cross-tenant exposure; signing-key compromise; Attestation or policy distribution down beyond the grace period | Page immediately; incident commander within 10 min; updates every 30 min; status page |
| SEV2 | A major function degraded: event lag over 5 min, Console unavailable, detections delayed, one tenant's enforcement affected | Page; updates hourly |
| SEV3 | Minor degradation with a workaround | Next business day |
| SEV4 | Cosmetic, no customer impact | Backlog |

- **Roles:** incident commander, operations lead, communications lead. One person does not hold two roles in a SEV1.
- **First move in any enforcement-related incident:** stop the harm with the smallest switch that works — rule to monitor → App to safe mode → global safe mode. Diagnose afterwards.
- **Communication:** status page for platform incidents; direct notice to affected tenants; security incidents follow SECURITY.md §11.
- **Afterwards:** a blameless review within 5 working days. Each action item becomes a regression test, a runbook change, or a lesson in MEMORY.md — otherwise it is not done.

## 9. Runbooks

| ID | Trigger | Immediate action | Resolution | Verify |
|---|---|---|---|---|
| RB-01 | Block or challenge rate anomaly; customer reports legitimate users blocked | Set the suspected rule to monitor; if unclear, App safe mode; halt rollouts | Identify the rule or signal, fix or roll back, replay traffic against the fix | Block rate back to baseline; affected tenant confirms |
| RB-02 | Ingest lag or backlog alarm | Scale consumers; confirm degradation order engaged | Remove the slow stage's bottleneck; replay from the log | Lag under threshold; freshness probe green |
| RB-03 | Attestation errors or latency over SLO | Shift traffic to the healthy region | Fix or roll back the faulty deployment | Probe green in all regions; verdict mix normal |
| RB-04 | Platform published a faulty Policy Bundle | Re-publish the previous bundle version; pin it | Fix compiler or data; add a replay test for the case | Shields report the pinned version |
| RB-05 | Faulty or malicious SDK release | Kill switch for Guard collectors; mark the version yanked; pin CDN assets to the previous version | Root cause, clean release, advisory with affected versions | Adoption dashboard shows the bad version draining |
| RB-06 | Signing-key compromise suspected | Disable the key; activate the standby key; publish a new signed key set | Re-sign bundles and remote configuration, force refresh, investigate access | All Shields accept the new key set; old key rejected |
| RB-07 | Analytics store pressure: disk, merges, slow queries | Shed per degradation order; pause heavy queries | Add capacity or adjust retention; move large tenants | Query budgets met |
| RB-08 | Volumetric or application-layer attack on edge services | Engage CDN protections and per-tenant throttles | Tune limits; block sources | SLOs recover; other tenants unaffected |
| RB-09 | Suspected sandbox escape or unexpected egress | Terminate all sandboxes; freeze the Prove account | Snapshot for forensics, rotate anything reachable, rebuild images | Clean-room test run passes; egress logs clean |
| RB-10 | Suspected cross-tenant exposure | Disable the affected feature path by flag | Scope the exposure, preserve evidence, fix, add a matrix test | Matrix suite passes; affected tenants notified |
| RB-11 | Model provider outage, rate limiting or refusal surge | Pause non-urgent AI jobs; mark Assessments `inconclusive` rather than scoring | Fail over per gateway configuration; resume queue | Queue drains; no score published without full coverage |
| RB-12 | Campaign emergency stop, or a target-impact complaint | Kill switch; destroy the Campaign machine | Review Rules of Engagement and engine behaviour; contact the tenant | No further traffic at the target |
| RB-13 | Tenant offboarding or deletion request | Confirm identity and authority | Run export, then deletion across all stores; revoke keys | Deletion report; spot check finds no records |
| RB-14 | Regional failure | Invoke failover for edge; assess the core | Restore core in the secondary region from replicas and backups | Recovery objectives in §10 met |
| RB-15 | Abuse report or Acceptable Use Policy suspicion | Suspend Prove for the Organization | Investigate with audit log and evidence; decide reinstatement or termination | Decision recorded |
| RB-16 | Customer reports Guard breaking their application | Per-App Guard kill switch | Reproduce on the compatibility matrix, fix, add the case to the false-positive corpus | Customer confirms; corpus test passes |

**RB-01 in detail (the one that matters most).**

1. Acknowledge. Open the *Enforcement health* dashboard: which App, which rule, since when.
2. Stop the harm: rule → monitor. If more than one rule or the cause is unknown: App safe mode (all rules observe). If several tenants are affected by a platform change: global safe mode and halt the rollout.
3. Confirm with the synthetic block probe and the tenant that legitimate traffic flows.
4. Diagnose using the decision evidence stored with each event: rule, signals, policy version, SDK version.
5. Fix forward or roll back. Replay the incident window against the fix before re-enabling.
6. Re-enable through a percentage rollout.
7. Review: add the traffic pattern to the benign replay set so it cannot regress.

**RB-06 in detail.**

1. Disable the suspected key in the key service; this stops new signatures immediately.
2. Promote the standby key (pre-provisioned, already trusted through the signed key set chain).
3. Publish the updated key set, signed by the root verification key embedded in the SDKs.
4. Re-sign and re-publish every active Policy Bundle and remote configuration; trigger a forced refresh over the push channel.
5. Review key-service audit logs for every use of the old key; identify any artifact it signed after the suspected compromise time.
6. Notify tenants per SECURITY.md §11. Rotate anything else the same access path could reach.

## 10. Backup, restore and disaster recovery

| Component | Recovery point | Recovery time | Method |
|---|---|---|---|
| Edge services | 0 (stateless) | ≤ 15 min, automatic | Multi-region active-active |
| PostgreSQL | ≤ 5 min | ≤ 60 min | Multi-zone, continuous archiving, cross-region replica |
| Event log | 0 for acknowledged events in-region; ≤ 15 min cross-region | ≤ 60 min | Replication factor three; cross-region archive |
| Analytics store | ≤ 15 min | ≤ 2 h | Replicated shards; rebuild from the archive when needed |
| Object store | 0 | ≤ 60 min | Versioning and cross-region replication |
| Signing keys | 0 | ≤ 15 min | Multi-region keys; standby keys pre-provisioned |
| Console | — | ≤ 60 min | Redeploy from the artifact |

- Backups are encrypted and retained 35 days.
- A restore of one store is tested every month; a full regional failover drill runs every quarter.
- A recovery that has not been rehearsed is treated as non-existent.

> **As built (slice 18h, 2026-11-24).** None of the above exists yet. What exists is a cold copy for the local embedded database: with the API stopped, `npm run data:backup -- --to <directory>` copies the data directory and the key files beside it, and `npm run data:restore -- --from <directory> --data-dir <directory> [--force]` verifies the copy and puts it back (README, "Backup and restore"). It has no schedule, no encryption, no second location and no point-in-time recovery. The release gate rehearses it locally (`gate-rollback-local`); that is not the rollback of a deployment that §5 asks for.

## 11. Capacity and cost

- Weekly review of the capacity model (PERFORMANCE.md §10) against measured growth; scale-ahead threshold at 60 % of the design point.
- Per-tenant quotas enforced at the edge; a tenant at 80 % of a quota sees it in the Console before it bites.
- Monthly cost review by unit metric (PERFORMANCE.md §11); anomalies above 20 % month-over-month get an owner.
- Model and sandbox spend have hard ceilings per tenant and globally, with alerts at 50 %, 80 % and 100 %.

## 12. Access and change management

- Production access is just-in-time, time-boxed, approved and recorded (SC-IAM-06). Access rights are reviewed monthly.
- Break-glass accounts are sealed, alarmed and tested quarterly.
- Changes outside the pipeline are prohibited; emergencies use the same pipeline with an expedited review and a retrospective.
- Customer-visible switches — safe mode, kill switches — require step-up authentication and can require two approvers (SC-IAM-03).

## 13. Security operations

| Activity | Cadence |
|---|---|
| Attestation key rotation | Daily, automated |
| Bundle-signing key rotation | Quarterly |
| Tenant data-key re-wrap | Yearly |
| Root verification key | Long-lived; a successor is embedded in SDKs well before rotation |
| Dependency and image patching | Critical within 7 days; routine weekly |
| Vulnerability triage | Per SECURITY.md §10 |
| Abuse desk review of manual-review targets | Within 1 business day |
| Platform security monitoring review | Daily |

## 14. Operating Prove

- **Engine upgrades.** Pin the new version → run the full reference suite on `ar-range` in staging → compare RRS and Findings with the previous version → promote only when differences are explained.
- **Model changes.** A new model or model version is a configuration change: re-baseline RRS on the reference corpus, record a new configuration identifier, and show it with every score. Scores from different configurations are never compared silently.
- **Calibration.** Quarterly human red-team scoring of the reference target; divergence above 15 points opens a rubric review.
- **Sandbox images** are rebuilt weekly and on every engine change.
- **Tier scheduling.** T1 on every Build, T2 nightly on the latest Build per App, T3 before a release when requested.
- **Licences.** Engines are built from source at pinned commits; licence and usage terms are reviewed at each upgrade.

## 15. Customer operations guide

The rollout that keeps customers safe — also the default path in the Console.

| Phase | Customer does | Result |
|---|---|---|
| Day 0 — Install | Add Shield in monitor mode, Guard in report-only, Harden on `balanced` for staging | First protected request visible; nothing can break |
| Days 1–7 — Learn | Review "would have blocked", tune rules, run policy simulation | Confidence in rule behaviour |
| Day 7+ — Enforce | Promote managed rules with 10 % → 50 % → 100 % rollout; set fail stance per route; enable Playbooks with a TTL | Protection active |
| Ongoing — Prove | RRS gate in CI; Pentest Campaigns against staging; weekly review | Regressions caught before release |

Rollback options, fastest first: rule to monitor (Console, seconds) → App safe mode (Console, seconds) → local Shield switch by environment variable (customer deploy) → Guard kill switch (minutes).

## 16. Support

| Plan | Channel | First response target |
|---|---|---|
| Free | Community and documentation | — |
| Pro | Email | 1 business day |
| Business | Email and chat | 4 business hours; SEV1 1 hour |
| Enterprise | Dedicated channel, named contact | SEV1 30 minutes, 24×7 |

Targets are proposals pending the packaging decision (PRD §12). A public status page covers every SLO-bearing service.

## 17. Data operations

- Retention is enforced by time-to-live in the analytics store and nightly jobs elsewhere; defaults in SECURITY.md §8.
- Deletion and export requests complete within 30 days and produce a report.
- Regional placement is verified by an automated check that fails when tenant data is found outside its region.
- Audit logs are retained at least one year and are exportable.

## 18. Operational calendar

| Cadence | Activities |
|---|---|
| Daily | SLO and enforcement-health review; abuse queue; security monitoring review |
| Weekly | Design-point load test; dependency updates; sandbox image rebuild; false-positive review |
| Monthly | Restore test; access review; cost review; SDK adoption review |
| Quarterly | Failover drill; internal red team; RRS calibration; key rotation; break-glass test; tabletop exercise for one SEV1 scenario |
| Yearly | Independent penetration test; policy and runbook review; disaster-recovery plan review |

## 19. Launch readiness

- [ ] Every SLO has a dashboard, an alert and a runbook.
- [ ] Safe mode, kill switches and rollback exercised in production-like conditions.
- [ ] Restore test and failover drill passed.
- [ ] On-call rota staffed; escalation paths tested.
- [ ] Status page, security page, data-processing agreement and sub-processor list published.
- [ ] All release gates in QASUITE.md §16 and SECURITY.md §12 green.
- [ ] Design partners have run the customer rollout (§15) to full enforcement.
