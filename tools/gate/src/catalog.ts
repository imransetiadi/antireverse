// The release-gate catalog (slice 18e): one entry per checklist line of QASUITE §16 (release exit criteria) and
// SECURITY §12 (release security gate). Each entry lists the checks that run today, the parts that cannot be checked
// yet (with the reason and the slice expected to add the check), and the entries it requires. A test reads both
// documents and fails on a line without an entry, or an entry without a line.

import { checklist } from "./docs.ts";

export const CHECKS = {
  verify: {
    title: "Lint, types, unit, integration and HTTP e2e tests (npm run verify)",
    slow: true,
    online: false,
  },
  "e2e-browser": { title: "Playwright browser journeys (npm run e2e)", slow: true, online: false },
  "matrix-audit": {
    title: "Audit-coverage matrix (every administrative route writes an audit entry)",
    slow: false,
    online: false,
  },
  "matrix-tenant": { title: "Cross-tenant isolation tests", slow: false, online: false },
  "matrix-authz": { title: "Authorization tests (key kinds, 401/403)", slow: false, online: false },
  "matrix-privacy": {
    title: "Privacy schema tests (Event allowlist, nothing else leaves or is stored)",
    slow: false,
    online: false,
  },
  "rrs-stand-in": {
    title: "Stand-in RRS regression: the slice-13 RRS gate on the reference Build at the recorded baseline (D-097)",
    slow: false,
    online: false,
  },
  "campaign-safety": {
    title:
      "Pentest Campaign safety: the request gate, the pinned transport, the scope-escape and kill-switch suite and the never-destructive suite (slice 15a)",
    slow: false,
    online: false,
  },
  "upgrade-local": {
    title:
      "Local schema upgrade: a database seeded at every migration prefix is upgraded to the head (slice 18h); not an SDK upgrade",
    slow: false,
    online: false,
  },
  "rollback-local": {
    title:
      "Local rollback rehearsal: the backup and restore commands, and backup, upgrade, restore, serve on one data directory (slice 18h); not staging",
    slow: false,
    online: false,
  },
  "kill-switch-drill": {
    title:
      "Local kill-switch drill: every switch that exists thrown and taken back over HTTP, with what the API records of each (slice 18h); not staging",
    slow: false,
    online: false,
  },
  "bench-shield": { title: "Shield overhead bench against PB-01 and PB-02", slow: true, online: false },
  "load-smoke": {
    title: "Local load smoke of the API against PB-21, SLO-02 and SLO-01 (client-side percentiles)",
    slow: false,
    online: false,
  },
  "npm-audit": { title: "npm audit: no High or Critical dependency vulnerability", slow: false, online: true },
} as const satisfies Record<string, { title: string; slow: boolean; online: boolean }>;

export type CheckId = keyof typeof CHECKS;
export const CHECK_IDS = Object.keys(CHECKS) as CheckId[];

export interface Gap {
  /** Why this part cannot be checked yet. */
  reason: string;
  /** The slice expected to add the check (PRD §18), or `unplanned`. */
  slice: string;
}

export interface Criterion {
  id: string;
  title: string;
  /** A checklist line of QASUITE §16 or SECURITY §12, or (doc `gate`) a criterion of the gate's own. */
  source: { doc: "QASUITE.md" | "SECURITY.md" | "gate"; section: string; text: string };
  checks: string[];
  gaps: Gap[];
  /** Other criteria this one includes (QASUITE "Security release gate complete"). */
  requires: string[];
  /** Facts the report shows beside the criterion without changing its state. */
  notes?: string[];
  /** The gate's own consistency check: shown and able to block, never counted as a checkable criterion that passed. */
  integrity?: true;
}

export const SOURCES = [
  { doc: "QASUITE.md", section: "16" },
  { doc: "SECURITY.md", section: "12" },
] as const;

const qa = (text: string) => ({ doc: "QASUITE.md", section: "16", text }) as const;
const sec = (text: string) => ({ doc: "SECURITY.md", section: "12", text }) as const;

export const CRITERIA: readonly Criterion[] = [
  {
    id: "qa16-gates",
    title: "Quality gates G0–G4",
    source: qa("Gates G0–G4 green on the release candidate."),
    checks: ["verify", "e2e-browser", "matrix-tenant", "matrix-authz", "bench-shield", "load-smoke"],
    gaps: [
      {
        reason:
          "G0–G4 also need a secret scan, security scans, detection replay, the equivalence corpus, accessibility checks, compatibility matrices, RRS at T2 and T3, a staging Pentest Campaign, fuzzing, a chaos subset, AI evaluations and a full load test; none has a runner yet",
        slice: "18",
      },
    ],
    requires: [],
  },
  {
    id: "qa16-resistance",
    title: "TC-PRV-006 thresholds",
    source: qa("TC-PRV-006 thresholds met; no Objective regressed by a tier."),
    checks: [],
    gaps: [
      {
        reason:
          "TC-PRV-006 needs a real AI agent: real assessments wait for the owner's model provider key and spend caps (D-067); only the stand-in runs locally, and its score is tracked against a baseline instead (gate-rrs-regression, D-097)",
        slice: "unplanned",
      },
      {
        reason: "'no Objective regressed by a tier' needs the previous release's Assessment results; none are kept",
        slice: "18",
      },
    ],
    requires: [],
  },
  {
    id: "qa16-detection",
    title: "Detection recall and false positives",
    source: qa("Detection recall ≥ 95 % and false positives ≤ 0.1 % per rule pack."),
    checks: [],
    gaps: [
      {
        reason: "no labelled attack and benign corpus per rule pack exists to measure recall and false positives",
        slice: "unplanned",
      },
    ],
    requires: [],
  },
  {
    id: "qa16-real-browser",
    title: "Real-browser corpus trusted",
    source: qa("Real-browser corpus ≥ 99.9 % `trusted`."),
    checks: [],
    gaps: [{ reason: "no real-browser corpus or device farm runs Guard attestation at scale", slice: "unplanned" }],
    requires: [],
  },
  {
    id: "qa16-performance",
    title: "Performance budgets",
    source: qa("All performance budgets met; no unaccepted regression."),
    checks: ["bench-shield", "load-smoke"],
    gaps: [
      {
        reason:
          "only PB-01, PB-02, PB-21, SLO-01 and SLO-02 are measured here; PB-13 and PB-15 are timed by the API's synthetic probes (AR_PROBES=1, slice 18g) inside one running instance against one local Shield, without load and not run by this gate, which is not the budget's measurement; PB-03–PB-20 and PB-22 need Redis, browsers, mobile profiles, the pipeline under load or the Harden corpus, and regressions need a stored baseline",
        slice: "18",
      },
    ],
    requires: [],
  },
  {
    id: "qa16-defects",
    title: "No open S1/S2, no new High/Critical pentest Finding",
    source: qa("No open S1 or S2; no new High or Critical Finding from TS-PENTEST."),
    checks: [],
    gaps: [
      { reason: "defects are not tracked in a system the gate can read", slice: "unplanned" },
      {
        reason:
          "TS-PENTEST needs a Campaign with a real engine against a staging target; slice 15a has the pipeline with a scripted stand-in, which is not a penetration test (its safety controls: gate-campaign-safety)",
        slice: "15b",
      },
    ],
    requires: [],
  },
  {
    id: "qa16-security-gate",
    title: "Security release gate complete",
    source: qa("Security release gate (SECURITY.md §12) complete."),
    checks: [],
    gaps: [],
    requires: [
      "sec12-threat-model",
      "sec12-vulnerabilities",
      "sec12-isolation",
      "sec12-sdk-artifacts",
      "sec12-rrs-pentest",
      "sec12-prompt-injection",
      "sec12-kill-switches",
      "sec12-audit-events",
    ],
  },
  {
    id: "qa16-upgrade",
    title: "Upgrade path from every SDK minor",
    source: qa("Upgrade path tested from every supported SDK minor."),
    checks: [],
    gaps: [
      {
        reason:
          "no SDK minor has been released, so there is no SDK upgrade path to test; what can be tested without a release is the database schema: every migration prefix with seeded data upgrades to the head (gate-upgrade-local, slice 18h), which says nothing about an older Shield, Guard or Harden against this API",
        slice: "unplanned",
      },
    ],
    requires: [],
  },
  {
    id: "qa16-rollback",
    title: "Rollback rehearsed",
    source: qa("Rollback rehearsed."),
    checks: [],
    gaps: [
      {
        reason:
          "there is no staging deployment to rehearse a rollback on, and no build of a previous version to roll back to; locally the data rollback is rehearsed — backup, upgrade, restore, serve on one data directory (gate-rollback-local, slice 18h) — while the previous version's code on the upgraded schema, the one-command rollback of a deployment and the automatic rollback after failed probes are not",
        slice: "18",
      },
    ],
    requires: [],
  },
  {
    id: "sec12-threat-model",
    title: "Threat model updated",
    source: sec("Threat model updated for every changed trust boundary."),
    checks: [],
    gaps: [
      {
        reason: "a human review of SECURITY §4–§6 against the release's changes; not machine-checkable",
        slice: "unplanned",
      },
    ],
    requires: [],
  },
  {
    id: "sec12-vulnerabilities",
    title: "No open Critical/High vulnerability",
    source: sec("No open Critical or High vulnerability in code, dependencies or images."),
    checks: ["npm-audit"],
    gaps: [{ reason: "no static analysis of our code and no container images to scan exist yet", slice: "18" }],
    requires: [],
  },
  {
    id: "sec12-isolation",
    title: "Cross-tenant, authorization and privacy tests",
    source: sec("Cross-tenant matrix, authorization matrix and privacy schema tests pass."),
    checks: ["matrix-tenant", "matrix-authz", "matrix-privacy"],
    gaps: [],
    requires: [],
  },
  {
    id: "sec12-sdk-artifacts",
    title: "SDK artifacts reproducible and signed",
    source: sec("SDK artifacts are reproducible, signed and carry provenance and a bill of materials."),
    checks: [],
    gaps: [
      {
        reason: "no SDK release pipeline exists (no published artifacts, signatures, provenance or SBOM)",
        slice: "18",
      },
    ],
    requires: [],
  },
  {
    id: "sec12-rrs-pentest",
    title: "Own Builds pass the RRS gate; no new High pentest Finding",
    source: sec("Our own Builds pass the RRS gate; no new High Finding from the staging Pentest Campaign."),
    checks: [],
    gaps: [
      {
        reason:
          "the RRS gate's thresholds need a real AI agent (D-097); the stand-in's score is tracked against a baseline instead (gate-rrs-regression)",
        slice: "unplanned",
      },
      {
        reason:
          "the staging Pentest Campaign needs a real engine and a staging target; slice 15a's Campaigns run a scripted stand-in, whose Findings say nothing about real exposure (its safety controls: gate-campaign-safety)",
        slice: "15b",
      },
    ],
    requires: [],
  },
  {
    id: "sec12-prompt-injection",
    title: "Prompt-injection evaluations",
    source: sec("Prompt-injection evaluations pass."),
    checks: [],
    gaps: [
      {
        reason: "the AI evaluation suite (TS-AI) needs a real model; only the stand-in agent runs (D-067)",
        slice: "unplanned",
      },
    ],
    requires: [],
  },
  {
    id: "sec12-kill-switches",
    title: "Kill switches and rollback exercised in staging",
    source: sec("Kill switches and rollback were exercised in staging for this release."),
    checks: [],
    gaps: [
      {
        reason:
          "there is no staging environment to exercise them in, and nothing records an exercise per release; locally every switch that exists is thrown and taken back by gate-kill-switch-drill (with gate-campaign-safety for running Campaigns) and the data rollback is rehearsed by gate-rollback-local (slice 18h); App safe mode, global safe mode and the Guard kill switch do not exist yet",
        slice: "18",
      },
    ],
    requires: [],
  },
  {
    id: "sec12-audit-events",
    title: "Audit events for every administrative action",
    source: sec("Audit events exist for every new administrative action."),
    checks: ["matrix-audit"],
    gaps: [],
    requires: [],
  },
  {
    id: "gate-rrs-regression",
    title: "Stand-in RRS does not regress",
    source: {
      doc: "gate",
      section: "D-097",
      text: "The stand-in agent's RRS on the reference Build stays at or above the baseline in tools/gate/baselines/rrs-stand-in.json.",
    },
    checks: ["rrs-stand-in"],
    gaps: [],
    requires: [],
    notes: [
      "Baseline recorded 2026-11-14: balanced 24, maximum 24 (stand-in, T1).",
      "W4 Tamper is achieved because an ES module Build gets no integrity check (Harden --integrity refuses ESM input): a Harden follow-up.",
    ],
  },
  {
    id: "gate-campaign-safety",
    title: "Pentest Campaigns stay in scope and stop on a kill switch",
    source: {
      doc: "gate",
      section: "D-105",
      text: "No Campaign request leaves its scope (redirects, a changing resolver, private addresses, excluded paths, other methods, absolute URLs, the budgets), and the owner's stop and the operator's kill switch end a Campaign at once: proven from the test target's own request log.",
    },
    checks: ["campaign-safety"],
    gaps: [],
    requires: [],
    notes: [
      "The engine is the scripted stand-in of slice 15a: it measures the pipeline and its safety controls. This is not a penetration test.",
      "The request gate is application code in the API process: there is no VM or egress proxy behind it (ticket 15a, honest limits).",
    ],
  },
  {
    id: "gate-upgrade-local",
    title: "Every earlier schema version upgrades to the head with its data",
    source: {
      doc: "gate",
      section: "D-120",
      text: "A database at every migration prefix below the head, holding a seeded row in every table of that version, is upgraded to the head by the start-up path: every row and value survives and can still be written, each audit chain verifies, row-level security isolates the tenants, the API serves the data through its routes with the keys seeded at the first migration, and a second migration run applies nothing.",
    },
    checks: ["upgrade-local"],
    gaps: [],
    requires: [],
    notes: [
      "No version has been released: 'a previous version' here is a migration prefix (the schema after 0001…K), not a release and not an SDK upgrade.",
      "The seeds are written against each version's columns, checks and triggers; the JSON inside them (Event payloads, Build manifests, Policy rules) has today's shape, because no older writer exists to copy.",
      "PGlite in memory, a few rows per table: this says nothing about the time or the locks of a migration on a large database.",
    ],
  },
  {
    id: "gate-rollback-local",
    title: "The backup taken before an upgrade restores, and the API serves it",
    source: {
      doc: "gate",
      section: "D-121",
      text: "A data directory at the schema before the head, with its key files, is backed up by the backup command, upgraded by an API start and written to; the restore command then puts back the old schema, every row and the key files byte for byte, and the API started on it serves the state from before the upgrade: the Shield key authenticates, the Policy Bundle verifies under the same public key, the attestation keys load and the audit chains verify.",
    },
    checks: ["rollback-local"],
    gaps: [],
    requires: [],
    notes: [
      "This is a data rollback: restoring a cold backup (npm run data:backup, npm run data:restore). Everything written after the backup is lost. Only a data directory is ever replaced, and only with --force.",
      "The previous version's code on the upgraded schema is not rehearsed: no build of a previous version exists, and the only code there is migrates the restored directory forward again when it starts.",
      "One process on one machine, temporary directories: not a deployment, not staging, and no backup schedule or off-site copy exists.",
    ],
  },
  {
    id: "gate-kill-switch-drill",
    title: "Every kill switch that exists works, on and off",
    source: {
      doc: "gate",
      section: "D-123",
      text: "Each switch is thrown, its effect observed, taken back, and normal behaviour observed again, over HTTP: a Rule set back to monitor and a Policy roll back as a real Shield applies them, AR_SHIELD_DISABLED and Shield's disabled option on a Shield in front of a handler, the operator's Campaign kill switch and the suspension of one Organization, and the service flag AR_PROVE_CAMPAIGNS; with what the API records of each read back (an audit entry where the switch writes one, the switch's own state where it does not).",
    },
    checks: ["kill-switch-drill", "campaign-safety"],
    gaps: [],
    requires: [],
    notes: [
      "App safe mode, global safe mode and the Guard kill switch do not exist in code yet (OPERATION §15 names them): nothing is drilled for them.",
      "Local: one API process and one Shield on loopback, a Shield that polls every 250 ms (the default is 5 s). This is not a drill in staging.",
      "AR_SHIELD_DISABLED and AR_PROVE_CAMPAIGNS are read at start: the drill starts a new Shield or API with the variable, as a redeploy would. Neither leaves an audit entry.",
      "Lifting the Campaign kill switch writes no audit entry: it is recorded in the switch's own state (read back by the drill) and in the API's log. Throwing it, and suspending or resuming an Organization, each write one in the affected Organization's chain.",
    ],
  },
];

/** Catalog errors: duplicate ids, unknown checks or requirements, empty entries, requirement cycles. */
export function validateCatalog(criteria: readonly Criterion[], checks: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const ids = new Set<string>();
  for (const c of criteria) {
    if (ids.has(c.id)) errors.push(`duplicate id ${c.id}`);
    ids.add(c.id);
    for (const check of c.checks) if (!(check in checks)) errors.push(`${c.id}: unknown check ${check}`);
    if (c.checks.length + c.gaps.length + c.requires.length === 0) errors.push(`${c.id}: no check, gap or requirement`);
  }
  for (const c of criteria)
    for (const r of c.requires) if (!ids.has(r)) errors.push(`${c.id}: unknown requirement ${r}`);
  const byId = new Map(criteria.map((c) => [c.id, c]));
  const visit = (id: string, path: string[]): void => {
    if (path.includes(id)) {
      errors.push(`requirement cycle: ${[...path, id].join(" → ")}`);
      return;
    }
    for (const r of byId.get(id)?.requires ?? []) if (byId.has(r)) visit(r, [...path, id]);
  };
  for (const c of criteria) visit(c.id, []);
  return [...new Set(errors)];
}

/**
 * The catalog against the documents (review M3): every checklist line of each source maps to exactly one entry, and
 * every entry of a source is a line of it. Run by the gate itself, so drift fails the release, not only a test.
 */
export function catalogDrift(
  docs: Readonly<Record<string, string>>,
  criteria: readonly Criterion[] = CRITERIA,
): string[] {
  const problems: string[] = [];
  for (const { doc, section } of SOURCES) {
    const text = docs[doc];
    if (text === undefined) {
      problems.push(`${doc}: not read`);
      continue;
    }
    let lines: string[];
    try {
      lines = checklist(text, section).map((l) => l.text);
    } catch (error) {
      problems.push(`${doc} §${section}: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }
    const own = criteria.filter((c) => c.source.doc === doc);
    for (const line of lines) {
      const n = own.filter((c) => c.source.text === line).length;
      if (n === 0) problems.push(`${doc} §${section}: unmapped line "${line}"`);
      if (n > 1) problems.push(`${doc} §${section}: line "${line}" has ${n} entries`);
    }
    for (const entry of own) {
      if (!lines.includes(entry.source.text)) {
        problems.push(`stale entry ${entry.id}: "${entry.source.text}" is not a line of ${doc} §${section}`);
      }
    }
  }
  return problems;
}
