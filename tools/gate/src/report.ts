// The gate report (slice 18e): a JSON document (signed) and its Markdown rendering, written under
// reports/gate/<timestamp>/. The Markdown is a view of the JSON; only the JSON carries the signature.
import type { Gap } from "./catalog.ts";
import type { Signature } from "./sign.ts";
import type { State } from "./verdict.ts";

export interface ReportCriterion {
  id: string;
  title: string;
  state: State;
  source: { doc: string; section: string; line: number | null; text: string };
  checks: string[];
  gaps: Gap[];
  requires: string[];
  notes: string[];
  reasons: string[];
}

export interface ReportCheck {
  id: string;
  title: string;
  state: State;
  summary: string;
  command: string | null;
  duration_ms: number | null;
  excerpt: string | null;
  measurements: Record<string, number | string>;
}

export interface Report {
  schema: "airverse.release-gate/1";
  generated_at: string;
  duration_ms: number;
  git: { commit: string; branch: string; dirty: boolean };
  tools: Record<string, string>;
  options: { only: string[] | null; skip_slow: boolean; online: boolean };
  /** True with --only: the other checks were not run, so the verdict covers less than a full gate. */
  partial: boolean;
  verdict: "releasable" | "blocked";
  all_checkable_passed: boolean;
  exit_code: number;
  reasons: string[];
  criteria: ReportCriterion[];
  checks: ReportCheck[];
  signature?: Signature;
}

const cell = (text: string) => text.replace(/\|/g, "\\|").replace(/\n/g, " ");

export function renderMarkdown(report: Report): string {
  const out: string[] = [];
  const yesNo = (b: boolean) => (b ? "yes" : "no");
  out.push("# Release gate report", "");
  out.push(`**Verdict: ${report.verdict}** (exit ${report.exit_code})`, "");
  out.push(
    `Every checkable criterion passed: ${yesNo(report.all_checkable_passed)}${report.partial ? " (partial run: --only)" : ""}`,
    "",
  );
  const counts = (["pass", "fail", "not-checkable"] as const).map(
    (s) => `${report.criteria.filter((c) => c.state === s).length} ${s}`,
  );
  out.push(`Criteria: ${counts.join(" · ")}`, "");
  out.push(
    `- Commit: \`${report.git.commit}\` on \`${report.git.branch}\`${report.git.dirty ? " (working tree dirty)" : ""}`,
    `- Generated: ${report.generated_at} in ${Math.round(report.duration_ms / 1_000)} s`,
    `- Options: only ${report.options.only?.join(", ") ?? "all"} · skip-slow ${yesNo(report.options.skip_slow)} · online ${yesNo(report.options.online)}`,
    `- Tools: ${Object.entries(report.tools)
      .map(([k, v]) => `${k} ${v}`)
      .join(" · ")}`,
  );
  if (report.signature) {
    out.push(
      `- Signature: ${report.signature.algorithm}, key fingerprint \`${report.signature.fingerprint}\` (signed: report.json; check with \`npm run gate:verify-report <report.json>\`)`,
    );
  }
  out.push("", "## Criteria", "", "| Criterion | State | Source | Checks |", "|---|---|---|---|");
  for (const c of report.criteria) {
    const source = `${c.source.doc}:${c.source.line ?? "?"} §${c.source.section} — ${c.source.text}`;
    const checks = [...c.checks, ...c.requires.map((r) => `→ ${r}`)].join(", ") || "—";
    out.push(`| ${c.id} | ${c.state} | ${cell(source)} | ${cell(checks)} |`);
  }
  if (report.reasons.length > 0) {
    out.push("", "## Why it is blocked", "");
    for (const reason of report.reasons) out.push(`- ${reason}`);
  }
  const noted = report.criteria.filter((c) => c.notes.length > 0);
  if (noted.length > 0) {
    out.push("", "## Notes", "");
    for (const c of noted) for (const note of c.notes) out.push(`- **${c.id}**: ${note}`);
  }
  const unchecked = report.criteria.filter((c) => c.gaps.length > 0);
  if (unchecked.length > 0) {
    out.push("", "## Not checkable", "");
    for (const c of unchecked) {
      for (const gap of c.gaps) out.push(`- **${c.id}**: ${gap.reason} (slice ${gap.slice})`);
    }
  }
  out.push("", "## Checks");
  for (const check of report.checks) {
    out.push("", `### ${check.id} — ${check.state}`, "", check.title, "", `- Result: ${check.summary}`);
    if (check.command) out.push(`- Command: \`${check.command}\``);
    if (check.duration_ms !== null) out.push(`- Duration: ${(check.duration_ms / 1_000).toFixed(1)} s`);
    const m = Object.entries(check.measurements);
    if (m.length > 0) out.push(`- Measured: ${m.map(([k, v]) => `${k} = ${v}`).join(" · ")}`);
    if (check.excerpt) out.push("", "```text", check.excerpt.replace(/```/g, "ʼʼʼ"), "```");
  }
  return `${out.join("\n")}\n`;
}
