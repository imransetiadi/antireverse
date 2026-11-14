// Reading the specification documents: the checklist lines of a section (QASUITE §16, SECURITY §12) and the latency
// targets of PERFORMANCE §2, so that the gate's catalog and thresholds follow the documents instead of copies.

export interface ChecklistLine {
  /** 1-based line number in the document. */
  line: number;
  text: string;
}

function sectionBounds(markdown: string, number: string): { start: number; end: number; lines: string[] } {
  const lines = markdown.split("\n");
  const start = lines.findIndex((l) => l.startsWith(`## ${number}. `));
  if (start < 0) throw new Error(`no section §${number}`);
  let end = lines.findIndex((l, i) => i > start && l.startsWith("## "));
  if (end < 0) end = lines.length;
  return { start, end, lines };
}

/** The text of section `## <number>. …` up to the next `## ` heading, trimmed. */
export function section(markdown: string, number: string): string {
  const { start, end, lines } = sectionBounds(markdown, number);
  return lines
    .slice(start + 1, end)
    .join("\n")
    .trim();
}

/** The top-level checklist lines (`- [ ] …` or `- [x] …`) of a section. */
export function checklist(markdown: string, number: string): ChecklistLine[] {
  const { start, end, lines } = sectionBounds(markdown, number);
  const out: ChecklistLine[] = [];
  for (let i = start + 1; i < end; i++) {
    // Any list marker (-, *, +, 1. or 1)), any spacing; at most one leading space, so nested lines are not criteria.
    const match = /^ ?(?:[-*+]|\d+[.)])\s+\[[ xX]\]\s+(.+)$/.exec(lines[i] as string);
    if (match) out.push({ line: i + 1, text: (match[1] as string).trim() });
  }
  if (out.length === 0) throw new Error(`§${number} has no checklist line`);
  return out;
}

export interface LatencyTarget {
  /** `all`, or PB-21's reads and writes. */
  variant: "all" | "read" | "write";
  percentile: number;
  ms: number;
}

export interface Budget {
  id: string;
  name: string;
  target: string;
  targets: LatencyTarget[];
  /** The `·` parts of the target cell that are not a latency target. */
  unparsed: string[];
}

// µ (U+00B5 micro sign) and μ (U+03BC Greek mu) both appear in practice.
const UNIT_MS: Record<string, number> = { ms: 1, s: 1_000, µs: 0.001, μs: 0.001 };
const TARGET = /^(?:(reads?|writes?)\s+)?p(\d{2})\s*(?:≤|<=|<)\s*([\d.,]+)\s*(ms|s|µs|μs)$/i;

/** Every `·` part of a target cell: read as a latency target ("Reads p95 ≤ 200 ms", "p99 < 500 μs"), or unparsed. */
export function budgetParts(target: string): { targets: LatencyTarget[]; unparsed: string[] } {
  const targets: LatencyTarget[] = [];
  const unparsed: string[] = [];
  for (const raw of target.split("·")) {
    const part = raw.trim();
    if (part === "") continue;
    const match = TARGET.exec(part);
    if (!match) {
      unparsed.push(part);
      continue;
    }
    const word = (match[1] ?? "").toLowerCase();
    const variant = word.startsWith("read") ? "read" : word.startsWith("write") ? "write" : "all";
    const ms = Number((match[3] as string).replace(/,/g, "")) * (UNIT_MS[match[4] as string] as number);
    targets.push({ variant, percentile: Number(match[2]), ms });
  }
  return { targets, unparsed };
}

/** The latency targets of a target cell (parts that are not latency targets are left out: see `budgetParts`). */
export function budgetTargets(target: string): LatencyTarget[] {
  return budgetParts(target).targets;
}

/** The rows of PERFORMANCE §2's budget table, by id. */
export function performanceBudgets(markdown: string): Map<string, Budget> {
  const budgets = new Map<string, Budget>();
  for (const line of section(markdown, "2").split("\n")) {
    const cells = line.split("|").map((c) => c.trim());
    const id = cells[1] ?? "";
    if (!/^PB-\d{2}$/.test(id)) continue;
    const target = cells[3] ?? "";
    budgets.set(id, { id, name: cells[2] ?? "", target, ...budgetParts(target) });
  }
  return budgets;
}

/** The targets the gate judges, per budget: exactly these, every part of the cell read. */
export const EXPECTED_TARGETS: Readonly<Record<string, readonly string[]>> = {
  "PB-01": ["all p50", "all p99"],
  "PB-02": ["all p50", "all p99"],
  "PB-21": ["read p95", "write p95"],
};

/** A budget's targets, or an error naming what could not be read, what is missing and what is unexpected. */
export function requireTargets(budgets: ReadonlyMap<string, Budget>, id: string): LatencyTarget[] {
  const budget = budgets.get(id);
  if (!budget) throw new Error(`${id}: not in PERFORMANCE §2`);
  const expected = EXPECTED_TARGETS[id] ?? [];
  const problems: string[] = budget.unparsed.map((part) => `cannot read "${part}"`);
  const have = budget.targets.map((t) => `${t.variant} p${t.percentile}`);
  for (const want of expected) if (!have.includes(want)) problems.push(`missing ${want}`);
  for (const got of have) if (!expected.includes(got)) problems.push(`unexpected ${got}`);
  if (problems.length > 0) throw new Error(`${id}: ${problems.join("; ")}`);
  return budget.targets;
}

/** The latency targets named in PERFORMANCE §3's indicator column ("server time p95 ≤ 50 ms, p99 ≤ 120 ms"). */
export function sloTargets(markdown: string): Map<string, Array<{ percentile: number; ms: number }>> {
  const out = new Map<string, Array<{ percentile: number; ms: number }>>();
  for (const line of section(markdown, "3").split("\n")) {
    const cells = line.split("|").map((c) => c.trim());
    const id = cells[1] ?? "";
    if (!/^SLO-\d{2}$/.test(id)) continue;
    const targets: Array<{ percentile: number; ms: number }> = [];
    for (const m of (cells[3] ?? "").matchAll(/p(\d{2})\s*(?:≤|<=|<)\s*([\d.,]+)\s*(ms|s|µs|μs)\b/g)) {
      targets.push({
        percentile: Number(m[1]),
        ms: Number((m[2] as string).replace(/,/g, "")) * (UNIT_MS[m[3] as string] as number),
      });
    }
    out.set(id, targets);
  }
  return out;
}
