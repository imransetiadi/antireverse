// The matrix checks (slice 18e, Jev 0.93 files_by_name_scan): there are no generated TS-TENANT / TS-AUTHZ matrices
// yet, so each matrix runs, whole, the test files that hold a test or describe name matching its pattern. Whole files,
// because a name filter (-t) skips the setup tests that later tests of the same file depend on.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface Matrix {
  id: "matrix-audit" | "matrix-tenant" | "matrix-authz" | "matrix-privacy";
  /** Vitest projects (root vitest.config.ts) whose test directories are scanned. */
  projects: string[];
  /** A test or describe name matching this selects the file. */
  pattern?: RegExp;
  /** Fixed files instead of a pattern. */
  files?: string[];
}

/** The test directory of each vitest project the matrices scan. */
export const PROJECT_DIRS: Record<string, string> = {
  api: "apps/api/test",
  protocol: "packages/protocol/test",
  "shield-node": "packages/shield-node/test",
};

export const MATRICES: readonly Matrix[] = [
  // Slice 18a's route-table coverage test: every administrative route writes an audit entry.
  { id: "matrix-audit", projects: ["api"], files: ["apps/api/test/audit-coverage.test.ts"] },
  {
    id: "matrix-tenant",
    projects: ["api"],
    pattern: /another Organization|other Organization|other tenant|cross-tenant|row-level security|isolates tenants/,
  },
  {
    id: "matrix-authz",
    projects: ["api"],
    pattern: /Shield key|admin key|without a key|\b40[13]\b|admin keys only|request role/,
  },
  {
    id: "matrix-privacy",
    projects: ["protocol", "shield-node", "api"],
    pattern: /privacy|allowlisted (?:keys|members)|from the allowlist only/,
  },
];

/** The literal names of `it`, `test` and `describe` calls (with modifiers such as `.skip` or `.each(...)`). */
export function testNames(source: string): string[] {
  const names: string[] = [];
  const re = /\b(?:it|test|describe)(?:\.\w+)*(?:\([^()]*\))?\(\s*(["'`])((?:\\.|(?!\1).)*)\1/g;
  for (const m of source.matchAll(re)) names.push(m[2] as string);
  return names;
}

function testFiles(dir: string): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const entry of entries.sort()) {
    const path = join(dir, entry);
    if (entry === "node_modules" || entry === "fixtures") continue;
    if (statSync(path).isDirectory()) out.push(...testFiles(path));
    else if (/\.test\.tsx?$/.test(entry)) out.push(path);
  }
  return out;
}

export interface SelectedFile {
  project: string;
  /** Relative to the repository root. */
  file: string;
  names: string[];
}

export function selectMatrixFiles(matrix: Matrix, root: string): SelectedFile[] {
  const out: SelectedFile[] = [];
  for (const project of matrix.projects) {
    const dir = PROJECT_DIRS[project];
    if (dir === undefined) throw new Error(`no test directory for project ${project}`);
    for (const path of testFiles(join(root, dir))) {
      const file = relative(root, path);
      const names = testNames(readFileSync(path, "utf8"));
      if (matrix.files) {
        if (matrix.files.includes(file)) out.push({ project, file, names });
        continue;
      }
      const matching = names.filter((n) => matrix.pattern?.test(n));
      if (matching.length > 0) out.push({ project, file, names: matching });
    }
  }
  return out;
}

interface JsonAssertion {
  title?: string;
  ancestorTitles?: string[];
  status?: string;
}

/** A name as written in the source, as a pattern over the titles vitest reports (`%s`, `$name`, `${…}` filled in). */
function namePattern(name: string): RegExp {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const filled = escaped
    .replace(/%[sdifjo#%]/g, ".*")
    .replace(/\\\$\\\{[^}]*\\\}/g, ".*")
    .replace(/\\\$[A-Za-z_][\w.]*/g, ".*");
  return new RegExp(`^${filled}$`, "s");
}

/**
 * Review H1: every matching name of every selected file ran and passed, read from vitest's JSON reporter. A test name
 * must have a passed result of that title; a describe name, at least one passed test under it; any matched result
 * that did not pass (skipped, todo, failed) is named.
 */
export function judgeMatrixJson(json: unknown, selected: readonly SelectedFile[], root: string): string[] {
  const results = (json as { testResults?: Array<{ name?: string; assertionResults?: JsonAssertion[] }> }).testResults;
  if (!Array.isArray(results)) return ["no JSON report"];
  const problems: string[] = [];
  for (const entry of selected) {
    const file = results.find((r) => r.name === join(root, entry.file) || r.name?.endsWith(`/${entry.file}`));
    const assertions = file?.assertionResults ?? [];
    for (const name of entry.names) {
      const pattern = namePattern(name);
      const matched = assertions.filter(
        (a) => pattern.test(a.title ?? "") || (a.ancestorTitles ?? []).some((t) => pattern.test(t)),
      );
      if (matched.length === 0) {
        problems.push(`${entry.file}: "${name}" did not run`);
        continue;
      }
      const notPassed = matched.filter((a) => a.status !== "passed");
      if (notPassed.length > 0) {
        const statuses = [...new Set(notPassed.map((a) => a.status ?? "unknown"))].join(", ");
        problems.push(`${entry.file}: "${name}" did not pass (${statuses})`);
      }
    }
  }
  return problems;
}
