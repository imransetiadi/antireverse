// The matrix checks (slice 18e, Jev 0.93 files_by_name_scan): there are no generated TS-TENANT / TS-AUTHZ matrices
// yet, so each matrix runs, whole, the test files that hold a test or describe name matching its pattern. Whole files,
// because a name filter (-t) skips the setup tests that later tests of the same file depend on.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { isTimingFile, timingProjectOf } from "../../../vitest.timing.ts";

export interface Matrix {
  id:
    | "matrix-audit"
    | "matrix-tenant"
    | "matrix-authz"
    | "matrix-privacy"
    | "campaign-safety"
    | "upgrade-local"
    | "rollback-local"
    | "kill-switch-drill"
    | "sdk-reproducible"
    | "sdk-install-smoke"
    | "sdk-equivalence"
    | "sdk-sbom-allowlist"
    | "sdk-signed-manifest";
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
  e2e: "tests/e2e",
  sdk: "tools/sdk/test",
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
  // Slice 15a: the safety controls of Pentest Campaigns. The request gate alone (every refusal reason, the budgets,
  // arbitrary engine output), the pinned transport (the pin assertion, no redirects, the read cap), the restart rule,
  // and — over HTTP against a local target, proven from the target's own request log — the scope-escape suite with
  // both kill switches and the never-destructive suite.
  {
    id: "campaign-safety",
    projects: ["api", "e2e"],
    files: [
      "apps/api/test/campaign-gate.test.ts",
      "apps/api/test/campaign-transport.test.ts",
      "apps/api/test/campaign-runner.test.ts",
      // The independent safety review's tests: write failures, redaction gaps, shutdown, one address under two names.
      "apps/api/test/campaign-review-redact.test.ts",
      "apps/api/test/campaign-review-runner.test.ts",
      "apps/api/test/campaign-review2-redact.test.ts",
      "apps/api/test/campaign-review2-transport.test.ts",
      "apps/api/test/campaign-review2-runner.test.ts",
      // The third review's: the socket read cap, unreadable bodies, a kill committed while a Campaign starts, the
      // evidence window and idempotent redaction, and what the database refuses (migration 0040).
      "apps/api/test/campaign-review3-transport.test.ts",
      "apps/api/test/campaign-review3-gate.test.ts",
      "apps/api/test/campaign-review3-runner.test.ts",
      "apps/api/test/campaign-review3-redact.test.ts",
      "apps/api/test/campaign-review3-db.test.ts",
      // The fourth review's: the probe catalog and text-free refusal rows, the operator's stop while the queue
      // moves, a stop that is final, the charset of a Content-Type, raw-read counting, and the states the database
      // lets a Campaign pass through.
      "apps/api/test/campaign-review4-gate.test.ts",
      "apps/api/test/campaign-review4-runner.test.ts",
      "apps/api/test/campaign-review4-routes.test.ts",
      "apps/api/test/campaign-review4-redact.test.ts",
      "apps/api/test/campaign-review4-transport.test.ts",
      "apps/api/test/campaign-review4-db.test.ts",
      // The fifth review's: an operator's stop that fails half-way or runs twice, a switch committed while the
      // engine returns, probes asked for concurrently, hidden characters in what is stored, a deletion request.
      "apps/api/test/campaign-review5-gate.test.ts",
      "apps/api/test/campaign-review5-runner.test.ts",
      "apps/api/test/campaign-review5-routes.test.ts",
      "apps/api/test/campaign-review5-redact.test.ts",
      "apps/api/test/campaign-review5-db.test.ts",
      // The sixth review's: an end that cannot be written at first, a cut that cannot read the queue, a burst of
      // probes in one tick, separating controls and zero-width characters (D-114), what a later kill may sign for.
      "apps/api/test/campaign-review6-gate.test.ts",
      "apps/api/test/campaign-review6-runner.test.ts",
      "apps/api/test/campaign-review6-routes.test.ts",
      "apps/api/test/campaign-review6-redact.test.ts",
      "apps/api/test/campaign-review6-db.test.ts",
      "tests/e2e/campaign-scope.http.test.ts",
      "tests/e2e/campaign-never-destructive.http.test.ts",
      "tests/e2e/campaign-review.http.test.ts",
    ],
  },
  // Slice 18h. Fixed files, judged like every matrix: each test of each file ran and passed.
  // Every migration prefix, seeded (apps/api/test/era-seed.ts), upgraded to the head and served.
  { id: "upgrade-local", projects: ["api"], files: ["apps/api/test/upgrade.test.ts"] },
  // The backup and restore commands on their own, then the rehearsal on a real data directory.
  {
    id: "rollback-local",
    projects: ["api"],
    files: ["apps/api/test/backup.test.ts", "apps/api/test/rollback-rehearsal.test.ts"],
  },
  // Each switch on and off again, over HTTP. Cutting a running Campaign is campaign-safety's.
  { id: "kill-switch-drill", projects: ["e2e"], files: ["tests/e2e/kill-switch-drill.http.test.ts"] },
  // Slice 23. The SDK packages built, packed and checked locally; fixed files, one check per property.
  // The build's shape, the one function that removes a build folder, and two clean builds byte for byte.
  {
    id: "sdk-reproducible",
    projects: ["sdk"],
    files: ["tools/sdk/test/safe.test.ts", "tools/sdk/test/build.test.ts", "tools/sdk/test/reproducible.test.ts"],
  },
  // A real npm install of the tarballs in an empty project, against a loopback registry, then plain Node.
  { id: "sdk-install-smoke", projects: ["sdk"], files: ["tools/sdk/test/install-smoke.test.ts"] },
  // The suites of protocol, shield-node and harden again on the compiled output, compared with the source run.
  { id: "sdk-equivalence", projects: ["sdk"], files: ["tools/sdk/test/equivalence.test.ts"] },
  // The runtime closure, the CycloneDX documents and the dependency allowlist.
  { id: "sdk-sbom-allowlist", projects: ["sdk"], files: ["tools/sdk/test/sbom-allowlist.test.ts"] },
  // The signed manifest and sdk:verify.
  // Slice 23b: with the release shape — the three publishable tarballs, their manifest and the owner's two checks
  // against a loopback registry. No network, no npm login.
  {
    id: "sdk-signed-manifest",
    projects: ["sdk"],
    files: ["tools/sdk/test/manifest.test.ts", "tools/sdk/test/release.test.ts"],
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
  for (const scanned of matrix.projects) {
    const dir = PROJECT_DIRS[scanned];
    if (dir === undefined) throw new Error(`no test directory for project ${scanned}`);
    for (const path of testFiles(join(root, dir))) {
      const file = relative(root, path);
      // A file that runs late (vitest.timing.ts, D-147) belongs to its project's late twin: it is run there.
      const project = isTimingFile(file) ? timingProjectOf(scanned) : scanned;
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

/**
 * Slice 18h review M1: what is wrong with the selection of a check that names its files — a listed file that was not
 * found (deleted, renamed, moved out of its project's test directory) or that holds no test. Such a check must fail:
 * the files that are left would otherwise pass for the whole of it. Empty for a pattern matrix.
 */
export function fixedFileProblems(matrix: Matrix, selected: readonly SelectedFile[]): string[] {
  const problems: string[] = [];
  for (const file of matrix.files ?? []) {
    const found = selected.find((entry) => entry.file === file);
    if (found === undefined) problems.push(`${file} is missing`);
    else if (found.names.length === 0) problems.push(`${file} holds no test`);
  }
  return problems;
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
