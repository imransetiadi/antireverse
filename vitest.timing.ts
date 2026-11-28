// The test files that run late (slice 23b; D-147, D-148, D-149). `npm test` runs four hundred files at once. A
// test whose time bound measures CPU work, a ratio of two timings, or the start of a process then reads several
// times slower than the code is: Guard's 25 ms budget (5.6 ms alone) read 25.6 ms and failed a release gate with
// unchanged code. Such a test is not weakened: its file runs whole, one file at a time, after every other file of
// the run — in a project named <project>-timing. No test file is changed.
//
// The rule for a new test: if its bound is on CPU work, on a ratio of two measured times, or on starting a process
// or a worker, its file belongs here. A deliberate wait with slack ("is stopped at the time limit", "waits at most
// 2 s", an end-to-end budget that waits for a poll) does not move under load and stays where it is.
//
// One list, read by vitest.config.ts, tools/sdk/vitest.dist.config.ts, the gate's matrices
// (tools/gate/src/matrix.ts) and tools/gate/test/timing.test.ts.

export interface TimingFile {
  /** The Vitest project the file belonged to; it now runs in `<project>-timing`. */
  project: string;
  /** Relative to the repository root. */
  file: string;
  /** What the bound measures. */
  kind: "cpu" | "ratio" | "start-up";
  why: string;
}

export const TIMING_SUFFIX = "-timing";

export const TIMING_FILES: readonly TimingFile[] = [
  {
    project: "guard",
    file: "packages/guard/test/integrity.test.ts",
    kind: "cpu",
    why: "PB-06: plan(), locate() and the marker search each stay one short task, under 25 ms (best of five). Alone 1.6 to 8.7 ms; in the full run up to 25.6 ms, which failed the gate twice.",
  },
  {
    project: "shield-node",
    file: "packages/shield-node/test/decide.test.ts",
    kind: "cpu",
    why: "decide() against a 16 KB path: p99 of 200 calls under 0.5 ms. Alone 0.21 ms, in the full run 0.34 ms.",
  },
  {
    project: "shield-node",
    file: "packages/shield-node/test/patches-differential.test.ts",
    kind: "ratio",
    why: "Matching grows linearly with the body: four times the body costs under ten times the time. A ratio of two measured times.",
  },
  {
    project: "shield-node",
    file: "packages/shield-node/test/shield.test.ts",
    kind: "start-up",
    why: "Three child processes must start, work and exit within 2 s. Alone 350 to 530 ms, in the full run up to 790 ms: most of it is starting Node.",
  },
  {
    project: "harden",
    file: "packages/harden/test/leaks.test.ts",
    kind: "ratio",
    why: "L4: ten times the findings cost under thirty times the scan time. A ratio of two measured times; it failed once under load in the equivalence run.",
  },
  {
    project: "prove",
    file: "packages/prove/test/sandbox.test.ts",
    kind: "start-up",
    why: "The sandbox child process starts in well under a second. Alone 48 ms, in the full run 433 ms: nine times slower.",
  },
  {
    project: "prove",
    file: "packages/prove/test/assess-worker.test.ts",
    kind: "start-up",
    why: "A run with a 1 s limit reports at most 1.5 s: the slack is what a worker needs to start and stop. Alone 1.04 s, in the full run 1.35 s; with a second suite running beside it, 1.96 and 2.70 s (failed).",
  },
  {
    project: "prove",
    file: "packages/prove/test/logic.test.ts",
    kind: "start-up",
    why: "Vectors run in a sandbox child under short limits (150 ms a vector, 5 s a batch). With a second suite running beside the full run, one batch ran out of time before its child had started, and a test that expects a refusal got a timeout.",
  },
  {
    project: "prove",
    file: "packages/prove/test/tamper.test.ts",
    kind: "start-up",
    why: "The same sandbox child under the same kind of limits as logic.test.ts: a loop is stopped at the time limit, within 3 s. Alone 372 ms, in the full run 445 ms.",
  },
  {
    project: "prove",
    file: "packages/prove/test/stand-in.test.ts",
    kind: "ratio",
    why: "The stand-in scans adversarial text in linear time: four times the text costs under ten times the time. A ratio of two measured times; between 2.7 and 9.3 across runs, and 10.8 (failed) in one full run.",
  },
  {
    project: "api",
    file: "apps/api/test/integrity-review.test.ts",
    kind: "cpu",
    why: "Forged integrity reports must not delay another visitor or cost the database: bounds on measured request times that read 16 to 22 ms in a quiet run and up to 186 ms of 250 in a busy one.",
  },
  {
    project: "api",
    file: "apps/api/test/campaign-review-redact.test.ts",
    kind: "cpu",
    why: "redactText on hostile 64 KB bodies under 250 ms each (alone up to 87 ms), and a ratio of two measured times for linear growth.",
  },
  {
    project: "api",
    file: "apps/api/test/campaign-review2-redact.test.ts",
    kind: "cpu",
    why: "Redaction and the stand-in's detectors on hostile 64 KB bodies under 250 ms each. Alone up to 57 ms, in the full run 50 ms.",
  },
];

/** Where each project's files live, relative to the repository root. */
const PROJECT_ROOTS: Readonly<Record<string, string>> = {
  guard: "packages/guard",
  "shield-node": "packages/shield-node",
  harden: "packages/harden",
  prove: "packages/prove",
  api: "apps/api",
};

/** The name of the project that runs a project's late files. */
export const timingProjectOf = (project: string): string => `${project}${TIMING_SUFFIX}`;

/** A project's late files, relative to the project's root (as `include` and `exclude` want them). Sorted. */
export function timingFilesOf(project: string): string[] {
  const root = PROJECT_ROOTS[project];
  return TIMING_FILES.filter((entry) => entry.project === project)
    .map((entry) => {
      if (root === undefined || !entry.file.startsWith(`${root}/`))
        throw new Error(`${entry.file} is not in ${project}`);
      return entry.file.slice(root.length + 1);
    })
    .sort();
}

/** Whether a file (relative to the repository root) runs late. */
export const isTimingFile = (file: string): boolean => TIMING_FILES.some((entry) => entry.file === file);

/** The projects that have late files, in the order their late projects run. */
export const TIMED_PROJECTS: readonly string[] = [...new Set(TIMING_FILES.map((entry) => entry.project))];
