import { createHash } from "node:crypto";
import {
  type AssessmentTier,
  type BuildManifest,
  EXAMPLE_BUILD_MANIFEST,
  type ObjectiveResult,
  type ScopeStatement,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import type { Assessor, AssessorInput, AssessorOutcome } from "../src/assess/assessor.ts";

// A controllable Assessor for the API's tests: each run waits until the test settles it.

export interface FakeRun {
  input: AssessorInput;
  resolve(outcome: AssessorOutcome): void;
  reject(error: unknown): void;
}

export interface FakeAssessor extends Assessor {
  runs: FakeRun[];
  /** Resolves with the `n`th run (0-based) once it has started. */
  run(n: number): Promise<FakeRun>;
}

export function fakeScope(tier: AssessmentTier): ScopeStatement {
  return { agent: { name: "fake", version: "1.0.0" }, model: "stand-in", toolbelt: "0.1.0", tier };
}

export function fakeAssessor(): FakeAssessor {
  const runs: FakeRun[] = [];
  const waiting: Array<{ n: number; resolve: (run: FakeRun) => void }> = [];
  return {
    runs,
    scope: fakeScope,
    assess(input) {
      return new Promise<AssessorOutcome>((resolve, reject) => {
        const run = { input, resolve, reject };
        runs.push(run);
        for (const waiter of [...waiting]) {
          if (waiter.n === runs.length - 1) {
            waiting.splice(waiting.indexOf(waiter), 1);
            waiter.resolve(run);
          }
        }
      });
    },
    run(n) {
      const existing = runs[n];
      if (existing !== undefined) return Promise.resolve(existing);
      return new Promise((resolve) => waiting.push({ n, resolve }));
    },
  };
}

const NOT_SUPPORTED = (objective: "W3" | "W4"): ObjectiveResult => ({
  objective,
  result: "not_attempted",
  reason: "not_supported",
  evidence: { summary: "Not assessed in this version.", recovered: [], calls: [] },
});

/** A 12a-shaped run: W2 achieved at T1, W1 and W5 not achieved, W3 and W4 not supported (inconclusive). */
export function inconclusiveResults(): ObjectiveResult[] {
  return [
    {
      objective: "W1",
      result: "not_achieved",
      cost: { calls: 10, seconds: 1 },
      evidence: {
        summary: "2 of 5 routes matched.",
        recovered: [{ kind: "routes", matched: 2, submitted: 3, inventory: 5 }],
        calls: [1],
      },
    },
    {
      objective: "W2",
      result: "achieved",
      tier: "T1",
      cost: { calls: 3, seconds: 0.5 },
      evidence: {
        summary: "Found a planted Canary.",
        recovered: [{ kind: "canary", canary_id: "cny_33d265fca16c848eb2f23f43" }],
        calls: [2],
      },
    },
    NOT_SUPPORTED("W3"),
    NOT_SUPPORTED("W4"),
    {
      objective: "W5",
      result: "not_achieved",
      cost: { calls: 12, seconds: 2 },
      evidence: {
        summary: "The replica refused the request.",
        recovered: [{ kind: "replay", status: 401 }],
        calls: [],
      },
    },
  ];
}

/** Every Objective attempted: W2 achieved at T1, the rest not achieved (scored). */
export function scoredResults(): ObjectiveResult[] {
  const notAchieved = (objective: "W3" | "W4"): ObjectiveResult => ({
    objective,
    result: "not_achieved",
    cost: { calls: 20, seconds: 3 },
    evidence: { summary: "Not achieved.", recovered: [], calls: [] },
  });
  const [w1, w2, , , w5] = inconclusiveResults() as [
    ObjectiveResult,
    ObjectiveResult,
    ObjectiveResult,
    ObjectiveResult,
    ObjectiveResult,
  ];
  return [w1, w2, notAchieved("W3"), notAchieved("W4"), w5];
}

export const sha256 = (bytes: Uint8Array | string): string => createHash("sha256").update(bytes).digest("hex");

/** A two-file artifact and a Manifest of `appId` whose artifact entries are exactly its files. */
export function artifactFor(
  appId: string,
  overrides: Partial<BuildManifest> = {},
): { manifest: BuildManifest; files: { path: string; base64: string }[]; contents: Map<string, string> } {
  const contents = new Map([
    ["dist/index.js", `console.log("shop ${newId("bld")}");fetch("/api/products");`],
    ["dist/vendor.js", "export const answer = 42;"],
  ]);
  const files = [...contents].map(([path, text]) => ({ path, base64: Buffer.from(text).toString("base64") }));
  const manifest: BuildManifest = {
    ...EXAMPLE_BUILD_MANIFEST,
    build_id: newId("bld"),
    app_id: appId,
    artifacts: [...contents].map(([path, text]) => ({ path, sha256: sha256(text), bytes: Buffer.byteLength(text) })),
    ...overrides,
  };
  return { manifest, files, contents };
}
