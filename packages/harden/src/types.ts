// Public types of the harden engine. The engine is pure (no I/O) and deterministic.

import type { Profile, TransformSummary } from "@antireverse/protocol";
import type * as t from "@babel/types";
import type { File } from "@babel/types";

export type { Profile, TransformSummary } from "@antireverse/protocol";

/** What a pass is given: the seeded PRNG, the raw seed, and the Babel types namespace. */
export interface PassContext {
  rng: () => number;
  seed: number;
  types: typeof t;
}

/** A single AST-to-AST transform. Mutates `ast` in place and reports how many nodes it changed. */
export interface Pass {
  name: "mangle" | "strings";
  /** `note: "eval"` means mangling was skipped because the file calls eval (which can reference a local by name). */
  run(ast: File, ctx: PassContext): { count: number; note?: "eval" };
}

/** Options for `harden`. The budget guards per-file gzip overhead. */
export interface HardenOptions {
  profile: Profile;
  seed: number;
  /** A map from a file path to `"skip"` emits that file byte-identical. */
  protectionMap?: Record<string, "skip">;
  /** Overhead ceilings as percentages. Defaults: size 35, run 15. */
  budget?: { sizePct: number; runPct: number };
}

/** The result for one input file. */
export interface FileResult {
  path: string;
  /** The protected code, or the original when skipped or unparseable. */
  code: string;
  /** True when the file was emitted unchanged (protection map, or a parse error). */
  skipped: boolean;
  /** When set, only mangling was applied (string encryption was over budget): the recorded reason. */
  mangleOnly?: string;
  /** When set, the file could not be parsed and was passed through: the reason. */
  error?: string;
  renamed: number;
  stringsEncrypted: number;
}

export interface HardenResult {
  files: FileResult[];
  transform: TransformSummary;
}
