// Reads the designated protected functions given with `--logic <file>` (slice 12b, W3 Logic): `{ functions: [...] }`
// with 1–5 functions, each an id, a description, up to 2 public examples and 10–200 hidden test vectors — the
// protocol's `LogicFileSchema` — in a file of at most 1 MB. The hidden vectors are what W3 is judged against, so the
// file is never given to the agent, never written into the output bundle and never printed: error messages name a
// place in the file (`functions[0].vectors`), never a value.
import { readFileSync, statSync } from "node:fs";
import { LOGIC_LIMITS, type LogicFile, LogicFileSchema } from "@antireverse/protocol";

export type ReadLogicResult = { logic: LogicFile } | { error: string };

const count = (n: number) => n.toLocaleString("en-US");

/** `functions[0].vectors[9].input` from a Zod issue path. */
function placeOf(path: readonly PropertyKey[]): string {
  let out = "";
  for (const part of path) out += typeof part === "number" ? `[${part}]` : `${out ? "." : ""}${String(part)}`;
  return out;
}

export function readLogic(file: string): ReadLogicResult {
  let raw: string;
  try {
    // Checked before reading, so an oversized file is refused without being loaded.
    const bytes = statSync(file).size;
    if (bytes > LOGIC_LIMITS.fileBytesMax) {
      return { error: `is larger than 1 MB (${count(bytes)} bytes; at most ${count(LOGIC_LIMITS.fileBytesMax)})` };
    }
    raw = readFileSync(file, "utf8");
  } catch {
    return { error: "cannot be read" };
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return { error: "is not JSON" };
  }
  const parsed = LogicFileSchema.safeParse(value);
  if (!parsed.success) {
    // A Zod message carries no input value; the place is a path of keys and positions.
    const issue = parsed.error.issues[0];
    const place = issue ? placeOf(issue.path) : "";
    const detail = issue ? `${place ? `${place}: ` : ""}${issue.message}` : "invalid";
    return {
      error: `is not a valid logic file (${detail}); expected { "functions": [{ "id", "description", "examples", "vectors" }] } with ${LOGIC_LIMITS.functionsMin}–${LOGIC_LIMITS.functionsMax} functions and ${LOGIC_LIMITS.vectorsMin}–${LOGIC_LIMITS.vectorsMax} vectors each`,
    };
  }
  return { logic: parsed.data };
}
