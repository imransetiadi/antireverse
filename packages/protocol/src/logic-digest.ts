import { createHash } from "node:crypto";
import { type LogicFile, LogicFileSchema } from "./logic.ts";
import { canonicalJson } from "./prove.ts";

/**
 * The digest of a logic file, as a Manifest's `logic_digest` (slice 12b): the SHA-256 hex of the canonical JSON
 * (`canonicalJson`: keys sorted, no whitespace) of the full function list sorted by id (UTF-16 code unit), after
 * validation (unknown keys stripped). Function order, key order and unknown keys do not change it; the input is not
 * changed. Throws a TypeError
 * for a file that is not a valid logic file (`LogicFileSchema`).
 */
export function logicDigest(file: LogicFile): string {
  const parsed = LogicFileSchema.safeParse(file);
  if (!parsed.success) throw new TypeError("A logic file has 1–5 valid functions, each id once, at most 1 MB.");
  const functions = [...parsed.data.functions].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return createHash("sha256").update(canonicalJson(functions), "utf8").digest("hex");
}
