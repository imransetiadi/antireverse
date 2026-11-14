// The stand-in RRS baseline (owner decision D-097, 2026-11-14): TC-PRV-006 waits for a real AI agent; meanwhile the
// stand-in's score on the reference Build must not drop below the score recorded here. The file is reviewed like
// code: raising a baseline is a decision, lowering one is a regression accepted on the record.
import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface RrsBaseline {
  decision: string;
  /** YYYY-MM-DD. */
  recorded: string;
  agent: string;
  tier: string;
  build: string;
  /** The lowest acceptable RRS per Harden profile. */
  profiles: Record<string, number>;
  source: string;
  notes: string[];
}

export const RRS_BASELINE_FILE = "tools/gate/baselines/rrs-stand-in.json";

export function loadRrsBaseline(root: string): RrsBaseline {
  const raw = JSON.parse(readFileSync(join(root, RRS_BASELINE_FILE), "utf8")) as Partial<RrsBaseline>;
  const profiles = raw.profiles ?? {};
  const ok =
    typeof raw.decision === "string" &&
    typeof raw.recorded === "string" &&
    /^\d{4}-\d{2}-\d{2}$/.test(raw.recorded) &&
    typeof raw.tier === "string" &&
    Object.keys(profiles).length > 0 &&
    Object.values(profiles).every((v) => Number.isInteger(v) && v >= 0 && v <= 100) &&
    Array.isArray(raw.notes);
  if (!ok) throw new Error(`${RRS_BASELINE_FILE}: malformed baseline`);
  return raw as RrsBaseline;
}
