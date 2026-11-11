// Review finding F3: the budget is a gate on the SHIPPED output. A file whose protected output still exceeds
// the size budget (even after the mangle-only fallback, and on the light profile) must be emitted unchanged.
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { DEFAULT_BUDGET, harden } from "../src/index.ts";

function gzipOverhead(original: string, out: string): number {
  const before = gzipSync(Buffer.from(original, "utf8")).length;
  const after = gzipSync(Buffer.from(out, "utf8")).length;
  return ((after - before) / before) * 100;
}

// Many one-character locals: mangling them to 2–5 character names enlarges even the mangle-only output past 35%.
const TINY = `export function f() {
  let a = 1, b = 2, c = 3, d = 4, e = 5, g = 6, h = 7, i = 8, j = 9, k = 10,
      l = 11, m = 12, n = 13, o = 14, p = 15, q = 16, r = 17, s = 18, t = 19, u = 20;
  return a+b+c+d+e+g+h+i+j+k+l+m+n+o+p+q+r+s+t+u;
}`;

describe("F3 — nothing ships over the size budget", () => {
  it.each(["light", "balanced"] as const)("emits the file within budget or unchanged (%s)", (profile) => {
    const result = harden({ "tiny.ts": TINY }, { profile, seed: 1 });
    const file = result.files[0];
    if (file === undefined) throw new Error("no file");
    const overhead = gzipOverhead(TINY, file.code);
    if (file.code !== TINY) {
      expect(overhead).toBeLessThanOrEqual(DEFAULT_BUDGET.sizePct);
    } else {
      // Emitted unchanged because no transform fit the budget — recorded with a reason.
      expect(file.mangleOnly ?? file.skipped).toBeTruthy();
    }
  });

  it("records why a file could not be protected within budget", () => {
    const result = harden({ "tiny.ts": TINY }, { profile: "balanced", seed: 1 });
    const file = result.files[0];
    if (file === undefined) throw new Error("no file");
    if (file.code === TINY) {
      expect(String(file.mangleOnly)).toMatch(/budget/i);
    }
  });
});
