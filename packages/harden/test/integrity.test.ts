import { describe, expect, it } from "vitest";
import { applyIntegrity, containsEsm } from "../src/passes/integrity.ts";

/** Runs wrapper source in an isolated function scope and returns whether it threw. */
function runWrapper(code: string): { threw: boolean; probe: unknown } {
  // The payload assigns to globalThis.__ar_probe when it executes.
  delete (globalThis as Record<string, unknown>).__ar_probe;
  let threw = false;
  // Indirect eval runs the wrapper in global scope, exactly as a <script> or bundler would at load.
  // biome-ignore lint/security/noGlobalEval: the integrity wrapper is designed to be eval'd at load.
  const indirectEval = eval;
  try {
    indirectEval(code);
  } catch {
    threw = true;
  }
  const probe = (globalThis as Record<string, unknown>).__ar_probe;
  delete (globalThis as Record<string, unknown>).__ar_probe;
  return { threw, probe };
}

const BUNDLED = `globalThis.__ar_probe = 7 * 6;`;

describe("integrity pass", () => {
  it("runs the untouched protected output without firing", () => {
    const wrapped = applyIntegrity(BUNDLED);
    const { threw, probe } = runWrapper(wrapped);
    expect(threw).toBe(false);
    expect(probe).toBe(42);
  });

  it("detects a one-byte change to the protected region", () => {
    const wrapped = applyIntegrity(BUNDLED);
    // Flip one byte inside the embedded payload (the 7 becomes an 8). The hash no longer matches.
    const tampered = wrapped.replace("7 * 6", "8 * 6");
    expect(tampered).not.toBe(wrapped);
    const { threw, probe } = runWrapper(tampered);
    expect(threw).toBe(true);
    expect(probe).toBeUndefined(); // the payload never executed
  });

  it("refuses ESM input with a clear message", () => {
    expect(containsEsm(`import x from "y"; x();`)).toBe(true);
    expect(containsEsm(`export const a = 1;`)).toBe(true);
    expect(containsEsm(`var a = 1; console.log(a);`)).toBe(false);
    expect(() => applyIntegrity(`import x from "y";`)).toThrow(/ESM|module|import|export|bundl/i);
  });
});
