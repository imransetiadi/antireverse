import { describe, expect, it } from "vitest";
import { makeNamer, mulberry32 } from "../src/rng.ts";

describe("mulberry32", () => {
  it("is deterministic for one seed", () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    const seqA = [a(), a(), a(), a()];
    const seqB = [b(), b(), b(), b()];
    expect(seqA).toEqual(seqB);
  });

  it("produces values in [0, 1)", () => {
    const r = mulberry32(7);
    for (let i = 0; i < 1000; i++) {
      const v = r();
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1);
    }
  });

  it("differs between seeds", () => {
    const a = mulberry32(1);
    const b = mulberry32(2);
    expect(a()).not.toBe(b());
  });
});

describe("makeNamer", () => {
  it("is collision-free across many names", () => {
    const next = makeNamer(mulberry32(123));
    const seen = new Set<string>();
    for (let i = 0; i < 5000; i++) {
      const name = next();
      expect(seen.has(name)).toBe(false);
      seen.add(name);
    }
  });

  it("produces valid identifier names (no digit lead)", () => {
    const next = makeNamer(mulberry32(5));
    for (let i = 0; i < 500; i++) {
      expect(next()).toMatch(/^[A-Za-z_$][A-Za-z0-9_$]*$/);
    }
  });

  it("is deterministic for one seed", () => {
    const one = makeNamer(mulberry32(99));
    const two = makeNamer(mulberry32(99));
    const a = [one(), one(), one()];
    const b = [two(), two(), two()];
    expect(a).toEqual(b);
  });

  it("avoids reserved names", () => {
    const reserved = new Set<string>();
    // Pre-generate a batch, then re-run reserving those exact names: none may reappear.
    const scout = makeNamer(mulberry32(3));
    for (let i = 0; i < 50; i++) reserved.add(scout());
    const next = makeNamer(mulberry32(3), reserved);
    for (let i = 0; i < 50; i++) expect(reserved.has(next())).toBe(false);
  });
});
