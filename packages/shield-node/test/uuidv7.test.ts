import { describe, expect, it } from "vitest";
import { uuidv7 } from "../src/uuidv7.ts";

const VERSION_7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const millisecondsOf = (id: string): number => Number.parseInt(id.replaceAll("-", "").slice(0, 12), 16);

describe("uuidv7", () => {
  it("matches the version-7 pattern (version and variant bits)", () => {
    for (let i = 0; i < 10_000; i++) expect(uuidv7(Date.now())).toMatch(VERSION_7);
  });

  it("carries the clock's milliseconds in the first 48 bits", () => {
    const now = Date.now() + 60_000; // ahead of every value created so far: the generator never goes backwards
    expect(millisecondsOf(uuidv7(now))).toBe(now);
  });

  it("sorts ascending as strings when created at increasing times", () => {
    const start = Date.now() + 120_000;
    const ids: string[] = [];
    for (let i = 0; i < 50; i++) ids.push(uuidv7(start + i * 3));
    expect([...ids].sort()).toEqual(ids);
    expect(ids.map(millisecondsOf)).toEqual(ids.map((_, i) => start + i * 3));
  });

  it("is strictly increasing and unique within one millisecond", () => {
    const now = Date.now() + 180_000;
    const ids: string[] = [];
    for (let i = 0; i < 200_000; i++) ids.push(uuidv7(now));
    for (let i = 1; i < ids.length; i++) {
      if (!((ids[i - 1] as string) < (ids[i] as string))) throw new Error(`not increasing at ${i}`);
    }
    expect(new Set(ids).size).toBe(ids.length);
  });

  // Last on purpose: the generator is monotonic per process, so this pins it to a far-future timestamp.
  it("encodes a given timestamp big-endian and does not go backwards when the clock does", () => {
    const a = uuidv7(0x02aabbccddee);
    expect(a.slice(0, 13)).toBe("02aabbcc-ddee");
    const b = uuidv7(Date.now());
    expect(b.slice(0, 13)).toBe("02aabbcc-ddee");
    expect(a < b).toBe(true);
    expect(b).toMatch(VERSION_7);
  });
});
