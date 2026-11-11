import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { type Component, EXAMPLE_INVENTORY } from "../src/index.ts";
import { componentsDigest } from "../src/server.ts";

const sha256 = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

describe("componentsDigest", () => {
  it("is the SHA-256 hex of the JSON of [{name, version, dev}] sorted by name, then version", () => {
    const components: Component[] = [
      { name: "b", version: "1.0.0", dev: false },
      { name: "a", version: "2.0.0", dev: true },
      { name: "a", version: "10.0.0", dev: false },
    ];
    const canonical = JSON.stringify([
      { name: "a", version: "10.0.0", dev: false },
      { name: "a", version: "2.0.0", dev: true },
      { name: "b", version: "1.0.0", dev: false },
    ]);
    expect(componentsDigest(components)).toBe(sha256(canonical));
    expect(componentsDigest(components)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("does not depend on input order or extra keys, and does not change its input", () => {
    const list = [...EXAMPLE_INVENTORY.components];
    const reversed = [...list].reverse();
    const extra = list.map((component) => ({ ...component, resolved: "https://registry.example/x.tgz" }));
    expect(componentsDigest(reversed)).toBe(componentsDigest(list));
    expect(componentsDigest(extra)).toBe(componentsDigest(list));
    expect(reversed[0]).toEqual(EXAMPLE_INVENTORY.components[2]);
  });

  it("orders by UTF-16 code unit, so capitals sort before lower case, and differs when a dev flag differs", () => {
    const upper = { name: "JSONStream", version: "1.3.5", dev: false };
    const lower = { name: "jsonstream", version: "1.0.0", dev: false };
    expect(componentsDigest([lower, upper])).toBe(sha256(JSON.stringify([upper, lower])));
    expect(componentsDigest([{ ...upper, dev: true }])).not.toBe(componentsDigest([upper]));
  });

  it("digests an empty list as the SHA-256 of []", () => {
    expect(componentsDigest([])).toBe(sha256("[]"));
  });
});
