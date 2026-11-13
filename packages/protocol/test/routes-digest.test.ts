import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { EXAMPLE_ROUTE_INVENTORY } from "../src/index.ts";
import { routesDigest } from "../src/server.ts";

const sha256 = (value: string): string => createHash("sha256").update(value, "utf8").digest("hex");

describe("routesDigest", () => {
  it("is the SHA-256 hex of the JSON of the entries, methods upper-cased, sorted by UTF-16 code unit", () => {
    const routes = ["post /b", "GET /a/:id", "GET /A"];
    expect(routesDigest(routes)).toBe(sha256(JSON.stringify(["GET /A", "GET /a/:id", "POST /b"])));
    expect(routesDigest(routes)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("does not depend on input order or method case, and does not change its input", () => {
    const list = [...EXAMPLE_ROUTE_INVENTORY];
    const reversed = [...list].reverse();
    expect(routesDigest(reversed)).toBe(routesDigest(list));
    expect(routesDigest(["get /a"])).toBe(routesDigest(["GET /a"]));
    expect(routesDigest(["GET /a"])).not.toBe(routesDigest(["GET /A"]));
    expect(reversed[0]).toBe(EXAMPLE_ROUTE_INVENTORY[EXAMPLE_ROUTE_INVENTORY.length - 1]);
  });

  it("digests an empty list as the SHA-256 of []", () => {
    expect(routesDigest([])).toBe(sha256("[]"));
  });

  it("throws a TypeError for an entry that is not a route", () => {
    expect(() => routesDigest(["GET /a/"])).toThrow(TypeError);
  });
});
