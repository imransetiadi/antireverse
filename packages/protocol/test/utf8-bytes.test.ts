import { describe, expect, it } from "vitest";
import { utf8Bytes } from "../src/shared.ts";

describe("utf8Bytes (internal)", () => {
  it("equals TextEncoder's length, a lone surrogate as its 3-byte replacement", () => {
    for (const value of ["", "abc", "é", "€", "😀", "a😀b", "\ud800", "\udc00x", "\ud800\ud800", "x\ud83d"]) {
      expect(utf8Bytes(value), JSON.stringify(value)).toBe(new TextEncoder().encode(value).length);
    }
  });

  it("stops at max + 1 once the bound is exceeded", () => {
    expect(utf8Bytes("abcd", 3)).toBe(4);
    expect(utf8Bytes("€€", 4)).toBe(5);
    expect(utf8Bytes("€", 3)).toBe(3);
    expect(utf8Bytes("x".repeat(100), 10)).toBe(11);
  });
});
