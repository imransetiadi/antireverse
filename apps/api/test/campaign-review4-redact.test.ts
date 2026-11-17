import { describe, expect, it } from "vitest";
import { BODY_WITHHELD, evidenceWindow, redactBody, redactHeaders } from "../src/campaign/redact.ts";

// Slice 15a, fourth independent safety review. R4: a Content-Type that names a charset in any way the parser does not
// read as UTF-8 or US-ASCII withholds the body. And what is stored of a window or a header holds no character that
// reorders or hides text, and no half of a surrogate pair.

const TEXT = '{"reports":[{"id":1}]}';
const read = (contentType: string) => redactBody(Buffer.from(TEXT), { contentType });

describe("review4 R4: the charset of a Content-Type", () => {
  it("the review's values are withheld, not read as UTF-8", () => {
    for (const type of [
      "charset=utf-7",
      "text/html charset=utf-7",
      'text/html; x=";charset=utf-8";charset=utf-7',
      "text/html; charset*=utf-7",
      `text/html; x=${"a".repeat(600)}; charset=utf-7`,
      `text/html;${" ".repeat(600)}charset=utf-7`,
    ]) {
      expect(read(type), type.slice(0, 60)).toBe(BODY_WITHHELD);
    }
  });

  it("anything that says `charset` without parsing to exactly one readable charset parameter is withheld", () => {
    for (const type of [
      "text/html; charset",
      "text/html; charset=",
      "text/html; charset =utf-8",
      "text/html; charset= utf-8",
      "text/html; charset=utf-8; charset=utf-7",
      "text/html; charset=utf-7; charset=utf-8",
      "text/html; charset=utf-8; charset=utf-8",
      'text/html; charset="utf-8',
      'text/html; charset="utf-8"x',
      'text/html; x="unclosed; charset=utf-8',
      'text/html; x="a\\"; charset=utf-7; y="b"',
      "text/html; CHARSET=UTF-16",
      "text/html; charset=utf-8, text/plain; charset=utf-7",
      "text/html; xcharset=utf-8",
      "text/html; charset-x=utf-8",
      "text/html;; charset=utf-8",
      "text/html; charset=utf-8;",
      "text/html\u0000; charset=utf-8",
      "text/html; charset=utf-8 (really utf-7)",
      "application/x-charset",
      "text/charset",
    ]) {
      expect(read(type), type).toBe(BODY_WITHHELD);
    }
    expect(redactBody(Buffer.from(TEXT), { contentType: ["text/html; charset=utf-8"] })).toBe(BODY_WITHHELD);
  });

  it("UTF-8 and US-ASCII, declared as a parameter in the forms the grammar allows, are read", () => {
    for (const type of [
      "text/html",
      "application/json",
      "text/html; charset=utf-8",
      "text/html;charset=UTF-8",
      'text/html; charset="utf-8"',
      "text/html; charset=utf8",
      "text/plain; charset=us-ascii",
      "text/html ; charset=utf-8",
      'multipart/x; boundary="a;b"; charset=utf-8',
      "text/html; version=1; charset=utf-8; q=0.9",
      "",
    ]) {
      expect(read(type), type).toBe(TEXT);
    }
    expect(redactBody(Buffer.from(TEXT), {})).toBe(TEXT);
  });

  it("documented limit: UTF-16 without a byte order mark and without a NUL can pass as text", () => {
    // U+4E2D U+6587 in UTF-16LE is the bytes 2D 4E 87 65: the last two are not UTF-8, so this one is withheld…
    expect(redactBody(Buffer.from("中文", "utf16le"))).toBe(BODY_WITHHELD);
    // …but code units whose two bytes are both ASCII (U+4E2D, U+5B57: `-N`, `W[`) are valid UTF-8, read as other
    // text. Nothing distinguishes them from ASCII without guessing; no check can match in them, so a check that
    // reads such a body says "ran, nothing reported".
    expect(redactBody(Buffer.from("中字", "utf16le"))).toBe("-NW[");
  });
});

describe("review4: what is stored holds no character that reorders or hides text", () => {
  it("the evidence window: bidi overrides, isolates, line and paragraph separators and other format characters become spaces", () => {
    const hostile =
      "a\u202eb\u202dc\u2028d\u2029e\u2066f\u2067g\u2068h\u2069i\u200ej\u200fk\u061cl\u200bm\u2060n\ufeffo\u00adp\u180eq\ufff9r";
    expect(evidenceWindow(hostile)).toBe("a b c d e f g h i j k l m n o p q r");
    // A line break and a tab stay; so do ordinary letters of any script.
    expect(evidenceWindow("α\tβ\nγ é 中 😀")).toBe("α\tβ\nγ é 中 😀");
    expect(evidenceWindow("\u202e".repeat(300))).toBe(" ".repeat(200));
    expect(evidenceWindow(hostile)).not.toMatch(/[\p{Cf}\p{Cc}\u2028\u2029]/u);
  });

  it("a kept header is cut on a code-point boundary, and holds no control or format character", () => {
    const kept = redactHeaders(
      { server: `${"x".repeat(255)}😀 tail`, "x-powered-by": "PHP\u202e/8\u2028", "cache-control": "\ud83d alone" },
      "shop.acme-shop.io",
    );
    expect(kept.server).toBe("x".repeat(255));
    expect(kept.server?.isWellFormed()).toBe(true);
    expect(kept["x-powered-by"]).toBe("PHP /8 ");
    expect(kept["cache-control"]).toBe(" alone");
    for (const value of Object.values(kept)) expect(value.isWellFormed()).toBe(true);
    const cookies = redactHeaders({ "set-cookie": Array.from({ length: 16 }, () => `${"n".repeat(60)}=v`) }, "h.io");
    expect(cookies["set-cookie"]?.isWellFormed()).toBe(true);
  });
});
