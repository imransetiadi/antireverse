// Review findings F1 (classes), F2 (reserved words), F4 (eval): the mangle pass must never change behaviour.
// These tests execute the protected output, across many seeds, so a desynced rename or an invalid identifier fails.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { harden } from "../src/index.ts";
import { makeNamer, mulberry32 } from "../src/rng.ts";
import type { Profile } from "../src/types.ts";

let tmpCount = 0;

/** Harden one module and import the protected output, so we observe its real runtime behaviour. */
async function runHardened(
  source: string,
  opts: { profile?: Profile; seed: number },
): Promise<Record<string, unknown>> {
  const result = harden({ "m.mjs": source }, { profile: opts.profile ?? "balanced", seed: opts.seed });
  const file = result.files[0];
  if (file === undefined) throw new Error("no file");
  if (file.error) throw new Error(`harden reported: ${file.error}`);
  const dir = mkdtempSync(join(tmpdir(), "harden-beh-"));
  const path = join(dir, `m${tmpCount++}.mjs`);
  writeFileSync(path, file.code, "utf8");
  try {
    return (await import(pathToFileURL(path).href)) as Record<string, unknown>;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const SEEDS = [0, 1, 2, 3, 7, 13, 42, 99, 1263, 1091];

describe("F1 — local classes keep working after mangling", () => {
  it.each(SEEDS)("a locally declared and used class (seed %i)", async (seed) => {
    const mod = await runHardened(
      `export function build() { class Service { ping() { return "pong"; } } return new Service().ping(); }`,
      { seed },
    );
    expect((mod.build as () => string)()).toBe("pong");
  });

  it.each(SEEDS)("a class whose static method references the class itself (seed %i)", async (seed) => {
    const mod = await runHardened(
      `export function make() { class Node { static create() { return new Node(); } who() { return "node"; } } return Node.create().who(); }`,
      { seed },
    );
    expect((mod.make as () => string)()).toBe("node");
  });

  it.each(SEEDS)("a class expression bound to a const and used (seed %i)", async (seed) => {
    const mod = await runHardened(
      `export function run() { const C = class { v() { return 5; } }; return new C().v(); }`,
      { seed },
    );
    expect((mod.run as () => number)()).toBe(5);
  });
});

describe("F2 — generated names are never reserved words", () => {
  it("the namer never returns a JavaScript reserved word over a large sample", () => {
    const rng = mulberry32(12345);
    const namer = makeNamer(rng);
    const reserved = new Set([
      "do",
      "if",
      "in",
      "for",
      "let",
      "new",
      "try",
      "var",
      "case",
      "else",
      "enum",
      "null",
      "this",
      "true",
      "void",
      "with",
      "break",
      "catch",
      "class",
      "const",
      "false",
      "super",
      "throw",
      "while",
      "yield",
      "delete",
      "export",
      "import",
      "return",
      "switch",
      "typeof",
      "default",
      "extends",
      "finally",
      "continue",
      "debugger",
      "function",
      "arguments",
      "await",
      "static",
    ]);
    for (let i = 0; i < 20_000; i++) {
      expect(reserved.has(namer())).toBe(false);
    }
  });

  it.each(SEEDS)("a local named like a soon-to-be reserved word still runs (seed %i)", async (seed) => {
    const mod = await runHardened(
      `export function f() { let total = 0; for (let item = 1; item <= 3; item++) total += item; return total; }`,
      { seed },
    );
    expect((mod.f as () => number)()).toBe(6);
  });
});

describe("F4 — a direct eval that reads a local is not broken", () => {
  it.each(SEEDS)("eval referencing a local binding (seed %i)", async (seed) => {
    const mod = await runHardened(`export function secretValue() { const secret = 42; return eval("secret"); }`, {
      seed,
    });
    expect((mod.secretValue as () => number)()).toBe(42);
  });
});
