// Package invariants: browser-ready ES modules, no runtime dependency, within the size budget (PB-05), and the
// constants Guard mirrors pinned to the protocol.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  ATTESTATION_HEADER,
  ATTESTATION_LIMITS,
  ATTESTATION_PATTERNS,
  ATTESTATION_SIGNALS,
  CONTENT_HASH_HEADER,
  EMPTY_CONTENT_SHA256,
  SIGNATURE_HEADER,
} from "../../protocol/src/index.ts";
import * as constants from "../src/constants.js";
import * as guard from "../src/index.js";

// Paths, not URL objects: under happy-dom `URL` is the window's, which node:fs refuses.
const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "../src");
const files = readdirSync(SRC).sort();
const jsFiles = files.filter((file) => file.endsWith(".js"));
const read = (file: string) => readFileSync(join(SRC, file), "utf8");
/** The source without comments (the sources hold no string containing "//" or "/*"). */
const code = (file: string) =>
  read(file)
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");
/** Every module specifier of `import … from "x"`, `export … from "x"`, `import("x")` and `import "x"`. */
const specifiers = (source: string) =>
  [...source.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*)["'`]([^"'`]+)["'`]/g)].map((match) => match[1]);

/** Size budget of Guard, gzip (PERFORMANCE PB-05). */
const BUDGET_BYTES = 35 * 1024;

describe("sources", () => {
  it("are plain ES modules with a hand-written index.d.ts", () => {
    expect(jsFiles).toContain("index.js");
    expect(files).toContain("index.d.ts");
    expect(files.filter((file) => !file.endsWith(".js") && file !== "index.d.ts")).toEqual([]);
  });

  it.each(jsFiles)("%s imports only relative .js modules (browser ESM): no node:, no package", (file) => {
    for (const specifier of specifiers(code(file))) {
      expect(specifier).toMatch(/^\.\.?\/[\w./-]+\.js$/);
    }
    expect(code(file)).not.toMatch(/node:|@antireverse\/|\brequire\s*\(|\bprocess\.|\bBuffer\b/);
  });

  it.each(jsFiles)("%s never logs", (file) => {
    expect(code(file)).not.toMatch(/\bconsole\s*\./);
  });

  it("gzip of all sources stays under 35 KB", () => {
    const all = files.map(read).join("\n");
    const size = gzipSync(all, { level: 9 }).byteLength;
    console.info(`guard src gzip: ${size} bytes (${files.length} files, ${Buffer.byteLength(all)} bytes raw)`);
    expect(size).toBeLessThan(BUDGET_BYTES);
  });

  it("the public entry exports exactly the documented API", () => {
    expect(Object.keys(guard).sort()).toEqual([
      "ATTESTATION_HEADER",
      "ATTESTATION_SIGNALS",
      "CONTENT_HASH_HEADER",
      "SIGNATURE_HEADER",
      "createGuard",
    ]);
    const instance = guard.createGuard({ appId: "app_89abcdef0123456789abcdef", endpoint: "https://x.test" });
    expect(Object.keys(instance).sort()).toEqual([
      "attest",
      "fetch",
      "headers",
      "sign",
      "signals",
      "start",
      "stop",
      "token",
    ]);
  });
});

describe("package.json", () => {
  const pkg = JSON.parse(readFileSync(join(HERE, "../package.json"), "utf8"));
  it("is an ES module package exporting the sources and their types, with no dependency", () => {
    expect(pkg.name).toBe("@antireverse/guard");
    expect(pkg.type).toBe("module");
    expect(pkg.exports).toEqual({ ".": { types: "./src/index.d.ts", default: "./src/index.js" } });
    expect(pkg.dependencies ?? {}).toEqual({});
  });
});

describe("constants pinned to the protocol", () => {
  it("header and signal ids", () => {
    expect(constants.ATTESTATION_HEADER).toBe(ATTESTATION_HEADER);
    expect(guard.ATTESTATION_HEADER).toBe(ATTESTATION_HEADER);
    expect([...constants.ATTESTATION_SIGNALS]).toEqual([...ATTESTATION_SIGNALS]);
    expect(Object.isFrozen(constants.ATTESTATION_SIGNALS)).toBe(true);
  });

  it("limits", () => {
    expect(constants.GUARD_LIMITS.ttlS).toBe(ATTESTATION_LIMITS.ttlS);
    expect(constants.GUARD_LIMITS.headerMax).toBe(ATTESTATION_LIMITS.headerMax);
    expect(constants.GUARD_LIMITS.reattestLeadMs).toBe(60_000);
  });

  it("patterns", () => {
    expect(constants.PATTERNS.device.source).toBe(ATTESTATION_PATTERNS.device.source);
    expect(constants.PATTERNS.nonce.source).toBe(ATTESTATION_PATTERNS.nonce.source);
    expect(constants.PATTERNS.jti.source).toBe(ATTESTATION_PATTERNS.jti.source);
    expect(constants.PATTERNS.coordinate.source).toBe(ATTESTATION_PATTERNS.coordinate.source);
  });

  it("signature headers and the empty content hash", () => {
    expect(constants.SIGNATURE_HEADER).toBe(SIGNATURE_HEADER);
    expect(constants.CONTENT_HASH_HEADER).toBe(CONTENT_HASH_HEADER);
    expect(constants.EMPTY_CONTENT_SHA256).toBe(EMPTY_CONTENT_SHA256);
    expect(guard.SIGNATURE_HEADER).toBe(SIGNATURE_HEADER);
    expect(guard.CONTENT_HASH_HEADER).toBe(CONTENT_HASH_HEADER);
  });

  it("device storage key", () => {
    expect(constants.DEVICE_STORAGE_KEY).toBe("ar.device");
  });
});
