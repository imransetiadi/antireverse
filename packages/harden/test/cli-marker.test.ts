// Slice 21a — the CLI around the integrity marker: on with --register, off with --no-integrity-marker, never
// without --register; the Manifest's `integrity.files`, the report and --json; a marker that does not fit never
// fails the run; and the bytes written to --out are exactly the bytes the Manifest's digests name.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { type BuildManifest, EXAMPLE_BUILD, RegisterBuildRequestSchema } from "@antireverse/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.ts";
import { markerStatement } from "../src/marker.ts";
import { beaconHostModule } from "./helpers.ts";

const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const ENDPOINT = "https://api.example.test";
const MODULE = beaconHostModule();

const temps: string[] = [];
afterEach(() => {
  vi.unstubAllGlobals();
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  temps.push(d);
  return d;
}

function bundle(files: Record<string, string | Buffer>): string {
  const d = tempDir("harden-cli21-");
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(join(d, rel, ".."), { recursive: true });
    writeFileSync(join(d, rel), content);
  }
  return d;
}

async function run(argv: string[], cwd: string) {
  let out = "";
  let err = "";
  const code = await main(argv, {
    env: { AR_ADMIN_KEY: KEY },
    cwd,
    stdout: (s) => {
      out += s;
    },
    stderr: (s) => {
      err += s;
    },
  });
  return { code, out, err };
}

/** Stubs the register call and returns the Manifests it received. */
function stubRegister(): BuildManifest[] {
  const manifests: BuildManifest[] = [];
  vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
    manifests.push(RegisterBuildRequestSchema.parse(JSON.parse(String(init.body))).manifest);
    return new Response(JSON.stringify({ build: EXAMPLE_BUILD }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  });
  return manifests;
}

const register = [
  "--register",
  "--endpoint",
  ENDPOINT,
  "--key-env",
  "AR_ADMIN_KEY",
  "--app",
  EXAMPLE_BUILD.app_id,
  "--environment",
  "development",
  "--build-version",
  "1.0.0",
];

const lastLine = (path: string) => readFileSync(path, "utf8").trimEnd().split("\n").at(-1) ?? "";
const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

describe("the integrity marker in the CLI", () => {
  it("is planted with --register: the Build id and the files, recorded in the Manifest and the report", async () => {
    const d = bundle({ "a.mjs": MODULE, "lib/b.mjs": `${MODULE}\nexport const b = 2;\n` });
    const out = join(tempDir("harden-out-"), "out");
    const manifests = stubRegister();
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...register, "--json"], d);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    const [manifest] = manifests;
    expect(manifest?.integrity).toEqual({ files: ["a.mjs", "lib/b.mjs"] });
    const json = JSON.parse(r.out);
    expect(json.integrity_marker).toEqual({ files: ["a.mjs", "lib/b.mjs"], planted_in: "a.mjs", dropped: 0 });
    // The planted statement names the Build the Manifest registers, and exactly the Manifest's files.
    const line = lastLine(join(out, "a.mjs"));
    expect(line).toBe(markerStatement(manifest?.build_id ?? "", ["a.mjs", "lib/b.mjs"]));
    const pushed = runInNewContext(`${line}\n;globalThis[Symbol.for("ar.build")]`, {});
    expect(JSON.parse(JSON.stringify(pushed))).toEqual([{ b: manifest?.build_id, f: ["a.mjs", "lib/b.mjs"] }]);
    expect(readFileSync(join(out, "lib/b.mjs"), "utf8")).not.toContain("ar.build");
    // The opt-in self-check wrapper is another feature and stays off (D-099).
    expect(manifest?.transform.integrity).toBe(false);
    expect(json.integrity).toBe(false);
  });

  it("says so in the human report", async () => {
    const d = bundle({ "a.mjs": MODULE });
    stubRegister();
    const r = await run(["harden", d, "--seed", "1", ...register], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain("✓ Integrity marker: 1 file in a.mjs");
  });

  it("--no-integrity-marker turns it off: nothing planted, no Manifest field, the report says off", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const out = join(tempDir("harden-out-"), "out");
    const manifests = stubRegister();
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...register, "--no-integrity-marker", "--json"], d);
    expect(r.code).toBe(0);
    expect(manifests[0]).not.toHaveProperty("integrity");
    expect(JSON.parse(r.out)).not.toHaveProperty("integrity_marker");
    expect(readFileSync(join(out, "a.mjs"), "utf8")).not.toContain("ar.build");
    const human = await run(["harden", d, "--seed", "1", ...register, "--no-integrity-marker"], d);
    expect(human.out).toContain("Integrity marker: off (--no-integrity-marker)");
  });

  it("is never planted without --register (a Build id nobody registered names nothing)", async () => {
    const d = bundle({ "a.mjs": MODULE });
    const out = join(tempDir("harden-out-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--out", out, "--json"], d);
    expect(r.code).toBe(0);
    expect(readFileSync(join(out, "a.mjs"), "utf8")).not.toContain("ar.build");
    expect(JSON.parse(r.out)).not.toHaveProperty("integrity_marker");
    const off = await run(["harden", d, "--seed", "1", "--no-integrity-marker"], d);
    expect(off.code).toBe(0);
    expect(off.out).not.toContain("Integrity marker");
  });

  it("the output is byte-identical with and without the marker, apart from the marker line", async () => {
    const d = bundle({ "a.mjs": MODULE, "b.mjs": `${MODULE}\nexport const b = 2;\n` });
    const withMarker = join(tempDir("harden-out-"), "out");
    const without = join(tempDir("harden-out-"), "out");
    const manifests = stubRegister();
    await run(["harden", d, "--seed", "1", "--out", withMarker, ...register], d);
    await run(["harden", d, "--seed", "1", "--out", without, ...register, "--no-integrity-marker"], d);
    const marker = `${markerStatement(manifests[0]?.build_id ?? "", ["a.mjs", "b.mjs"])}\n`;
    expect(readFileSync(join(withMarker, "a.mjs"), "utf8")).toBe(readFileSync(join(without, "a.mjs"), "utf8") + marker);
    expect(readFileSync(join(withMarker, "b.mjs"))).toEqual(readFileSync(join(without, "b.mjs")));
  });

  it("never fails the run: a marker that fits with fewer files is planted so, and the report and Manifest say it", async () => {
    const files: Record<string, string> = { "a.mjs": MODULE };
    for (let i = 0; i < 31; i++) {
      const name = createHash("sha256").update(`p${i}`).digest("hex");
      files[`${name}/${name.split("").reverse().join("")}.mjs`] = `${MODULE}\nexport const n${i} = ${i};\n`;
    }
    const d = bundle(files);
    const out = join(tempDir("harden-out-"), "out");
    const manifests = stubRegister();
    const r = await run(["harden", d, "--seed", "1", "--profile", "light", "--out", out, ...register, "--json"], d);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    const json = JSON.parse(r.out);
    const listed: string[] = manifests[0]?.integrity?.files ?? [];
    expect(listed.length).toBeGreaterThan(0);
    expect(listed.length).toBeLessThan(32);
    expect(json.integrity_marker).toEqual({
      files: listed,
      planted_in: json.canaries_planted_in,
      dropped: 32 - listed.length,
    });
    expect(lastLine(join(out, json.canaries_planted_in))).toBe(markerStatement(manifests[0]?.build_id ?? "", listed));
    const human = await run(["harden", d, "--seed", "1", "--profile", "light", ...register], d);
    expect(human.code).toBe(0);
    expect(human.out).toMatch(
      new RegExp(`! Integrity marker: ${listed.length} of 32 files in \\S+ \\(the rest did not fit the size budget\\)`),
    );
  });

  it("with --integrity the wrapper hashes the planted marker and the Manifest still names the bytes on disk", async () => {
    const script = `var out = [];\n${Array.from({ length: 80 }, (_, i) => `out.push("entry number ${i} of the bundled script, value ${createHash("sha256").update(String(i)).digest("hex")}");`).join("\n")}\n`;
    const d = bundle({ "app.js": script });
    const out = join(tempDir("harden-out-"), "out");
    const manifests = stubRegister();
    const r = await run(["harden", d, "--seed", "1", "--out", out, "--integrity", ...register, "--json"], d);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    expect(manifests[0]?.transform.integrity).toBe(true);
    expect(manifests[0]?.integrity).toEqual({ files: ["app.js"] });
    expect(manifests[0]?.artifacts[0]?.sha256).toBe(sha256(readFileSync(join(out, "app.js"))));
  });
});

describe("the Manifest's digests are the bytes on disk (what a browser will hash)", () => {
  const BOM = "\uFEFF";
  const body = (note: string) => `${MODULE}\nexport const note = ${JSON.stringify(note)};\n`;
  const fixtures: Record<string, string | Buffer> = {
    "plain.mjs": body("plain"),
    "bom.mjs": BOM + body("starts with a byte order mark"),
    "crlf.mjs": body("windows line endings").replace(/\n/g, "\r\n"),
    "non-ascii.mjs": body("grüße — 日本語 — 🙂 — naïve café"),
    "bom-crlf-non-ascii.mjs": BOM + body("ünï — 🙂").replace(/\n/g, "\r\n"),
    // Emitted unchanged (protection map): the same rule holds for a file Harden does not touch.
    "skipped-bom-crlf.mjs": BOM + body("skipped — ü").replace(/\n/g, "\r\n"),
    "types.d.ts": `${BOM}export declare const note: string; // ü\r\n`,
  };

  for (const profile of ["light", "balanced"]) {
    it(`sha256(readFileSync(out/path)) equals artifacts[].sha256 and bytes, BOM, CRLF and non-ASCII included (${profile})`, async () => {
      const d = bundle(fixtures);
      const map = join(tempDir("harden-map-"), "map.json");
      writeFileSync(map, JSON.stringify({ "skipped-bom-crlf.mjs": "skip" }));
      const out = join(tempDir("harden-out-"), "out");
      const manifests = stubRegister();
      const r = await run(
        ["harden", d, "--seed", "3", "--profile", profile, "--map", map, "--out", out, ...register],
        d,
      );
      expect(r.err).toBe("");
      expect(r.code).toBe(0);
      const artifacts = manifests[0]?.artifacts ?? [];
      expect(artifacts.map((a) => a.path).sort()).toEqual(Object.keys(fixtures).sort());
      for (const artifact of artifacts) {
        const bytes = readFileSync(join(out, artifact.path));
        expect({ path: artifact.path, sha256: sha256(bytes), bytes: bytes.length }).toEqual(artifact);
      }
      // The skipped file is byte-identical to its input, BOM and CRLF kept.
      expect(readFileSync(join(out, "skipped-bom-crlf.mjs"))).toEqual(readFileSync(join(d, "skipped-bom-crlf.mjs")));
      // Every file the marker lists is an artifact with those bytes.
      for (const path of manifests[0]?.integrity?.files ?? []) {
        expect(artifacts.some((a) => a.path === path)).toBe(true);
      }
      expect(manifests[0]?.integrity?.files.length).toBeGreaterThan(0);
    });
  }
});
