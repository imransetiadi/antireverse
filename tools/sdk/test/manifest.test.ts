// Slice 23, criterion 7: the signed manifest and `sdk:verify`. What a valid result proves is small and said plainly:
// these are the files the holder of that key signed. A changed, missing or extra file, a changed manifest, a bad
// signature and an unknown signer all fail.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { type GateKey, loadOrCreateKey, signReport } from "../../gate/src/sign.ts";
import { MANIFEST_FILE, type SdkManifest, verifyArtifacts } from "../src/manifest.ts";
import { SDK_PACKAGES } from "../src/packages.ts";
import { buildAndPack, type PackResult } from "../src/pipeline.ts";
import { BUILD_MARKER } from "../src/safe.ts";
import { sdkVersion } from "../src/stage.ts";
import { filesOf, layoutIn, tempBase } from "./helpers.ts";

const base = tempBase("manifest");
const layout = layoutIn(base, "pack");
const keyFile = join(base, "keys/gate-key.json");
const otherKeyFile = join(base, "keys/other-key.json");
let key: GateKey;
let other: GateKey;
let result: PackResult;
let copies = 0;

/** A copy of the packed folder to damage. */
function copy(): string {
  const dir = join(base, `copy-${++copies}`);
  cpSync(layout.out, dir, { recursive: true });
  return dir;
}
const manifestOf = (dir: string) =>
  JSON.parse(readFileSync(join(dir, MANIFEST_FILE), "utf8")) as SdkManifest & { signature: unknown };
const verify = (dir: string, expect?: string) =>
  verifyArtifacts(dir, { localFingerprint: key.fingerprint, ...(expect ? { expect } : {}) });
const tarball = (dir: string, short = "harden") => join(dir, `antireverse-${short}-${sdkVersion()}.tgz`);

beforeAll(async () => {
  key = loadOrCreateKey(keyFile);
  other = loadOrCreateKey(otherKeyFile);
  result = await buildAndPack(layout, { key });
});

describe("the signed manifest", () => {
  it("lists each tarball and its bill of materials with size and SHA-256, the commit and the tools", () => {
    const manifest = manifestOf(layout.out);
    expect(manifest.schema).toBe("airverse.sdk-artifacts/1");
    expect(manifest.statement).toMatch(/not provenance/);
    expect(manifest.statement).toMatch(/local build, not a release/);
    expect(manifest.statement).not.toMatch(/are not published/);
    expect(manifest.packages.map((p) => p.name)).toEqual(SDK_PACKAGES.map((pkg) => pkg.name));
    for (const entry of manifest.packages) {
      expect(entry.version).toBe(sdkVersion());
      for (const file of [entry.tarball, entry.sbom]) {
        expect(file.size).toBe(readFileSync(join(layout.out, file.file)).length);
        expect(file.sha256).toMatch(/^[0-9a-f]{64}$/);
      }
      expect(entry.tarball.file).toMatch(/^antireverse-[a-z-]+-\d+\.\d+\.\d+\.tgz$/);
      expect(entry.sbom.file).toBe(entry.tarball.file.replace(/\.tgz$/, ".cdx.json"));
    }
    expect(manifest.packages[1]?.dependencies).toEqual({});
    expect(manifest.packages[3]?.dependencies).toMatchObject({ zod: "4.6.7", "@babel/parser": "8.1.0" });
    expect(manifest.packages[3]?.vendored).toEqual(["@antireverse/protocol"]);
    for (const entry of manifest.packages) {
      expect(Object.keys(entry.dependencies).filter((name) => name.startsWith("@antireverse/"))).toEqual([]);
    }
    expect(manifest.source.commit === null || /^[0-9a-f]{40}$/.test(manifest.source.commit)).toBe(true);
    expect(manifest.toolchain.node).toBe(process.versions.node);
    expect(manifest.toolchain.npm).toMatch(/^\d+\.\d+\.\d+/);
    expect(manifest.toolchain.typescript).toMatch(/^\d+\.\d+\.\d+/);
    expect(manifest.signature).toMatchObject({ algorithm: "Ed25519", fingerprint: key.fingerprint });
  });

  it("the output folder holds the tarballs, the bills of materials, the manifest and the marker: nothing else", () => {
    const expected = [
      BUILD_MARKER,
      MANIFEST_FILE,
      ...result.manifest.packages.flatMap((p) => [p.tarball.file, p.sbom.file]),
    ].sort();
    expect(filesOf(layout.out)).toEqual(expected);
  });

  it("each bill of materials names its tarball's SHA-256, and Harden's the protocol tarball whose files it carries", () => {
    for (const entry of result.manifest.packages) {
      const sbom = JSON.parse(readFileSync(join(layout.out, entry.sbom.file), "utf8"));
      expect(sbom.metadata.component.hashes).toEqual([{ alg: "SHA-256", content: entry.tarball.sha256 }]);
    }
    const harden = JSON.parse(readFileSync(join(layout.out, result.manifest.packages[3]?.sbom.file as string), "utf8"));
    expect(harden.metadata.component.components[0].hashes).toEqual([
      { alg: "SHA-256", content: result.manifest.packages[0]?.tarball.sha256 },
    ]);
  });

  it("no private key and no path of this machine is in anything that was written", () => {
    for (const file of filesOf(layout.out)) {
      if (file.endsWith(".tgz")) continue;
      const text = readFileSync(join(layout.out, file), "utf8");
      expect(text, file).not.toMatch(/PRIVATE KEY/);
      expect(text, file).not.toContain(REPO_ROOT);
      expect(text, file).not.toContain(base);
    }
    expect(filesOf(layout.out).join(" ")).not.toMatch(/key/i);
  });
});

describe("verifyArtifacts", () => {
  it("accepts the folder as packed, signed by the local key", () => {
    const outcome = verify(layout.out);
    expect(outcome.problems).toEqual([]);
    expect(outcome.fingerprint).toBe(key.fingerprint);
    expect(outcome.trusted).toBe(true);
    expect(outcome.ok).toBe(true);
  });

  it("fails on a changed byte, a shorter file and a longer file", () => {
    const flipped = copy();
    const bytes = readFileSync(tarball(flipped));
    bytes[bytes.length - 20] = (bytes[bytes.length - 20] as number) ^ 1;
    writeFileSync(tarball(flipped), bytes);
    expect(verify(flipped).problems).toEqual([
      expect.stringMatching(/antireverse-harden-.*\.tgz: SHA-256 does not match/),
    ]);
    const shorter = copy();
    truncateSync(tarball(shorter), 100);
    expect(verify(shorter).problems).toEqual([
      expect.stringMatching(/antireverse-harden-.*\.tgz: size 100, the manifest says \d+/),
    ]);
    const longer = copy();
    appendFileSync(join(longer, `antireverse-guard-${sdkVersion()}.cdx.json`), " ");
    expect(verify(longer).problems).toEqual([expect.stringMatching(/antireverse-guard-.*\.cdx\.json: size/)]);
    for (const dir of [flipped, shorter, longer]) expect(verify(dir).ok).toBe(false);
  });

  it("fails on a missing file, and on a file that became a symbolic link or a folder", () => {
    const missing = copy();
    rmSync(tarball(missing, "protocol"));
    expect(verify(missing).problems).toEqual([expect.stringMatching(/antireverse-protocol-.*\.tgz: missing/)]);
    const linked = copy();
    renameSync(tarball(linked), join(base, "moved.tgz"));
    symlinkSync(join(base, "moved.tgz"), tarball(linked));
    expect(verify(linked).problems).toEqual([expect.stringMatching(/antireverse-harden-.*\.tgz: not a regular file/)]);
    const folder = copy();
    rmSync(tarball(folder));
    mkdirSync(tarball(folder));
    expect(verify(folder).problems).toEqual([expect.stringMatching(/antireverse-harden-.*\.tgz: not a regular file/)]);
  });

  it("fails on an extra file, an extra folder, and a marker that is not the marker", () => {
    const extra = copy();
    copyFileSync(tarball(extra), join(extra, "antireverse-harden-9.9.9.tgz"));
    expect(verify(extra).problems).toEqual(["antireverse-harden-9.9.9.tgz: not listed in the manifest"]);
    const hidden = copy();
    mkdirSync(join(hidden, ".cache"));
    expect(verify(hidden).problems).toEqual([".cache: not listed in the manifest"]);
    const marker = copy();
    writeFileSync(join(marker, BUILD_MARKER), "something else");
    expect(verify(marker).problems).toEqual([`${BUILD_MARKER}: not listed in the manifest`]);
    const none = copy();
    rmSync(join(none, BUILD_MARKER));
    expect(verify(none).ok).toBe(true);
  });

  it("fails on a changed manifest: a digest, a version, the statement, a removed package", () => {
    const changes: Array<(m: SdkManifest) => void> = [
      (m) => {
        (m.packages[0] as SdkManifest["packages"][number]).tarball.sha256 = "0".repeat(64);
      },
      (m) => {
        (m.packages[0] as SdkManifest["packages"][number]).version = "1.0.0";
      },
      (m) => {
        m.statement = "Built by a trusted pipeline.";
      },
      (m) => {
        m.packages.pop();
      },
    ];
    for (const change of changes) {
      const dir = copy();
      const manifest = manifestOf(dir);
      change(manifest);
      writeFileSync(join(dir, MANIFEST_FILE), JSON.stringify(manifest, null, 2));
      const outcome = verify(dir);
      expect(outcome.problems).toContain(`${MANIFEST_FILE}: signature does not verify`);
      expect(outcome.ok).toBe(false);
    }
  });

  it("fails without a manifest, with one that is not JSON, without a signature and with another schema", () => {
    const none = copy();
    rmSync(join(none, MANIFEST_FILE));
    expect(verify(none).problems).toEqual([`${MANIFEST_FILE}: missing`]);
    const broken = copy();
    writeFileSync(join(broken, MANIFEST_FILE), "{");
    expect(verify(broken).problems).toEqual([`${MANIFEST_FILE}: not JSON`]);
    const unsigned = copy();
    const { signature: _signature, ...body } = manifestOf(unsigned);
    writeFileSync(join(unsigned, MANIFEST_FILE), JSON.stringify(body));
    expect(verify(unsigned).problems).toEqual([`${MANIFEST_FILE}: no signature`]);
    const schema = copy();
    writeFileSync(
      join(schema, MANIFEST_FILE),
      JSON.stringify(signReport({ ...body, schema: "airverse.release-gate/1" }, key)),
    );
    expect(verify(schema).problems).toEqual([
      `${MANIFEST_FILE}: not an SDK artifact manifest (schema airverse.release-gate/1)`,
    ]);
    expect(verifyArtifacts(join(base, "absent")).problems).toEqual([`${MANIFEST_FILE}: missing`]);
  });

  it("a folder changed and signed again by another key verifies only for someone who expects that key", () => {
    const dir = copy();
    appendFileSync(tarball(dir), "tampered");
    const { signature: _signature, ...body } = manifestOf(dir);
    const harden = body.packages[3] as SdkManifest["packages"][number];
    harden.tarball.size = readFileSync(tarball(dir)).length;
    harden.tarball.sha256 = createHash("sha256")
      .update(readFileSync(tarball(dir)))
      .digest("hex");
    writeFileSync(join(dir, MANIFEST_FILE), JSON.stringify(signReport(body, other)));
    const outcome = verify(dir);
    expect(outcome.problems).toEqual([]);
    expect(outcome.fingerprint).toBe(other.fingerprint);
    expect(outcome.trusted).toBe(false);
    expect(outcome.ok).toBe(false);
    expect(verify(dir, other.fingerprint).ok).toBe(true);
    // Without a local key and without --expect nobody is trusted.
    expect(verifyArtifacts(layout.out).trusted).toBe(false);
    expect(verifyArtifacts(layout.out, { expect: key.fingerprint }).ok).toBe(true);
  });

  // Review L4: --expect names the one signer the caller trusts. The local key is not a second way in.
  it("with an expected fingerprint only that signer is trusted, also when the local key signed", () => {
    const outcome = verifyArtifacts(layout.out, { localFingerprint: key.fingerprint, expect: other.fingerprint });
    expect(outcome.problems).toEqual([]);
    expect(outcome.fingerprint).toBe(key.fingerprint);
    expect(outcome.trusted).toBe(false);
    expect(outcome.ok).toBe(false);
    expect(verifyArtifacts(layout.out, { localFingerprint: key.fingerprint, expect: key.fingerprint }).ok).toBe(true);
  });

  // Review L3: whatever the manifest file holds, the answer is a list of problems.
  it("answers with a problem for a manifest that is null, a list, malformed inside, a folder, or too large", () => {
    const shapes: Array<[string | null, RegExp]> = [
      ["null", /not a manifest/],
      ["[1,2]", /not a manifest/],
      ['"text"', /not a manifest/],
      [`{"schema":"airverse.sdk-artifacts/1","pad":"${"x".repeat(1024 * 1024)}"}`, /larger than 1048576 bytes/],
      [null, /not a regular file/],
    ];
    for (const [content, problem] of shapes) {
      const dir = copy();
      if (content === null) {
        rmSync(join(dir, MANIFEST_FILE));
        mkdirSync(join(dir, MANIFEST_FILE));
      } else writeFileSync(join(dir, MANIFEST_FILE), content);
      const outcome = verify(dir);
      expect(outcome.ok).toBe(false);
      expect(outcome.problems.join(" "), String(content).slice(0, 30)).toMatch(problem);
    }
    const inside = copy();
    const { signature: _signature, ...body } = manifestOf(inside);
    writeFileSync(
      join(inside, MANIFEST_FILE),
      JSON.stringify(signReport({ ...body, packages: [null, 5, { name: "x" }] }, key)),
    );
    expect(verify(inside).problems.filter((p) => /a package entry is malformed/.test(p))).toHaveLength(3);
    const none = copy();
    writeFileSync(join(none, MANIFEST_FILE), JSON.stringify(signReport({ ...body, packages: "all" }, key)));
    expect(verify(none).problems).toContain(`${MANIFEST_FILE}: lists no package`);
  });

  it("refuses a manifest whose file names leave the folder, even when it is signed", () => {
    const dir = copy();
    const { signature: _signature, ...body } = manifestOf(dir);
    (body.packages[0] as SdkManifest["packages"][number]).tarball.file = "../copy-1/x.tgz";
    writeFileSync(join(dir, MANIFEST_FILE), JSON.stringify(signReport(body, key)));
    expect(verify(dir).problems).toContain(
      `${MANIFEST_FILE}: a file name that is not a plain name ("../copy-1/x.tgz")`,
    );
    expect(verify(dir).ok).toBe(false);
  });
});

describe("the commands", () => {
  const tsx = join(REPO_ROOT, "node_modules/tsx/dist/cli.mjs");
  const cliKey = join(base, "cli-keys/gate-key.json");
  const run = (args: string[], env: Record<string, string> = {}) =>
    new Promise<{ code: number; stdout: string; stderr: string }>((done) => {
      execFile(
        process.execPath,
        [tsx, join(REPO_ROOT, "tools/sdk/src/cli.ts"), ...args],
        { cwd: REPO_ROOT, env: { ...process.env, AR_GATE_KEY_FILE: cliKey, ...env } },
        (error, stdout, stderr) =>
          done({ code: error ? (typeof error.code === "number" ? error.code : -1) : 0, stdout, stderr }),
      );
    });
  const dir = join(base, "cli");

  it("sdk:pack writes the folder, names every file with its digest and says what the signature is", async () => {
    const out = await run(["pack", "--dir", dir]);
    expect(out.code, out.stderr + out.stdout).toBe(0);
    for (const pkg of SDK_PACKAGES) expect(out.stdout).toContain(`antireverse-${pkg.short}-${sdkVersion()}.tgz`);
    expect(out.stdout).toMatch(/sha256 [0-9a-f]{64}/);
    expect(out.stdout).toMatch(/a local signature/);
    expect(out.stdout).toMatch(/not provenance/);
    expect(out.stdout).toMatch(/Nothing was published/);
    expect(out.stdout + out.stderr).not.toMatch(/PRIVATE KEY/);
    expect(readdirSync(join(dir, "out"))).toContain(MANIFEST_FILE);
    // The same source, the same tarballs as the in-process pack above.
    const packed = JSON.parse(readFileSync(join(dir, "out", MANIFEST_FILE), "utf8")) as SdkManifest;
    expect(packed.packages.map((p) => p.tarball.sha256)).toEqual(result.manifest.packages.map((p) => p.tarball.sha256));
    expect(packed.packages.map((p) => p.sbom.sha256)).toEqual(result.manifest.packages.map((p) => p.sbom.sha256));
  });

  it("sdk:verify exits 0 for that folder, 1 when a file changed, 1 for an unknown signer, 2 on a usage error", async () => {
    const good = await run(["verify", join(dir, "out")]);
    expect(good.code, good.stdout + good.stderr).toBe(0);
    expect(good.stdout).toMatch(/^valid: /);
    expect(good.stdout).toMatch(/not provenance/);
    const unknown = await run(["verify", join(dir, "out")], { AR_GATE_KEY_FILE: join(base, "cli-keys/none.json") });
    expect(unknown.code).toBe(1);
    expect(unknown.stdout).toMatch(/^UNTRUSTED KEY: /);
    // Verifying never creates a key.
    expect(existsSync(join(base, "cli-keys/none.json"))).toBe(false);
    const fingerprint = loadOrCreateKey(cliKey).fingerprint;
    const expected = await run(["verify", join(dir, "out"), "--expect", fingerprint], {
      AR_GATE_KEY_FILE: join(base, "cli-keys/none.json"),
    });
    expect(expected.code).toBe(0);
    // L4: an expected fingerprint that is not the signer's fails, although the local key signed.
    const elsewhere = await run(["verify", join(dir, "out"), "--expect", other.fingerprint]);
    expect(elsewhere.code).toBe(1);
    expect(elsewhere.stdout).toMatch(/^UNTRUSTED KEY: /);
    appendFileSync(join(dir, "out", `antireverse-guard-${sdkVersion()}.tgz`), "x");
    const bad = await run(["verify", join(dir, "out")]);
    expect(bad.code).toBe(1);
    expect(bad.stdout).toMatch(/^INVALID: /);
    expect(bad.stdout).toMatch(/antireverse-guard-.*size/);
    // L3: a huge manifest is answered, not thrown.
    const huge = join(base, "huge");
    cpSync(join(dir, "out"), huge, { recursive: true });
    writeFileSync(join(huge, MANIFEST_FILE), Buffer.alloc(40 * 1024 * 1024, "{"));
    const big = await run(["verify", huge]);
    expect(big.code).toBe(1);
    expect(big.stdout).toMatch(/^INVALID: /);
    expect(big.stdout).toMatch(/larger than/);
    expect(big.stderr).toBe("");
    expect((await run(["verify"])).code).toBe(2);
    expect((await run(["verify", join(dir, "out"), "--expect", "nothex"])).code).toBe(2);
    expect((await run(["publish"])).code).toBe(2);
    expect((await run([])).code).toBe(2);
  });

  // Review L1: every command that empties a folder names it first.
  it("sdk:allowlist and sdk:build name the folders they empty before they do, and the list goes to standard output alone", async () => {
    const target = join(base, "cli-allowlist");
    const listed = await run(["allowlist", "--dir", target]);
    expect(listed.code, listed.stderr).toBe(0);
    expect(JSON.parse(listed.stdout)).toEqual(
      JSON.parse(readFileSync(join(REPO_ROOT, "tools/sdk/allowlist.json"), "utf8")),
    );
    expect(listed.stderr).toMatch(/Removing and writing again/);
    for (const part of ["build/protocol", "build/shield-node", "build/guard", "build/harden", "work"]) {
      expect(listed.stderr).toContain(join(target, part));
    }
    expect(listed.stderr).not.toContain(join(target, "out"));
    expect(existsSync(join(target, "out"))).toBe(false);
    const built = await run(["build", "--dir", join(base, "cli-build")]);
    expect(built.code, built.stderr).toBe(0);
    expect(built.stdout).toMatch(/Removing and writing again/);
    expect(built.stdout).toContain(join(base, "cli-build/build/harden"));
    expect(existsSync(join(base, "cli-build/work"))).toBe(false);
  });

  it("sdk:pack refuses a --dir that is not a temporary folder of ours, before it builds anything", async () => {
    const out = await run(["pack", "--dir", join(REPO_ROOT, "apps/api/.data")]);
    expect(out.code).toBe(2);
    expect(out.stderr).toMatch(/refusing/);
    expect(out.stdout).toBe("");
  });

  it("the pack fails, packing and signing nothing, when the allowlist does not match", async () => {
    const refused = layoutIn(base, "refused");
    await expect(buildAndPack(refused, { key, allowlist: { about: "", packages: {} } })).rejects.toThrow(
      /no allowlist entry/,
    );
    expect(existsSync(refused.out)).toBe(false);
  });
});
