// Slice 18e: the gate key (Ed25519, mode 0600, outside the repository, created on first use) and the report signature.
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "../src/paths.ts";
import { canonicalJson, defaultKeyFile, loadOrCreateKey, signReport, verifyReport } from "../src/sign.ts";

const dirs: string[] = [];
const temp = () => {
  const dir = mkdtempSync(join(tmpdir(), "gate-sign-"));
  dirs.push(dir);
  return dir;
};
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

describe("canonicalJson", () => {
  it("sorts keys at every depth and keeps array order", () => {
    expect(canonicalJson({ b: 1, a: [{ d: 1, c: 2 }, 3], e: null })).toBe('{"a":[{"c":2,"d":1},3],"b":1,"e":null}');
  });
});

describe("the gate key", () => {
  it("defaults to the user's config directory, outside the repository", () => {
    expect(defaultKeyFile({})).toBe(join(homedir(), ".config", "airverse", "gate-key.json"));
    expect(defaultKeyFile({ XDG_CONFIG_HOME: "/x/cfg" })).toBe("/x/cfg/airverse/gate-key.json");
    expect(defaultKeyFile({ AR_GATE_KEY_FILE: "/k/gate.json" })).toBe("/k/gate.json");
  });

  it("is created on first use with mode 0600 in a 0700 directory, then reused", () => {
    const file = join(temp(), "nested", "gate-key.json");
    const first = loadOrCreateKey(file);
    expect(first.created).toBe(true);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(statSync(join(file, "..")).mode & 0o777).toBe(0o700);
    const again = loadOrCreateKey(file);
    expect(again.created).toBe(false);
    expect(again.fingerprint).toBe(first.fingerprint);
    expect(first.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses a key file readable by others, and one inside the repository", () => {
    const file = join(temp(), "gate-key.json");
    loadOrCreateKey(file);
    chmodSync(file, 0o644);
    expect(() => loadOrCreateKey(file)).toThrow(/mode 644/);
    expect(() => loadOrCreateKey(join(REPO_ROOT, "gate-key.json"))).toThrow(/inside the repository/);
  });

  it("never puts the private key into a signed report", () => {
    const key = loadOrCreateKey(join(temp(), "k.json"));
    const stored = JSON.parse(readFileSync(key.file, "utf8")) as { private_key: string };
    const signed = signReport({ hello: "world" }, key);
    expect(JSON.stringify(signed)).not.toContain(stored.private_key);
  });
});

describe("signing and verification", () => {
  const key = loadOrCreateKey(join(temp(), "k.json"));
  const report = { verdict: "blocked", criteria: [{ id: "a", state: "pass" }], git: { commit: "abc", dirty: false } };

  it("verifies an untouched report and names the key", () => {
    const signed = signReport(report, key);
    expect(signed.signature.algorithm).toBe("Ed25519");
    expect(signed.signature.fingerprint).toBe(key.fingerprint);
    expect(verifyReport(signed)).toEqual({ ok: true, fingerprint: key.fingerprint });
    // Key order does not matter: the signed bytes are canonical.
    const reordered = JSON.parse(JSON.stringify({ signature: signed.signature, ...report }));
    expect(verifyReport(reordered).ok).toBe(true);
  });

  it("fails when any field is changed", () => {
    const signed = signReport(report, key);
    const tampered = JSON.parse(JSON.stringify(signed));
    tampered.verdict = "releasable";
    expect(verifyReport(tampered)).toEqual({ ok: false, reason: "signature does not verify" });
    const tampered2 = JSON.parse(JSON.stringify(signed));
    tampered2.criteria[0].state = "fail";
    expect(verifyReport(tampered2).ok).toBe(false);
  });

  it("fails on a swapped key, a wrong fingerprint, or no signature", () => {
    const other = loadOrCreateKey(join(temp(), "other.json"));
    const signed = signReport(report, key);
    const swapped = {
      ...signed,
      signature: { ...signed.signature, public_key: signReport(report, other).signature.public_key },
    };
    expect(verifyReport(swapped)).toEqual({ ok: false, reason: "fingerprint does not match the public key" });
    const swappedBoth = { ...signed, signature: signReport(report, other).signature, verdict: "releasable" };
    expect(verifyReport(swappedBoth).ok).toBe(false);
    expect(verifyReport({ ...report })).toEqual({ ok: false, reason: "no signature" });
  });

  it("checks the signer against an expected fingerprint when one is given", () => {
    const signed = signReport(report, key);
    expect(verifyReport(signed, { expectedFingerprint: key.fingerprint }).ok).toBe(true);
    expect(verifyReport(signed, { expectedFingerprint: "0".repeat(64) })).toEqual({
      ok: false,
      reason: "signed by another key",
    });
  });

  it("round-trips through a file", () => {
    const file = join(temp(), "report.json");
    writeFileSync(file, `${JSON.stringify(signReport(report, key), null, 2)}\n`);
    expect(verifyReport(JSON.parse(readFileSync(file, "utf8"))).ok).toBe(true);
  });
});
