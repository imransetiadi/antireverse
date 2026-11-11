// Slice 07 — the leak scan. Every rule has a positive and a negative case. Realistic-looking tokens are built
// programmatically from harmless pieces so that no secret-shaped literal sits in the repository; the AWS key is
// AWS's own documented example value.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LEAK_RULES } from "@antireverse/protocol";
import { leakFingerprint } from "@antireverse/protocol/server";
import { afterEach, describe, expect, it } from "vitest";
import { loadAllowlist, maskValue, scanLeaks } from "../src/leaks/scan.ts";

const EMPTY = { version: 1 as const, allow: [] };

/** Scans one text file at `path` with an empty allowlist. */
function scanOne(text: string, path = "app.js") {
  return scanLeaks([{ path, text }], [path], EMPTY);
}

function rulesOf(text: string, path = "app.js"): string[] {
  return scanOne(text, path).findings.map((f) => f.rule);
}

// Harmless building blocks for fake tokens.
const ALNUM36 = "A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6S7t8"; // 36 alphanumerics
const AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE";
const fakeGithub = (prefix: string) => `${prefix}_${ALNUM36}`;
const fakeStripe = (prefix: string) => `${prefix}_live_${ALNUM36.slice(0, 24)}`;
const fakeSlack = () => ["xo", "xb-", "1234567890-abcdefABCDEF"].join("");
const fakeGoogle = () => `${["AI", "za"].join("")}${"Sy0123456789_abcdefghij-KLMNOPQRSTU".slice(0, 35)}`;
const fakePem = () =>
  [
    `-----BEGIN ${"RSA PRIVATE"} KEY-----`,
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX",
    `-----END ${"RSA PRIVATE"} KEY-----`,
  ].join("\n");
const HIGH_ENTROPY = "Zq8Lr2Tx5Vb9Nm3Kc7Wd"; // 20 distinct characters: entropy ~4.3 bits/char

describe("leak rules — one positive and one negative per rule", () => {
  it("knows every rule id of the protocol", () => {
    const seen = new Set<string>();
    const samples = [
      "//# sourceMappingURL=app.js.map",
      fakePem(),
      `const k = "${AWS_EXAMPLE}";`,
      `const t = "${fakeGithub("ghp")}";`,
      `const s = "${fakeStripe("sk")}";`,
      `const s = "${fakeSlack()}";`,
      `const g = "${fakeGoogle()}";`,
      `const clientSecret = "${HIGH_ENTROPY}";`,
      `fetch("http://10.0.0.5/admin");`,
    ];
    for (const s of samples) for (const r of rulesOf(s)) seen.add(r);
    expect([...seen].sort()).toEqual(LEAK_RULES.map((r) => r.id).sort());
  });

  it("source-map: a .map file, a sourceMappingURL comment and an inline data: map", () => {
    const fromName = scanLeaks([], ["app.js.map"], EMPTY);
    expect(fromName.findings.map((f) => f.rule)).toEqual(["source-map"]);
    expect(rulesOf("x();\n//# sourceMappingURL=app.js.map\n")).toEqual(["source-map"]);
    expect(rulesOf("x();\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==\n")).toEqual([
      "source-map",
    ]);
    expect(rulesOf("/*# sourceMappingURL=style.css.map */", "style.css")).toEqual(["source-map"]);
  });
  it("source-map negative: a map-like name and the word in prose", () => {
    expect(scanLeaks([], ["sitemap.xml", "app.mapper.js"], EMPTY).findings).toEqual([]);
    expect(rulesOf(`const doc = "see the sourceMappingURL docs";`)).toEqual([]);
  });

  it("private-key positive and negative", () => {
    expect(rulesOf(`const pem = \`${fakePem()}\`;`)).toEqual(["private-key"]);
    expect(rulesOf(`-----BEGIN ${"PUBLIC"} KEY-----\nMIIB\n-----END PUBLIC KEY-----`)).toEqual([]);
  });

  it("aws-access-key positive (AKIA and ASIA) and negative", () => {
    expect(rulesOf(`const k = "${AWS_EXAMPLE}";`)).toEqual(["aws-access-key"]);
    expect(rulesOf(`const k = "${AWS_EXAMPLE.replace("AKIA", "ASIA")}";`)).toEqual(["aws-access-key"]);
    expect(rulesOf(`const k = "AKIAshort";`)).toEqual([]);
    expect(rulesOf(`const k = "${AWS_EXAMPLE.toLowerCase()}";`)).toEqual([]);
  });

  it("github-token positive for every prefix and negative", () => {
    for (const p of ["ghp", "gho", "ghu", "ghs", "ghr"])
      expect(rulesOf(`t = "${fakeGithub(p)}";`)).toEqual(["github-token"]);
    expect(rulesOf(`t = "ghx_${ALNUM36}";`)).toEqual([]);
    expect(rulesOf(`t = "ghp_${ALNUM36.slice(0, 20)}";`)).toEqual([]);
  });

  it("stripe-secret positive (sk_live, rk_live) and negative (test keys, short)", () => {
    expect(rulesOf(`k = "${fakeStripe("sk")}";`)).toEqual(["stripe-secret"]);
    expect(rulesOf(`k = "${fakeStripe("rk")}";`)).toEqual(["stripe-secret"]);
    expect(rulesOf(`k = "sk_test_${ALNUM36.slice(0, 24)}";`)).toEqual([]);
    expect(rulesOf(`k = "sk_live_${ALNUM36.slice(0, 10)}";`)).toEqual([]);
  });

  it("slack-token positive and negative", () => {
    expect(rulesOf(`s = "${fakeSlack()}";`)).toEqual(["slack-token"]);
    expect(rulesOf(`s = "xoxz-1234567890-abc";`)).toEqual([]);
  });

  it("google-api-key positive and negative", () => {
    expect(fakeGoogle()).toHaveLength(39);
    expect(rulesOf(`g = "${fakeGoogle()}";`)).toEqual(["google-api-key"]);
    expect(rulesOf(`g = "${fakeGoogle().slice(0, 20)}";`)).toEqual([]);
  });

  it("secret-assignment positive: names, quoted keys and the = / : forms", () => {
    expect(rulesOf(`const clientSecret = "${HIGH_ENTROPY}";`)).toEqual(["secret-assignment"]);
    expect(rulesOf(`const cfg = { api_key: '${HIGH_ENTROPY}' };`)).toEqual(["secret-assignment"]);
    expect(rulesOf(`{ "password": "${HIGH_ENTROPY}" }`, "config.json")).toEqual(["secret-assignment"]);
    expect(rulesOf(`let AUTH_TOKEN = \`${HIGH_ENTROPY}\`;`)).toEqual(["secret-assignment"]);
  });
  it("secret-assignment negative: low entropy, short value, harmless name, comparison", () => {
    expect(rulesOf(`const password = "aaaaaaaaaaaaaaaaaaaaaaaa";`)).toEqual([]);
    expect(rulesOf(`const token = "Zq8Lr2Tx";`)).toEqual([]);
    expect(rulesOf(`const label = "${HIGH_ENTROPY}";`)).toEqual([]);
    expect(rulesOf(`if (token === "${HIGH_ENTROPY}") {}`)).toEqual([]);
  });

  it("internal-url positive: localhost, loopback, private, link-local, internal suffixes", () => {
    for (const url of [
      "http://localhost:3000/x",
      "https://127.0.0.1/api",
      "http://[::1]:8080/",
      "http://10.1.2.3/",
      "http://172.20.0.1/",
      "https://192.168.1.10/admin",
      "http://169.254.169.254/latest",
      "https://billing.internal/v1",
      "http://printer.local",
      "https://wiki.corp/page",
      "http://nas.lan/",
    ]) {
      expect(rulesOf(`fetch("${url}");`), url).toEqual(["internal-url"]);
    }
  });
  it("internal-url negative: public hosts and near misses", () => {
    for (const url of [
      "https://example.com/",
      "http://172.32.0.1/",
      "https://8.8.8.8/",
      "https://local.example.com/",
    ]) {
      expect(rulesOf(`fetch("${url}");`), url).toEqual([]);
    }
  });
});

describe("findings carry no value", () => {
  it("gives rule, path, 1-based line, a mask and the protocol fingerprint", () => {
    const text = `// header\nconst ok = 1;\nconst k = "${AWS_EXAMPLE}";\n`;
    const { findings } = scanOne(text, "src/keys.js");
    expect(findings).toEqual([
      {
        rule: "aws-access-key",
        path: "src/keys.js",
        line: 3,
        masked: "AKIA…",
        fingerprint: leakFingerprint("aws-access-key", "src/keys.js", AWS_EXAMPLE),
      },
    ]);
    expect(JSON.stringify(findings)).not.toContain(AWS_EXAMPLE);
  });

  it("masks at most 4 characters and never more than a quarter of the value", () => {
    expect(maskValue(AWS_EXAMPLE)).toBe("AKIA…");
    expect(maskValue("abcdefgh")).toBe("ab…");
    expect(maskValue("abc")).toBe("…");
    expect(maskValue("x".repeat(100))).toBe("xxxx…");
  });
});

describe("review fixes M1/M2/L4", () => {
  const LONG_SECRET = `${HIGH_ENTROPY}Yp4Fh6Jg1Qs0`; // 32 characters, high entropy

  it("M1: a TypeScript type annotation before = is still a secret assignment", () => {
    expect(rulesOf(`const apiToken: string = "${LONG_SECRET}";`, "a.ts")).toEqual(["secret-assignment"]);
    expect(rulesOf(`let clientSecret: Readonly<string> | undefined = '${LONG_SECRET}';`, "a.ts")).toEqual([
      "secret-assignment",
    ]);
    // The annotation must end in "=": an object's next key is not taken as a type.
    expect(rulesOf(`const o = { token: other, label: "${LONG_SECRET}" };`)).toEqual([]);
    expect(rulesOf(`const f = (token: string) => "${LONG_SECRET}";`, "a.ts")).toEqual([]);
  });

  it("M1: no catastrophic backtracking on a long hostile line", () => {
    const hostile = `token: ${"a ".repeat(100_000)}`;
    const hostile2 = `password${": x".repeat(50_000)} = 'short'`;
    const started = performance.now();
    rulesOf(hostile, "a.ts");
    rulesOf(hostile2, "a.ts");
    rulesOf(hostile, ".env");
    expect(performance.now() - started).toBeLessThan(2000);
  });

  it("M2: unquoted values in .env, YAML, INI-like and extension-less config files", () => {
    expect(rulesOf(`SECRET_TOKEN=${LONG_SECRET}\n`, ".env")).toEqual(["secret-assignment"]);
    expect(rulesOf(`export API_KEY=${LONG_SECRET}`, ".env.production")).toEqual(["secret-assignment"]);
    expect(rulesOf(`auth:\n  client_secret: ${LONG_SECRET}\n`, "config/app.yml")).toEqual(["secret-assignment"]);
    expect(rulesOf(`client_secret: ${LONG_SECRET}`, "app.yaml")).toEqual(["secret-assignment"]);
    expect(rulesOf(`password = ${LONG_SECRET}`, "db.ini")).toEqual(["secret-assignment"]);
    expect(rulesOf(`db.password=${LONG_SECRET}`, "app.properties")).toEqual(["secret-assignment"]);
    expect(rulesOf(`token = ${LONG_SECRET}`, "settings.conf")).toEqual(["secret-assignment"]);
    expect(rulesOf(`SECRET_TOKEN=${LONG_SECRET}`, "Procfile")).toEqual(["secret-assignment"]);
    const finding = scanOne(`# comment\nSECRET_TOKEN=${LONG_SECRET}\n`, ".env").findings[0];
    expect(finding?.line).toBe(2);
    expect(finding?.fingerprint).toBe(leakFingerprint("secret-assignment", ".env", LONG_SECRET));
  });

  it("M2: negatives — low entropy, short, harmless name, and JS files keep the quoted rule only", () => {
    expect(rulesOf("SECRET_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ".env")).toEqual([]);
    expect(rulesOf("SECRET_TOKEN=Zq8Lr2Tx", ".env")).toEqual([]);
    expect(rulesOf(`LOG_LEVEL=${LONG_SECRET}`, ".env")).toEqual([]);
    expect(rulesOf(`token = ${LONG_SECRET}`, "app.js")).toEqual([]);
  });

  it("M2: a quoted value in a config file is reported once", () => {
    expect(scanOne(`SECRET_TOKEN="${LONG_SECRET}"`, ".env").findings).toHaveLength(1);
    expect(scanOne(`client_secret: '${LONG_SECRET}'`, "app.yml").findings).toHaveLength(1);
    expect(scanOne(`token = "${LONG_SECRET}"`, "a.toml").findings).toHaveLength(1);
  });

  it("L4: 50,000 findings in one file are scanned quickly with correct lines", () => {
    const text = (count: number): string =>
      Array.from({ length: count }, (_, i) => `fetch("http://10.0.${(i >> 8) & 255}.${i & 255}/p${i}");`).join("\n");
    /** The fastest of `runs` scans of `body`, in milliseconds, and the findings of the last one. */
    const fastest = (body: string, runs: number) => {
      let best = Number.POSITIVE_INFINITY;
      let findings: ReturnType<typeof scanOne>["findings"] = [];
      for (let r = 0; r < runs; r++) {
        const started = performance.now();
        findings = scanOne(body, "big.js").findings;
        best = Math.min(best, performance.now() - started);
      }
      return { best, findings };
    };
    // "Quickly" is checked as growth, not as a wall-clock bound: alone the 50,000-line scan takes about 130 ms, but
    // under the load of the full test run beside other suites it took 2.2 s and failed a 2 s bound. Ten times the
    // findings must cost well under a hundred times as long — what the line lookup cost before L4 (it rescanned the
    // text for every finding). A bound of 30 allows for noise; a quadratic scan lands near 100.
    const small = fastest(text(5_000), 3);
    const large = fastest(text(50_000), 2);
    expect(large.best / Math.max(small.best, 1)).toBeLessThan(30);
    expect(large.best).toBeLessThan(30_000); // a guard against a hang, not a speed claim
    const { findings } = large;
    expect(small.findings).toHaveLength(5_000);
    expect(findings).toHaveLength(50_000);
    expect(findings[49_999]?.line).toBe(50_000);
    expect(findings[12_345]?.line).toBe(12_346);
  }, 60_000);
});

describe("allowlist", () => {
  it("suppresses a finding by its fingerprint and counts it", () => {
    const fp = leakFingerprint("aws-access-key", "app.js", AWS_EXAMPLE);
    const result = scanLeaks([{ path: "app.js", text: `k = "${AWS_EXAMPLE}"` }], ["app.js"], {
      version: 1,
      allow: [{ fingerprint: fp, reason: "documented example value" }],
    });
    expect(result.findings).toEqual([]);
    expect(result.suppressed).toBe(1);
  });

  it("a fingerprint is bound to the path: the same value elsewhere is still found", () => {
    const fp = leakFingerprint("aws-access-key", "app.js", AWS_EXAMPLE);
    const result = scanLeaks([{ path: "other.js", text: `k = "${AWS_EXAMPLE}"` }], ["other.js"], {
      version: 1,
      allow: [{ fingerprint: fp, reason: "documented example value" }],
    });
    expect(result.findings).toHaveLength(1);
    expect(result.suppressed).toBe(0);
  });

  let cwd = "";
  afterEach(() => {
    if (cwd) rmSync(cwd, { recursive: true, force: true });
    cwd = "";
  });

  it("loads the default .antireverse/leak-allow.json relative to the working directory", () => {
    cwd = mkdtempSync(join(tmpdir(), "harden-allow-"));
    mkdirSync(join(cwd, ".antireverse"));
    const fp = "0".repeat(32);
    writeFileSync(
      join(cwd, ".antireverse", "leak-allow.json"),
      JSON.stringify({ version: 1, allow: [{ fingerprint: fp, reason: "r" }] }),
    );
    const loaded = loadAllowlist({ cwd });
    expect(loaded).toEqual({ allow: { version: 1, allow: [{ fingerprint: fp, reason: "r" }] } });
  });

  it("a missing default file is an empty allowlist", () => {
    cwd = mkdtempSync(join(tmpdir(), "harden-allow-"));
    expect(loadAllowlist({ cwd })).toEqual({ allow: { version: 1, allow: [] } });
  });

  it("a given file that is missing fails", () => {
    cwd = mkdtempSync(join(tmpdir(), "harden-allow-"));
    const loaded = loadAllowlist({ cwd, file: "nope.json" });
    expect("error" in loaded).toBe(true);
  });

  it("a malformed file fails (bad JSON, wrong shape), and the error never echoes the content", () => {
    cwd = mkdtempSync(join(tmpdir(), "harden-allow-"));
    writeFileSync(join(cwd, "bad.json"), `{ "version": 1, "allow": [ ${AWS_EXAMPLE}`);
    const bad = loadAllowlist({ cwd, file: "bad.json" });
    expect("error" in bad).toBe(true);
    if ("error" in bad) expect(bad.error).not.toContain(AWS_EXAMPLE);
    writeFileSync(join(cwd, "shape.json"), JSON.stringify({ version: 2, allow: [] }));
    expect("error" in loadAllowlist({ cwd, file: "shape.json" })).toBe(true);
    mkdirSync(join(cwd, ".antireverse"));
    writeFileSync(join(cwd, ".antireverse", "leak-allow.json"), "not json");
    expect("error" in loadAllowlist({ cwd })).toBe(true);
  });
});
