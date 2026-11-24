// Slice 23, criterion 4: the four tarballs, installed by a real `npm install` into an empty project in a temporary
// folder outside the repository, run on this machine's plain Node. Third-party packages come from a loopback
// registry filled from the repository's node_modules (D-131): no network, no user cache, install scripts off.
import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { loadOrCreateKey } from "../../gate/src/sign.ts";
import { readAllowlist } from "../src/allowlist.ts";
import { type ExecResult, exec } from "../src/exec.ts";
import { npmEnv, npmPack, type PackedTarball } from "../src/pack.ts";
import { SDK_PACKAGES } from "../src/packages.ts";
import { buildAndPack, type PackResult } from "../src/pipeline.ts";
import { type LoopbackRegistry, packThirdParty, startRegistry } from "../src/registry.ts";
import { layoutIn, tempBase } from "./helpers.ts";

const base = tempBase("install");
const layout = layoutIn(base, "pack");
const project = join(base, "project");
const alone = join(base, "harden-alone");
const npmWork = join(base, "npm");
let packed: PackResult;
let registry: LoopbackRegistry;
let thirdParty: Awaited<ReturnType<typeof packThirdParty>>;
let install: ExecResult;
let installRequests: LoopbackRegistry["requests"];

/** Plain Node: this process's binary, no flags, no NODE_OPTIONS, no Airverse variables, no npm variables. */
function plainEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(npm_|AR_|NODE_OPTIONS$|VITEST|TSX_)/i.test(key)) continue;
    env[key] = value;
  }
  return { ...env, PATH: `${dirname(process.execPath)}:${process.env.PATH ?? ""}` };
}
const node = (args: string[], cwd = project) => exec(process.execPath, args, { cwd, env: plainEnv() });
const npmInstall = (cwd: string, tarballs: string[]) =>
  exec("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballs], {
    cwd,
    env: npmEnv(npmWork, { registry: registry.url }),
  });

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const path = join(dir, entry);
    const stat = lstatSync(path);
    if (stat.isDirectory()) out.push(...walk(path));
    else if (stat.isFile()) out.push(path);
  }
  return out;
}

/** A bundle large enough to hold the Canaries within the size budget: a small pricing module. */
const BUNDLE = `
const TIERS = { free: 0, pro: 1900, business: 4900, "enterprise-eu": 9900, team: 2900, startup: 1500 };
export function priceOf(tier) {
  const cents = TIERS[tier];
  if (cents === undefined) throw new Error("unknown tier: " + tier);
  return cents;
}
export function label(tier) {
  return "the " + tier + " plan costs " + priceOf(tier) + " cents per seat each month, billed yearly";
}
export function discounted(cents, pct) {
  const factor = 1 - pct / 100;
  return Math.round(cents * factor);
}
export function format(cents) {
  const euros = (cents / 100).toFixed(2);
  return "EUR " + euros;
}
export function table() {
  return Object.keys(TIERS).map((tier) => [tier, format(discounted(priceOf(tier), 10)), label(tier)]);
}
export function invoice(lines, tier) {
  const subtotal = lines.reduce((sum, line) => sum + line.quantity * priceOf(tier), 0);
  const tax = Math.round(subtotal * 0.21);
  return { subtotal, tax, total: subtotal + tax, currency: "EUR", note: "VAT reverse-charged for EU businesses" };
}
export function summary(lines, tier) {
  const { total, currency } = invoice(lines, tier);
  return lines.length + " line(s) on the " + tier + " plan, total " + format(total) + " (" + currency + ")";
}
export function compareTiers(firstTier, secondTier) {
  const firstPrice = priceOf(firstTier);
  const secondPrice = priceOf(secondTier);
  const difference = Math.abs(firstPrice - secondPrice);
  const cheaperTier = firstPrice <= secondPrice ? firstTier : secondTier;
  return { cheaperTier, difference, formattedDifference: format(difference) };
}
export function recommend(expectedSeats, budgetCents) {
  const affordableTiers = Object.keys(TIERS).filter((tier) => priceOf(tier) * expectedSeats <= budgetCents);
  affordableTiers.sort((left, right) => priceOf(right) - priceOf(left));
  return affordableTiers.length > 0 ? affordableTiers[0] : "free";
}
`;
/** What a caller sees of the bundle: the same before and after hardening. */
const PROBE =
  'JSON.stringify([m.table(), m.summary([{ quantity: 2 }, { quantity: 5 }], "pro"), m.recommend(3, 10000), m.compareTiers("team", "startup"), m.invoice([{ quantity: 1 }], "business")])';

beforeAll(async () => {
  packed = await buildAndPack(layout, { key: loadOrCreateKey(join(base, "keys/gate-key.json")) });
  mkdirSync(npmWork, { recursive: true });
  thirdParty = await packThirdParty(packed.closures, join(base, "registry"), npmWork);
  registry = await startRegistry(thirdParty);
  for (const dir of [project, alone]) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "package.json"),
      `${JSON.stringify({ name: "consumer", version: "1.0.0", private: true, type: "module" }, null, 2)}\n`,
    );
  }
  install = await npmInstall(
    project,
    packed.tarballs.map((tarball) => tarball.path),
  );
  installRequests = [...registry.requests];
});

afterAll(async () => {
  await registry?.close();
});

describe("npm install of the four tarballs in an empty project", () => {
  it("is outside the repository, and succeeds", () => {
    expect(relative(REPO_ROOT, project).startsWith("..")).toBe(true);
    expect(install.code, install.stderr).toBe(0);
    for (const pkg of SDK_PACKAGES) {
      const dir = join(project, "node_modules", pkg.name);
      expect(lstatSync(dir).isDirectory(), pkg.name).toBe(true);
      expect(lstatSync(dir).isSymbolicLink(), pkg.name).toBe(false);
    }
  });

  it("asked the registry only for packages on the allowlist, and every request was answered", () => {
    const listed = new Set(
      Object.values(readAllowlist().packages).flatMap((entry) =>
        Object.keys(entry.thirdParty).map((id) => id.slice(0, id.lastIndexOf("@"))),
      ),
    );
    const names = installRequests.filter((r) => !r.path.startsWith("-/")).map((r) => r.path);
    expect(names.length).toBeGreaterThan(10);
    for (const name of names) expect(listed.has(name), name).toBe(true);
    expect(installRequests.filter((r) => r.status !== 200)).toEqual([]);
    // No @antireverse name is ever asked from a registry: whoever registers that scope gets no say (D-140).
    expect(registry.requests.filter((r) => r.path.includes("antireverse"))).toEqual([]);
  });

  it("installs exactly the allowlisted closure: nothing else is in node_modules", () => {
    const lock = JSON.parse(readFileSync(join(project, "package-lock.json"), "utf8")) as {
      packages: Record<string, { version: string; hasInstallScript?: boolean }>;
    };
    const installed = Object.entries(lock.packages)
      .filter(([key]) => key !== "")
      .map(([key, entry]) => `${key.slice(key.lastIndexOf("node_modules/") + 13)}@${entry.version}`);
    const allowed = new Set(Object.values(readAllowlist().packages).flatMap((entry) => Object.keys(entry.thirdParty)));
    for (const pkg of packed.manifest.packages) allowed.add(`${pkg.name}@${pkg.version}`);
    expect([...new Set(installed)].sort()).toEqual([...allowed].sort());
    expect(Object.values(lock.packages).filter((entry) => entry.hasInstallScript)).toEqual([]);
  });

  it("Harden alone installs and runs, and a registry that offers its own @antireverse/protocol is never asked for it (D-140)", async () => {
    // A registry on which someone else has published the protocol's name at the same version.
    const decoyDir = join(base, "decoy");
    mkdirSync(decoyDir, { recursive: true });
    const decoyManifest = {
      name: "@antireverse/protocol",
      version: packed.manifest.packages[0]?.version,
      type: "module",
      exports: { ".": "./index.js", "./server": "./index.js" },
    };
    writeFileSync(join(decoyDir, "package.json"), JSON.stringify(decoyManifest));
    writeFileSync(join(decoyDir, "index.js"), 'throw new Error("code from the registry ran");\n');
    const [decoy] = await npmPack([decoyDir], join(base, "decoy-out"), npmWork);
    const hostile = await startRegistry([...thirdParty, { manifest: decoyManifest, tarball: decoy as PackedTarball }]);
    try {
      const harden = packed.tarballs.find((tarball) => tarball.name === "@antireverse/harden") as PackedTarball;
      const result = await exec("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", harden.path], {
        cwd: alone,
        env: npmEnv(join(base, "npm-alone"), { registry: hostile.url }),
      });
      expect(result.code, result.stderr).toBe(0);
      expect(hostile.requests.filter((r) => r.path.includes("antireverse"))).toEqual([]);
      expect(hostile.requests.length).toBeGreaterThan(10);
      expect(readdirSync(join(alone, "node_modules/@antireverse"))).toEqual(["harden"]);
      const help = await node([join(alone, "node_modules/.bin/antireverse"), "--help"], alone);
      expect(help.code, help.stderr).toBe(0);
      expect(help.stdout).toContain("antireverse harden <dir>");
      // The control: the same registry does hand out the decoy to a project that asks for the name.
      const asks = join(base, "asks");
      mkdirSync(asks, { recursive: true });
      writeFileSync(join(asks, "package.json"), JSON.stringify({ name: "asks", version: "1.0.0", private: true }));
      const asked = await exec(
        "npm",
        ["install", "--ignore-scripts", "--no-audit", "--no-fund", `@antireverse/protocol@${decoyManifest.version}`],
        {
          cwd: asks,
          env: npmEnv(join(base, "npm-asks"), { registry: hostile.url }),
        },
      );
      expect(asked.code, asked.stderr).toBe(0);
      expect(readFileSync(join(asks, "node_modules/@antireverse/protocol/index.js"), "utf8")).toContain(
        "code from the registry ran",
      );
    } finally {
      await hostile.close();
    }
  });
});

// Review L2: what the packed manifests say about Node, observed with npm's engine-strict on this Node.
describe("engines under engine-strict", () => {
  const [major, minor] = process.versions.node.split(".").map(Number) as [number, number];
  /** Babel 8's range, ^22.18.0 || >=24.11.0. */
  const babelRuns = (major === 22 && minor >= 18) || (major === 24 && minor >= 11) || major > 24;
  const strict = async (name: string, short: string) => {
    const dir = join(base, `strict-${short}`);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "consumer", version: "1.0.0", private: true }));
    const tarball = packed.tarballs.find((t) => t.name === name) as PackedTarball;
    return exec("npm", ["install", "--engine-strict", "--ignore-scripts", "--no-audit", "--no-fund", tarball.path], {
      cwd: dir,
      env: npmEnv(join(base, `npm-strict-${short}`), { registry: registry.url }),
    });
  };

  it("Shield, Guard and the protocol install on every Node the repository supports", async () => {
    for (const [name, short] of [
      ["@antireverse/shield-node", "shield"],
      ["@antireverse/guard", "guard"],
      ["@antireverse/protocol", "protocol"],
    ] as const) {
      const result = await strict(name, short);
      expect(result.code, `${name}: ${result.stderr}`).toBe(0);
      expect(result.stderr, name).not.toMatch(/EBADENGINE/);
    }
  });

  it("Harden installs where Babel's range holds, and is refused under engine-strict below it, naming Harden itself", async () => {
    const result = await strict("@antireverse/harden", "harden");
    if (babelRuns) {
      expect(result.code, result.stderr).toBe(0);
    } else {
      expect(result.code).not.toBe(0);
      expect(result.stderr).toMatch(/EBADENGINE/);
      expect(result.stderr).toMatch(/@antireverse\/harden@/);
      // Without engine-strict the same install warns and works: the main install of this file, used by every test below.
      expect(install.code).toBe(0);
      expect(install.stderr).toMatch(/EBADENGINE[\s\S]*@antireverse\/harden@/);
    }
  });
});

describe("the installed packages on plain Node", () => {
  it("this is a Node without default type stripping, or the tree holds nothing that would need it", () => {
    const sources = walk(join(project, "node_modules/@antireverse")).filter(
      (file) => /\.(ts|tsx|mts|cts)$/.test(file) && !file.endsWith(".d.ts"),
    );
    expect(sources).toEqual([]);
    expect(existsSync(join(project, "node_modules/tsx"))).toBe(false);
    expect(existsSync(join(project, "node_modules/typescript"))).toBe(false);
  });

  it("nothing in the project points into the repository", () => {
    for (const file of ["package.json", "package-lock.json"]) {
      const text = readFileSync(join(project, file), "utf8");
      expect(text, file).not.toContain(REPO_ROOT);
      expect(text, file).not.toMatch(/packages\/(shield-node|guard|harden|protocol)/);
    }
    for (const file of walk(join(project, "node_modules"))) {
      if (statSync(file).size > 4 * 1024 * 1024) continue;
      expect(readFileSync(file).includes(REPO_ROOT), relative(project, file)).toBe(false);
    }
  });

  it("createShield loads and reports itself disabled without a key", async () => {
    writeFileSync(
      join(project, "shield.mjs"),
      [
        'import { createShield, SDK_NAME } from "@antireverse/shield-node";',
        "const lines = [];",
        "const logger = { info: (m) => lines.push(m), warn: (m) => lines.push(m), error: (m) => lines.push(m) };",
        "const shield = createShield({ logger });",
        "const decision = shield.decide({ method: 'GET', path: '/', ip: '203.0.113.9', headers: {} });",
        "console.log(JSON.stringify({ name: SDK_NAME, stats: shield.stats(), middleware: typeof shield.express(), decision,",
        '  entry: import.meta.resolve("@antireverse/shield-node") }));',
        "await shield.close();",
      ].join("\n"),
    );
    const result = await node(["shield.mjs"]);
    expect(result.code, result.stderr).toBe(0);
    const printed = JSON.parse(result.stdout) as {
      name: string;
      stats: { disabledReason: string };
      middleware: string;
      entry: string;
    };
    expect(printed.stats.disabledReason).toBe("no Shield key was given");
    expect(printed.middleware).toBe("function");
    expect(printed.entry).toMatch(/node_modules\/@antireverse\/shield-node\/dist\/index\.js$/);
    expect(printed.entry).toContain(project.replace(/^\/private/, ""));
  });

  it("antireverse --help works through the npm bin, started by node and by itself", async () => {
    const bin = join(project, "node_modules/.bin/antireverse");
    const byNode = await node([bin, "--help"]);
    expect(byNode.stderr).toBe("");
    expect(byNode.code).toBe(0);
    expect(byNode.stdout).toContain("antireverse harden <dir>");
    expect(statSync(bin).mode & 0o111).not.toBe(0);
    const direct = await exec(bin, ["--help"], { cwd: project, env: plainEnv() });
    expect(direct.code, direct.stderr).toBe(0);
    expect(direct.stdout).toBe(byNode.stdout);
    const usage = await node([bin, "gate", "--min-rrs", "5"]);
    expect(usage.code).toBe(2);
    expect(usage.stderr).toContain("gate: missing --assessment");
  });

  it("a real Harden run protects a small bundle, proves equivalence with --test, and the result behaves the same", async () => {
    mkdirSync(join(project, "bundle"), { recursive: true });
    writeFileSync(join(project, "bundle/app.js"), BUNDLE);
    writeFileSync(
      join(project, "check.mjs"),
      [
        'import { pathToFileURL } from "node:url";',
        'import { join } from "node:path";',
        'const m = await import(pathToFileURL(join(process.cwd(), "app.js")).href);',
        `const got = ${PROBE};`,
        'if (got !== process.env.EXPECTED_RESULT) { console.error("got " + got); process.exit(1); }',
      ].join("\n"),
    );
    writeFileSync(join(project, "run-bundle.mjs"), `import * as m from "./bundle/app.js";\nconsole.log(${PROBE});\n`);
    const expected = (await node(["run-bundle.mjs"])).stdout.trim();
    expect(expected).toContain("VAT reverse-charged");
    const bin = join(project, "node_modules/.bin/antireverse");
    const report = await exec(process.execPath, [bin, "harden", "bundle", "--profile", "balanced", "--seed", "7"], {
      cwd: project,
      env: plainEnv(),
    });
    expect(report.code, report.stderr + report.stdout).toBe(0);
    expect(existsSync(join(project, "out"))).toBe(false);
    const written = await exec(
      process.execPath,
      [
        bin,
        "harden",
        "bundle",
        "--profile",
        "balanced",
        "--seed",
        "7",
        "--out",
        "out",
        "--test",
        `node ${JSON.stringify(join(project, "check.mjs"))}`,
      ],
      { cwd: project, env: { ...plainEnv(), EXPECTED_RESULT: expected } },
    );
    expect(written.code, written.stderr + written.stdout).toBe(0);
    const before = readFileSync(join(project, "bundle/app.js"), "utf8");
    const after = readFileSync(join(project, "out/app.js"), "utf8");
    expect(after).not.toBe(before);
    expect(after).not.toContain("affordableTiers");
    writeFileSync(join(project, "run-out.mjs"), `import * as m from "./out/app.js";\nconsole.log(${PROBE});\n`);
    const ran = await node(["run-out.mjs"]);
    expect(ran.code, ran.stderr).toBe(0);
    expect(ran.stdout.trim()).toBe(expected);
    // The equivalence gate is real: a wrong expectation fails the run and writes nothing.
    const wrong = await exec(
      process.execPath,
      [
        bin,
        "harden",
        "bundle",
        "--seed",
        "7",
        "--out",
        "out-wrong",
        "--test",
        `node ${JSON.stringify(join(project, "check.mjs"))}`,
      ],
      { cwd: project, env: { ...plainEnv(), EXPECTED_RESULT: "something else" } },
    );
    expect(wrong.code).not.toBe(0);
    expect(existsSync(join(project, "out-wrong"))).toBe(false);
  });

  it("Guard imports as plain ES modules: by package name in Node, and file by file with relative .js imports only", async () => {
    const dist = join(project, "node_modules/@antireverse/guard/dist");
    const modules = readdirSync(dist).filter((file) => file.endsWith(".js"));
    expect(modules).toContain("index.js");
    for (const file of modules) {
      const code = readFileSync(join(dist, file), "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/[^\n]*/g, "");
      for (const match of code.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*)["'`]([^"'`]+)["'`]/g)) {
        expect(match[1], file).toMatch(/^\.\.?\/[\w./-]+\.js$/);
        expect(existsSync(join(dist, match[1] as string)), `${file} imports ${match[1]}`).toBe(true);
      }
      expect(code, file).not.toMatch(/node:|\brequire\s*\(|\bprocess\.|\bBuffer\b/);
    }
    writeFileSync(
      join(project, "guard.mjs"),
      [
        'import * as byName from "@antireverse/guard";',
        'import * as byFile from "./node_modules/@antireverse/guard/dist/index.js";',
        'const guard = byName.createGuard({ appId: "app_89abcdef0123456789abcdef", endpoint: "https://airverse.example" });',
        "console.log(JSON.stringify({ exports: Object.keys(byName).sort(), same: byName.createGuard === byFile.createGuard, members: Object.keys(guard).sort() }));",
      ].join("\n"),
    );
    const result = await node(["guard.mjs"]);
    expect(result.code, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      exports: ["ATTESTATION_HEADER", "ATTESTATION_SIGNALS", "CONTENT_HASH_HEADER", "SIGNATURE_HEADER", "createGuard"],
      same: true,
      members: ["attest", "fetch", "headers", "sign", "signals", "start", "stop", "token"],
    });
  });

  it("the protocol loads, both entries, and Harden's library entry too", async () => {
    writeFileSync(
      join(project, "protocol.mjs"),
      [
        'import { EventBatchSchema, SHIELD_KEY_PATTERN } from "@antireverse/protocol";',
        'import { generateKey } from "@antireverse/protocol/server";',
        'import { harden, DEFAULT_BUDGET } from "@antireverse/harden";',
        "console.log(JSON.stringify({ schema: typeof EventBatchSchema.safeParse, pattern: SHIELD_KEY_PATTERN instanceof RegExp,",
        "  generate: typeof generateKey, harden: typeof harden, budget: typeof DEFAULT_BUDGET,",
        '  own: import.meta.resolve("@antireverse/protocol") }));',
      ].join("\n"),
    );
    const result = await node(["protocol.mjs"]);
    expect(result.code, result.stderr).toBe(0);
    const printed = JSON.parse(result.stdout) as { own: string };
    expect(printed).toMatchObject({ schema: "function", pattern: true, generate: "function", harden: "function" });
    expect(printed.own).toMatch(/node_modules\/@antireverse\/protocol\/dist\/index\.js$/);
  });

  it("a TypeScript consumer of the four packages type-checks, and the types are real (not any)", async () => {
    writeFileSync(
      join(project, "consumer.ts"),
      [
        'import { createGuard, type Guard } from "@antireverse/guard";',
        'import { harden, type HardenResult } from "@antireverse/harden";',
        'import { EventBatchSchema, type ShieldEvent } from "@antireverse/protocol";',
        'import { generateKey } from "@antireverse/protocol/server";',
        'import { createShield, type Shield, type ShieldStats } from "@antireverse/shield-node";',
        "",
        'const shield: Shield = createShield({ key: process.env.AR_SHIELD_KEY, endpoint: "http://127.0.0.1:8787" });',
        "// @ts-expect-error a Shield needs its endpoint named",
        "createShield({});",
        "// @ts-expect-error a key is a string, when there is one",
        'createShield({ key: 5, endpoint: "" });',
        "const stats: ShieldStats = shield.stats();",
        "export const reason: string | null = stats.disabledReason;",
        "// @ts-expect-error a reason is not a number: this line fails to compile if Shield's types were `any`",
        "export const wrongShield: number = stats.disabledReason;",
        'export const guard: Guard = createGuard({ appId: "app_89abcdef0123456789abcdef", endpoint: "https://airverse.example" });',
        "// @ts-expect-error Guard has no such member",
        "guard.nothing();",
        "export const parsed = EventBatchSchema.safeParse({});",
        "// @ts-expect-error a parse result is not a string",
        "export const wrongProtocol: string = parsed;",
        "export type Event = ShieldEvent;",
        "// @ts-expect-error an Event is an object, not a number",
        "export const wrongEvent: ShieldEvent = 5;",
        "export const key = generateKey;",
        "// @ts-expect-error harden needs arguments",
        "export const result: HardenResult = harden();",
      ].join("\n"),
    );
    const tsc = join(REPO_ROOT, "node_modules/typescript/bin/tsc");
    const result = await exec(
      process.execPath,
      [
        tsc,
        "--noEmit",
        "--strict",
        "--target",
        "es2024",
        "--lib",
        "es2024,dom",
        "--module",
        "nodenext",
        "--moduleResolution",
        "nodenext",
        "--skipLibCheck",
        "--types",
        "node",
        "--typeRoots",
        join(REPO_ROOT, "node_modules/@types"),
        "consumer.ts",
      ],
      { cwd: project, env: plainEnv() },
    );
    expect(result.stdout + result.stderr).toBe("");
    expect(result.code).toBe(0);
  });

  // Review M4: the guides' own snippets must compile for a strict TypeScript project against the packed types —
  // they read the key from process.env, which is `string | undefined`, and Shield handles a missing key at run time.
  it("the createShield snippets of the guides compile under --strict, without skipLibCheck, against the packed Shield", async () => {
    const snippets: string[] = [];
    for (const doc of ["docs/shield.md", "docs/getting-started.md", "README.md"]) {
      const text = readFileSync(join(REPO_ROOT, doc), "utf8");
      for (const match of text.matchAll(/```(?:ts|js)\n([\s\S]*?)```/g)) {
        const code = match[1] as string;
        if (code.includes("createShield({") && code.includes("process.env.AR_SHIELD_KEY")) snippets.push(code);
      }
    }
    expect(snippets.length).toBeGreaterThanOrEqual(4);
    const dir = join(project, "guides");
    mkdirSync(dir, { recursive: true });
    // What the snippets take from the reader's project: Express, and their own request handler.
    writeFileSync(
      join(dir, "ambient.d.ts"),
      [
        'declare module "express" {',
        '  import type { IncomingMessage, ServerResponse } from "node:http";',
        "  type Handler = (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void;",
        "  interface App { use(...handlers: unknown[]): void; get(path: string, handler: Handler): void; listen(port: number): void }",
        "  const express: { (): App; json(options?: { verify?: unknown }): Handler; static(root: string): Handler };",
        "  export default express;",
        "}",
        "declare const app: { use(...handlers: unknown[]): void };",
        'declare function handle(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse): void;',
      ].join("\n"),
    );
    const files = snippets.map((code, index) => {
      const file = join(dir, `snippet-${index}.ts`);
      writeFileSync(file, `${code}\nexport {};\n`);
      return file;
    });
    const result = await exec(
      process.execPath,
      [
        join(REPO_ROOT, "node_modules/typescript/bin/tsc"),
        "--noEmit",
        "--strict",
        "--exactOptionalPropertyTypes",
        "--target",
        "es2024",
        "--lib",
        "es2024",
        "--module",
        "nodenext",
        "--moduleResolution",
        "nodenext",
        "--types",
        "node",
        "--typeRoots",
        join(REPO_ROOT, "node_modules/@types"),
        join(dir, "ambient.d.ts"),
        ...files,
      ],
      { cwd: project, env: plainEnv() },
    );
    expect(result.stdout + result.stderr).toBe("");
    expect(result.code).toBe(0);
  });
});

// Review M3: the other way to use Shield is the clone's folder. With the clone inside the project npm also installs
// the folder's development dependencies, and asks the registry for each. None of them may be an @antireverse name:
// that scope is not registered on npm, so whoever registers it could answer.
describe("the clone path: Shield's folder installed from a clone inside the project", () => {
  it("npm asks the registry for no @antireverse name, only for the public development dependencies", async () => {
    const dir = join(base, "clone-inside");
    const folder = join(dir, "airverse/packages/shield-node");
    mkdirSync(folder, { recursive: true });
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "consumer", version: "1.0.0", private: true, type: "module" }),
    );
    // The folder as a clone has it: its manifest and its source.
    cpSync(join(REPO_ROOT, "packages/shield-node/package.json"), join(folder, "package.json"));
    cpSync(join(REPO_ROOT, "packages/shield-node/src"), join(folder, "src"), { recursive: true });
    const empty = await startRegistry([]);
    try {
      const result = await exec(
        "npm",
        ["install", "--ignore-scripts", "--no-audit", "--no-fund", "./airverse/packages/shield-node"],
        {
          cwd: dir,
          env: npmEnv(join(base, "npm-clone"), { registry: empty.url }),
        },
      );
      const asked = [...new Set(empty.requests.map((r) => r.path))].sort();
      expect(
        asked.filter((name) => name.includes("antireverse")),
        result.stderr.slice(-400),
      ).toEqual([]);
      // Public names, owned by their projects on the public registry: asking for them is ordinary.
      expect(asked).toEqual(["@types/express", "express"]);
    } finally {
      await empty.close();
    }
  });

  it("no SDK package's manifest names another @antireverse package in any dependency field", () => {
    for (const pkg of SDK_PACKAGES) {
      const manifest = JSON.parse(
        readFileSync(join(REPO_ROOT, "packages", pkg.short, "package.json"), "utf8"),
      ) as Record<string, Record<string, string> | undefined>;
      for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
        expect(
          Object.keys(manifest[field] ?? {}).filter((name) => name.startsWith("@antireverse/")),
          `${pkg.short} ${field}`,
        ).toEqual([]);
      }
    }
  });
});
