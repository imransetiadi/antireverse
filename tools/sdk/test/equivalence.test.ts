// Slice 23, criterion 5: the compiled output behaves like the source. The whole suites of protocol, shield-node and
// harden run twice — on the source as always, and on the compiled output through the redirect of
// src/dist-plugin.ts — and the two runs are compared test by test.
import { cpSync, existsSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join, relative } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { timingFilesOf, timingProjectOf } from "../../../vitest.timing.ts";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import { buildAll } from "../src/build.ts";
import { DIST_EXCLUDED, DIST_OUTSIDE_THE_GUARD, DIST_PACKAGES, distRedirect } from "../src/dist-plugin.ts";
import { mergeRerun, notPassedFiles, type RunReport } from "../src/equivalence.ts";
import { type ExecResult, exec } from "../src/exec.ts";
import { layoutIn, tempBase } from "./helpers.ts";

const base = tempBase("equivalence");
const layout = layoutIn(base, "eq");
/** As the plugin names compiled files: by real path (the temporary directory is a symbolic link on some systems). */
const buildRoot = join(realpathSync(base), "eq/build");
const vitest = join(REPO_ROOT, "node_modules/vitest/vitest.mjs");

type Report = RunReport;

/** file (relative to the repository) → "full name: status", sorted. */
function byFile(report: Report): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const file of report.testResults) {
    out.set(relative(REPO_ROOT, file.name), file.assertionResults.map((a) => `${a.fullName}: ${a.status}`).sort());
  }
  return out;
}

function childEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(VITEST|NODE_OPTIONS$|AR_)/.test(key)) continue;
    env[key] = value;
  }
  return { ...env, ...extra };
}

type Mode = "source" | "compiled";
let firstRuns: Record<Mode, ExecResult>;
let source: Report;
let dist: Report;
/** The files that were run a second time, alone, because a result of the first run was not "passed" (D-143). */
const reruns: Record<Mode, string[]> = { source: [], compiled: [] };
let runs = 0;

/** One Vitest run of a mode; `files`: only these (absolute paths), else everything. */
async function run(mode: Mode, files: readonly string[] = []): Promise<{ result: ExecResult; report: Report | null }> {
  const json = join(base, `${mode}-${++runs}.json`);
  const args =
    mode === "source"
      ? // Each package's project and, where it has late files (vitest.timing.ts), its late twin: every test once.
        DIST_PACKAGES.flatMap((pkg) => [
          pkg.short,
          ...(timingFilesOf(pkg.short).length > 0 ? [timingProjectOf(pkg.short)] : []),
        ]).flatMap((name) => ["--project", name])
      : ["--config", join(REPO_ROOT, "tools/sdk/vitest.dist.config.ts")];
  const result = await exec(
    process.execPath,
    [vitest, "run", ...args, "--reporter=json", `--outputFile=${json}`, ...files],
    { cwd: REPO_ROOT, env: childEnv(mode === "compiled" ? { AR_SDK_BUILD_ROOT: buildRoot } : {}), timeoutMs: 280_000 },
  );
  return { result, report: existsSync(json) ? (JSON.parse(readFileSync(json, "utf8")) as Report) : null };
}

/** The whole suite of a mode, then once more, alone, the files with a result that is not "passed". */
async function settled(mode: Mode): Promise<{ result: ExecResult; report: Report }> {
  const first = await run(mode);
  if (first.report === null) return { result: first.result, report: { testResults: [] } as unknown as Report };
  const files = notPassedFiles(first.report);
  if (files.length === 0) return { result: first.result, report: first.report };
  reruns[mode] = files.map((file) => relative(REPO_ROOT, file));
  console.warn(`equivalence (${mode}): running a second time, alone: ${reruns[mode].join(", ")}`);
  const second = await run(mode, files);
  return {
    result: first.result,
    report: second.report === null ? first.report : mergeRerun(first.report, second.report, files),
  };
}

beforeAll(async () => {
  await buildAll(layout);
  // One after the other: both suites hold tests with a wall-clock budget, which two runs at once can push over it.
  const sourceRun = await settled("source");
  const distRun = await settled("compiled");
  firstRuns = { source: sourceRun.result, compiled: distRun.result };
  source = sourceRun.report;
  dist = distRun.report;
});

describe("the suites on the compiled output", () => {
  it("both runs finished, and every test of both passed: none failed, skipped or left as todo", () => {
    // A first run may have ended with a failure that the second run of that file cleared (D-143): what counts is
    // the settled result below. A run that produced no report at all has no tests and fails here.
    expect(source.testResults.length, firstRuns.source.stderr.slice(-2000)).toBeGreaterThan(90);
    expect(dist.testResults.length, firstRuns.compiled.stderr.slice(-2000)).toBeGreaterThan(90);
    if (reruns.source.length + reruns.compiled.length === 0) {
      expect(firstRuns.source.code, firstRuns.source.stderr.slice(-2000)).toBe(0);
      expect(firstRuns.compiled.code, firstRuns.compiled.stderr.slice(-2000)).toBe(0);
    }
    for (const report of [source, dist]) {
      expect(report.numFailedTests).toBe(0);
      expect(report.numPendingTests).toBe(0);
      expect(report.numTodoTests).toBe(0);
      expect(report.numPassedTests).toBe(report.numTotalTests);
      expect(report.testResults.filter((file) => file.status !== "passed").map((file) => file.name)).toEqual([]);
    }
    expect(dist.numPassedTests).toBeGreaterThan(4_000);
  });

  it("the compiled run has every test file of the source run but the listed ones, and no other", () => {
    const excluded = DIST_EXCLUDED.map((entry) => entry.file);
    const sourceFiles = [...byFile(source).keys()].sort();
    const distFiles = [...byFile(dist).keys()].sort();
    expect(distFiles).toEqual(sourceFiles.filter((file) => !excluded.includes(file)));
    for (const file of excluded) expect(sourceFiles, file).toContain(file);
    for (const pkg of DIST_PACKAGES) {
      expect(
        distFiles.filter((file) => file.startsWith(`packages/${pkg.short}/test/`)).length,
        pkg.short,
      ).toBeGreaterThan(20);
    }
  });

  it("file by file, the same tests ran with the same result", () => {
    const sourceTests = byFile(source);
    const distTests = byFile(dist);
    let compared = 0;
    for (const [file, tests] of distTests) {
      expect(tests, file).toEqual(sourceTests.get(file));
      expect(tests.length, file).toBeGreaterThan(0);
      compared += tests.length;
    }
    expect(compared).toBe(dist.numTotalTests);
    const left = DIST_EXCLUDED.reduce((n, entry) => n + (sourceTests.get(entry.file)?.length ?? 0), 0);
    expect(source.numTotalTests - dist.numTotalTests).toBe(left);
  });

  it("the compiled run never reuses a transform cached on disk (a cached module would skip the redirect and the guard)", () => {
    const config = readFileSync(join(REPO_ROOT, "tools/sdk/vitest.dist.config.ts"), "utf8");
    expect(config.match(/fsModuleCache: false/g)?.length).toBe(2);
    // D-147: the compiled run has the same late twins as the root configuration, from the same list.
    expect(config).toContain('from "../../vitest.timing.ts"');
    expect(config).toContain("fileParallelism: false");
    expect(config).toContain("groupOrder");
    expect(config).not.toMatch(/fsModuleCache: true/);
  });

  it("the list of files left out is short, each exists and has a reason", () => {
    expect(DIST_EXCLUDED.length).toBeLessThanOrEqual(2);
    for (const entry of DIST_EXCLUDED) {
      expect(existsSync(join(REPO_ROOT, entry.file)), entry.file).toBe(true);
      expect(entry.reason.length).toBeGreaterThan(40);
    }
  });
});

describe("the redirect", () => {
  // Created lazily: the build folder exists once beforeAll has run.
  let made: ReturnType<typeof distRedirect> | undefined;
  const plugin = {
    get resolveId() {
      made ??= distRedirect({ repoRoot: REPO_ROOT, buildRoot: join(base, "eq/build") });
      return made.resolveId;
    },
    get load() {
      made ??= distRedirect({ repoRoot: REPO_ROOT, buildRoot: join(base, "eq/build") });
      return made.load;
    },
  };
  const context = {
    resolve: async (source: string, importer?: string) => ({ id: `resolved:${source}:${importer}` }),
    error: (message: string): never => {
      throw new Error(message);
    },
  };
  const resolveId = (source: string, importer?: string) => plugin.resolveId.call(context, source, importer);
  const testFile = (pkg: string, file = "x.test.ts") => join(REPO_ROOT, "packages", pkg, "test", file);

  it("sends a test's import of a source module, and a package name, to the compiled file", async () => {
    expect(await resolveId("../src/index.ts", testFile("shield-node"))).toBe(join(buildRoot, "shield-node/index.js"));
    expect(await resolveId("../src/policy/verify.ts", testFile("shield-node"))).toBe(
      join(buildRoot, "shield-node/policy/verify.js"),
    );
    expect(await resolveId("../src/cli.ts?mock=1", testFile("harden"))).toBe(join(buildRoot, "harden/cli.js"));
    expect(await resolveId(join(REPO_ROOT, "packages/harden/src/leaks/scan.ts"), testFile("harden"))).toBe(
      join(buildRoot, "harden/leaks/scan.js"),
    );
    expect(await resolveId("@antireverse/protocol", testFile("harden"))).toBe(join(buildRoot, "protocol/index.js"));
    expect(await resolveId("@antireverse/protocol/server", testFile("shield-node"))).toBe(
      join(buildRoot, "protocol/server.js"),
    );
    expect(await resolveId("@antireverse/harden", testFile("harden"))).toBe(join(buildRoot, "harden/index.js"));
  });

  it("leaves test helpers, other packages and Node's modules alone, and finds a compiled file's packages from the source folder", async () => {
    expect(await resolveId("./helpers.ts", testFile("harden"))).toBeNull();
    expect(await resolveId("vitest", testFile("harden"))).toBeNull();
    expect(await resolveId("node:fs", join(buildRoot, "harden/cli.js"))).toBeNull();
    expect(await resolveId("./engine.js", join(buildRoot, "harden/cli.js"))).toBeNull();
    expect(await resolveId("../../guard/src/index.js", testFile("harden"))).toBeNull();
    expect(await resolveId("zod", join(buildRoot, "harden/_protocol/api.js"))).toEqual({
      id: `resolved:zod:${join(REPO_ROOT, "packages/harden/src/index.ts")}`,
    });
    expect(await resolveId("@babel/parser", join(buildRoot, "harden/babel.js"))).toEqual({
      id: `resolved:@babel/parser:${join(REPO_ROOT, "packages/harden/src/index.ts")}`,
    });
  });

  it("fails on a source module that has no compiled file, on an unknown entry, and on any source module that is loaded", async () => {
    await expect(resolveId("../src/not-there.ts", testFile("harden"))).rejects.toThrow(
      /no compiled file for packages\/harden\/src\/not-there\.ts/,
    );
    await expect(resolveId("@antireverse/protocol/internal", testFile("harden"))).rejects.toThrow(/not an entry/);
    for (const pkg of DIST_PACKAGES) {
      const file = join(REPO_ROOT, "packages", pkg.short, "src/index.ts");
      expect(() => plugin.load.call(context, file)).toThrow(
        /a source module was loaded in a run on the compiled output/,
      );
      expect(() => plugin.load.call(context, `${file}?v=1`)).toThrow(/source module was loaded/);
    }
    expect(plugin.load.call(context, testFile("harden"))).toBeNull();
    expect(plugin.load.call(context, join(buildRoot, "harden/index.js"))).toBeNull();
    expect(plugin.load.call(context, join(REPO_ROOT, "packages/guard/src/index.js"))).toBeNull();
  });
});

// Review M1: the load guard sees modules that Vite loads. A test that starts a child process, or reads a source
// file as text, is outside it. Every such test file is named in DIST_OUTSIDE_THE_GUARD with what happens to it in the
// compiled run; a new one fails here until it is looked at.
describe("what the load guard cannot see", () => {
  const OUTSIDE =
    /\bspawn(?:Sync)?\b|\bexecFile(?:Sync)?\b|\bexecSync\b|\bfork\(|new Worker|worker_threads|experimental-strip-types|new URL\(\s*["'`]\.\.\/(?:\.\.\/)?src|["'`]\.\.\/src["'`/]\s*[,)]/;
  function files(dir: string): string[] {
    return readdirSync(dir).flatMap((entry) => {
      const path = join(dir, entry);
      return statSync(path).isDirectory() ? files(path) : [path];
    });
  }

  it("every test file that starts a process or reads the source as text is listed, with what the compiled run does about it", () => {
    const found = DIST_PACKAGES.flatMap((pkg) => files(join(REPO_ROOT, "packages", pkg.short, "test")))
      .filter((file) => /\.(ts|mjs|js)$/.test(file) && OUTSIDE.test(readFileSync(file, "utf8")))
      .map((file) => relative(REPO_ROOT, file))
      .sort();
    expect(found).toEqual(DIST_OUTSIDE_THE_GUARD.map((entry) => entry.file).sort());
    for (const entry of DIST_OUTSIDE_THE_GUARD) {
      expect(["compiled", "source-text", "excluded"]).toContain(entry.runs);
      expect(entry.how.length, entry.file).toBeGreaterThan(30);
    }
    for (const entry of DIST_EXCLUDED) {
      expect(DIST_OUTSIDE_THE_GUARD.find((other) => other.file === entry.file)?.runs).toBe("excluded");
    }
  });

  it("a child process of the compiled run cannot load a source module: Node itself refuses it", async () => {
    const guard = join(REPO_ROOT, "tools/sdk/src/child-guard.mjs");
    const env = { ...childEnv(), NODE_OPTIONS: `--import ${JSON.stringify(guard)}`, AR_SDK_GUARD_ROOT: REPO_ROOT };
    const script = join(base, "child.mjs");
    writeFileSync(script, "await import(process.argv[2]);\nconsole.log('loaded');\n");
    const source = await exec(
      process.execPath,
      ["--experimental-strip-types", script, join(REPO_ROOT, "packages/shield-node/src/uuidv7.ts")],
      { cwd: base, env },
    );
    expect(source.code).not.toBe(0);
    expect(source.stderr).toMatch(
      /a source module was loaded in a run on the compiled output: packages\/shield-node\/src\/uuidv7\.ts/,
    );
    const compiled = await exec(process.execPath, [script, join(buildRoot, "shield-node/uuidv7.js")], {
      cwd: base,
      env,
    });
    expect(compiled.stderr).toBe("");
    expect(compiled.stdout).toBe("loaded\n");
    // Without the guard the same child loads the source: the guard is what refuses it.
    const unguarded = await exec(
      process.execPath,
      ["--experimental-strip-types", "--no-warnings", script, join(REPO_ROOT, "packages/shield-node/src/uuidv7.ts")],
      { cwd: base, env: childEnv() },
    );
    expect(unguarded.stdout).toBe("loaded\n");
  });

  it("Shield's exit fixture runs the compiled Shield: intact it lets the process end, with every unref() taken out it does not", async () => {
    // A second build folder, damaged: nothing may keep a process alive, and now the sockets and timers do.
    const damaged = layoutIn(base, "damaged");
    for (const pkg of DIST_PACKAGES) cpSync(layout.dist(pkg), damaged.dist(pkg), { recursive: true });
    const shield = join(base, "damaged/build/shield-node");
    let removed = 0;
    for (const file of ["transport.js", "emitter.js", "policy/poller.js"]) {
      const text = readFileSync(join(shield, file), "utf8");
      const without = text.replace(/^.*\.unref\(\).*$/gm, (line) => {
        removed += 1;
        return line.includes("=>") ? line.replace(/\(socket\) => socket\.unref\(\)/, "() => {}") : "";
      });
      writeFileSync(join(shield, file), without);
    }
    expect(removed).toBeGreaterThanOrEqual(5);
    // An ingest that never answers, as in shield.test.ts.
    const silent = createServer(() => {});
    await new Promise<void>((done) => silent.listen(0, "127.0.0.1", done));
    const endpoint = `http://127.0.0.1:${(silent.address() as AddressInfo).port}`;
    const fixture = join(REPO_ROOT, "packages/shield-node/test/fixtures/exit.mjs");
    const guard = join(REPO_ROOT, "tools/sdk/src/child-guard.mjs");
    // Exactly what the compiled run gives a test's child: plain node, the compiled root, the child guard.
    const start = (root: string) =>
      exec(process.execPath, [fixture, "emitter", endpoint], {
        cwd: REPO_ROOT,
        env: {
          ...childEnv(),
          AR_SDK_COMPILED_ROOT: root,
          AR_SDK_GUARD_ROOT: REPO_ROOT,
          NODE_OPTIONS: `--import ${JSON.stringify(guard)}`,
        },
        timeoutMs: 3_000,
      });
    try {
      const intact = await start(buildRoot);
      expect(intact.stderr).toBe("");
      expect(intact.code).toBe(0);
      expect(JSON.parse(intact.stdout)).toMatchObject({ buffered: 0, sent: 0 });
      const hung = await start(join(realpathSync(base), "damaged/build"));
      // Killed by the time limit: the damaged compiled files, not the source, are what ran.
      expect(hung.code).not.toBe(0);
      expect(JSON.parse(hung.stdout)).toMatchObject({ buffered: 0, sent: 0 });
    } finally {
      silent.closeAllConnections();
      await new Promise<void>((done) => silent.close(() => done()));
    }
    // And the test hands the fixture the compiled root with plain node: no flag for TypeScript in the compiled run.
    const test = readFileSync(join(REPO_ROOT, "packages/shield-node/test/shield.test.ts"), "utf8");
    expect(test).toMatch(
      /process\.env\.AR_SDK_COMPILED_ROOT \? \[\] : \["--experimental-strip-types", "--no-warnings"\]/,
    );
    const config = readFileSync(join(REPO_ROOT, "tools/sdk/vitest.dist.config.ts"), "utf8");
    for (const name of ["AR_SDK_COMPILED_ROOT", "AR_SDK_GUARD_ROOT", "NODE_OPTIONS", "child-guard.mjs"])
      expect(config).toContain(name);
    expect(readFileSync(join(REPO_ROOT, "tools/sdk/src/child-guard-hooks.mjs"), "utf8")).toContain(
      JSON.stringify(DIST_PACKAGES.map((pkg) => pkg.short)).replaceAll(",", ", "),
    );
  });
});

// D-143: a test with a wall-clock budget can fail under load. A file with a result that is not "passed" is run once
// more, alone, in the same mode, and that result counts. Nothing is dropped and nothing is accepted as failed.
describe("the second run of a file that did not pass", () => {
  const file = (name: string, results: Array<[string, string]>, status = "passed") => ({
    name,
    status,
    assertionResults: results.map(([fullName, s]) => ({ fullName, status: s })),
  });
  const report = (files: RunReport["testResults"]): RunReport => {
    const all = files.flatMap((f) => f.assertionResults);
    return {
      numTotalTests: all.length,
      numPassedTests: all.filter((a) => a.status === "passed").length,
      numFailedTests: all.filter((a) => a.status === "failed").length,
      numPendingTests: all.filter((a) => a.status === "pending" || a.status === "skipped").length,
      numTodoTests: all.filter((a) => a.status === "todo").length,
      testResults: files,
    };
  };

  it("names the files with a test that failed, was skipped or left as todo, and files that failed as a whole", () => {
    const first = report([
      file(
        "/r/a.test.ts",
        [
          ["one", "passed"],
          ["two", "failed"],
        ],
        "failed",
      ),
      file("/r/b.test.ts", [["three", "passed"]]),
      file("/r/c.test.ts", [["four", "skipped"]]),
      file("/r/d.test.ts", [], "failed"),
      file("/r/e.test.ts", [["five", "todo"]]),
    ]);
    expect(notPassedFiles(first)).toEqual(["/r/a.test.ts", "/r/c.test.ts", "/r/d.test.ts", "/r/e.test.ts"]);
    expect(notPassedFiles(report([file("/r/b.test.ts", [["three", "passed"]])]))).toEqual([]);
  });

  it("takes the second run's result for those files only, and counts again", () => {
    const first = report([
      file(
        "/r/a.test.ts",
        [
          ["one", "passed"],
          ["two", "failed"],
        ],
        "failed",
      ),
      file("/r/b.test.ts", [["three", "passed"]]),
    ]);
    const merged = mergeRerun(
      first,
      report([
        file("/r/a.test.ts", [
          ["one", "passed"],
          ["two", "passed"],
        ]),
      ]),
      ["/r/a.test.ts"],
    );
    expect(merged).toMatchObject({ numTotalTests: 3, numPassedTests: 3, numFailedTests: 0 });
    expect(merged.testResults.map((f) => [f.name, f.status])).toEqual([
      ["/r/a.test.ts", "passed"],
      ["/r/b.test.ts", "passed"],
    ]);
  });

  it("a test that fails again stays failed, and a file the second run did not report stays as it was", () => {
    const first = report([
      file("/r/a.test.ts", [["two", "failed"]], "failed"),
      file("/r/c.test.ts", [["four", "failed"]], "failed"),
    ]);
    const again = mergeRerun(first, report([file("/r/a.test.ts", [["two", "failed"]], "failed")]), [
      "/r/a.test.ts",
      "/r/c.test.ts",
    ]);
    expect(again.numFailedTests).toBe(2);
    expect(notPassedFiles(again)).toEqual(["/r/a.test.ts", "/r/c.test.ts"]);
    // A second run cannot bring in a file that was not asked for, or make a test disappear.
    const sneaky = mergeRerun(first, report([file("/r/b.test.ts", [["x", "passed"]]), file("/r/a.test.ts", [])]), [
      "/r/a.test.ts",
    ]);
    expect(sneaky.testResults.map((f) => f.name)).toEqual(["/r/a.test.ts", "/r/c.test.ts"]);
    expect(notPassedFiles(sneaky)).toContain("/r/a.test.ts");
  });

  it("the real runs say which files needed a second run (none, when the machine was quiet)", () => {
    expect(Array.isArray(reruns.source)).toBe(true);
    expect(Array.isArray(reruns.compiled)).toBe(true);
    if (reruns.source.length + reruns.compiled.length > 0)
      console.warn(`equivalence: run a second time, alone: ${JSON.stringify(reruns)}`);
  });
});
