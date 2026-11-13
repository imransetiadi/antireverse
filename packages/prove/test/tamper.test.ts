// Slice 12b — W4 Tamper: the submitted file runs in a fresh sandbox worker with stub browser globals and an eval
// recorder; achieved when no integrity-check failure occurred, the run set the nonce marker, and the code that ran
// is still the original with a small edit (prefix + suffix ≥ 90 %). The integrity wrapper is Harden's own
// applyIntegrity (imported in tests only).

import { readFileSync } from "node:fs";
import { applyIntegrity } from "@antireverse/harden";
import { EvidenceSchema } from "@antireverse/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { tamperEdit } from "../src/agent.ts";
import { extractPayload, runBaseline, runTamper, similarity, TAMPER_MARKER, verifyTamper } from "../src/tamper.ts";
import type { Submission } from "../src/toolbelt.ts";

const NONCE = "0123456789abcdef";
const APP = [
  "var cart = [];",
  "function add(item) { cart.push(item); return cart.length; }",
  "var el = document.createElement('div'); el.appendChild(document.createTextNode('hi'));",
  "window.addEventListener('load', function () { add(localStorage.getItem('k')); });",
  `var label = navigator.userAgent + location.href + "${"x".repeat(400)}";`,
  "globalThis.appReady = add('first') === 1;",
].join("\n");
const WRAPPED = applyIntegrity(APP);
const FAST = { timeoutMs: 1_500 };

let n = 0;
function submission(path: string, code: string): Submission {
  n += 1;
  return { objective: "W4", payload: { path, code }, callIndex: n, cost: { calls: 7, seconds: 2 } };
}
const marker = `${TAMPER_MARKER}=${JSON.stringify(NONCE)};`;

describe("similarity", () => {
  it("is common prefix plus common suffix as a share of the original, without overlap", () => {
    expect(similarity("abcdef", "abcdef")).toBe(1);
    expect(similarity("abcdef", "XXabcdef")).toBe(1);
    expect(similarity("abcdef", "abcXdef")).toBe(1);
    expect(similarity("abcdef", "")).toBe(0);
    expect(similarity("aaaa", "aa")).toBe(0.5);
    expect(similarity("", "x")).toBe(0);
  });
});

describe("runTamper", () => {
  it("gives the code stub browser globals that swallow calls", async () => {
    const run = await runTamper(`${APP}\n${marker}`, FAST);
    expect(run.errors).toEqual([]);
    expect(run.marker).toBe(NONCE);
  });

  it("recovers the integrity wrapper's payload from the original by evaluating it under the recorder", async () => {
    expect(await extractPayload(WRAPPED, FAST)).toBe(APP);
    expect(await extractPayload(APP, FAST)).toBeNull();
  });

  it("counts an eval of code similar to the reference that set the marker inside it", async () => {
    const run = await runTamper(tamperEdit(WRAPPED, NONCE), { ...FAST, nonce: NONCE, reference: APP });
    expect(run.errors).toEqual([]);
    expect(run.evalCount).toBe(1);
    expect(run.bestSetInside).toBeGreaterThanOrEqual(0.9);
  });

  it("reports an integrity failure as an error", async () => {
    const edited = WRAPPED.replace("var cart = [];", "var cart = [1];");
    const run = await runTamper(edited, FAST);
    expect(run.errors.some((e) => e.includes("integrity check failed"))).toBe(true);
  });

  it("is isolated: no require, process or network; a loop is stopped at the time limit", async () => {
    const isolated = await runTamper(
      `${marker} globalThis.seen = [typeof require, typeof process, typeof fetch].join(); require('fs');`,
      FAST,
    );
    expect(isolated.errors.join()).toMatch(/require is not defined/);
    expect(isolated.marker).toBe(NONCE);
    const started = Date.now();
    const loop = await runTamper("for (;;) {}", { timeoutMs: 300 });
    expect(loop.timedOut).toBe(true);
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it("the code cannot forge the eval record: the recorder sits outside its reach", async () => {
    const run = await runTamper(
      `${marker} try { globalThis.__hostRecord && globalThis.__hostRecord(${JSON.stringify(APP)}); } catch (e) {}`,
      FAST,
    );
    expect(run.evalCount).toBe(0);
  });

  it("cannot reach process, a file or the child's output channel through the import() promise", async () => {
    const repoFile = new URL("../package.json", import.meta.url).pathname;
    for (const body of [
      "return typeof process",
      `return process.getBuiltinModule("node:fs").readFileSync(${JSON.stringify(repoFile)}, "utf8")`,
      'return process.getBuiltinModule("node:child_process").execFileSync("/bin/echo", ["x"]).toString()',
      'process.stdout.write("{}\\n"); return "wrote"',
    ]) {
      for (const prefix of ["", 'import a from "a"; ']) {
        const code = `${prefix}const p = import("x"); p.catch(() => {}); try { ${TAMPER_MARKER} = String(p.constructor.constructor(${JSON.stringify(body)})()); } catch (e) { ${TAMPER_MARKER} = "blocked " + e.name; }`;
        const run = await runTamper(code, FAST);
        // Review N1: any source with import() or import.meta is refused before it compiles.
        expect(run.marker, `${prefix}${body}`).toBeNull();
        expect(run.errors.join(" "), `${prefix}${body}`).toMatch(/import\(\) and import\.meta are not available/);
      }
    }
  });
});

describe("verifyTamper (W4)", () => {
  const plain = new Map([["dist/app.js", APP]]);
  const wrapped = new Map([["dist/app.js", WRAPPED]]);

  it("a Build without integrity: a small marker edit is achieved (D-075)", async () => {
    const s = submission("dist/app.js", tamperEdit(APP, NONCE));
    const verdict = await verifyTamper([s], { artifact: plain, integrity: false, nonce: NONCE, ...FAST });
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: { callIndex: s.callIndex } });
    if (verdict?.kind !== "judged") throw new Error();
    expect(verdict.evidence.summary).toMatch(/dist\/app\.js/);
    expect(verdict.evidence.summary).not.toContain("cart");
    expect(EvidenceSchema.safeParse(verdict.evidence).success).toBe(true);
  });

  it("an integrity Build is defeated by the stand-in's edit (marker in the payload, hash comparison neutralised)", async () => {
    const edited = tamperEdit(WRAPPED, NONCE);
    expect(edited).not.toBe(WRAPPED);
    const verdict = await verifyTamper([submission("dist/app.js", edited)], {
      artifact: wrapped,
      integrity: true,
      nonce: NONCE,
      ...FAST,
    });
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: { callIndex: expect.any(Number) } });
  });

  it("with the integrity check still on, an edited payload is not achieved", async () => {
    const payloadOnly = WRAPPED.replace('var __payload="', `var __payload="${marker.replace(/"/g, '\\"')}`);
    const verdict = await verifyTamper([submission("dist/app.js", payloadOnly)], {
      artifact: wrapped,
      integrity: true,
      nonce: NONCE,
      ...FAST,
    });
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: null });
    if (verdict?.kind !== "judged") throw new Error();
    expect(verdict.evidence.summary).toMatch(/the integrity check failed/);
  });

  it("deleting the code and setting the marker never counts, with or without integrity", async () => {
    for (const [artifact, integrity] of [
      [plain, false],
      [wrapped, true],
    ] as const) {
      const verdict = await verifyTamper([submission("dist/app.js", marker)], {
        artifact,
        integrity,
        nonce: NONCE,
        ...FAST,
      });
      expect(verdict).toMatchObject({ kind: "judged", achievedAt: null });
    }
    // An integrity Build where the wrapper is deleted and a tiny payload is eval'd: still not the original.
    const tiny = `${marker} (0, eval)("var x = 1;");`;
    expect(
      await verifyTamper([submission("dist/app.js", tiny)], {
        artifact: wrapped,
        integrity: true,
        nonce: NONCE,
        ...FAST,
      }),
    ).toMatchObject({ achievedAt: null });
  });

  it("the marker must carry this run's nonce", async () => {
    const verdict = await verifyTamper([submission("dist/app.js", tamperEdit(APP, "ffffffffffffffff"))], {
      artifact: plain,
      integrity: false,
      nonce: NONCE,
      ...FAST,
    });
    expect(verdict).toMatchObject({ achievedAt: null });
  });

  it("a file run that throws counts only when the original ends with the same error (review N2, real bundles)", async () => {
    // The original completes: a submission that throws after the marker does not count.
    const throwsAfter = await verifyTamper(
      [submission("dist/app.js", `${tamperEdit(APP, NONCE)}\nmissingFunction();`)],
      {
        artifact: plain,
        integrity: false,
        nonce: NONCE,
        ...FAST,
      },
    );
    expect(throwsAfter).toMatchObject({ achievedAt: null });
    // The original itself ends with that error in the stub environment: the same ending counts.
    const throwing = `${APP}\nmissingFunction();`;
    const sameError = await verifyTamper([submission("dist/app.js", tamperEdit(throwing, NONCE))], {
      artifact: new Map([["dist/app.js", throwing]]),
      integrity: false,
      nonce: NONCE,
      ...FAST,
    });
    expect(sameError).toMatchObject({ achievedAt: { callIndex: expect.any(Number) } });
    // A different error does not.
    const otherError = await verifyTamper(
      [submission("dist/app.js", `${tamperEdit(APP, NONCE)}\notherMissingFunction();`)],
      { artifact: new Map([["dist/app.js", throwing]]), integrity: false, nonce: NONCE, ...FAST },
    );
    expect(otherError).toMatchObject({ achievedAt: null });
  });

  it("judges up to three submissions in order and returns null when none was made", async () => {
    const bad = submission("dist/app.js", marker);
    const good = submission("dist/app.js", tamperEdit(APP, NONCE));
    const verdict = await verifyTamper([bad, good], { artifact: plain, integrity: false, nonce: NONCE, ...FAST });
    expect(verdict).toMatchObject({ achievedAt: { callIndex: good.callIndex } });
    if (verdict?.kind !== "judged") throw new Error();
    expect(verdict.evidence.calls).toEqual([bad.callIndex, good.callIndex]);
    expect(await verifyTamper([], { artifact: plain, integrity: false, nonce: NONCE })).toBeNull();
  });
});

describe("W4 on ES modules", () => {
  const ESM = [
    'import { createApp } from "framework";',
    'import config from "./config.js";',
    'import * as utils from "utils";',
    "const app = createApp(config);",
    'app.mount("#root");',
    'utils.track("start");',
    `export const label = "${"m".repeat(400)}";`,
    "export default app;",
  ].join("\n");
  const esm = new Map([["dist/app.mjs", ESM]]);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("tells a module from a script as Harden's containsEsm does (Babel, sourceType unambiguous), in the child", async () => {
    expect((await runTamper(ESM, FAST)).module).toBe(true);
    expect((await runTamper("export default 1;", FAST)).module).toBe(true);
    expect((await runTamper(APP, FAST)).module).toBe(false);
    expect((await runTamper(WRAPPED, FAST)).module).toBe(false);
    expect((await runTamper("this is not { JavaScript", FAST)).module).toBe(false);
  });

  it("runs a module with every import linked to permissive stubs (named, default, namespace)", async () => {
    const run = await runTamper(`${ESM}\n${marker}`, FAST);
    expect(run.errors).toEqual([]);
    expect(run.marker).toBe(NONCE);
  });

  it("refuses a module with a dynamic import() before it compiles (review N1)", async () => {
    const run = await runTamper(
      `import "polyfills"; const lazy = await import("lazy-chunk"); lazy.default.init(); ${marker}`,
      FAST,
    );
    expect(run.marker).toBeNull();
    expect(run.errors.join(" ")).toMatch(/import\(\) and import\.meta are not available/);
  });

  it("module namespaces and stubs belong to the sandbox's realm, never the child's", async () => {
    const run = await runTamper(
      `import * as ns from "a"; import d from "b"; ${TAMPER_MARKER} = [(function () {}) instanceof Function && Function.prototype === Object.getPrototypeOf(function () {}),Object.getPrototypeOf(ns) === null, Object.getPrototypeOf(d) === Object.getPrototypeOf(function () {}), Object.getPrototypeOf(window) === Object.getPrototypeOf(function () {})].join();`,
      FAST,
    );
    expect(run.marker).toBe("true,true,true,true");
  });

  it("an ESM file without integrity, with the stand-in's marker edit, is achieved", async () => {
    const verdict = await verifyTamper([submission("dist/app.mjs", tamperEdit(ESM, NONCE))], {
      artifact: esm,
      integrity: false,
      nonce: NONCE,
      ...FAST,
    });
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: { callIndex: expect.any(Number) } });
  });

  it("an ESM file whose import is used at top level still runs to a marker placed after it", async () => {
    const verdict = await verifyTamper([submission("dist/app.mjs", `${ESM}\n${marker}`)], {
      artifact: esm,
      integrity: false,
      nonce: NONCE,
      ...FAST,
    });
    expect(verdict).toMatchObject({ achievedAt: { callIndex: expect.any(Number) } });
  });

  it("an ESM file whose code was deleted, leaving the marker and an import, is not achieved", async () => {
    const verdict = await verifyTamper(
      [submission("dist/app.mjs", `import { createApp } from "framework";\n${marker}`)],
      { artifact: esm, integrity: false, nonce: NONCE, ...FAST },
    );
    expect(verdict).toMatchObject({ kind: "judged", achievedAt: null });
  });

  it("the experimental-flag warning never reaches the host's output or the run's errors", async () => {
    const written: string[] = [];
    const write = process.stderr.write.bind(process.stderr);
    vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string | Uint8Array, ...rest: unknown[]) => {
      written.push(String(chunk));
      return (write as (...args: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof process.stderr.write);
    const warnings: string[] = [];
    const onWarning = (warning: Error) => warnings.push(warning.message);
    process.on("warning", onWarning);
    try {
      const run = await runTamper(`${ESM}\n${marker}`, FAST);
      expect(run.errors.join(" ")).not.toMatch(/ExperimentalWarning|experimental/i);
    } finally {
      process.off("warning", onWarning);
    }
    expect(written.join("")).not.toMatch(/ExperimentalWarning|VM Modules/);
    expect(warnings.join(" ")).not.toMatch(/VM Modules/);
  });
});

describe("tamperEdit (the stand-in's W4 edit)", () => {
  it("puts the marker first in a plain file", () => {
    expect(tamperEdit(APP, NONCE).startsWith(marker)).toBe(true);
  });

  it("puts the marker first in an integrity payload and neutralises the hash comparison", () => {
    const edited = tamperEdit(WRAPPED, NONCE);
    expect(edited).toContain("if(false&&__h(__payload)!==");
    const literal = /var __payload=("(?:[^"\\]|\\.)*");/.exec(edited)?.[1] as string;
    expect((JSON.parse(literal) as string).startsWith(marker)).toBe(true);
    expect(edited.length).toBeLessThanOrEqual(WRAPPED.length * 2);
  });
});

// Review 12b F2: W4 was achieved on integrity Builds without neutralising the check.
describe("W4 on integrity Builds: only code similar to the payload, evaluated with the marker set inside it", () => {
  const facts = { artifact: new Map([["dist/app.js", WRAPPED]]), integrity: true, nonce: NONCE, ...FAST };
  const payload = JSON.stringify(APP);

  it("A: a marker before an unchanged wrapper is not achieved (set outside any eval)", async () => {
    const verdict = await verifyTamper([submission("dist/app.js", `${marker}\n${WRAPPED}`)], facts);
    expect(verdict).toMatchObject({ achievedAt: null });
  });

  it("B: recording a payload string that never runs (SyntaxError) is not achieved", async () => {
    const code = `${marker} try { eval(${payload} + "\\n}"); } catch (e) {}`;
    expect(await verifyTamper([submission("dist/app.js", code)], facts)).toMatchObject({ achievedAt: null });
  });

  it("C: a forged result message is not achieved (the escape is closed and lines need the run's token)", async () => {
    const code = `import("x").constructor.constructor("process.stdout.write(JSON.stringify({ module: false, errors: [], integrityFailed: false, marker: '${NONCE}', evalCount: 1, bestSetInside: 1, timedOut: false }) + '\\n')")();`;
    expect(await verifyTamper([submission("dist/app.js", code)], facts)).toMatchObject({ achievedAt: null });
  });

  it("the payload evaluated unchanged with the marker set outside it is not achieved", async () => {
    const code = `${marker} (0, eval)(${payload});`;
    expect(await verifyTamper([submission("dist/app.js", code)], facts)).toMatchObject({ achievedAt: null });
  });

  it("the stand-in's edit still is, and the evidence says code similar to the original was evaluated", async () => {
    const verdict = await verifyTamper([submission("dist/app.js", tamperEdit(WRAPPED, NONCE))], facts);
    expect(verdict).toMatchObject({ achievedAt: { callIndex: expect.any(Number) } });
    if (verdict?.kind !== "judged") throw new Error();
    expect(verdict.evidence.summary).toMatch(/code similar to the original was evaluated/);
    expect(verdict.evidence.summary).not.toMatch(/ran\b/);
  });
});

// Review N1: the import() promise was a child main-realm object; its prototype chain let the code set
// Object.prototype.toJSON there and forge the result line with the token.
describe("W4: import() is unreachable, so the child's realm cannot be polluted", () => {
  it.each([
    ["script", 'globalThis.__airverse_tamper = String(Object.getPrototypeOf(import("y")) === Promise.prototype);'],
    [
      "module",
      'import a from "a"; const p = import("y"); globalThis.__airverse_tamper = String(Object.getPrototypeOf(p));',
    ],
    ["import.meta", 'import a from "a"; globalThis.__airverse_tamper = String(import.meta);'],
    ["a comment between", 'globalThis.__airverse_tamper = String(import /* c */ ("y"));'],
    ["eval at run time", `${marker} eval('import("y")');`],
    ["the Function constructor at run time", `${marker} Function('return import("y")')();`],
    ["an async function's constructor", `${marker} (async function () {}).constructor('return import("y")')();`],
  ])("%s: refused", async (_name, code) => {
    const run = await runTamper(code, FAST);
    expect(run.errors.join(" ")).toMatch(/import\(\) and import\.meta are not available/);
    expect(run.marker === "true" || run.marker === "false").toBe(false);
  });

  it("allows the word in a string or comment when the file parses (no false refusal)", async () => {
    const run = await runTamper(`// import("x") in a comment\nvar s = "import(y)"; ${marker}`, FAST);
    expect(run.errors).toEqual([]);
    expect(run.marker).toBe(NONCE);
  });

  it("the toJSON forge (review repro tojson.mjs) is not achieved", async () => {
    const forge =
      'try { const p = import("y"); p.catch(() => {}); const HostObject = Object.getPrototypeOf(Object.getPrototypeOf(p));' +
      `HostObject.toJSON = function () { const t = this.token; delete HostObject.toJSON; return { module: false, errors: [], integrityFailed: false, marker: "${NONCE}", evalCount: 1, bestSetInside: 1, timedOut: false, token: t }; }; } catch (e) {}`;
    const verdict = await verifyTamper([submission("dist/app.js", forge)], {
      artifact: new Map([["dist/app.js", WRAPPED]]),
      integrity: true,
      nonce: NONCE,
      ...FAST,
    });
    expect(verdict).toMatchObject({ achievedAt: null });
  });

  it("stub globals cannot be replaced (non-writable, non-configurable)", async () => {
    const run = await runTamper(
      `globalThis.window = 1; try { Object.defineProperty(globalThis, "document", { value: 2 }); } catch (e) {} ${TAMPER_MARKER} = String(window === 1) + String(document === 2);`,
      FAST,
    );
    expect(run.marker).toBe("falsefalse");
  });
});

// Review N2 (Jev: behavioural_trace): the code that ran must be the protected code — the eval (or the file run)
// completes normally, the marker statement is inside the evaluated source, and the run reproduces ≥ 90 % of the
// original's trace of interactions with the stub globals.
describe("W4: the behavioural trace", () => {
  const W4RULE_APP = [
    "var cart=[];function add(i){cart.push(i);return cart.length;}",
    "window.addEventListener('load', function () { add(1); });",
    "globalThis.appReady=add('first')===1;",
    `var pad='${"x".repeat(400)}';`,
  ].join("\n");
  const wrapped = applyIntegrity(W4RULE_APP);
  const integrityFacts = { artifact: new Map([["app.js", wrapped]]), integrity: true, nonce: NONCE, ...FAST };
  const payload = JSON.stringify(W4RULE_APP);

  it("the original's trace names the interactions with the stub globals, in order, names only", async () => {
    const baseline = await runBaseline(APP, FAST);
    expect(baseline.trace.length).toBeGreaterThan(3);
    expect(baseline.trace).toContain("call document.createElement");
    expect(baseline.trace).toContain("get window.addEventListener");
    // Names only: no argument or value ('hi', 'k', 'first', the user agent) is ever recorded.
    expect(baseline.trace.join(" ")).not.toMatch(/\bhi\b|\bk\b|\bfirst\b|#root/);
  });

  it("marker; throw 0; payload (eval'd) is not achieved: the eval does not complete", async () => {
    const code = `try { eval('${marker.replace(/"/g, '\\"')} throw 0;\\n' + ${payload}); } catch (e) {}`;
    expect(await verifyTamper([submission("app.js", code)], integrityFacts)).toMatchObject({ achievedAt: null });
  });

  it("marker; if (0) { payload } is not achieved", async () => {
    const code = `(0, eval)('${marker.replace(/"/g, '\\"')} if (0) {' + ${payload} + '}');`;
    expect(await verifyTamper([submission("app.js", code)], integrityFacts)).toMatchObject({ achievedAt: null });
  });

  it("the globalHook attack (review repro w4rule.mjs) is not achieved", async () => {
    const code = `globalThis.window = { addEventListener() { globalThis.__airverse_tamper = "${NONCE}"; } };\n${wrapped}`;
    expect(await verifyTamper([submission("app.js", code)], integrityFacts)).toMatchObject({ achievedAt: null });
  });

  it("the throwFirst attack (review repro w4rule.mjs) is not achieved", async () => {
    const code = `try { eval('globalThis.__airverse_tamper="${NONCE}"; throw 0;\\n' + ${payload}); } catch (e) {} globalThis.__airverse_tamper = "x"; delete globalThis.__airverse_tamper;`;
    expect(await verifyTamper([submission("app.js", code)], integrityFacts)).toMatchObject({ achievedAt: null });
  });

  it("the stand-in's honest edit is achieved, with integrity and without, and the evidence names the trace", async () => {
    const withIntegrity = await verifyTamper([submission("app.js", tamperEdit(wrapped, NONCE))], integrityFacts);
    expect(withIntegrity).toMatchObject({ achievedAt: { callIndex: expect.any(Number) } });
    if (withIntegrity?.kind !== "judged") throw new Error();
    expect(withIntegrity.evidence.summary).toMatch(/reproduced \d+ % of the original's global interactions/);
    const without = await verifyTamper([submission("app.js", tamperEdit(W4RULE_APP, NONCE))], {
      artifact: new Map([["app.js", W4RULE_APP]]),
      integrity: false,
      nonce: NONCE,
      ...FAST,
    });
    expect(without).toMatchObject({ achievedAt: { callIndex: expect.any(Number) } });
  });

  it("a run that skips the protected code's global interactions is not achieved", async () => {
    // The payload evaluated with its window call removed: text still ≥ 90 % similar, trace not reproduced.
    const gutted = W4RULE_APP.replace("window.addEventListener('load', function () { add(1); });", "");
    const code = tamperEdit(W4RULE_APP, NONCE).replace("window.addEventListener('load', function () { add(1); });", "");
    expect(similarity(W4RULE_APP, gutted)).toBeGreaterThanOrEqual(0.85);
    const verdict = await verifyTamper([submission("app.js", code)], {
      artifact: new Map([["app.js", W4RULE_APP]]),
      integrity: false,
      nonce: NONCE,
      ...FAST,
    });
    expect(verdict).toMatchObject({ achievedAt: null });
  });

  it("an ESM file whose original touches no stub global falls back to the textual rule and says so", async () => {
    const esmApp =
      'import { createApp } from "framework";\nconst app = createApp();\napp.mount("#root");\nexport default app;';
    const verdict = await verifyTamper([submission("app.mjs", tamperEdit(esmApp, NONCE))], {
      artifact: new Map([["app.mjs", esmApp]]),
      integrity: false,
      nonce: NONCE,
      ...FAST,
    });
    expect(verdict).toMatchObject({ achievedAt: { callIndex: expect.any(Number) } });
    if (verdict?.kind !== "judged") throw new Error();
    expect(verdict.evidence.summary).toMatch(/no global interactions to trace; judged on the text/);
  });
});

// The real reference bundles (apps/range/web built with esbuild as the 12b e2e test does, then hardened with
// --profile balanced --seed 1; the classic one also with --integrity). Kept as .fixture files so no formatter touches
// them (the integrity hash covers every byte). Harden's string decoder needs atob and TextDecoder.
describe("W4 on the reference bundles", () => {
  const read = (name: string) => readFileSync(new URL(`./fixtures/range/${name}`, import.meta.url), "utf8");
  const ESM_BUNDLE = read("bundle.mjs.fixture");
  const CLASSIC_BUNDLE = read("bundle-integrity.js.fixture");
  const esmFacts = { artifact: new Map([["bundle.mjs", ESM_BUNDLE]]), integrity: false, nonce: NONCE, ...FAST };
  const classicFacts = { artifact: new Map([["bundle.js", CLASSIC_BUNDLE]]), integrity: true, nonce: NONCE, ...FAST };
  const literal = /var __payload=("(?:[^"\\]|\\.)*");/.exec(CLASSIC_BUNDLE)?.[1] as string;
  const forge =
    'try { const p = import("y"); p.catch(() => {}); const H = Object.getPrototypeOf(Object.getPrototypeOf(p));' +
    `H.toJSON = function () { return { marker: "${NONCE}", completedNormally: true, bestSetInside: 1, token: this.token }; }; } catch (e) {}`;

  it("the sandbox has the browser's atob, btoa, TextDecoder and TextEncoder", async () => {
    const run = await runTamper(
      `${TAMPER_MARKER} = new TextDecoder().decode(Uint8Array.from(atob(btoa("ok")), (c) => c.charCodeAt(0))) + new TextEncoder().encode("é").length;`,
      FAST,
    );
    expect(run.errors).toEqual([]);
    expect(run.marker).toBe("ok2");
  });

  it("both originals run to completion in the stub environment", async () => {
    for (const code of [ESM_BUNDLE, CLASSIC_BUNDLE]) {
      const run = await runTamper(code, FAST);
      expect(run.errors).toEqual([]);
      expect(run.completedNormally).toBe(true);
    }
    expect((await runBaseline(CLASSIC_BUNDLE, FAST)).payload).toBe(JSON.parse(literal));
  });

  it("the stand-in's edit is achieved on both", async () => {
    expect(await verifyTamper([submission("bundle.mjs", tamperEdit(ESM_BUNDLE, NONCE))], esmFacts)).toMatchObject({
      achievedAt: { callIndex: expect.any(Number) },
    });
    expect(
      await verifyTamper([submission("bundle.js", tamperEdit(CLASSIC_BUNDLE, NONCE))], classicFacts),
    ).toMatchObject({
      achievedAt: { callIndex: expect.any(Number) },
    });
  });

  it.each([
    ["throwFirst", `${marker} throw 0;\n${ESM_BUNDLE}`],
    ["if (0)", `${marker} if (0) {\n${ESM_BUNDLE}\n}`],
    ["globalHook", `globalThis.window = { addEventListener() { ${marker} } };\n${ESM_BUNDLE}`],
    ["tojson", forge],
  ])("ESM: %s is not achieved", async (_name, code) => {
    expect(await verifyTamper([submission("bundle.mjs", code)], esmFacts)).toMatchObject({ achievedAt: null });
  });

  it.each([
    ["throwFirst", `try { eval('${marker.replace(/"/g, '\\"')} throw 0;\\n' + ${literal}); } catch (e) {}`],
    ["if (0)", `(0, eval)('${marker.replace(/"/g, '\\"')} if (0) {' + ${literal} + '}');`],
    ["globalHook", `globalThis.window = { addEventListener() { ${marker} } };\n${CLASSIC_BUNDLE}`],
    ["marker before the unchanged wrapper", `${marker}\n${CLASSIC_BUNDLE}`],
    ["tojson", forge],
  ])("classic with integrity: %s is not achieved", async (_name, code) => {
    expect(await verifyTamper([submission("bundle.js", code)], classicFacts)).toMatchObject({ achievedAt: null });
  });
});
