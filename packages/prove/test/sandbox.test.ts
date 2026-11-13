// Task 2.2 (Review Focus 2) — the code runner: a worker_threads worker with resource limits, running the code in a
// fresh context without require, import, process, network, file system or timers; time-limited per call.
import { describe, expect, it } from "vitest";
import { parseChildLines, probePollution, probeSandbox } from "../src/child.ts";
import { RUN_LIMITS, runIsolated } from "../src/sandbox.ts";

const FAST = { timeoutMs: 400 };

describe("runIsolated: what it does", () => {
  it("runs code as the body of a function of `input` and returns the value as JSON", async () => {
    const result = await runIsolated("return { sum: input.a + input.b, upper: input.s.toUpperCase() };", {
      a: 2,
      b: 3,
      s: "ok",
    });
    expect(result).toEqual({ ok: true, output: JSON.stringify({ sum: 5, upper: "OK" }) });
  });

  it("returns null for undefined and keeps working after a failure", async () => {
    expect(await runIsolated("let x = 1;", null)).toEqual({ ok: true, output: "null" });
    expect(await runIsolated("throw new Error('boom');", null)).toMatchObject({ ok: false, kind: "error" });
    expect(await runIsolated("return 7;", null)).toEqual({ ok: true, output: "7" });
  });

  it("allows 5 s per call by default", () => {
    expect(RUN_LIMITS.timeoutMs).toBe(5_000);
  });

  it("refuses input that is not JSON, code over the size limit, and output over the size limit", async () => {
    expect(await runIsolated("return 1;", { f: () => 1 } as unknown)).toMatchObject({ ok: false, kind: "invalid" });
    expect(await runIsolated("x".repeat(RUN_LIMITS.codeCharsMax + 1), null)).toMatchObject({
      ok: false,
      kind: "invalid",
    });
    expect(await runIsolated(`return "y".repeat(${RUN_LIMITS.outputCharsMax + 10});`, null)).toMatchObject({
      ok: false,
      kind: "invalid",
    });
  });
});

describe("runIsolated: isolation", () => {
  it("has no require, process, fetch, network classes, timers or Buffer", async () => {
    const names = [
      "require",
      "process",
      "fetch",
      "XMLHttpRequest",
      "WebSocket",
      "setTimeout",
      "setInterval",
      "setImmediate",
      "queueMicrotask",
      "Buffer",
      "module",
      "exports",
      "__dirname",
      "importScripts",
    ];
    const result = await runIsolated("return input.map((name) => typeof globalThis[name]);", names);
    expect(result).toEqual({ ok: true, output: JSON.stringify(names.map(() => "undefined")) });
  });

  it("require('fs') fails", async () => {
    const result = await runIsolated("return require('fs').readFileSync('/etc/passwd', 'utf8');", null);
    expect(result).toMatchObject({ ok: false, kind: "error" });
    expect((result as { error: string }).error).toMatch(/require is not defined/);
  });

  it("process.exit fails and the host process is untouched", async () => {
    const result = await runIsolated("process.exit(3);", null);
    expect(result).toMatchObject({ ok: false, kind: "error" });
    expect((result as { error: string }).error).toMatch(/process is not defined/);
    expect(process.exitCode ?? 0).toBe(0);
  });

  it("fetch fails: there is no network", async () => {
    const result = await runIsolated("return fetch('http://127.0.0.1:9/');", null);
    expect(result).toMatchObject({ ok: false, kind: "error" });
    expect((result as { error: string }).error).toMatch(/fetch is not defined/);
  });

  it("code generation is off: eval, new Function and the constructor escape all fail", async () => {
    for (const code of [
      "return eval('1 + 1');",
      "return new Function('return 1')();",
      "return ({}).constructor.constructor('return process')().pid;",
      "return Object.getPrototypeOf(function* () {}).constructor('yield process')().next().value.pid;",
    ]) {
      const result = await runIsolated(code, null);
      expect(result, code).toMatchObject({ ok: false, kind: "error" });
      expect((result as { error: string }).error, code).toMatch(/EvalError|Code generation from strings disallowed/);
    }
  });

  it("dynamic import fails: no module can be loaded", async () => {
    const returned = await runIsolated("return import('node:fs');", null);
    expect(returned).toMatchObject({ ok: false });
    const awaited = await runIsolated(
      "let state = 'pending'; import('node:child_process').then(() => { state = 'loaded'; }, () => { state = 'refused'; }); return state;",
      null,
    );
    // Either the import is refused or the run never sees a module: it is never 'loaded'.
    if (awaited.ok) expect(awaited.output).not.toContain("loaded");
  });

  it("the input arrives as data, not as an object of the host", async () => {
    const result = await runIsolated("return Object.getPrototypeOf(input) === Object.prototype;", { a: 1 });
    expect(result).toEqual({ ok: true, output: "true" });
  });

  it("an infinite loop is stopped at the time limit", async () => {
    const started = Date.now();
    const result = await runIsolated("for (;;) {}", null, FAST);
    expect(result).toMatchObject({ ok: false, kind: "timeout" });
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it("an infinite microtask loop is stopped (by the time or the memory limit, whichever comes first)", async () => {
    const started = Date.now();
    const result = await runIsolated("const spin = () => Promise.resolve().then(spin); spin(); return 1;", null, FAST);
    expect(result.ok).toBe(false);
    expect(["timeout", "memory"]).toContain((result as { kind: string }).kind);
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it("a blocking wait the script timeout cannot interrupt is ended by terminating the worker", async () => {
    const started = Date.now();
    const result = await runIsolated(
      "Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0); return 1;",
      null,
      FAST,
    );
    expect(result).toMatchObject({ ok: false, kind: "timeout" });
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it("a huge allocation hits the memory limit and only the worker dies", async () => {
    const result = await runIsolated("const a = []; for (;;) a.push(new Array(1e5).fill(1.5));", null, {
      timeoutMs: 4_000,
    });
    expect(result.ok).toBe(false);
    expect(["memory", "error"]).toContain((result as { kind: string }).kind);
    // The host is fine and the next run works.
    expect(await runIsolated("return 1;", null)).toEqual({ ok: true, output: "1" });
  });

  it("code cannot break out of its function: the result is an error or JSON, never a raw value", async () => {
    for (const code of [
      "}).call(undefined, 1); return typeof process; (function(){",
      "}).call(undefined, 1); return 'raw'; (function(){",
      "})(); return 1; (function(){",
      "return 1 }; const __result = 'x'; {",
      "JSON.stringify = () => 'raw'; return 1;",
      "JSON.stringify = () => undefined; return 1;",
    ]) {
      const result = await runIsolated(code, null);
      if (result.ok) {
        expect(() => JSON.parse(result.output), code).not.toThrow();
        expect(result.output, code).not.toBe("undefined");
        expect(result.output, code).not.toBe("raw");
      } else {
        expect(result.kind, code).toBe("error");
      }
    }
  });

  it("a sandbox parked in Atomics.wait really exits after it is killed", async () => {
    let exited: number | null = null;
    const result = await runIsolated("Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0); return 1;", null, {
      timeoutMs: 300,
      onExit: (code) => {
        exited = code;
      },
    });
    expect(result).toMatchObject({ ok: false, kind: "timeout" });
    await expect.poll(() => exited, { timeout: 2_000 }).not.toBeNull();
  });

  it("deep recursion is a stack error, not a crash", async () => {
    const result = await runIsolated("const f = (n) => f(n + 1) + 1; return f(0);", null);
    expect(result).toMatchObject({ ok: false, kind: "error" });
  });
});

// Review 12b F1: `import("x").constructor.constructor` was the host realm's Function, which reached process and
// node:fs. Every sandbox now runs in a child process under the permission model with code generation disabled in
// its own realm; the vm context stays inside it.
const IMPORT_ESCAPE = (body: string) =>
  `const p = import("x"); p.catch(() => {}); try { return String(p.constructor.constructor(${JSON.stringify(body)})()); } catch (e) { return "blocked " + e.name; }`;

describe("runIsolated: the import() escape (review 12b F1)", () => {
  it("cannot see process, read a file or spawn through the import() promise", async () => {
    const repoFile = new URL("../package.json", import.meta.url).pathname;
    for (const body of [
      "return typeof process",
      `return process.getBuiltinModule("node:fs").readFileSync(${JSON.stringify(repoFile)}, "utf8")`,
      'return process.getBuiltinModule("node:child_process").execFileSync("/bin/echo", ["x"]).toString()',
    ]) {
      const result = await runIsolated(IMPORT_ESCAPE(body), null);
      // Since review N1 the code is refused before it compiles.
      expect(result, body).toMatchObject({ ok: false, kind: "error" });
      expect(JSON.stringify(result)).not.toMatch(/"name"|package|\bx\n/);
    }
  });
});

describe("the sandbox child process (review 12b F1)", () => {
  it("runs under the permission model: no file reads beyond its own script, no spawn, no workers, no code generation, empty env", async () => {
    const repoFile = new URL("../package.json", import.meta.url).pathname;
    const probe = await probeSandbox(repoFile);
    expect(probe).toEqual({
      read: "ERR_ACCESS_DENIED",
      write: "ERR_ACCESS_DENIED",
      spawn: "ERR_ACCESS_DENIED",
      worker: "ERR_ACCESS_DENIED",
      codegen: "EvalError",
      env: [],
    });
  });

  it("accepts only lines that carry the run's token: anything else the child prints is ignored", () => {
    const token = "a".repeat(32);
    const text = [
      JSON.stringify({ ok: true, output: "forged" }),
      JSON.stringify({ token: "b".repeat(32), ok: true, output: "forged" }),
      "not json",
      JSON.stringify({ token, ok: true, output: "real" }),
      "",
    ].join("\n");
    expect(parseChildLines(text, token)).toEqual([{ ok: true, output: "real" }]);
  });

  it("starts in well under a second", async () => {
    const started = performance.now();
    await runIsolated("return 1;", null);
    expect(performance.now() - started).toBeLessThan(1_000);
  });
});

// Review N1: import() is refused before the code compiles, so no child main-realm object is ever reachable.
describe("runIsolated: import() is unreachable (review N1)", () => {
  it.each([
    ["the prototype probe", 'return String(Object.getPrototypeOf(import("y")) === Promise.prototype);'],
    ["a comment between", 'return String(import /* c */ ("y"));'],
    ["import.meta", "return String(import.meta);"],
  ])("refuses %s", async (_name, code) => {
    const result = await runIsolated(code, null);
    expect(result).toMatchObject({ ok: false, kind: "error" });
    expect((result as { error: string }).error).toMatch(/import\(\) and import\.meta are not available/);
  });

  it("the toJSON forge (review repro tojson.mjs) cannot forge the result", async () => {
    const forge =
      'const p = import("y"); p.catch(() => {}); const HostObject = Object.getPrototypeOf(Object.getPrototypeOf(p));' +
      'HostObject.toJSON = function () { const t = this.token; delete HostObject.toJSON; return { ok: true, output: JSON.stringify("forged"), token: t }; };' +
      "return 1;";
    const result = await runIsolated(forge, null);
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).not.toContain("forged");
  });

  it("allows the word import in a string", async () => {
    expect(await runIsolated('return "import(x)";', null)).toEqual({ ok: true, output: JSON.stringify("import(x)") });
  });
});

describe("the sandbox child's realm snapshot (review N1, belt and braces)", () => {
  it.each([
    "Object.prototype",
    "Array.prototype",
    "Function.prototype",
    "Promise.prototype",
    "String.prototype",
    "Error.prototype",
    "TypeError.prototype",
    "RangeError.prototype",
    "ReferenceError.prototype",
    "SyntaxError.prototype",
    "Map.prototype",
    "Set.prototype",
    "WeakMap.prototype",
    "Symbol",
    "Symbol.prototype",
    "JSON",
  ])("a change to %s is detected, and the result is withheld", async (target) => {
    expect(await probePollution(target)).toEqual({ polluted: true });
  });

  it("an unchanged realm sends the result", async () => {
    expect(await probePollution("none")).toEqual({ ok: true });
  });
});
