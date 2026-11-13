// Task 2.2 (Review Focus 2) — the code runner: a worker_threads worker with resource limits, running the code in a
// fresh context without require, import, process, network, file system or timers; time-limited per call.
import { describe, expect, it } from "vitest";
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

  it("a worker parked in Atomics.wait really exits after it is terminated", async () => {
    let exited: number | null = null;
    const result = await runIsolated("Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0); return 1;", null, {
      timeoutMs: 300,
      onWorkerExit: (code) => {
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
