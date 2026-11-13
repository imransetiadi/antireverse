// Task 2.2 — the Toolbelt over an in-memory artifact: read-only list, read (range-limited), literal search (≤ 200
// hits), beautify, run in the isolated worker, submit; every call charged to the budget and recorded with a
// summary that never carries content, patterns, code or submitted values.
import { describe, expect, it } from "vitest";
import { Budget, BudgetExhaustedError } from "../src/budget.ts";
import { createToolbelt, TOOLBELT_LIMITS } from "../src/toolbelt.ts";

const SECRET = "sk_live_0123456789abcdefABCDEFGH";
const APP = `const k="${SECRET}";function a(b){return fetch("/api/cart",{method:"POST",body:b})}`;

function setup(files: Record<string, string | Uint8Array> = {}, limits = { calls: 100, seconds: 1000 }) {
  const budget = new Budget(limits, () => 0);
  const handle = createToolbelt({
    artifact: { "dist/app.js": APP, "dist/vendor/lib.js": "export const x = 1;", "index.html": "<p>hi</p>", ...files },
    budget,
    runTimeoutMs: 1_000,
  });
  return { budget, ...handle };
}

describe("list", () => {
  it("lists every file under a folder with its size, sorted", async () => {
    const { toolbelt } = setup();
    expect(await toolbelt.list()).toEqual({
      ok: true,
      truncated: false,
      files: [
        { path: "dist/app.js", bytes: Buffer.byteLength(APP) },
        { path: "dist/vendor/lib.js", bytes: 19 },
        { path: "index.html", bytes: 9 },
      ],
    });
    expect(await toolbelt.list("dist/vendor/")).toMatchObject({ files: [{ path: "dist/vendor/lib.js" }] });
    expect(await toolbelt.list("nothing")).toMatchObject({ ok: true, files: [] });
  });
});

describe("read", () => {
  it("reads a range and says whether more follows", async () => {
    const { toolbelt } = setup();
    expect(await toolbelt.read("dist/app.js", { offset: 6, length: 1 })).toEqual({
      ok: true,
      path: "dist/app.js",
      offset: 6,
      text: "k",
      bytes: Buffer.byteLength(APP),
      more: true,
    });
    const whole = await toolbelt.read("dist/app.js");
    expect(whole).toMatchObject({ ok: true, text: APP, more: false });
  });

  it("never returns more than the read limit at once", async () => {
    const big = "a".repeat(TOOLBELT_LIMITS.readBytesMax * 2 + 5);
    const { toolbelt } = setup({ "big.js": big });
    const first = await toolbelt.read("big.js", { length: TOOLBELT_LIMITS.readBytesMax * 10 });
    expect(first).toMatchObject({ ok: true, more: true });
    expect((first as { text: string }).text.length).toBe(TOOLBELT_LIMITS.readBytesMax);
    expect(await toolbelt.read("big.js", { offset: big.length + 10 })).toMatchObject({
      ok: true,
      text: "",
      more: false,
    });
  });

  it("fails for an unknown path or a bad range, and the call still counts", async () => {
    const { toolbelt, budget } = setup();
    expect(await toolbelt.read("../etc/passwd")).toMatchObject({ ok: false, kind: "invalid" });
    expect(await toolbelt.read("dist/app.js", { offset: -1 })).toMatchObject({ ok: false, kind: "invalid" });
    expect(budget.calls()).toBe(2);
  });

  it("is read-only: the artifact is copied, changing the caller's bytes changes nothing", async () => {
    const bytes = new TextEncoder().encode("original");
    const { toolbelt } = setup({ "copy.txt": bytes });
    bytes.set(new TextEncoder().encode("CHANGED!"));
    expect(await toolbelt.read("copy.txt")).toMatchObject({ text: "original" });
  });
});

describe("search", () => {
  it("finds a literal (not a regular expression) with path, line, column and a preview", async () => {
    const { toolbelt } = setup({ "notes.txt": "first\nsecond a.b line\n" });
    expect(await toolbelt.search("a.b")).toEqual({
      ok: true,
      truncated: false,
      hits: [{ path: "notes.txt", line: 2, column: 8, preview: "second a.b line" }],
    });
    expect(await toolbelt.search("a.c")).toMatchObject({ hits: [] });
  });

  it("returns at most 200 hits and says it was cut", async () => {
    const { toolbelt } = setup({ "many.txt": "x\n".repeat(500) });
    const result = await toolbelt.search("x", { path: "many.txt", maxHits: 10_000 });
    expect(result).toMatchObject({ ok: true, truncated: true });
    expect((result as { hits: unknown[] }).hits).toHaveLength(200);
    expect(TOOLBELT_LIMITS.searchHitsMax).toBe(200);
  });

  it("limits to one file or folder", async () => {
    const { toolbelt } = setup();
    expect(await toolbelt.search("export", { path: "dist/vendor" })).toMatchObject({
      hits: [{ path: "dist/vendor/lib.js" }],
    });
  });

  it("refuses an empty or over-long pattern", async () => {
    const { toolbelt } = setup();
    expect(await toolbelt.search("")).toMatchObject({ ok: false, kind: "invalid" });
    expect(await toolbelt.search("y".repeat(TOOLBELT_LIMITS.patternCharsMax + 1))).toMatchObject({ ok: false });
  });
});

describe("beautify", () => {
  it("reformats minified JavaScript", async () => {
    const { toolbelt } = setup();
    const result = await toolbelt.beautify("dist/app.js");
    expect(result).toMatchObject({ ok: true, path: "dist/app.js", truncated: false });
    const code = (result as { code: string }).code;
    expect(code.split("\n").length).toBeGreaterThan(3);
    expect(code).toContain('fetch("/api/cart"');
  });

  it("fails for a file that is not JavaScript, and for an unknown path", async () => {
    const { toolbelt } = setup();
    expect(await toolbelt.beautify("index.html")).toMatchObject({ ok: false, kind: "invalid" });
    expect(await toolbelt.beautify("missing.js")).toMatchObject({ ok: false, kind: "invalid" });
  });
});

describe("submit W1: the distinct-endpoint cap", () => {
  it("refuses a W1 submission that would take the run's distinct endpoints over the cap; the call is recorded as refused", async () => {
    const budget = new Budget({ calls: 100, seconds: 1000 }, () => 0);
    const { toolbelt, submissions, calls } = createToolbelt({ artifact: { "a.js": "x" }, budget, mapEndpointCap: 4 });
    expect(await toolbelt.submit("W1", { endpoints: ["GET /a", "GET /b", "get /a/"] })).toEqual({
      ok: true,
      accepted: true,
    });
    // 2 distinct so far ("get /a/" is "GET /a"); 3 more would make 5 > 4.
    expect(await toolbelt.submit("W1", { endpoints: ["GET /c", "GET /d", "GET /e"] })).toMatchObject({
      ok: false,
      kind: "invalid",
    });
    expect(calls[1]?.summary).toMatch(/refused/);
    expect(submissions).toHaveLength(1);
    // Repeats and up to the cap are still accepted.
    expect(await toolbelt.submit("W1", { endpoints: ["GET /a", "GET /c", "GET /d"] })).toMatchObject({ ok: true });
    expect(await toolbelt.submit("W1", { endpoints: ["GET /e"] })).toMatchObject({ ok: false });
    expect(submissions).toHaveLength(2);
  });

  it("has no cap when none is given", async () => {
    const { toolbelt } = setup();
    const many = Array.from({ length: 500 }, (_, i) => `GET /g${i}`);
    expect(await toolbelt.submit("W1", { endpoints: many })).toMatchObject({ ok: true });
  });
});

describe("run and submit", () => {
  it("runs code in the isolated worker", async () => {
    const { toolbelt } = setup();
    expect(await toolbelt.run("return input * 2;", 21)).toEqual({ ok: true, output: "42" });
    expect(await toolbelt.run("return require('fs');")).toMatchObject({ ok: false, kind: "error" });
  });

  it("accepts submissions for W1, W2 and W5 and records them with the cost at submission", async () => {
    const { toolbelt, submissions } = setup();
    await toolbelt.list();
    expect(await toolbelt.submit("W2", { values: [SECRET] })).toEqual({ ok: true, accepted: true });
    expect(await toolbelt.submit("W1", { endpoints: ["POST /api/cart"] })).toEqual({ ok: true, accepted: true });
    expect(await toolbelt.submit("W5", { request: { method: "post", path: "/api/cart", body: "{}" } })).toEqual({
      ok: true,
      accepted: true,
    });
    expect(submissions.map((s) => [s.objective, s.callIndex, s.cost.calls])).toEqual([
      ["W2", 1, 2],
      ["W1", 2, 3],
      ["W5", 3, 4],
    ]);
    expect(submissions[2]?.payload).toEqual({
      request: { method: "POST", path: "/api/cart", headers: {}, body: "{}" },
    });
  });

  it("refuses OPTIONS for W5: a preflight is not a replay", async () => {
    const { toolbelt, submissions } = setup();
    expect(
      await toolbelt.submit("W5", {
        request: { method: "options", path: "/api/orders", headers: { "access-control-request-method": "POST" } },
      }),
    ).toMatchObject({ ok: false, kind: "invalid" });
    expect(submissions).toHaveLength(0);
  });

  it("refuses W3 and W4 (not supported), a second W5 request, and malformed payloads", async () => {
    const { toolbelt, submissions } = setup();
    expect(await toolbelt.submit("W3", { values: [] })).toMatchObject({ ok: false, kind: "invalid" });
    expect(await toolbelt.submit("W4", { values: [] })).toMatchObject({ ok: false });
    expect(await toolbelt.submit("W2", { values: "x" } as never)).toMatchObject({ ok: false });
    expect(await toolbelt.submit("W1", { endpoints: [1] } as never)).toMatchObject({ ok: false });
    expect(await toolbelt.submit("W5", { request: { method: "GET", path: "no-slash" } })).toMatchObject({ ok: false });
    expect(await toolbelt.submit("W5", { request: { method: "GET", path: "/a" } })).toMatchObject({ ok: true });
    expect(await toolbelt.submit("W5", { request: { method: "GET", path: "/b" } })).toMatchObject({ ok: false });
    expect(await toolbelt.submit("W9" as never, { values: [] })).toMatchObject({ ok: false });
    expect(submissions).toHaveLength(1);
  });
});

describe("the call log and the budget", () => {
  it("records every call in order with its cumulative cost and a summary without secrets", async () => {
    const budget = new Budget(
      { calls: 100, seconds: 1000 },
      (() => {
        let ms = 0;
        return () => (ms += 10);
      })(),
    );
    const { toolbelt, calls } = createToolbelt({ artifact: { "dist/app.js": APP }, budget, runTimeoutMs: 1_000 });
    await toolbelt.list();
    await toolbelt.read("dist/app.js");
    await toolbelt.search(SECRET);
    await toolbelt.beautify("dist/app.js");
    await toolbelt.run(`return "${SECRET}";`);
    await toolbelt.submit("W2", { values: [SECRET] });
    expect(calls.map((c) => [c.index, c.tool, c.cost.calls])).toEqual([
      [0, "list", 1],
      [1, "read", 2],
      [2, "search", 3],
      [3, "beautify", 4],
      [4, "run", 5],
      [5, "submit", 6],
    ]);
    for (const call of calls) {
      expect(call.summary.length).toBeGreaterThan(0);
      expect(call.summary.length).toBeLessThanOrEqual(200);
      expect(call.cost.seconds).toBeGreaterThan(0);
    }
    const log = JSON.stringify(calls);
    expect(log).not.toContain(SECRET);
    expect(log).not.toContain("sk_live");
    expect(log).not.toContain("fetch");
  });

  it("once the calls are spent every tool rejects with BudgetExhaustedError and nothing more is recorded", async () => {
    const { toolbelt, calls, budget } = setup({}, { calls: 2, seconds: 1000 });
    await toolbelt.list();
    await toolbelt.read("dist/app.js");
    await expect(toolbelt.search("a")).rejects.toBeInstanceOf(BudgetExhaustedError);
    await expect(toolbelt.submit("W2", { values: ["a"] })).rejects.toBeInstanceOf(BudgetExhaustedError);
    expect(calls).toHaveLength(2);
    expect(budget.cost().calls).toBe(2);
  });

  it("knows which calls showed the agent a value (for evidence), without putting it in the log", async () => {
    const { toolbelt, callsShowing } = setup();
    await toolbelt.list();
    await toolbelt.read("dist/app.js");
    await toolbelt.search("vendor");
    expect(callsShowing(SECRET)).toEqual([1]);
    expect(callsShowing("never-seen")).toEqual([]);
  });
});
