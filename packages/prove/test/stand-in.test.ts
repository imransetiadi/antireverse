// Task 2.3 — the AdversaryAgent seam and the deterministic stand-in agent: it works only through the Toolbelt,
// finds Canary-shaped and secret-shaped strings (W2), URL path literals and fetch/XHR call sites (W1), and builds
// one request from the observed routes (W5), within its budget.
import { canaryStatement } from "@antireverse/harden";
import { EXAMPLE_CANARIES, EXAMPLE_LOGIC, LogicPublicSchema, STAND_IN_MODEL } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { STAND_IN_AGENT, StandInAgent, tamperEdit } from "../src/agent.ts";
import { Budget } from "../src/budget.ts";
import { TAMPER_MARKER } from "../src/tamper.ts";
import { createToolbelt } from "../src/toolbelt.ts";
import type {
  AgentContext,
  LogicSubmissionPayload,
  MapSubmission,
  ReplaySubmission,
  SecretsSubmission,
  TamperSubmissionPayload,
} from "../src/types.ts";

const TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
const APP = [
  "const base = 'https://shop.example.com';",
  `const cfg = { apiToken: "${TOKEN}", label: "hello" };`,
  // biome-ignore lint/suspicious/noTemplateCurlyInString: the fixture is source text with a template literal
  "export function load(id) { return fetch(`/api/products/${id}`); }",
  'export function add(item) { return fetch("/api/cart", { method: "POST", body: JSON.stringify(item) }); }',
  "export function list() { return fetch(base + '/api/products?page=1'); }",
  "function save(p) { const x = new XMLHttpRequest(); x.open('PUT', '/api/profile'); x.send(p); }",
  "const help = '/help/about';",
  canaryStatement(EXAMPLE_CANARIES),
].join("\n");

const NONCE = "0123456789abcdef";
const CONTEXT: AgentContext = {
  tier: "T1",
  objectives: [
    { id: "W1", name: "Map", submit: "endpoints" },
    { id: "W2", name: "Secrets", submit: "values" },
    { id: "W4", name: "Tamper", submit: "file" },
    { id: "W5", name: "Replay", submit: "request" },
  ],
  logic: [],
  tamper: { nonce: NONCE, marker: TAMPER_MARKER },
};
const PRICE = EXAMPLE_LOGIC.functions[0] as (typeof EXAMPLE_LOGIC.functions)[number];
const WITH_LOGIC: AgentContext = {
  ...CONTEXT,
  objectives: [...CONTEXT.objectives, { id: "W3", name: "Logic", submit: "body" }],
  logic: [LogicPublicSchema.parse(PRICE)],
};

async function runStandIn(
  files: Record<string, string>,
  limits = { calls: 150, seconds: 900 },
  context: AgentContext = CONTEXT,
) {
  const budget = new Budget(limits, () => 0);
  const handle = createToolbelt({
    artifact: files,
    budget,
    logicIds: context.logic.map((entry) => entry.id),
  });
  await new StandInAgent().run(context, handle.toolbelt, budget);
  const payload = <T>(objective: string) =>
    handle.submissions.find((s) => s.objective === objective)?.payload as T | undefined;
  return { ...handle, budget, payload };
}

describe("StandInAgent", () => {
  it("states its scope: name, version and the stand-in model", () => {
    const agent = new StandInAgent();
    expect(agent.name).toBe("stand-in");
    expect(agent.model).toBe(STAND_IN_MODEL);
    expect(agent.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(STAND_IN_AGENT).toEqual({ name: agent.name, version: agent.version, model: agent.model });
  });

  it("submits Canary-shaped and secret-shaped strings for W2", async () => {
    const { payload } = await runStandIn({ "dist/app.js": APP });
    const values = payload<SecretsSubmission>("W2")?.values ?? [];
    for (const canary of EXAMPLE_CANARIES) expect(values).toContain(canary.value);
    expect(values).toContain(TOKEN);
    expect(values).not.toContain("hello");
  });

  it("submits path literals and fetch/XHR call sites for W1, with methods and :param", async () => {
    const { payload } = await runStandIn({ "dist/app.js": APP });
    const endpoints = payload<MapSubmission>("W1")?.endpoints ?? [];
    expect(endpoints).toEqual(
      expect.arrayContaining(["GET /api/products/:param", "POST /api/cart", "GET /api/products", "PUT /api/profile"]),
    );
    expect(endpoints).toContain(`GET ${EXAMPLE_CANARIES[1]?.value}`);
    expect(endpoints.some((e) => e.includes("help"))).toBe(false);
  });

  it("builds one unsigned request for W5 from an observed call site, preferring one that changes state", async () => {
    const { payload, submissions } = await runStandIn({ "dist/app.js": APP });
    expect(payload<ReplaySubmission>("W5")).toEqual({
      request: { method: "POST", path: "/api/cart", headers: { "content-type": "application/json" }, body: "{}" },
    });
    expect(submissions.filter((s) => s.objective === "W5")).toHaveLength(1);
  });

  it("works only through the Toolbelt: every step is a recorded call", async () => {
    const { calls } = await runStandIn({ "dist/app.js": APP, "dist/b.js": "fetch('/api/b')" });
    expect(calls.map((c) => c.tool)).toEqual(["list", "read", "read", "submit", "submit", "submit", "submit"]);
  });

  it("reads a large file in chunks", async () => {
    const big = `${"x".repeat(70_000)}\nfetch("/api/late", { method: "DELETE" });`;
    const { payload, calls } = await runStandIn({ "big.js": big });
    expect(calls.filter((c) => c.tool === "read")).toHaveLength(2);
    expect(payload<MapSubmission>("W1")?.endpoints).toContain("DELETE /api/late");
  });

  it("scans adversarial text in linear time (its patterns cannot be made to backtrack for long)", async () => {
    const hostile = {
      "a.js": "x".repeat(300_000),
      "b.js": `token = "${"y".repeat(200_000)}`,
      "c.js": `fetch("/api/${"z".repeat(200_000)}`,
      "d.js": `"/api/${"q".repeat(200_000)}`,
      "e.js": `http://${"a.".repeat(100_000)}`,
    };
    const started = Date.now();
    await runStandIn(hostile);
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("is deterministic", async () => {
    const files = { "dist/app.js": APP, "dist/b.js": "fetch('/api/b')" };
    const a = await runStandIn(files);
    const b = await runStandIn(files);
    expect(b.submissions.map((s) => s.payload)).toEqual(a.submissions.map((s) => s.payload));
    expect(b.calls.map((c) => [c.tool, c.summary])).toEqual(a.calls.map((c) => [c.tool, c.summary]));
  });

  it("stays within a small budget, keeping calls for its submissions, and ends without throwing", async () => {
    const files = Object.fromEntries(
      Array.from({ length: 10 }, (_, i) => [`f${i}.js`, `fetch("/api/f${i}"); const token = "${TOKEN}";`]),
    );
    const { calls, budget, payload } = await runStandIn(files, { calls: 7, seconds: 900 });
    expect(budget.calls()).toBe(7);
    expect(calls.filter((c) => c.tool === "submit")).toHaveLength(4);
    expect(payload<MapSubmission>("W1")?.endpoints).toEqual(["GET /api/f0", "GET /api/f1"]);
  });

  it("ends cleanly when the budget cannot even hold its submissions", async () => {
    const { calls } = await runStandIn({ "a.js": APP }, { calls: 1, seconds: 900 });
    expect(calls.map((c) => c.tool)).toEqual(["list"]);
  });

  it("submits nothing for W1 and W2 when it finds nothing, and a request for the root for W5", async () => {
    const { payload } = await runStandIn({ "a.js": "export const x = 1;" });
    expect(payload<SecretsSubmission>("W2")).toBeUndefined();
    expect(payload<MapSubmission>("W1")).toBeUndefined();
    expect(payload<ReplaySubmission>("W5")).toEqual({ request: { method: "GET", path: "/", headers: {} } });
  });

  it("W3: submits a lookup over each designated function's public examples", async () => {
    const { submissions } = await runStandIn({ "a.js": "var x = 1;" }, undefined, WITH_LOGIC);
    const w3 = submissions.filter((s) => s.objective === "W3").map((s) => s.payload as LogicSubmissionPayload);
    expect(w3).toHaveLength(1);
    expect(w3[0]?.function_id).toBe(PRICE.id);
    expect(w3[0]?.body).toContain(JSON.stringify(JSON.stringify(PRICE.examples[0]?.input)));
    for (const vector of PRICE.vectors.slice(2)) expect(w3[0]?.body).not.toContain(JSON.stringify(vector.input));
  });

  it("W4: submits the first fully read JS file with the marker edit and this run's nonce", async () => {
    const file = "var x = 1;\n".repeat(20);
    const { payload } = await runStandIn({ "a.js": file, "b.css": "p{}", "c.js": file });
    expect(payload<TamperSubmissionPayload>("W4")).toEqual({ path: "a.js", code: tamperEdit(file, NONCE) });
  });
});
