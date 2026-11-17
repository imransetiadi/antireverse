import { Worker } from "node:worker_threads";
import {
  CAMPAIGN_LIMITS,
  type CampaignExchange,
  type CampaignProbe,
  campaignRequestTarget,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  campaignWorkerOptions,
  type EngineCheck,
  type EngineFinding,
  runCampaignEngine,
  runStandIn,
  STAND_IN_CATALOG,
  STAND_IN_MARKER,
  standInEngine,
} from "../src/index.ts";

// Slice 15a, third independent safety review. F5 (D-107): a check reports a window of at most 200 characters around
// what it matched, not a position in a body. And the worker an engine runs in is started without the environment of
// the API process. No test here opens a socket: the "target" is a function.

type Ok = Extract<CampaignExchange, { ok: true }>;
const answer = (seq: number, status: number, body: string, extra: Partial<Ok> = {}): Ok => ({
  ok: true,
  seq,
  status,
  headers: { "content-type": "text/html" },
  body,
  truncated: false,
  location: null,
  withheld: false,
  ...extra,
});

const PAD = "lorem ipsum dolor sit amet ".repeat(400);

/** A target with every seeded weakness, each buried in a long body. */
function weakTarget(probe: CampaignProbe, seq: number): CampaignExchange {
  const target = campaignRequestTarget(probe) ?? "";
  if (target === "/") return answer(seq, 200, `${PAD}<h1>ar-range</h1>${PAD}`);
  if (target === "/api/orders/x") {
    return answer(
      seq,
      500,
      `${PAD}Error: order id is not a number\n    at loadOrder (/srv/ar-range/${"deep/".repeat(60)}orders.js:42:11)\n${PAD}`,
    );
  }
  if (target === "/api/admin/reports") return answer(seq, 200, `${PAD}{"reports":[{"id":"rpt_orders_weekly"}]}${PAD}`);
  if (target === "/api/orders/1001") return answer(seq, 200, `{"order_id":"1001","synthetic":true}${PAD}`);
  if (target.startsWith("/search?")) return answer(seq, 200, `${PAD}<p>Results for <b>${probe.query?.q}</b></p>${PAD}`);
  if (target.startsWith("/go?"))
    return answer(seq, 302, "", { location: "other-host", headers: { location: "other-host" } });
  return answer(seq, 404, "not found");
}

async function run(respond: (probe: CampaignProbe, seq: number) => CampaignExchange = weakTarget) {
  const checks: EngineCheck[] = [];
  const findings: EngineFinding[] = [];
  const bodies = new Map<number, string>();
  let seq = 0;
  await runStandIn({
    intensity: "safe-active",
    async request(probe) {
      const exchange = respond(probe, ++seq);
      if (exchange.ok) bodies.set(exchange.seq, exchange.body);
      return exchange;
    },
    check: (check) => checks.push(check),
    finding: (finding) => findings.push(finding),
  });
  return { checks, findings, bodies };
}

describe("review3 F5: a check reports an evidence window, not a position", () => {
  it("every Finding carries a window of at most 200 characters that is a piece of the body it saw", async () => {
    const { findings, bodies, checks } = await run();
    expect(checks.map((check) => check.result)).toEqual(Array.from({ length: 6 }, () => "reported"));
    expect(findings).toHaveLength(12);
    for (const finding of findings) {
      expect(Object.keys(finding).sort()).toEqual(["check_id", "path", "seq", "severity", "title", "window"]);
      expect(typeof finding.window).toBe("string");
      expect(finding.window.length).toBeLessThanOrEqual(CAMPAIGN_LIMITS.evidenceWindowMax);
      expect(bodies.get(finding.seq)).toContain(finding.window);
    }
  });

  it("the window is built around what the check matched", async () => {
    const { findings } = await run();
    const window = (id: string) => findings.find((finding) => finding.check_id === id)?.window ?? "";
    // Checks that read no body have no window.
    expect(window("RW-01")).toBe("");
    expect(window("RW-06")).toBe("");
    expect(window("RW-02")).toMatch(/Error: order id is not a number\n {4}at loadOrder \(\/srv\/ar-range\//);
    expect(window("RW-03")).toContain('"reports"');
    expect(window("RW-04").startsWith('{"order_id"')).toBe(true);
    expect(window("RW-05")).toContain(STAND_IN_MARKER);
  });

  it("the engine module names each check's title and severity, for a host that does not take them from a report", () => {
    expect(standInEngine.findings).toEqual(
      Object.fromEntries(STAND_IN_CATALOG.map((check) => [check.id, { title: check.title, severity: check.severity }])),
    );
    expect(Object.isFrozen(standInEngine.findings)).toBe(true);
  });

  it("through the worker too: a Finding arrives with its window", async () => {
    const findings: EngineFinding[] = [];
    let seq = 0;
    await runCampaignEngine({
      intensity: "safe-active",
      request: async (probe) => weakTarget(probe as CampaignProbe, ++seq),
      onCheck() {},
      onFinding: (finding) => void findings.push(finding as EngineFinding),
    });
    expect(findings).toHaveLength(12);
    expect(findings.every((finding) => finding.window.length <= 200 && !("at" in finding))).toBe(true);
  });
});

describe("review3: the engine's worker is started without the API's environment", () => {
  it("campaignWorkerOptions gives the worker an empty environment, no standard streams and its memory limits", () => {
    const options = campaignWorkerOptions("passive");
    expect(options.env).toEqual({});
    expect(options).toMatchObject({ stdout: false, stderr: false, workerData: { intensity: "passive" } });
    expect(options.resourceLimits).toMatchObject({ maxOldGenerationSizeMb: 64 });
  });

  it("a worker started with those options sees no environment variable, whatever the API process holds", async () => {
    process.env.AR_REVIEW3_CANARY = "must-not-reach-the-engine";
    try {
      const seen = await new Promise<string[]>((resolve, reject) => {
        const worker = new Worker('require("node:worker_threads").parentPort.postMessage(Object.keys(process.env));', {
          ...campaignWorkerOptions("passive"),
          eval: true,
          execArgv: [],
        });
        worker.once("message", resolve);
        worker.once("error", reject);
      });
      expect(seen).toEqual([]);
    } finally {
      delete process.env.AR_REVIEW3_CANARY;
    }
  });

  it("control: a worker started without those options does see it", async () => {
    process.env.AR_REVIEW3_CANARY = "visible";
    try {
      const seen = await new Promise<string[]>((resolve, reject) => {
        const worker = new Worker('require("node:worker_threads").parentPort.postMessage(Object.keys(process.env));', {
          eval: true,
          execArgv: [],
        });
        worker.once("message", resolve);
        worker.once("error", reject);
      });
      expect(seen).toContain("AR_REVIEW3_CANARY");
    } finally {
      delete process.env.AR_REVIEW3_CANARY;
    }
  });
});
