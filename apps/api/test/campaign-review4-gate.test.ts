import {
  type AuthorizeResult,
  CAMPAIGN_LIMITS,
  type CampaignCatalogProbe,
  type CampaignEndReason,
  type CampaignExchange,
  campaignAskedBucket,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createGate, type GateControl, type GateDeps, type GateRecord, type GateSend } from "../src/campaign/gate.ts";
import { type PinnedResponse, READ_OVERSHOOT_BYTES_MAX, requestReadMax } from "../src/prove/verify.ts";

// Slice 15a, fourth independent safety review: the request gate, alone, every dependency a stand-in. R1 (D-110): the
// gate sends only probes of the engine's declared catalog, and keeps nothing an engine chose as text. And the
// switches are the last thing read before a request leaves.

const HOST = "shop.acme-shop.io";
const ROE = "roe_0123456789abcdef01234567";
const CAMPAIGN = "cmp_0123456789abcdef01234567";
const ALLOWED: AuthorizeResult = { allowed: true, roe_id: ROE };
const RUNNING: GateControl = { killed: false, suspended: false, stopRequested: false, deletionPending: false };
const MARKER = '"><airverse-probe-marker>';
const CATALOG: CampaignCatalogProbe[] = [
  { method: "GET", path: "/" },
  { method: "GET", path: "/api/admin/reports" },
  { method: "GET", path: "/search", query: { q: { exact: MARKER } } },
  { method: "GET", path: "/reflect", query: { m: { token: { prefix: "airverse-", hex: 16 } } } },
];
/** What a target might answer: 2,700 characters no engine may carry out of the gate. */
const BODY = Array.from({ length: 300 }, (_, i) => `secret${String(i).padStart(3, "0")}`).join("");

const ok = (body = BODY): PinnedResponse => ({
  ok: true,
  status: 200,
  headers: {},
  headerBytes: 0,
  body: Buffer.from(body),
  truncated: false,
  remoteAddress: "203.0.113.10",
  bytesRead: Buffer.byteLength(body),
});

function harness(extra: Partial<GateDeps> = {}) {
  const state = { clock: 1_000_000, control: { ...RUNNING } as GateControl, authorize: ALLOWED as AuthorizeResult };
  const sent: GateSend[] = [];
  const records: GateRecord[] = [];
  const ends: CampaignEndReason[] = [];
  const order: string[] = [];
  const controller = new AbortController();
  const deps: GateDeps = {
    campaign: { id: CAMPAIGN, host: HOST, roeId: ROE, intensity: "safe-active" },
    // Fifth review: a Finding rests only on a probe declared for its check; here every probe serves RW-01.
    catalog: CATALOG.map((probe) => ({ ...probe, checks: ["RW-01"] })),
    async control() {
      order.push("control");
      return { ...state.control };
    },
    async authorize() {
      order.push("authorize");
      return state.authorize;
    },
    async transport(send) {
      order.push("transport");
      sent.push(send);
      state.clock += 20;
      return ok();
    },
    async record(entry) {
      order.push("record");
      records.push({ ...entry });
    },
    async settle(entry) {
      const index = records.findIndex((row) => row.seq === entry.seq);
      records[index] = { ...entry };
    },
    now: () => state.clock,
    async sleep(ms) {
      state.clock += ms;
    },
    signal: controller.signal,
    onEnd: (reason) => {
      ends.push(reason);
      controller.abort(reason);
    },
    ...extra,
  };
  return { gate: createGate(deps), state, sent, records, ends, order, controller };
}

const refusal = (exchange: CampaignExchange) => ("refused" in exchange ? exchange.refused : null);

describe("review4 R1 (D-110): only probes of the engine's catalog are sent", () => {
  it("the review's engine: body text as refused paths and as query values — none of it is sent or kept", async () => {
    const h = harness();
    const first = await h.gate.request({ method: "GET", path: "/api/admin/reports" });
    const body = first.ok ? first.body : "";
    expect(body.length).toBeGreaterThan(2048);
    // Eight refused TRACE probes, each with 256 characters of the body as its path.
    const answers: CampaignExchange[] = [];
    for (let i = 0; i < 8; i++) {
      answers.push(await h.gate.request({ method: "TRACE", path: body.slice(i * 256, (i + 1) * 256) }));
    }
    // And one GET whose query values are 640 characters of it.
    answers.push(
      await h.gate.request({
        method: "GET",
        path: "/search",
        query: { a: body.slice(0, 320), b: body.slice(320, 640) },
      }),
    );
    expect(h.sent.map((send) => send.target)).toEqual(["/api/admin/reports"]);
    // The first of them ended the Campaign: the engine is not doing what was reviewed.
    expect(answers[0]).toEqual({ ok: false, refused: "method_not_allowed", fatal: true });
    expect(answers.slice(1).every((answer) => refusal(answer) === "campaign_ended")).toBe(true);
    expect(h.ends).toEqual(["method_not_allowed"]);
    expect(h.records.slice(1)).toEqual([
      {
        seq: 2,
        method: "OTHER",
        target: null,
        outcome: "refused",
        reason: "method_not_allowed",
        status: null,
        failure: null,
        bytes: 0,
        ms: 0,
        asked: 256,
      },
    ]);
    expect(JSON.stringify(h.records)).not.toMatch(/secret\d/);
  });

  it("a well-formed GET that is not in the catalog is refused, logged without its text, and ends the Campaign", async () => {
    const cases: [unknown, string, number][] = [
      [
        { method: "GET", path: "/search", query: { a: BODY.slice(0, 320), b: BODY.slice(320, 640) } },
        "not_in_catalog",
        649,
      ],
      [{ method: "GET", path: "/search", query: { q: BODY.slice(0, 100) } }, "not_in_catalog", 108],
      [{ method: "GET", path: "/search" }, "not_in_catalog", 7],
      [{ method: "GET", path: "/secret000secret001" }, "not_in_catalog", 19],
      [{ method: "HEAD", path: "/" }, "not_in_catalog", 1],
      [{ method: "GET", path: "/reflect", query: { m: "airverse-0123456789abcdeg" } }, "not_in_catalog", 34],
      [{ method: "GET", path: `/${"s".repeat(600)}` }, "path_not_canonical", 601],
      [{ method: "GET", path: "/", query: { q: "x".repeat(600) } }, "query_not_canonical", 602],
      [{ method: "GET", path: "/", note: BODY }, "malformed_probe", 1],
      [BODY, "malformed_probe", 0],
      [{ method: BODY, path: BODY }, "method_not_allowed", 2700],
    ];
    for (const [probe, reason, asked] of cases) {
      const h = harness();
      expect(await h.gate.request(probe), reason).toEqual({ ok: false, refused: reason, fatal: true });
      expect(h.sent).toEqual([]);
      expect(h.ends).toEqual([reason]);
      expect(h.records).toHaveLength(1);
      // Fifth review (D-113): the count is kept as its bucket.
      expect(h.records[0]).toMatchObject({
        target: null,
        outcome: "refused",
        reason,
        asked: campaignAskedBucket(asked),
      });
      expect(["GET", "HEAD", "OTHER", null]).toContain(h.records[0]?.method);
      expect(JSON.stringify(h.records)).not.toMatch(/secret\d|sss|xxx/);
    }
  });

  it("the count of what was asked is bounded, whatever is asked", async () => {
    const h = harness();
    await h.gate.request({ method: "GET", path: "p".repeat(3_000_000) });
    expect(h.records[0]?.asked).toBe(1_000_000);
    const many = harness();
    await many.gate.request({
      method: "GET",
      path: "/",
      query: Object.fromEntries(Array.from({ length: 5000 }, (_, i) => [`k${i}`, "v".repeat(500)])),
    });
    expect(many.records[0]?.asked).toBeLessThanOrEqual(1_000_000);
    expect(many.records[0]?.asked).toBeGreaterThan(8 * 500);
  });

  it("a probe of the catalog is sent with its catalog target; a token value passes by its shape only", async () => {
    const h = harness();
    expect((await h.gate.request({ method: "GET", path: "/search", query: { q: MARKER } })).ok).toBe(true);
    h.state.clock += 5000;
    expect(
      (await h.gate.request({ method: "GET", path: "/reflect", query: { m: "airverse-00112233aabbccdd" } })).ok,
    ).toBe(true);
    expect(h.sent.map((send) => send.target)).toEqual([
      "/search?q=%22%3E%3Cairverse-probe-marker%3E",
      "/reflect?m=airverse-00112233aabbccdd",
    ]);
    expect(h.records.map((row) => [row.outcome, row.target, row.asked])).toEqual([
      ["sent", "/search?q=%22%3E%3Cairverse-probe-marker%3E", null],
      ["sent", "/reflect?m=airverse-00112233aabbccdd", null],
    ]);
    expect(h.gate.evidence(1, "", "RW-01")?.target).toBe("/search?q=%22%3E%3Cairverse-probe-marker%3E");
  });

  it("a catalog probe refused for another reason keeps its catalog target in the log", async () => {
    const h = harness();
    h.state.authorize = { allowed: false, reason: "path_excluded" };
    expect(await h.gate.request({ method: "GET", path: "/search", query: { q: MARKER } })).toEqual({
      ok: false,
      refused: "path_excluded",
      fatal: false,
    });
    expect(h.records).toMatchObject([
      { method: "GET", target: "/search?q=%22%3E%3Cairverse-probe-marker%3E", reason: "path_excluded", asked: 256 },
    ]);
    expect(h.ends).toEqual([]);
  });

  it("the catalog is checked when the gate is made, and is the gate's own copy", async () => {
    expect(() => harness({ catalog: [{ method: "GET", path: "/a/../b" }] })).toThrow(TypeError);
    expect(() => harness({ catalog: [{ method: "POST", path: "/" }] as never })).toThrow(TypeError);
    expect(() => harness({ catalog: undefined as never })).toThrow(TypeError);
    const mine: CampaignCatalogProbe[] = [{ method: "GET", path: "/" }];
    const h = harness({ catalog: mine });
    // Adding to the list afterwards — as code that runs later might try — changes nothing.
    mine.push({ method: "GET", path: "/later" });
    expect(refusal(await h.gate.request({ method: "GET", path: "/later" }))).toBe("not_in_catalog");
    expect(h.sent).toEqual([]);
  });

  it("an empty catalog sends nothing but the ownership request", async () => {
    const h = harness({ catalog: [] });
    expect((await h.gate.ownership()).ok).toBe(true);
    expect(refusal(await h.gate.request({ method: "GET", path: "/" }))).toBe("not_in_catalog");
    expect(h.sent.map((send) => send.target)).toEqual(["/.well-known/airverse-verification.txt"]);
  });
});

describe("review4 R7: the 2 MB of a Campaign hold against connections that all read to their bound", () => {
  it("every request reads its cap and one TCP read more: the total never passes 2 MB", async () => {
    // What the transport can report at most for a request: `requestReadMax(body cap)` and one read of overshoot.
    const worst = (send: GateSend): number => requestReadMax(send.bodyBytesMax) + READ_OVERSHOOT_BYTES_MAX;
    const sent: GateSend[] = [];
    const h = harness({
      async transport(send) {
        sent.push(send);
        return { ...ok("x"), bytesRead: worst(send) };
      },
    });
    for (let n = 0; n < 60; n++) {
      h.state.clock += 2000;
      const exchange = await h.gate.request({ method: "GET", path: "/" });
      if (!exchange.ok) {
        expect(exchange).toMatchObject({ refused: "byte_budget" });
        break;
      }
    }
    expect(sent.length).toBeGreaterThan(5);
    expect(h.gate.counters().bytes).toBeLessThanOrEqual(CAMPAIGN_LIMITS.responseBytesMax);
    // The reserve is exactly that bound: headers, TLS, framing and one read. No more is kept back than can be read.
    expect(CAMPAIGN_LIMITS.responseBytesMax - h.gate.counters().bytes).toBeLessThan(requestReadMax(0) + 65_536 + 1);
  });
});

describe("review4: the switches are the last thing read before a request leaves", () => {
  it("for a probe: authorize, then control, then the send", async () => {
    const h = harness();
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.order).toEqual(["control", "authorize", "record", "authorize", "control", "transport"]);
  });

  it("for the ownership request too", async () => {
    const h = harness();
    await h.gate.ownership();
    expect(h.order).toEqual(["control", "authorize", "record", "authorize", "control", "transport"]);
  });

  it("a kill committed while the authorization is read again holds the request back", async () => {
    const h = harness();
    let reads = 0;
    const gate = createGate({
      campaign: { id: CAMPAIGN, host: HOST, roeId: ROE, intensity: "safe-active" },
      catalog: CATALOG,
      control: async () => ({ ...h.state.control }),
      async authorize() {
        // The second read of the authorization: the operator's kill is committed while it runs.
        if (++reads === 2) h.state.control = { ...RUNNING, killed: true };
        return ALLOWED;
      },
      transport: async (send) => {
        h.sent.push(send);
        return ok();
      },
      record: async () => {},
      settle: async () => {},
      now: () => 1,
      sleep: async () => {},
      signal: h.controller.signal,
      onEnd: (reason) => void h.ends.push(reason),
    });
    expect(refusal(await gate.request({ method: "GET", path: "/" }))).toBe("operator_kill");
    expect(h.sent).toEqual([]);
    expect(h.ends).toEqual(["operator_kill"]);
  });
});
