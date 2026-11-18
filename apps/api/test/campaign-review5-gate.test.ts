import type { AuthorizeResult, CampaignCatalogProbe, CampaignEndReason, CampaignExchange } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createGate, type GateControl, type GateDeps, type GateRecord, type GateSend } from "../src/campaign/gate.ts";
import type { PinnedResponse } from "../src/prove/verify.ts";

// Slice 15a, fifth independent safety review: the request gate, alone, every dependency a stand-in. A probe asked for
// while another is in flight is judged against the catalog first (5, D-113); how much a refused probe asked for is a
// bucket; a sent target has the catalog's name order; a Finding rests only on a probe declared for its check.

const HOST = "shop.acme-shop.io";
const ROE = "roe_0123456789abcdef01234567";
const CAMPAIGN = "cmp_0123456789abcdef01234567";
const ALLOWED: AuthorizeResult = { allowed: true, roe_id: ROE };
const RUNNING: GateControl = { killed: false, suspended: false, stopRequested: false, deletionPending: false };
const CATALOG: CampaignCatalogProbe[] = [
  { method: "GET", path: "/", checks: ["RW-01"] },
  { method: "GET", path: "/api/admin/reports", checks: ["RW-03"] },
  { method: "GET", path: "/both", checks: ["RW-02", "RW-04"] },
  { method: "GET", path: "/plain" },
  { method: "GET", path: "/search", query: { q: { exact: "a b" }, lang: { exact: "en" } }, checks: ["RW-05"] },
];

const ok = (body = "body of the response"): PinnedResponse => ({
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
  const state = { clock: 1_000_000 };
  const sent: GateSend[] = [];
  const records: GateRecord[] = [];
  const ends: CampaignEndReason[] = [];
  const controller = new AbortController();
  /** Set to hold the next response back until it is released. */
  const flight: { release: (() => void) | null; hold: boolean } = { release: null, hold: false };
  const deps: GateDeps = {
    campaign: { id: CAMPAIGN, host: HOST, roeId: ROE, intensity: "safe-active" },
    catalog: CATALOG,
    control: async () => ({ ...RUNNING }),
    authorize: async () => ALLOWED,
    async transport(send) {
      sent.push(send);
      state.clock += 20;
      if (flight.hold) {
        await new Promise<void>((resolve) => {
          flight.release = resolve;
          send.signal.addEventListener("abort", () => resolve(), { once: true });
        });
      }
      return send.signal.aborted ? { ok: false, reason: "timeout" } : ok();
    },
    async record(entry) {
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
  return { gate: createGate(deps), state, sent, records, ends, flight, controller };
}

const until = async (condition: () => boolean) => {
  for (let i = 0; i < 200 && !condition(); i++) await new Promise((resolve) => setTimeout(resolve, 1));
  if (!condition()) throw new Error("timed out");
};

describe("review5 5 (D-113): a probe asked for while another is in flight", () => {
  it("the review's channel: 19 concurrent probes whose sizes spell a body — the first ends the Campaign, no size is kept", async () => {
    const secret = "customer Jane Roe lives at 12 Elm Stre";
    const h = harness();
    h.flight.hold = true;
    const first = h.gate.request({ method: "GET", path: "/" });
    await until(() => h.sent.length === 1);
    const answers: CampaignExchange[] = [];
    for (let i = 0; i < 19; i++) {
      // Two characters of the body in each size, as the reviewer's engine did.
      const size = secret.charCodeAt(2 * i) * 256 + secret.charCodeAt(2 * i + 1);
      answers.push(await h.gate.request({ method: "GET", path: `/${"x".repeat(size - 1)}` }));
    }
    expect(answers[0]).toMatchObject({ ok: false, fatal: true });
    expect(["path_not_canonical", "not_in_catalog"]).toContain((answers[0] as { refused: string }).refused);
    expect(answers.slice(1).every((answer) => "refused" in answer && answer.refused === "campaign_ended")).toBe(true);
    await first;
    expect(h.ends).toHaveLength(1);
    const refused = h.records.filter((row) => row.outcome === "refused");
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ target: null, asked: 1_000_000 });
    // Nothing in the log is a number of the engine's choosing.
    for (const row of h.records) expect([null, 0, 256, 1024, 1_000_000]).toContain(row.asked);
  });

  it("outside the catalog is fatal even when concurrent: malformed, another method, not canonical, not declared", async () => {
    const cases: [unknown, string][] = [
      ["not a probe", "malformed_probe"],
      [{ method: "TRACE", path: "/" }, "method_not_allowed"],
      [{ method: "GET", path: "/a/../b" }, "path_not_canonical"],
      [{ method: "GET", path: "/", query: { "a b": "1" } }, "query_not_canonical"],
      [{ method: "GET", path: "/nowhere" }, "not_in_catalog"],
    ];
    for (const [probe, reason] of cases) {
      const h = harness();
      h.flight.hold = true;
      const first = h.gate.request({ method: "GET", path: "/" });
      await until(() => h.sent.length === 1);
      expect(await h.gate.request(probe), reason).toEqual({ ok: false, refused: reason, fatal: true });
      expect(h.ends).toEqual([reason]);
      // The request in flight is cut: the Campaign has ended.
      expect(await first).toMatchObject({ ok: false });
      expect(h.sent).toHaveLength(1);
    }
  });

  it("a catalog probe asked for concurrently is refused without ending the Campaign, and keeps its catalog target", async () => {
    const h = harness();
    h.flight.hold = true;
    const first = h.gate.request({ method: "GET", path: "/" });
    await until(() => h.sent.length === 1);
    expect(await h.gate.request({ method: "GET", path: "/search", query: { lang: "en", q: "a b" } })).toEqual({
      ok: false,
      refused: "concurrent_request",
      fatal: false,
    });
    expect(h.ends).toEqual([]);
    expect(h.records.at(-1)).toMatchObject({
      outcome: "refused",
      reason: "concurrent_request",
      method: "GET",
      target: "/search?q=a%20b&lang=en",
      asked: 256,
    });
    h.flight.release?.();
    expect((await first).ok).toBe(true);
    expect(h.sent).toHaveLength(1);
  });
});

describe("review5: what a refused probe asked for is a bucket, in every refusal", () => {
  it("0, at most 256, at most 1,024, more", async () => {
    const sizes: [unknown, number][] = [
      ["x", 0],
      [{ method: "GET", path: "" }, 0],
      [{ method: "GET", path: "/n" }, 256],
      [{ method: "GET", path: `/${"n".repeat(255)}` }, 256],
      [{ method: "GET", path: `/${"n".repeat(256)}` }, 1024],
      [{ method: "GET", path: `/${"n".repeat(1023)}` }, 1024],
      [{ method: "GET", path: `/${"n".repeat(1024)}` }, 1_000_000],
      [{ method: "GET", path: "/", query: { q: "v".repeat(5000) } }, 1_000_000],
    ];
    for (const [probe, bucket] of sizes) {
      const h = harness();
      await h.gate.request(probe);
      expect(h.records).toMatchObject([{ outcome: "refused", target: null, asked: bucket }]);
    }
  });
});

describe("review5: the target sent and stored has the catalog's name order", () => {
  it("whatever order the engine lists the names in, one target", async () => {
    const targets = new Set<string>();
    for (const query of [
      { q: "a b", lang: "en" },
      { lang: "en", q: "a b" },
    ]) {
      const h = harness();
      expect((await h.gate.request({ method: "GET", path: "/search", query })).ok).toBe(true);
      targets.add(`${h.sent[0]?.target} | ${h.records[0]?.target} | ${h.gate.evidence(1, "", "RW-05")?.target}`);
    }
    expect([...targets]).toEqual(["/search?q=a%20b&lang=en | /search?q=a%20b&lang=en | /search?q=a%20b&lang=en"]);
  });
});

describe("review5: a Finding rests only on a probe declared for its check", () => {
  it("evidence is given for a check the request's probe names, and for no other", async () => {
    const h = harness();
    await h.gate.request({ method: "GET", path: "/api/admin/reports" });
    h.state.clock += 5000;
    await h.gate.request({ method: "GET", path: "/both" });
    h.state.clock += 5000;
    await h.gate.request({ method: "GET", path: "/plain" });
    expect(h.gate.evidence(1, "body", "RW-03")).toMatchObject({ target: "/api/admin/reports", excerpt: "body" });
    // The review's case: the admin check's Finding on another check's request, and the other way round.
    expect(h.gate.evidence(1, "body", "RW-01")).toBeNull();
    expect(h.gate.evidence(2, "body", "RW-03")).toBeNull();
    expect(h.gate.evidence(2, "body", "RW-02")).not.toBeNull();
    expect(h.gate.evidence(2, "body", "RW-04")).not.toBeNull();
    // A probe that names no check carries no Finding.
    expect(h.gate.evidence(3, "", "RW-01")).toBeNull();
    for (const check of [undefined, null, "", 7, "RW-0", {}]) {
      expect(h.gate.evidence(1, "body", check as never)).toBeNull();
    }
  });
});
