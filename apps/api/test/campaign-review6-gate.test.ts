import type { AuthorizeResult, CampaignCatalogProbe, CampaignEndReason } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createGate, type GateControl, type GateDeps, type GateRecord, type GateSend } from "../src/campaign/gate.ts";
import type { PinnedResponse } from "../src/prove/verify.ts";

// Slice 15a, sixth independent safety review: the request gate, alone, every dependency a stand-in. F3: a burst of
// probes in one tick writes at most one refused row before the Campaign has ended. F7: a refused catalog probe is
// logged with its token masked.

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
  { method: "GET", path: "/reflect", query: { m: { token: { prefix: "airverse-", hex: 32 } } }, checks: ["RW-05"] },
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

describe("review6 F3: a burst of probes in one tick", () => {
  it("190 probes outside the catalog at once: one refused row, the Campaign failed, one request at the target", async () => {
    const h = harness();
    h.flight.hold = true;
    const first = h.gate.request({ method: "GET", path: "/" });
    await until(() => h.sent.length === 1);
    // The review's burst: every (method, size, reason) combination it could tell apart, 190 probes, none awaited.
    const methods = ["GET", "TRACE", "HEAD", 7];
    const sizes = [0, 10, 300, 2000];
    const burst = Array.from({ length: 190 }, (_, i) =>
      h.gate.request({
        method: methods[i % 4],
        path: `/${"x".repeat(sizes[Math.floor(i / 4) % 4] as number)}${i % 3 === 0 ? "/../y" : ""}`,
      }),
    );
    const answers = await Promise.all(burst);
    await first;
    expect(answers.filter((answer) => "refused" in answer && answer.refused !== "campaign_ended")).toHaveLength(1);
    expect(answers.filter((answer) => "refused" in answer && answer.refused === "campaign_ended")).toHaveLength(189);
    expect(h.records.filter((row) => row.outcome === "refused")).toHaveLength(1);
    expect(h.records).toHaveLength(2);
    expect(h.ends).toHaveLength(1);
    expect(h.sent).toHaveLength(1);
    expect(h.gate.counters().refused).toBe(1);
  });

  it("a burst with nothing in flight: the first is judged, the next ends the Campaign, the rest write nothing", async () => {
    const h = harness();
    const answers = await Promise.all(
      Array.from({ length: 50 }, (_, i) => h.gate.request({ method: "TRACE", path: `/${"x".repeat(i * 40)}` })),
    );
    expect(h.records.filter((row) => row.outcome === "refused").length).toBeLessThanOrEqual(2);
    expect(h.ends).toHaveLength(1);
    expect(h.sent).toEqual([]);
    expect(
      answers.filter((answer) => "refused" in answer && answer.refused === "campaign_ended").length,
    ).toBeGreaterThan(47);
  });

  it("a burst of catalog probes while one is in flight: twenty refusals at most, then the Campaign has ended", async () => {
    const h = harness();
    h.flight.hold = true;
    const first = h.gate.request({ method: "GET", path: "/" });
    await until(() => h.sent.length === 1);
    const answers = await Promise.all(
      Array.from({ length: 190 }, () => h.gate.request({ method: "GET", path: "/plain" })),
    );
    await first;
    const refused = h.records.filter((row) => row.outcome === "refused");
    expect(refused).toHaveLength(20);
    expect(new Set(refused.map((row) => `${row.method} ${row.target} ${row.asked} ${row.reason}`))).toEqual(
      new Set(["GET /plain 256 concurrent_request"]),
    );
    expect(h.ends).toEqual(["refusal_limit"]);
    expect(answers.filter((answer) => "refused" in answer && answer.refused === "campaign_ended")).toHaveLength(170);
  });

  it("the end is set before the refused row is written: a log that cannot be written changes nothing of it", async () => {
    const order: string[] = [];
    const h = harness({
      async record() {
        order.push("record");
        throw new Error("the log is not writable");
      },
      onEnd: (reason) => void order.push(`end ${reason}`),
    });
    expect(await h.gate.request({ method: "TRACE", path: "/" })).toMatchObject({ ok: false, fatal: true });
    expect(order).toEqual(["end method_not_allowed", "record"]);
    expect(h.gate.ended()).toBe("method_not_allowed");
  });
});

describe("review6 F7: a refused catalog probe keeps no token", () => {
  it("19 concurrent probes with 128 bits each: the rows hold the prefix and a fixed word", async () => {
    const h = harness();
    h.flight.hold = true;
    const first = h.gate.request({ method: "GET", path: "/" });
    await until(() => h.sent.length === 1);
    const tokens = Array.from({ length: 19 }, (_, i) => i.toString(16).padStart(2, "0").repeat(16));
    for (const token of tokens) {
      expect(await h.gate.request({ method: "GET", path: "/reflect", query: { m: `airverse-${token}` } })).toEqual({
        ok: false,
        refused: "concurrent_request",
        fatal: false,
      });
    }
    h.flight.release?.();
    await first;
    const refused = h.records.filter((row) => row.outcome === "refused");
    expect(refused.map((row) => row.target)).toEqual(tokens.map(() => "/reflect?m=airverse-[token]"));
    for (const token of tokens) expect(JSON.stringify(h.records)).not.toContain(token);
  });

  it("refused for any other reason too: the Rules exclude its path, the budget is spent", async () => {
    const h = harness({ authorize: async () => ({ allowed: false, reason: "path_excluded" }) });
    await h.gate.request({ method: "GET", path: "/reflect", query: { m: `airverse-${"ab".repeat(16)}` } });
    expect(h.records).toMatchObject([
      { outcome: "refused", reason: "path_excluded", target: "/reflect?m=airverse-[token]" },
    ]);
  });

  it("a probe that is sent keeps its real target: the target saw it", async () => {
    const h = harness();
    const token = "0123456789abcdef".repeat(2);
    expect((await h.gate.request({ method: "GET", path: "/reflect", query: { m: `airverse-${token}` } })).ok).toBe(
      true,
    );
    expect(h.sent[0]?.target).toBe(`/reflect?m=airverse-${token}`);
    expect(h.records[0]).toMatchObject({ outcome: "sent", target: `/reflect?m=airverse-${token}` });
    expect(h.gate.evidence(1, "", "RW-05")?.target).toBe(`/reflect?m=airverse-${token}`);
  });
});
