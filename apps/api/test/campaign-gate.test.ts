import {
  AUTHORIZE_REASONS,
  type AuthorizeResult,
  CAMPAIGN_LIMITS,
  type CampaignCatalogProbe,
  type CampaignEndReason,
  type CampaignExchange,
  FATAL_CAMPAIGN_REFUSALS,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createGate, type GateControl, type GateDeps, type GateRecord, type GateSend } from "../src/campaign/gate.ts";
import type { PinnedResponse } from "../src/prove/verify.ts";

// Slice 15a: the request gate, alone. Every dependency is a stand-in: the clock, the sleep, the database reads
// (control and authorize), the transport and the log. Nothing here opens a socket.

const HOST = "shop.acme-shop.io";
const ROE = "roe_0123456789abcdef01234567";
const CAMPAIGN = "cmp_0123456789abcdef01234567";
const ALLOWED: AuthorizeResult = { allowed: true, roe_id: ROE };

/**
 * The probes the scripted "engine" of these tests may send (fourth review, D-110): the gate sends nothing that is not
 * declared. A test of a probe outside it says so.
 */
const CATALOG: CampaignCatalogProbe[] = [
  ...["/", "/a", "/b", "/c", "/x", "/next", "/never", "/admin", "/api/orders/x", "/api/admin/reports", "/search"].map(
    (path) => ({ method: "GET" as const, path }),
  ),
  { method: "HEAD", path: "/" },
  { method: "HEAD", path: "/x" },
  { method: "GET", path: "/search", query: { q: { exact: "a b" } } },
  { method: "GET", path: "/go", query: { to: { exact: "https://evil.example.net/x" } } },
];

const ok = (status = 200, body = "ok", headers: Record<string, string | string[]> = {}): PinnedResponse => ({
  ok: true,
  status,
  headers,
  headerBytes: 0,
  body: Buffer.from(body),
  truncated: false,
  remoteAddress: "203.0.113.10",
  bytesRead: Buffer.byteLength(body),
});

function harness(
  options: {
    respond?: (send: GateSend, n: number) => PinnedResponse | Promise<PinnedResponse>;
    extra?: Partial<GateDeps>;
  } = {},
) {
  const state = {
    clock: Date.parse("2026-11-16T10:00:00.000Z"),
    control: { killed: false, suspended: false, stopRequested: false, deletionPending: false } as GateControl,
    authorize: ALLOWED as AuthorizeResult,
    transportMs: 20,
  };
  const sent: GateSend[] = [];
  const records: GateRecord[] = [];
  const sleeps: number[] = [];
  const ends: CampaignEndReason[] = [];
  const authorized: { host: string; path: string; intensity: string }[] = [];
  const order: string[] = [];
  const controller = new AbortController();
  const deps: GateDeps = {
    campaign: { id: CAMPAIGN, host: HOST, roeId: ROE, intensity: "safe-active" },
    catalog: CATALOG,
    async control() {
      order.push("control");
      return { ...state.control };
    },
    async authorize(request) {
      order.push("authorize");
      authorized.push(request);
      return state.authorize;
    },
    async transport(send) {
      order.push("transport");
      sent.push(send);
      state.clock += state.transportMs;
      return (options.respond ?? (() => ok()))(send, sent.length);
    },
    async record(entry) {
      order.push("record");
      records.push({ ...entry });
    },
    async settle(entry) {
      const index = records.findIndex((row) => row.seq === entry.seq);
      if (records[index]?.outcome !== "sending") throw new Error("settled a row that is not sending");
      records[index] = { ...entry };
    },
    now: () => state.clock,
    async sleep(ms) {
      order.push("sleep");
      sleeps.push(ms);
      state.clock += ms;
    },
    signal: controller.signal,
    onEnd: (reason) => {
      ends.push(reason);
    },
    ...options.extra,
  };
  const gate = createGate(deps);
  return { deps: () => deps, gate, state, sent, records, sleeps, ends, authorized, order, controller };
}

const refusal = (exchange: CampaignExchange) => ("refused" in exchange ? exchange.refused : null);

describe("an allowed probe", () => {
  it("is sent as GET with the identifying headers only, and answered redacted", async () => {
    const BODY = "hello jane@acme-shop.io sk_live_4eC39HqLyjWDarjtT1zdp7dc";
    const h = harness({
      respond: () =>
        ok(200, BODY, {
          "content-type": "text/html",
          "set-cookie": ["sid=abcdef123456; HttpOnly"],
          "x-secret": "nope",
        }),
    });
    const exchange = await h.gate.request({ method: "GET", path: "/search", query: { q: "a b" } });
    expect(h.sent).toHaveLength(1);
    expect(h.sent[0]).toMatchObject({ method: "GET", target: "/search?q=a%20b" });
    expect(h.sent[0]?.headers).toEqual({
      "user-agent": "Airverse-Campaign/1",
      "x-airverse-campaign": CAMPAIGN,
      accept: "*/*",
    });
    expect(h.sent[0]?.bodyBytesMax).toBe(CAMPAIGN_LIMITS.responseReadBytesMax);
    expect(exchange).toEqual({
      ok: true,
      seq: 1,
      status: 200,
      headers: { "content-type": "text/html", "set-cookie": "sid=[redacted]; HttpOnly" },
      body: "hello [redacted-email] [redacted-key]",
      truncated: false,
      location: null,
      withheld: false,
    });
    // The form authorised is the form sent: authorize saw exactly the path of the request target — when the probe
    // was judged, and once more right before it left (third review, F4).
    expect(h.authorized).toEqual([
      { host: HOST, path: "/search", intensity: "safe-active" },
      { host: HOST, path: "/search", intensity: "safe-active" },
    ]);
    expect(h.records).toEqual([
      {
        seq: 1,
        method: "GET",
        target: "/search?q=a%20b",
        outcome: "sent",
        reason: null,
        status: 200,
        failure: null,
        bytes: BODY.length,
        ms: 20,
        asked: null,
      },
    ]);
    expect(h.gate.counters()).toEqual({ sent: 1, refused: 0, bytes: BODY.length });
  });

  it("checks in the ticket's order: control, shape, method, path, authorize, rules, budgets, spacing, send", async () => {
    const h = harness();
    await h.gate.request({ method: "HEAD", path: "/" });
    await h.gate.request({ method: "GET", path: "/" });
    // Third review, F4: after the spacing wait and the log row, the authorization and the switches are read once
    // more — the switches last (fourth review) — and nothing is awaited between that read and the send.
    expect(h.order).toEqual([
      "control",
      "authorize",
      "record",
      "authorize",
      "control",
      "transport",
      "control",
      "authorize",
      "sleep",
      "record",
      "authorize",
      "control",
      "transport",
    ]);
  });

  it("keeps a redirect's Location only as a category, and never follows it", async () => {
    const h = harness({ respond: () => ok(302, "", { location: "https://evil.example.net/x?token=1" }) });
    const exchange = await h.gate.request({ method: "GET", path: "/go", query: { to: "https://evil.example.net/x" } });
    expect(exchange).toMatchObject({
      ok: true,
      status: 302,
      location: "other-host",
      headers: { location: "other-host" },
    });
    expect(JSON.stringify(exchange)).not.toContain("evil.example.net");
    expect(h.sent).toHaveLength(1);
  });
});

describe("refusals", () => {
  it("each control flag refuses before anything else, ends the Campaign, and nothing is sent", async () => {
    const cases: [keyof GateControl, string][] = [
      ["killed", "operator_kill"],
      ["suspended", "organization_suspended"],
      ["stopRequested", "owner_stop"],
      ["deletionPending", "deletion_pending"],
    ];
    for (const [flag, reason] of cases) {
      const h = harness();
      h.state.control[flag] = true;
      // Also malformed: the control check comes first.
      const exchange = await h.gate.request({ method: "POST", path: "//x", body: "y" });
      expect(exchange).toEqual({ ok: false, refused: reason, fatal: true });
      expect(h.sent).toEqual([]);
      expect(h.ends).toEqual([reason]);
      expect(h.records).toMatchObject([{ outcome: "refused", reason, status: null }]);
      expect(h.order).toEqual(["control", "record"]);
    }
  });

  it("with several flags at once the order is kill, suspension, stop, deletion", async () => {
    const h = harness();
    h.state.control = { killed: true, suspended: true, stopRequested: true, deletionPending: true };
    expect(refusal(await h.gate.request({ method: "GET", path: "/" }))).toBe("operator_kill");
  });

  it("refuses a malformed probe: host, scheme, port, body, headers and cookies are not expressible", async () => {
    const probes: unknown[] = [
      null,
      undefined,
      "GET /",
      42,
      [],
      {},
      { method: "GET" },
      { path: "/" },
      { method: 1, path: "/" },
      { method: "GET", path: 7 },
      { method: "GET", path: "/", query: "a=b" },
      { method: "GET", path: "/", query: null },
      { method: "GET", path: "/", host: "evil.example.net" },
      { method: "GET", path: "/", url: "https://evil.example.net/" },
      { method: "GET", path: "/", port: 8443 },
      { method: "GET", path: "/", scheme: "http" },
      { method: "GET", path: "/", body: "x" },
      { method: "GET", path: "/", headers: { cookie: "a=b" } },
      { method: "GET", path: "/", cookies: "a=b" },
    ];
    // Fourth review (D-110): a probe that is not one of the engine's catalog ends the Campaign, so each is asked of
    // a gate of its own.
    for (const probe of probes) {
      const h = harness();
      expect({ probe, refused: refusal(await h.gate.request(probe)) }).toEqual({ probe, refused: "malformed_probe" });
      expect(h.sent).toEqual([]);
      expect(h.authorized).toEqual([]);
      expect(h.ends).toEqual(["malformed_probe"]);
      expect(h.records.every((r) => r.outcome === "refused" && r.reason === "malformed_probe")).toBe(true);
      expect(h.records.every((r) => r.target === null)).toBe(true);
    }
  });

  it("refuses every method but GET and HEAD", async () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "get", "Get", "GET ", ""]) {
      const h = harness();
      // The path is wrong too: the method check comes first.
      const exchange = await h.gate.request({ method, path: "//x" });
      expect({ method, refused: refusal(exchange) }).toEqual({ method, refused: "method_not_allowed" });
      expect(h.sent).toEqual([]);
      expect(h.authorized).toEqual([]);
      // Fourth review (D-110): it ends the Campaign, and the row holds a fixed label, not the engine's word.
      expect(h.ends).toEqual(["method_not_allowed"]);
      expect(h.records).toMatchObject([{ method: "OTHER", target: null }]);
    }
  });

  it("refuses a path or a query that is not canonical, before authorize is asked", async () => {
    const fresh = () => {
      const h = harness();
      h.state.authorize = { allowed: false, reason: "out_of_scope" };
      return h;
    };
    for (const path of [
      "https://evil.example.net/",
      "//evil.example.net/",
      "/a/../admin",
      "/a%2fb",
      "/a?b",
      "/\\x",
      "",
    ]) {
      const h = fresh();
      expect({ path, refused: refusal(await h.gate.request({ method: "GET", path })) }).toEqual({
        path,
        refused: "path_not_canonical",
      });
      expect(h.authorized).toEqual([]);
      expect(h.sent).toEqual([]);
    }
    for (const query of [{ "x y": "1" }, { x: "a\nb" }]) {
      const h = fresh();
      expect(refusal(await h.gate.request({ method: "GET", path: "/a", query }))).toBe("query_not_canonical");
      expect(h.authorized).toEqual([]);
      expect(h.sent).toEqual([]);
    }
  });

  it("refuses with authorize's reason; only an excluded path lets the Campaign go on", async () => {
    for (const reason of AUTHORIZE_REASONS) {
      const h = harness();
      h.state.authorize = { allowed: false, reason };
      const fatal = reason !== "path_excluded";
      expect(await h.gate.request({ method: "GET", path: "/admin" })).toEqual({ ok: false, refused: reason, fatal });
      expect(h.sent).toEqual([]);
      expect(h.ends).toEqual(fatal ? [reason] : []);
      expect((FATAL_CAMPAIGN_REFUSALS as readonly string[]).includes(reason)).toBe(fatal);
    }
  });

  it("refuses once the Rules of Engagement are not the ones bound at creation", async () => {
    const h = harness();
    h.state.authorize = { allowed: true, roe_id: "roe_ffffffffffffffffffffffff" };
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({
      ok: false,
      refused: "rules_replaced",
      fatal: true,
    });
    expect(h.sent).toEqual([]);
    expect(h.ends).toEqual(["rules_replaced"]);
  });

  it("ends the Campaign at 20 refusals; after the end nothing is checked, sent or logged", async () => {
    // Fourth review (D-110): a probe outside the catalog ends the Campaign at once. The 20 are for refusals that
    // let it go on: a catalog probe whose path the Rules exclude.
    const h = harness();
    h.state.authorize = { allowed: false, reason: "path_excluded" };
    for (let n = 1; n <= 19; n++) {
      expect(await h.gate.request({ method: "GET", path: "/admin" })).toEqual({
        ok: false,
        refused: "path_excluded",
        fatal: false,
      });
    }
    expect(h.ends).toEqual([]);
    expect(await h.gate.request({ method: "GET", path: "/admin" })).toEqual({
      ok: false,
      refused: "path_excluded",
      fatal: true,
    });
    expect(h.ends).toEqual(["refusal_limit"]);
    expect(h.gate.ended()).toBe("refusal_limit");
    expect(h.records).toHaveLength(20);
    const before = h.order.length;
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({
      ok: false,
      refused: "campaign_ended",
      fatal: true,
    });
    expect(h.order).toHaveLength(before);
    expect(h.records).toHaveLength(20);
    expect(h.sent).toEqual([]);
    expect(h.gate.counters()).toEqual({ sent: 0, refused: 20, bytes: 0 });
  });

  // Fourth review (D-110): this row used to hold the first 256 characters of what was asked. It holds none of it now.
  it("logs of a refused probe how much it asked for, and nothing of what", async () => {
    const h = harness();
    await h.gate.request({ method: "GET", path: `/${"a".repeat(5000)}\r\nX: y` });
    expect(h.records).toMatchObject([{ method: "GET", target: null, asked: 5007, reason: "path_not_canonical" }]);
    const other = harness();
    await other.gate.request({ method: "DELETE\r\n", path: "/x" });
    expect(other.records).toMatchObject([{ method: "OTHER", target: null, asked: 2 }]);
  });
});

describe("budgets", () => {
  it("sends at most 60 requests; the budget is charged before the call", async () => {
    const h = harness({
      respond: (_send, n) => {
        // Seen from inside the transport: this request is already counted.
        expect(h.gate.counters().sent).toBe(n);
        return ok();
      },
    });
    h.state.transportMs = 0;
    for (let n = 1; n <= CAMPAIGN_LIMITS.requestsMax; n++) {
      expect((await h.gate.request({ method: "GET", path: "/" })).ok).toBe(true);
    }
    // 59 waits of one second: inside the time budget.
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({
      ok: false,
      refused: "request_budget",
      fatal: true,
    });
    expect(h.sent).toHaveLength(60);
    expect(h.ends).toEqual(["request_budget"]);
  });

  it("counts a request whose transport fails or throws", async () => {
    const h = harness({
      respond: (_send, n) => {
        if (n === 1) throw new Error("boom");
        return { ok: false, reason: "connect_failed" };
      },
    });
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({ ok: false, seq: 1, error: "connect_failed" });
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({ ok: false, seq: 2, error: "connect_failed" });
    expect(h.gate.counters().sent).toBe(2);
    expect(h.records.map((r) => [r.outcome, r.failure])).toEqual([
      ["sent", "connect_failed"],
      ["sent", "connect_failed"],
    ]);
  });

  it("does not start a request whose deadline would cross the 300th second", async () => {
    const h = harness();
    h.state.transportMs = 0;
    const start = h.state.clock;
    const wall = CAMPAIGN_LIMITS.wallTimeS * 1000;
    expect((await h.gate.request({ method: "GET", path: "/" })).ok).toBe(true);
    // A request started now may take 5 s: it ends at the 300th second exactly, which is still inside.
    h.state.clock = start + wall - CAMPAIGN_LIMITS.requestTimeoutMs;
    expect((await h.gate.request({ method: "GET", path: "/" })).ok).toBe(true);
    // The next one would wait a second and could then run past the end: refused now, without waiting.
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({
      ok: false,
      refused: "time_budget",
      fatal: true,
    });
    expect(h.sleeps).toEqual([]);
    expect(h.sent).toHaveLength(2);

    const late = harness();
    late.state.clock += wall - CAMPAIGN_LIMITS.requestTimeoutMs + 1;
    expect(refusal(await late.gate.request({ method: "GET", path: "/" }))).toBe("time_budget");
    expect(late.sent).toEqual([]);
  });

  it("does not start a request whose deadline would cross the end of the window", async () => {
    const asked: [string, number][] = [];
    let holds = true;
    const h = harness({
      extra: {
        async windowHolds(path, aheadMs) {
          asked.push([path, aheadMs]);
          return holds;
        },
      },
    });
    h.state.transportMs = 100;
    expect((await h.gate.request({ method: "GET", path: "/a" })).ok).toBe(true);
    expect((await h.gate.request({ method: "GET", path: "/b" })).ok).toBe(true);
    // Asked for the time the request may still be running at: the spacing wait and the request's deadline ahead.
    expect(asked).toEqual([
      ["/a", CAMPAIGN_LIMITS.requestTimeoutMs],
      ["/b", 900 + CAMPAIGN_LIMITS.requestTimeoutMs],
    ]);
    holds = false;
    expect(await h.gate.request({ method: "GET", path: "/c" })).toEqual({
      ok: false,
      refused: "outside_window",
      fatal: true,
    });
    expect(h.sent).toHaveLength(2);
    expect(h.ends).toEqual(["outside_window"]);
  });

  it("reads at most 2 MB in all: a request is not started without room for its headers, its TLS share and a late read", async () => {
    const big = "x".repeat(CAMPAIGN_LIMITS.responseReadBytesMax);
    const h = harness({ respond: (send) => ok(200, big.slice(0, send.bodyBytesMax)) });
    h.state.transportMs = 0;
    let exchange = await h.gate.request({ method: "GET", path: "/" });
    while (exchange.ok) exchange = await h.gate.request({ method: "GET", path: "/" });
    expect(exchange).toEqual({ ok: false, refused: "byte_budget", fatal: true });
    // Third review, F1: the reserve also holds the framing allowance of a request (64 KB). Fourth review, R7: and
    // one TCP read of overshoot (64 KB) instead of two — 160 KB in all. 29 full reads; for the 30th, 192 KB are
    // left, of which 160 KB are kept back.
    expect(h.sent.map((s) => s.bodyBytesMax)).toEqual([
      ...Array(29).fill(CAMPAIGN_LIMITS.responseReadBytesMax),
      32_768,
    ]);
    expect(h.gate.counters().bytes).toBe(CAMPAIGN_LIMITS.responseBytesMax - 163_840);
  });

  it("review2 L5: counts what the connection read — the handshake, 1xx responses and failed responses too", async () => {
    const answers: PinnedResponse[] = [
      { ...ok(200, "y".repeat(100)), headerBytes: 300, bytesRead: 3400 } as PinnedResponse,
      { ok: false, reason: "timeout", bytesRead: 72_000 },
      { ok: false, reason: "invalid_response", bytesRead: 40_000 },
      { ok: false, reason: "connect_failed", bytesRead: 0 },
    ];
    const h = harness({ respond: (_send, n) => answers[n - 1] as PinnedResponse });
    for (let n = 0; n < 4; n++) await h.gate.request({ method: "GET", path: "/" });
    expect(h.gate.counters().bytes).toBe(3400 + 72_000 + 40_000);
    expect(h.records.map((row) => [row.failure, row.bytes])).toEqual([
      [null, 3400],
      ["timeout", 72_000],
      ["invalid_response", 40_000],
      ["connect_failed", 0],
    ]);
  });
});

describe("the request log (review M2)", () => {
  it("writes the row before the request goes out, and settles it afterwards", async () => {
    const h = harness({
      respond: (_send, n) => {
        // Seen from inside the transport: the row is there already.
        expect(h.records.at(-1)).toMatchObject({ seq: n, outcome: "sending", status: null, failure: null, bytes: 0 });
        return ok(204, "");
      },
    });
    await h.gate.request({ method: "GET", path: "/" });
    await h.gate.request({ method: "HEAD", path: "/x" });
    expect(h.records.map((row) => [row.seq, row.method, row.target, row.outcome, row.status])).toEqual([
      [1, "GET", "/", "sent", 204],
      [2, "HEAD", "/x", "sent", 204],
    ]);
  });

  it("review2 L7: a request that never left is logged as not sent, and is not counted as sent", async () => {
    const controller = new AbortController();
    const h = harness({ extra: { signal: controller.signal } });
    const record = h.deps().record;
    h.deps().record = async (entry) => {
      await record(entry);
      // The owner's stop lands while the row is being written.
      controller.abort("owner_stop");
    };
    const gate = createGate(h.deps());
    await gate.request({ method: "GET", path: "/never" });
    expect(h.sent).toHaveLength(0);
    expect(gate.counters().sent).toBe(0);
    expect(h.records).toMatchObject([{ seq: 1, target: "/never", outcome: "not_sent", status: null, failure: null }]);
    expect(gate.ended()).toBe("owner_stop");
  });

  it("review2 M3: tells the engine when a body was withheld as not text", async () => {
    const h = harness({ respond: (_send, n) => ok(200, n === 1 ? 'a\u0000{"reports":[]}' : '{"reports":[]}') });
    expect(await h.gate.request({ method: "GET", path: "/" })).toMatchObject({
      ok: true,
      withheld: true,
      body: "[binary or non-UTF-8 body withheld]",
    });
    expect(await h.gate.request({ method: "GET", path: "/" })).toMatchObject({ ok: true, withheld: false });
  });

  it("sends nothing when the row cannot be written, and ends the Campaign", async () => {
    const h = harness({
      extra: {
        async record() {
          throw new Error("could not extend file");
        },
      },
    });
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({
      ok: false,
      refused: "campaign_ended",
      fatal: true,
    });
    expect(h.sent).toEqual([]);
    expect(h.ends).toEqual(["engine_error"]);
  });

  it("a result that cannot be recorded leaves the row as sending: the request is never missing from the log", async () => {
    const h = harness({
      extra: {
        async settle() {
          throw new Error("could not extend file");
        },
      },
    });
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({
      ok: false,
      refused: "campaign_ended",
      fatal: true,
    });
    expect(h.sent).toHaveLength(1);
    expect(h.records).toMatchObject([{ seq: 1, outcome: "sending", target: "/" }]);
    expect(h.gate.counters().sent).toBe(1);
    expect(h.ends).toEqual(["engine_error"]);
    expect(refusal(await h.gate.request({ method: "GET", path: "/" }))).toBe("campaign_ended");
    expect(h.sent).toHaveLength(1);
  });

  it("treats a status outside 100 to 599 as a failed request: the engine is not handed the response", async () => {
    for (const status of [999, 0, 99, 600, 1.5, Number.NaN]) {
      const h = harness({ respond: () => ok(status, "odd jane@acme-shop.io") });
      expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({
        ok: false,
        seq: 1,
        error: "invalid_response",
      });
      expect(h.records).toMatchObject([{ outcome: "sent", status: null, failure: "invalid_response", bytes: 0 }]);
      expect(h.gate.evidence(1, "")).toBeNull();
    }
    const refusedByTransport = harness({ respond: () => ({ ok: false, reason: "invalid_response" }) });
    expect(await refusedByTransport.gate.request({ method: "GET", path: "/" })).toMatchObject({
      error: "invalid_response",
    });
  });

  it("refuses a request target over 1,024 characters before authorize is asked", async () => {
    const h = harness();
    const long = "x".repeat(512);
    expect(await h.gate.request({ method: "GET", path: "/", query: { a: long, b: long, c: long } })).toEqual({
      ok: false,
      refused: "query_not_canonical",
      fatal: true,
    });
    expect(h.sent).toEqual([]);
    expect(h.authorized).toEqual([]);
    // A target within the bound, declared by the catalog, is sent (on a gate of its own: the refusal above ended
    // the first, fourth review).
    const within = harness({ extra: { catalog: [{ method: "GET", path: "/", query: { a: { exact: long } } }] } });
    expect((await within.gate.request({ method: "GET", path: "/", query: { a: long } })).ok).toBe(true);
    expect(within.sent[0]?.target).toHaveLength(516);
  });
});

describe("the ownership check goes through the gate (review M1, L3)", () => {
  it("is the first row of the log, counts in the 60 requests and in the spacing, and hands back the file's body", async () => {
    const h = harness({ respond: (send) => ok(200, send.target === "/" ? "home" : "the-token\n") });
    h.state.transportMs = 100;
    expect(await h.gate.ownership()).toEqual({ ok: true, body: "the-token\n" });
    expect(h.sent[0]).toMatchObject({
      method: "GET",
      target: "/.well-known/airverse-verification.txt",
      bodyBytesMax: 1024,
      headers: { "user-agent": "Airverse-Campaign/1", "x-airverse-campaign": CAMPAIGN, accept: "text/plain" },
    });
    // Third review, F4: judged like any other request — the switches (as the start checks read them: the Campaign
    // is not running yet) and the authorization, and both once more right before it leaves.
    expect(h.authorized).toEqual([
      { host: HOST, path: "/.well-known/airverse-verification.txt", intensity: "safe-active" },
      { host: HOST, path: "/.well-known/airverse-verification.txt", intensity: "safe-active" },
    ]);
    expect(h.order).toEqual(["control", "authorize", "record", "authorize", "control", "transport"]);
    expect(h.records).toMatchObject([
      { seq: 1, method: "GET", target: "/.well-known/airverse-verification.txt", outcome: "sent", status: 200 },
    ]);
    // The first probe waits for the spacing after it.
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.sleeps).toEqual([900]);
    h.state.transportMs = 0;
    let exchange = await h.gate.request({ method: "GET", path: "/" });
    while (exchange.ok) exchange = await h.gate.request({ method: "GET", path: "/" });
    expect(exchange).toMatchObject({ refused: "request_budget" });
    // 60 in all reached the target: the ownership check and 59 probes.
    expect(h.sent).toHaveLength(CAMPAIGN_LIMITS.requestsMax);
    expect(h.gate.counters().sent).toBe(CAMPAIGN_LIMITS.requestsMax);
  });

  it("is refused unsent when the Rules of Engagement exclude the verification path, or no longer allow the test", async () => {
    const excluded = harness();
    excluded.state.authorize = { allowed: false, reason: "path_excluded" };
    expect(await excluded.gate.ownership()).toEqual({ ok: false, reason: "verification_path_excluded", sent: false });
    const lapsed = harness();
    lapsed.state.authorize = { allowed: false, reason: "target_not_verified" };
    expect(await lapsed.gate.ownership()).toEqual({ ok: false, reason: "target_not_verified", sent: false });
    const replaced = harness();
    replaced.state.authorize = { allowed: true, roe_id: "roe_ffffffffffffffffffffffff" };
    expect(await replaced.gate.ownership()).toEqual({ ok: false, reason: "rules_replaced", sent: false });
    for (const h of [excluded, lapsed, replaced]) {
      expect(h.sent).toEqual([]);
      expect(h.records).toEqual([]);
      // The runner writes the refusal: the gate does not end a Campaign that has not started.
      expect(h.ends).toEqual([]);
    }
  });

  it("answers target_not_verified, sent, for anything but a whole 200", async () => {
    const answers: PinnedResponse[] = [
      ok(404, "no"),
      ok(302, "", { location: "https://elsewhere.acme-shop.io/" }),
      { ...ok(200, "x".repeat(1024)), truncated: true } as PinnedResponse,
      { ok: false, reason: "timeout" },
      { ok: false, reason: "tls_failed" },
      { ok: false, reason: "invalid_response" },
    ];
    for (const answer of answers) {
      const h = harness({ respond: () => answer });
      expect(await h.gate.ownership()).toEqual({ ok: false, reason: "target_not_verified", sent: true });
      expect(h.records).toHaveLength(1);
      expect(h.records[0]?.outcome).toBe("sent");
    }
  });

  it("waits for the host's last request, whichever Campaign made it, and tells when it sends", async () => {
    const sends: number[] = [];
    const base = Date.parse("2026-11-16T10:00:00.000Z");
    const h = harness({ extra: { previousSendAt: base - 400, onSend: (at) => void sends.push(at) } });
    expect((await h.gate.ownership()).ok).toBe(true);
    expect(h.sleeps).toEqual([600]);
    expect(sends).toEqual([base + 600]);
    await h.gate.request({ method: "GET", path: "/" });
    expect(sends).toHaveLength(2);
  });

  it("goes on from what an earlier process logged and sent: one log and one budget per Campaign", async () => {
    const h = harness({ extra: { already: { seq: 7, sent: 58, refused: 2, bytes: 1000 } } });
    h.state.transportMs = 0;
    expect((await h.gate.ownership()).ok).toBe(true);
    expect(h.records[0]).toMatchObject({ seq: 8, outcome: "sent" });
    expect((await h.gate.request({ method: "GET", path: "/" })).ok).toBe(true);
    expect(refusal(await h.gate.request({ method: "GET", path: "/" }))).toBe("request_budget");
    expect(h.gate.counters()).toMatchObject({ sent: 60, refused: 3 });
    expect(h.sent).toHaveLength(2);
  });

  it("sends nothing after a stop during the start checks", async () => {
    const h = harness();
    h.controller.abort("api_shutdown");
    expect(await h.gate.ownership()).toEqual({ ok: false, reason: "api_shutdown", sent: false });
    expect(h.sent).toEqual([]);
  });
});

describe("spacing", () => {
  it("starts requests at least one second apart, by the injected clock", async () => {
    const h = harness();
    h.state.transportMs = 300;
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.sleeps).toEqual([]);
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.sleeps).toEqual([700]);
    h.state.clock += 1500;
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.sleeps).toEqual([700]);
    // A refused probe does not move the spacing (one the Campaign survives: a path the Rules exclude).
    h.state.authorize = { allowed: false, reason: "path_excluded" };
    await h.gate.request({ method: "GET", path: "/admin" });
    h.state.authorize = ALLOWED;
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.sleeps).toEqual([700, 700]);
  });

  it("refuses a second request while one is in flight", async () => {
    let release: (response: PinnedResponse) => void = () => {};
    const h = harness({ respond: () => new Promise<PinnedResponse>((resolve) => (release = resolve)) });
    const first = h.gate.request({ method: "GET", path: "/" });
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(await h.gate.request({ method: "GET", path: "/b" })).toEqual({
      ok: false,
      refused: "concurrent_request",
      fatal: false,
    });
    release(ok());
    expect((await first).ok).toBe(true);
    expect(h.sent).toHaveLength(1);
  });
});

describe("target health", () => {
  it("ends after five failures in a row; a response in between starts the count again", async () => {
    const outcomes: PinnedResponse[] = [
      { ok: false, reason: "timeout" },
      { ok: false, reason: "connect_failed" },
      ok(500),
      { ok: false, reason: "tls_failed" },
      ok(200),
      { ok: false, reason: "timeout" },
      ok(502),
      { ok: false, reason: "address_mismatch" },
      ok(500),
      { ok: false, reason: "timeout" },
    ];
    const h = harness({ respond: (_send, n) => outcomes[n - 1] as PinnedResponse });
    for (let n = 0; n < 9; n++) await h.gate.request({ method: "GET", path: "/" });
    expect(h.ends).toEqual([]);
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.ends).toEqual(["target_unhealthy"]);
    // A pin mismatch reaches the engine and the log as a connection failure.
    expect(h.records[7]).toMatchObject({ outcome: "sent", failure: "connect_failed", status: null });
    expect(refusal(await h.gate.request({ method: "GET", path: "/" }))).toBe("campaign_ended");
  });

  it("ends on a 429, and on a 503 with Retry-After; a bare 503 is one failure", async () => {
    const limited = harness({ respond: () => ok(429) });
    await limited.gate.request({ method: "GET", path: "/" });
    expect(limited.ends).toEqual(["target_rate_limited"]);

    const busy = harness({ respond: (_s, n) => (n === 1 ? ok(503) : ok(503, "", { "retry-after": "120" })) });
    await busy.gate.request({ method: "GET", path: "/" });
    expect(busy.ends).toEqual([]);
    await busy.gate.request({ method: "GET", path: "/" });
    expect(busy.ends).toEqual(["target_unavailable"]);
  });
});

describe("a stop in flight", () => {
  it("aborts the request's signal, logs it as aborted and ends the Campaign as stopped", async () => {
    const h = harness({
      respond: (send) =>
        new Promise<PinnedResponse>((resolve) => {
          send.signal.addEventListener("abort", () => resolve({ ok: false, reason: "timeout" }), { once: true });
        }),
    });
    const pending = h.gate.request({ method: "GET", path: "/" });
    await new Promise((resolve) => setTimeout(resolve, 5));
    h.controller.abort();
    expect(await pending).toEqual({ ok: false, seq: 1, error: "aborted" });
    expect(h.records).toMatchObject([{ outcome: "sent", failure: "aborted" }]);
    expect(h.gate.ended()).toBe("owner_stop");
    expect(refusal(await h.gate.request({ method: "GET", path: "/" }))).toBe("campaign_ended");
    expect(h.sent).toHaveLength(1);
  });

  it("gives each request its own five-second deadline", async () => {
    const h = harness({
      respond: (send) =>
        new Promise<PinnedResponse>((resolve) => {
          send.signal.addEventListener("abort", () => resolve({ ok: false, reason: "timeout" }), { once: true });
        }),
    });
    const gate = createGate({ ...h.deps(), limits: { requestTimeoutMs: 30 } });
    expect(await gate.request({ method: "GET", path: "/" })).toEqual({ ok: false, seq: 1, error: "timeout" });
    expect(gate.ended()).toBeNull();
  });
});

describe("evidence", () => {
  // Third review (D-107): the evidence is a window of at most 200 characters that the check cut around its match —
  // no longer 2 KB of the body around a position, and no hash of the body.
  it("comes from what the gate holds: request, status, allowlisted headers and the evidence window", async () => {
    const body = `${"a".repeat(3000)} Error: boom\n    at handler (/srv/app.js:1:1) mail jane@acme-shop.io`;
    const h = harness({ respond: () => ok(500, body, { "content-type": "text/plain", "x-other": "no" }) });
    const exchange = await h.gate.request({ method: "GET", path: "/api/orders/x" });
    const seen = exchange.ok ? exchange.body : "";
    const evidence = h.gate.evidence(1, seen.slice(seen.indexOf("Error: boom"), seen.indexOf("Error: boom") + 200));
    expect(evidence).toMatchObject({
      method: "GET",
      target: "/api/orders/x",
      status: 500,
      headers: { "content-type": "text/plain" },
      truncated: false,
      location: null,
    });
    expect(evidence).not.toHaveProperty("body_sha256");
    expect(evidence?.excerpt.length).toBeLessThanOrEqual(CAMPAIGN_LIMITS.evidenceWindowMax);
    expect(evidence?.excerpt).toContain("Error: boom");
    expect(evidence?.excerpt).not.toContain("jane@");
    expect(h.gate.evidence(2, "")).toBeNull();
    expect(h.gate.evidence(Number.NaN, "")).toBeNull();
  });
});

describe("arbitrary engine output (property)", () => {
  // A small deterministic generator: the same probes on every run.
  function generator(seed: number) {
    let s = seed >>> 0;
    const next = () => {
      s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
      return s / 2 ** 32;
    };
    const pick = <T>(values: readonly T[]): T => values[Math.floor(next() * values.length)] as T;
    const PIECES = [
      "/",
      "//",
      "/a",
      "/admin",
      "..",
      ".",
      "%2e%2e",
      "%2f",
      "\\",
      "?",
      "#",
      ";",
      ":",
      "@",
      " ",
      "\r\n",
      "\u0000",
      "https://evil.example.net",
      "evil.example.net",
      "169.254.169.254",
      "localhost",
      "é",
      "x".repeat(40),
      "~",
      "-",
      "_",
      "a.b",
      "api",
      "orders",
      "1001",
      "search",
    ];
    const text = () => Array.from({ length: Math.floor(next() * 6) }, () => pick(PIECES)).join("");
    const METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "get", "", "CONNECT", 7, null];
    const value = (): unknown =>
      pick<() => unknown>([
        text,
        () => next() * 100,
        () => null,
        () => ({ [text()]: text() }),
        () => [text()],
        () => true,
      ])();
    const probe = (): unknown => {
      const kind = next();
      if (kind < 0.05) return value();
      // Often enough a probe that may pass, so that the budgets are exercised too.
      if (kind < 0.45) {
        const path = `/${Array.from({ length: Math.floor(next() * 3) }, () => pick(["api", "orders", "1001", "a.b", "~"])).join("/")}`;
        return next() < 0.3
          ? { method: pick(["GET", "HEAD"]), path, query: { [pick(["q", "to"])]: text() } }
          : { method: pick(["GET", "HEAD"]), path };
      }
      const out: Record<string, unknown> = { method: pick(METHODS), path: next() < 0.5 ? `/${text()}` : text() };
      if (next() < 0.4) out.query = next() < 0.7 ? { [pick(["q", "to", "a b", "x"])]: value() } : value();
      if (next() < 0.25) out[pick(["host", "url", "body", "headers", "cookies", "port", "scheme", "auth"])] = value();
      return out;
    };
    return { probe };
  }

  it("whatever an engine asks, the transport only ever sees a canonical GET or HEAD inside the budgets", async () => {
    const TARGET = /^\/[A-Za-z0-9\-._~/]*(?:\?[A-Za-z0-9_.\-~%=&]*)?$/;
    let sentInAll = 0;
    for (let round = 0; round < 60; round++) {
      const h = harness();
      h.state.transportMs = 0;
      const { probe } = generator(round + 1);
      for (let n = 0; n < 80; n++) await h.gate.request(probe());
      expect(h.sent.length).toBeLessThanOrEqual(CAMPAIGN_LIMITS.requestsMax);
      expect(h.gate.counters().refused).toBeLessThanOrEqual(CAMPAIGN_LIMITS.refusalsMax);
      for (const send of h.sent) {
        expect(["GET", "HEAD"]).toContain(send.method);
        expect(send.target).toMatch(TARGET);
        expect(send.target.startsWith("//")).toBe(false);
        const path = send.target.split("?")[0] as string;
        expect(path.split("/")).not.toContain("..");
        expect(path.split("/")).not.toContain(".");
        expect(Object.keys(send.headers).sort()).toEqual(["accept", "user-agent", "x-airverse-campaign"]);
        expect(send.bodyBytesMax).toBeLessThanOrEqual(CAMPAIGN_LIMITS.responseReadBytesMax);
      }
      // Every authorised path is exactly the path that was sent, in order.
      const sentPaths = h.sent.map((send) => send.target.split("?")[0]);
      expect(h.authorized.map((a) => a.path).filter((path) => sentPaths.includes(path)).length).toBeGreaterThanOrEqual(
        sentPaths.length,
      );
      for (const record of h.records) expect(record.target === null || record.target.length <= 1024).toBe(true);
      // Fourth review (D-110): only probes of the catalog are sent; a refused row holds no text unless it is the
      // catalog's; and the first probe outside the catalog ended the Campaign.
      for (const send of h.sent) expect(send.target).toBe("/");
      for (const record of h.records) expect(record.target === null || record.target === "/").toBe(true);
      expect(h.gate.counters().refused).toBeLessThanOrEqual(1);
      sentInAll += h.sent.length;
    }
    // The generator does produce sendable probes: the property is not vacuous. (Far fewer than before the catalog:
    // the first probe outside it ends a Campaign.)
    expect(sentInAll).toBeGreaterThan(5);
  });
});
