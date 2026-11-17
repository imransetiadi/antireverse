import {
  type AuthorizeResult,
  CAMPAIGN_LIMITS,
  type CampaignCatalogProbe,
  type CampaignEndReason,
  type CampaignExchange,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createGate, type GateControl, type GateDeps, type GateRecord, type GateSend } from "../src/campaign/gate.ts";
import { BODY_WITHHELD } from "../src/campaign/redact.ts";
import type { PinnedResponse } from "../src/prove/verify.ts";

// Slice 15a, third independent safety review: the request gate, alone, every dependency a stand-in. A connection over
// its read cap (F1), bodies that cannot be read as UTF-8 text (F3), the switches and the authorization read again
// right before a request leaves — the ownership request included (F4) — and the evidence window (F5, D-107).

const HOST = "shop.acme-shop.io";
const ROE = "roe_0123456789abcdef01234567";
const CAMPAIGN = "cmp_0123456789abcdef01234567";
const ALLOWED: AuthorizeResult = { allowed: true, roe_id: ROE };
const RUNNING: GateControl = { killed: false, suspended: false, stopRequested: false, deletionPending: false };

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

const ok = (
  status = 200,
  body: string | Uint8Array = "ok",
  headers: Record<string, string | string[]> = {},
  truncated = false,
): PinnedResponse => ({
  ok: true,
  status,
  headers,
  headerBytes: 0,
  body: Buffer.from(body),
  truncated,
  remoteAddress: "203.0.113.10",
  bytesRead: Buffer.byteLength(body),
});

function harness(
  options: {
    respond?: (send: GateSend, n: number) => PinnedResponse | Promise<PinnedResponse>;
    extra?: Partial<GateDeps>;
    previousSendAt?: number;
  } = {},
) {
  const state = {
    clock: 1_000_000,
    control: { ...RUNNING } as GateControl,
    authorize: ALLOWED as AuthorizeResult,
    /** Runs while the gate waits for the spacing. */
    duringSleep: null as null | (() => void),
    /** Runs while the `sending` row is being written. */
    duringRecord: null as null | (() => void),
    settleFails: 0,
    refuseNotSent: false,
  };
  const sent: GateSend[] = [];
  const records: GateRecord[] = [];
  const ends: CampaignEndReason[] = [];
  const order: string[] = [];
  const phases: string[] = [];
  const controller = new AbortController();
  const deps: GateDeps = {
    campaign: { id: CAMPAIGN, host: HOST, roeId: ROE, intensity: "safe-active" },
    catalog: CATALOG,
    async control(phase) {
      order.push("control");
      phases.push(phase);
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
      return (options.respond ?? (() => ok()))(send, sent.length);
    },
    async record(entry) {
      order.push("record");
      records.push({ ...entry });
      if (entry.outcome === "sending") state.duringRecord?.();
    },
    async settle(entry) {
      if (state.settleFails > 0) {
        state.settleFails--;
        throw new Error("the log is not writable");
      }
      if (entry.outcome === "not_sent" && state.refuseNotSent) throw new Error("the Campaign has ended");
      const index = records.findIndex((row) => row.seq === entry.seq);
      if (records[index]?.outcome !== "sending") throw new Error("settled a row that is not sending");
      records[index] = { ...entry };
    },
    now: () => state.clock,
    async sleep(ms) {
      order.push("sleep");
      state.clock += ms;
      state.duringSleep?.();
    },
    signal: controller.signal,
    onEnd: (reason) => {
      ends.push(reason);
    },
    previousSendAt: options.previousSendAt,
    ...options.extra,
  };
  return { gate: createGate(deps), state, sent, records, ends, order, phases, controller };
}

const refusal = (exchange: CampaignExchange) => ("refused" in exchange ? exchange.refused : null);
const answered = (exchange: CampaignExchange) => {
  if (!exchange.ok) throw new Error("expected an answer");
  return exchange;
};

describe("review3 F1: a connection over its read cap", () => {
  it("is logged with what it really read, and ends the Campaign on its byte budget", async () => {
    // The review's number: about 1 GB read for one request.
    const h = harness({ respond: () => ({ ok: false, reason: "read_limit", bytesRead: 1_050_624_947 }) });
    expect(await h.gate.request({ method: "GET", path: "/" })).toEqual({ ok: false, seq: 1, error: "read_limit" });
    expect(h.records).toMatchObject([{ seq: 1, outcome: "sent", failure: "read_limit", bytes: 1_050_624_947 }]);
    expect(h.gate.counters().bytes).toBe(1_050_624_947);
    expect(h.ends).toEqual(["byte_budget"]);
    expect(await h.gate.request({ method: "GET", path: "/next" })).toMatchObject({ refused: "campaign_ended" });
    expect(h.sent).toHaveLength(1);
  });

  it("refuses the Campaign on its byte budget when it is the ownership request", async () => {
    const h = harness({ respond: () => ({ ok: false, reason: "read_limit", bytesRead: 400_000 }) });
    expect(await h.gate.ownership()).toEqual({ ok: false, reason: "byte_budget", sent: true });
    expect(h.records).toMatchObject([{ outcome: "sent", failure: "read_limit", bytes: 400_000 }]);
  });

  it("keeps room for a whole request's reads: no request starts that could carry the count past 2 MB", async () => {
    // Each answer reads 150,000 bytes. A request may read up to 16 KB of headers, its body cap, 16 KB of TLS, 64 KB of
    // framing and one late socket read (64 KB): none starts without that room.
    const h = harness({ respond: () => ({ ...ok(), bytesRead: 150_000 }) });
    let exchanges = 0;
    for (;;) {
      const exchange = await h.gate.request({ method: "GET", path: "/" });
      if (!exchange.ok) {
        expect(refusal(exchange)).toBe("byte_budget");
        break;
      }
      exchanges++;
    }
    const room = CAMPAIGN_LIMITS.responseBytesMax - h.gate.counters().bytes;
    expect(room).toBeGreaterThan(0);
    // Fourth review, R7: one late read (64 KB), not two — the transport counts raw reads.
    expect(room).toBeLessThanOrEqual(16_384 + 16_384 + 65_536 + 65_536);
    expect(exchanges).toBe(h.sent.length);
    expect(h.sent.at(-1)?.bodyBytesMax).toBeLessThanOrEqual(CAMPAIGN_LIMITS.responseReadBytesMax);
    expect(h.sent.every((send) => send.bodyBytesMax > 0)).toBe(true);
  });
});

describe("review3 F3: a body that cannot be read as UTF-8 text is withheld", () => {
  const TEXT = '{"reports":[{"id":1}]}';
  const withheld = async (body: string | Uint8Array, headers: Record<string, string>, truncated = false) => {
    const h = harness({ respond: () => ok(200, body, headers, truncated) });
    const exchange = answered(await h.gate.request({ method: "GET", path: "/api/admin/reports" }));
    return { withheld: exchange.withheld, body: exchange.body };
  };

  it("withholds a body with a content-encoding, though it holds no NUL (the review's `br` body)", async () => {
    for (const encoding of ["br", "gzip", "deflate", "zstd", "identity, br", "x-unknown", ""]) {
      expect(await withheld(TEXT, { "content-encoding": encoding }), encoding).toEqual({
        withheld: true,
        body: BODY_WITHHELD,
      });
    }
  });

  it("reads a body whose content-encoding is identity, or absent", async () => {
    for (const headers of [{}, { "content-encoding": "identity" }, { "content-encoding": " Identity " }]) {
      expect(await withheld(TEXT, headers)).toEqual({ withheld: false, body: TEXT });
    }
  });

  it("withholds bytes that are not valid UTF-8 (the review's bytes OR-ed with 0x80)", async () => {
    const high = Uint8Array.from(Buffer.from(TEXT), (byte) => byte | 0x80);
    expect(await withheld(high, { "content-type": "text/plain; charset=ibm037" })).toEqual({
      withheld: true,
      body: BODY_WITHHELD,
    });
    expect(await withheld(high, {})).toEqual({ withheld: true, body: BODY_WITHHELD });
    expect(await withheld(Uint8Array.from([0x7b, 0xc3, 0x28, 0x7d]), {})).toEqual({
      withheld: true,
      body: BODY_WITHHELD,
    });
  });

  it("withholds a body that declares another charset, even when its bytes would decode", async () => {
    for (const type of [
      "text/plain; charset=ibm037",
      "text/html; charset=ISO-8859-1",
      'text/html; charset="utf-16le"',
      "text/html;charset=windows-1252",
      "text/html; charset=utf-7",
      "text/html; charset=",
    ]) {
      expect(await withheld(TEXT, { "content-type": type }), type).toEqual({ withheld: true, body: BODY_WITHHELD });
    }
  });

  it("reads UTF-8 and US-ASCII, declared or not", async () => {
    const text = '{"reports":["żółw", "😀"]}';
    for (const type of [
      "application/json",
      "application/json; charset=utf-8",
      'text/html; charset="UTF-8"',
      "text/plain; charset=us-ascii",
      "text/plain;CHARSET=utf8",
    ]) {
      expect(await withheld(text, { "content-type": type }), type).toEqual({ withheld: false, body: text });
    }
  });

  it("reads a body cut at the read cap inside a character: only the cut character is lost", async () => {
    const whole = Buffer.from(`${TEXT}😀`);
    expect(await withheld(whole.subarray(0, whole.length - 2), {}, true)).toEqual({ withheld: false, body: TEXT });
    // Not cut: a character that ends early is not UTF-8.
    expect((await withheld(whole.subarray(0, whole.length - 2), {}, false)).withheld).toBe(true);
  });
});

describe("review3 F4: the ownership request is judged by the switches too", () => {
  const cases: [Partial<GateControl>, CampaignEndReason][] = [
    [{ killed: true }, "operator_kill"],
    [{ suspended: true }, "organization_suspended"],
    [{ stopRequested: true }, "owner_stop"],
    [{ deletionPending: true }, "deletion_pending"],
    [{ killed: true, suspended: true, stopRequested: true, deletionPending: true }, "operator_kill"],
  ];

  it("is not sent when a switch is on: the review's unit case, and each switch alone", async () => {
    for (const [control, reason] of cases) {
      const h = harness();
      h.state.control = { ...RUNNING, ...control };
      expect(await h.gate.ownership(), reason).toEqual({ ok: false, reason, sent: false });
      expect(h.sent).toHaveLength(0);
      expect(h.records).toEqual([]);
      // Read as the start checks' control: a Campaign that is still queued is not "stopped" for that alone.
      expect(h.phases).toEqual(["start"]);
    }
  });

  it("is not sent when a switch comes on during the spacing wait", async () => {
    for (const [control, reason] of cases) {
      const h = harness({ previousSendAt: 1_000_000 });
      h.state.duringSleep = () => {
        h.state.control = { ...RUNNING, ...control };
      };
      expect(await h.gate.ownership(), reason).toEqual({ ok: false, reason, sent: false });
      expect(h.order).toContain("sleep");
      expect(h.sent).toHaveLength(0);
      expect(h.gate.counters().sent).toBe(0);
    }
  });

  it("is not sent when the Target lapses or the Rules are replaced during the spacing wait", async () => {
    const lapsed = harness({ previousSendAt: 1_000_000 });
    lapsed.state.duringSleep = () => {
      lapsed.state.authorize = { allowed: false, reason: "target_not_verified" };
    };
    expect(await lapsed.gate.ownership()).toEqual({ ok: false, reason: "target_not_verified", sent: false });
    expect(lapsed.sent).toHaveLength(0);

    const replaced = harness({ previousSendAt: 1_000_000 });
    replaced.state.duringSleep = () => {
      replaced.state.authorize = { allowed: true, roe_id: "roe_ffffffffffffffffffffffff" };
    };
    expect(await replaced.gate.ownership()).toEqual({ ok: false, reason: "rules_replaced", sent: false });
    expect(replaced.sent).toHaveLength(0);
  });

  it("reads the run's control for a probe, and the start checks' for the ownership request", async () => {
    const h = harness();
    expect((await h.gate.ownership()).ok).toBe(true);
    h.state.clock += 5000;
    await h.gate.request({ method: "GET", path: "/" });
    expect(new Set(h.phases.slice(0, 2))).toEqual(new Set(["start"]));
    expect(new Set(h.phases.slice(2))).toEqual(new Set(["run"]));
  });
});

describe("review3 F4: the switches and the authorization are read again right before a probe leaves", () => {
  it("control and authorize are read after the `sending` row is written, with nothing awaited before the send", async () => {
    const h = harness();
    await h.gate.request({ method: "GET", path: "/" });
    // Fourth review: of the two, the switches are read last.
    expect(h.order).toEqual(["control", "authorize", "record", "authorize", "control", "transport"]);
  });

  it("the suspected case: authorization withdrawn during the spacing wait — the probe is not sent", async () => {
    const h = harness({ previousSendAt: 1_000_000 });
    h.state.duringSleep = () => {
      h.state.authorize = { allowed: false, reason: "target_not_verified" };
    };
    const exchange = await h.gate.request({ method: "GET", path: "/api/admin/reports" });
    expect(h.order).toContain("sleep");
    expect(h.sent).toHaveLength(0);
    expect(exchange).toEqual({ ok: false, refused: "target_not_verified", fatal: true });
    expect(h.ends).toEqual(["target_not_verified"]);
    // Its row says that it never left, and the refusal follows it. Nothing counts as sent.
    expect(h.records.map((row) => `${row.seq} ${row.outcome} ${row.reason ?? "-"}`)).toEqual([
      "1 not_sent -",
      "2 refused target_not_verified",
    ]);
    expect(h.gate.counters()).toMatchObject({ sent: 0, refused: 1 });
  });

  it("a path excluded during the wait refuses the probe without ending the Campaign", async () => {
    const h = harness({ previousSendAt: 1_000_000 });
    h.state.duringSleep = () => {
      h.state.authorize = { allowed: false, reason: "path_excluded" };
      h.state.duringSleep = null;
    };
    expect(await h.gate.request({ method: "GET", path: "/a" })).toEqual({
      ok: false,
      refused: "path_excluded",
      fatal: false,
    });
    expect(h.sent).toHaveLength(0);
    expect(h.ends).toEqual([]);
  });

  it("a switch that comes on during the spacing wait, or while the row is written, stops the probe", async () => {
    const switches: [Partial<GateControl>, string][] = [
      [{ killed: true }, "operator_kill"],
      [{ suspended: true }, "organization_suspended"],
      [{ stopRequested: true }, "owner_stop"],
      [{ deletionPending: true }, "deletion_pending"],
    ];
    for (const moment of ["duringSleep", "duringRecord"] as const) {
      for (const [control, reason] of switches) {
        const h = harness({ previousSendAt: 1_000_000 });
        h.state[moment] = () => {
          h.state.control = { ...RUNNING, ...control };
        };
        const exchange = await h.gate.request({ method: "GET", path: "/" });
        expect(refusal(exchange), `${moment} ${reason}`).toBe(reason);
        expect(h.sent).toHaveLength(0);
        expect(h.ends).toEqual([reason]);
        expect(h.gate.counters().sent).toBe(0);
      }
    }
  });

  it("Rules replaced while the row is written: not sent", async () => {
    const h = harness();
    h.state.duringRecord = () => {
      h.state.authorize = { allowed: true, roe_id: "roe_ffffffffffffffffffffffff" };
    };
    expect(refusal(await h.gate.request({ method: "GET", path: "/" }))).toBe("rules_replaced");
    expect(h.sent).toHaveLength(0);
  });

  it("a control that cannot be read before the send: nothing is sent and the Campaign ends", async () => {
    let reads = 0;
    const h = harness({
      extra: {
        async control() {
          if (++reads > 1) throw new Error("the database is away");
          return { ...RUNNING };
        },
      },
    });
    expect(await h.gate.request({ method: "GET", path: "/" })).toMatchObject({ ok: false, fatal: true });
    expect(h.sent).toHaveLength(0);
    expect(h.ends).toEqual(["engine_error"]);
    expect(h.records).toMatchObject([{ seq: 1, outcome: "not_sent" }]);
  });
});

describe("review3 F6 (D-108): a row whose Campaign has ended is settled as sent", () => {
  it("a stop while the row is written, with `not_sent` refused by the database: settled as sent and cut off", async () => {
    const h = harness();
    h.state.refuseNotSent = true;
    h.state.duringRecord = () => h.controller.abort("operator_kill");
    expect(await h.gate.request({ method: "GET", path: "/" })).toMatchObject({ refused: "campaign_ended" });
    expect(h.sent).toHaveLength(0);
    expect(h.records).toMatchObject([{ seq: 1, outcome: "sent", failure: "aborted", status: null, bytes: 0 }]);
    expect(h.ends).toEqual(["operator_kill"]);
  });

  it("while the Campaign has not ended, the same row says not_sent", async () => {
    const h = harness();
    h.state.duringRecord = () => h.controller.abort("owner_stop");
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.records).toMatchObject([{ seq: 1, outcome: "not_sent" }]);
    expect(h.ends).toEqual(["owner_stop"]);
  });
});

describe("review3: a stop is a stop, even when the cut request's row cannot be settled", () => {
  it("the owner's stop in flight, the settle failing: the Campaign ends as stopped by the owner", async () => {
    const h = harness({
      respond: (send) =>
        new Promise<PinnedResponse>((resolve) => {
          send.signal.addEventListener("abort", () => resolve({ ok: false, reason: "timeout", bytesRead: 3000 }), {
            once: true,
          });
          h.state.settleFails = 1;
          queueMicrotask(() => h.controller.abort("owner_stop"));
        }),
    });
    expect(await h.gate.request({ method: "GET", path: "/" })).toMatchObject({ refused: "campaign_ended" });
    expect(h.gate.ended()).toBe("owner_stop");
    expect(h.ends).toEqual(["owner_stop"]);
    // The row stays `sending`: sent, its result not recorded.
    expect(h.records).toMatchObject([{ seq: 1, outcome: "sending" }]);
  });

  it("without a stop, a settle that fails still ends the Campaign as an error of ours", async () => {
    const h = harness();
    h.state.settleFails = 1;
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.ends).toEqual(["engine_error"]);
  });
});

describe("review3 F5 (D-107): evidence is a window of at most 200 characters", () => {
  const BODY = `${"a@b.cd ".repeat(9000)}<p>"><airverse-probe-marker></p> api_key=sk_live_4eC39HqLyjWDarjtT1zdp7dc tail`;

  it("holds the request, the status, the kept headers and the window — no hash, no other part of the body", async () => {
    const h = harness({ respond: () => ok(200, BODY, { "content-type": "text/html", "x-other": "no" }) });
    const exchange = answered(await h.gate.request({ method: "GET", path: "/search" }));
    const window = exchange.body.slice(exchange.body.indexOf('<p>"><airverse'), exchange.body.indexOf("</p>") + 4);
    const evidence = h.gate.evidence(1, window);
    expect(evidence).toEqual({
      method: "GET",
      target: "/search",
      status: 200,
      headers: { "content-type": "text/html" },
      excerpt: '<p>"><airverse-probe-marker></p>',
      truncated: false,
      location: null,
    });
    expect(Object.keys(evidence ?? {})).not.toContain("body_sha256");
  });

  it("the review's F2 body: redaction lengthened it past 64 KB, and the evidence is still there", async () => {
    const h = harness({ respond: () => ok(200, BODY) });
    const exchange = answered(await h.gate.request({ method: "GET", path: "/search" }));
    expect(exchange.body.indexOf('"><airverse-probe-marker>')).toBeGreaterThan(CAMPAIGN_LIMITS.responseReadBytesMax);
    expect(h.gate.evidence(1, '"><airverse-probe-marker>')?.excerpt).toBe('"><airverse-probe-marker>');
  });

  it("never trusts the engine: a window that is too long, is not text, or is not in the body it names is refused", async () => {
    const h = harness({ respond: () => ok(200, `before ${"x".repeat(400)} after`) });
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.gate.evidence(1, "x".repeat(CAMPAIGN_LIMITS.evidenceWindowMax))?.excerpt).toHaveLength(200);
    expect(h.gate.evidence(1, "x".repeat(CAMPAIGN_LIMITS.evidenceWindowMax + 1))).toBeNull();
    expect(h.gate.evidence(1, "not in the body")).toBeNull();
    expect(h.gate.evidence(1, 7 as never)).toBeNull();
    expect(h.gate.evidence(1, undefined as never)).toBeNull();
    expect(h.gate.evidence(1, { length: 1 } as never)).toBeNull();
    expect(h.gate.evidence(2, "")).toBeNull();
    expect(h.gate.evidence(Number.NaN, "")).toBeNull();
    // A check that reads no body has an empty window.
    expect(h.gate.evidence(1, "")?.excerpt).toBe("");
  });

  it("redacts the window again and still holds it to 200 characters", async () => {
    // The engine is handed the redacted body; were anything of it not, the window is redacted on its own again.
    const h = harness({ respond: () => ok(200, `<p>${"q ".repeat(80)}</p>`) });
    await h.gate.request({ method: "GET", path: "/" });
    const evidence = h.gate.evidence(1, "q ".repeat(80));
    expect(evidence?.excerpt.length).toBeLessThanOrEqual(CAMPAIGN_LIMITS.evidenceWindowMax);
    const leaky = harness({ respond: () => ok(200, "x") });
    await leaky.gate.request({ method: "GET", path: "/" });
    expect(leaky.gate.evidence(1, "x")?.excerpt).toBe("x");
  });

  it("has no window for a body that was withheld", async () => {
    const h = harness({ respond: () => ok(200, "secret", { "content-encoding": "br" }) });
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.gate.evidence(1, "binary")).toBeNull();
    expect(h.gate.evidence(1, BODY_WITHHELD)).toBeNull();
    expect(h.gate.evidence(1, "")?.excerpt).toBe("");
  });

  it("keeps no control character in the window", async () => {
    const h = harness({ respond: () => ok(500, "Error: boom\r\n\u001b[31m    at handler (/srv/app.js:1:1)") });
    await h.gate.request({ method: "GET", path: "/" });
    expect(h.gate.evidence(1, "boom\r\n\u001b[31m    at handler")?.excerpt).toBe("boom \n [31m    at handler");
  });

  it("keeps of a Content-Security-Policy only that it was there: a nonce or a report token is not kept", async () => {
    const h = harness({
      respond: () =>
        ok(200, "x", {
          "content-security-policy":
            "script-src 'nonce-r4nd0mN0nce' 'self'; report-uri https://csp.acme-shop.io/r?token=hunter2",
          "x-frame-options": "DENY",
        }),
    });
    const exchange = answered(await h.gate.request({ method: "GET", path: "/" }));
    expect(exchange.headers).toEqual({ "content-security-policy": "[present]", "x-frame-options": "DENY" });
    expect(JSON.stringify(h.gate.evidence(1, ""))).not.toMatch(/r4nd0m|hunter2/);
  });
});
