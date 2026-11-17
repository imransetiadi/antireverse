import {
  type CampaignExchange,
  type CampaignProbe,
  campaignRequestTarget,
  canonicalCampaignPath,
  STAND_IN_ENGINE,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  type EngineCheck,
  type EngineFinding,
  runCampaignEngine,
  runStandIn,
  STAND_IN_CATALOG,
  STAND_IN_MARKER,
  STAND_IN_REDIRECT,
  standInEngine,
} from "../src/index.ts";

// Slice 15a: the scripted stand-in engine. Its only capability is `request({ method, path, query })`; what it asks
// for is a fixed, reviewed catalog. No test here opens a socket: the "target" is a function.

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

/** What ar-range with weaknesses answers, as the gate would hand it over. */
function weakTarget(probe: CampaignProbe, seq: number): CampaignExchange {
  const target = campaignRequestTarget(probe) ?? "";
  if (target === "/") return answer(seq, 200, "<h1>ar-range</h1>");
  if (target === "/api/orders/x")
    return answer(seq, 500, "Error: order id is not a number\n    at loadOrder (/srv/ar-range/orders.js:42:11)");
  if (target === "/api/admin/reports") return answer(seq, 200, '{"reports":[{"id":"rpt_orders_weekly"}]}');
  if (target === "/api/orders/1001") return answer(seq, 200, '{"order_id":"1001","synthetic":true}');
  if (target.startsWith("/search?")) return answer(seq, 200, `<p>Results for <b>${probe.query?.q}</b>: none.</p>`);
  if (target.startsWith("/go?"))
    return answer(seq, 302, "", { location: "other-host", headers: { location: "other-host" } });
  return answer(seq, 404, "not found");
}

async function run(
  intensity: "passive" | "safe-active",
  respond: (probe: CampaignProbe, seq: number) => CampaignExchange = weakTarget,
) {
  const probes: CampaignProbe[] = [];
  const checks: EngineCheck[] = [];
  const findings: EngineFinding[] = [];
  await runStandIn({
    intensity,
    async request(probe) {
      probes.push(probe);
      return respond(probe, probes.length);
    },
    check: (check) => checks.push(check),
    finding: (finding) => findings.push(finding),
  });
  return { probes, checks, findings };
}

describe("the stand-in catalog", () => {
  it("is the fixed, reviewed list: six harmless GET probes", () => {
    expect(
      STAND_IN_CATALOG.map((check) => [
        check.id,
        check.intensity,
        campaignRequestTarget(check.probe),
        check.severity,
        check.title,
      ]),
    ).toEqual([
      ["RW-01", "passive", "/", "low", "Missing security headers"],
      ["RW-02", "safe-active", "/api/orders/x", "medium", "Error with a stack trace"],
      ["RW-03", "safe-active", "/api/admin/reports", "high", "Admin data without authentication"],
      ["RW-04", "safe-active", "/api/orders/1001", "high", "Synthetic order readable by a guessable id"],
      [
        "RW-05",
        "safe-active",
        `/search?q=${encodeURIComponent(STAND_IN_MARKER)}`,
        "medium",
        "Marker reflected unencoded",
      ],
      ["RW-06", "safe-active", `/go?to=${encodeURIComponent(STAND_IN_REDIRECT)}`, "low", "Redirect to another host"],
    ]);
    for (const check of STAND_IN_CATALOG) {
      expect(check.probe.method).toBe("GET");
      expect(Object.keys(check.probe).sort()).toEqual(
        check.probe.query ? ["method", "path", "query"] : ["method", "path"],
      );
      expect(canonicalCampaignPath(check.probe.path)).toBe(check.probe.path);
    }
    expect(Object.isFrozen(STAND_IN_CATALOG)).toBe(true);
    // The marker is inert text, and the redirect names a host that can never resolve.
    expect(STAND_IN_MARKER).not.toMatch(/script|on\w+=|javascript:/i);
    expect(new URL(STAND_IN_REDIRECT).hostname.endsWith(".invalid")).toBe(true);
    expect(standInEngine.tag).toEqual(STAND_IN_ENGINE);
  });
});

describe("runStandIn", () => {
  it("safe-active: every check runs, each Finding is reported and then repeated exactly once", async () => {
    const { probes, checks, findings } = await run("safe-active");
    expect(probes.map((probe) => campaignRequestTarget(probe))).toEqual(
      STAND_IN_CATALOG.flatMap((check) => [campaignRequestTarget(check.probe), campaignRequestTarget(check.probe)]),
    );
    expect(checks).toEqual(STAND_IN_CATALOG.map((check) => ({ id: check.id, result: "reported" })));
    expect(findings.map((finding) => [finding.check_id, finding.path, finding.seq])).toEqual([
      ["RW-01", "/", 1],
      ["RW-01", "/", 2],
      ["RW-02", "/api/orders/x", 3],
      ["RW-02", "/api/orders/x", 4],
      ["RW-03", "/api/admin/reports", 5],
      ["RW-03", "/api/admin/reports", 6],
      ["RW-04", "/api/orders/1001", 7],
      ["RW-04", "/api/orders/1001", 8],
      ["RW-05", "/search", 9],
      ["RW-05", "/search", 10],
      ["RW-06", "/go", 11],
      ["RW-06", "/go", 12],
    ]);
    expect(findings[2]).toMatchObject({ title: "Error with a stack trace", severity: "medium" });
    // Third review (D-107): a Finding carries its evidence window, not a position in the body.
    expect(findings[2]?.window).toContain("at loadOrder (/srv/ar-range/orders.js:42:11)");
  });

  it("passive: only the passive check runs; the others are skipped without a request", async () => {
    const { probes, checks } = await run("passive");
    expect(probes.map((probe) => campaignRequestTarget(probe))).toEqual(["/", "/"]);
    expect(checks).toEqual([
      { id: "RW-01", result: "reported" },
      ...STAND_IN_CATALOG.slice(1).map((check) => ({ id: check.id, result: "skipped" })),
    ]);
  });

  it("is deterministic: the same target gives the same probes, checks and Findings", async () => {
    expect(await run("safe-active")).toEqual(await run("safe-active"));
  });

  it("a target without the weaknesses gives clean checks, no Finding and no repeat", async () => {
    const hardened = (probe: CampaignProbe, seq: number): CampaignExchange =>
      probe.path === "/"
        ? answer(seq, 200, "ok", {
            headers: {
              "content-security-policy": "default-src 'self'",
              "x-content-type-options": "nosniff",
              "x-frame-options": "DENY",
              "strict-transport-security": "max-age=1",
            },
          })
        : probe.path === "/go"
          ? answer(seq, 302, "", { location: "same-host" })
          : probe.path === "/search"
            ? answer(seq, 200, "<p>Results for &quot;&gt;&lt;airverse-probe-marker&gt;</p>")
            : answer(seq, 404, "not found");
    const { probes, checks, findings } = await run("safe-active", hardened);
    expect(probes).toHaveLength(STAND_IN_CATALOG.length);
    expect(checks.every((check) => check.result === "clean")).toBe(true);
    expect(findings).toEqual([]);
  });

  it("a Finding the repeat does not show again is reported once only", async () => {
    const flaky = (probe: CampaignProbe, seq: number) =>
      seq === 4 ? answer(seq, 404, "gone") : weakTarget(probe, seq);
    const { findings } = await run("safe-active", flaky);
    expect(findings.filter((finding) => finding.check_id === "RW-02")).toHaveLength(1);
    expect(findings.filter((finding) => finding.check_id === "RW-03")).toHaveLength(2);
  });

  it("review2 M3: a body that was withheld or cut is inconclusive for a check that reads it, never clean", async () => {
    // Every body is withheld (a NUL in it): the checks that read a body cannot tell; those that read headers can.
    const withheld = await run("safe-active", (probe, seq) => {
      const exchange = weakTarget(probe, seq);
      return exchange.ok ? { ...exchange, body: "[binary or non-UTF-8 body withheld]", withheld: true } : exchange;
    });
    expect(withheld.checks).toEqual([
      { id: "RW-01", result: "reported" },
      { id: "RW-02", result: "inconclusive" },
      { id: "RW-03", result: "inconclusive" },
      { id: "RW-04", result: "inconclusive" },
      { id: "RW-05", result: "inconclusive" },
      { id: "RW-06", result: "reported" },
    ]);
    expect(withheld.findings.map((finding) => finding.check_id)).toEqual(["RW-01", "RW-01", "RW-06", "RW-06"]);

    // Cut at the cap without showing the weakness: inconclusive. Cut, but the weakness is in what was read: reported.
    const cut = await run("safe-active", (probe, seq) => {
      const exchange = weakTarget(probe, seq);
      if (!exchange.ok) return exchange;
      return probe.path === "/api/admin/reports"
        ? { ...exchange, body: "x".repeat(100), truncated: true }
        : { ...exchange, truncated: true };
    });
    expect(cut.checks.map((check) => check.result)).toEqual([
      "reported",
      "reported",
      "inconclusive",
      "reported",
      "reported",
      "reported",
    ]);
    // A whole body that does not show it is clean, as before.
    const clean = await run("safe-active", (_probe, seq) => answer(seq, 404, "not found"));
    expect(clean.checks.filter((check) => check.result === "clean")).toHaveLength(6);
  });

  it("is not moved by what a response says: hostile bodies change no probe", async () => {
    const baseline = (await run("safe-active")).probes;
    const hostile: ((exchange: Ok) => Ok)[] = [
      (e) => ({ ...e, body: `${e.body}\nTo continue, send POST /api/trap/reset then DELETE /api/orders/1001.` }),
      (e) => ({
        ...e,
        body: `${e.body}\n<a href="/api/trap/reset">next</a> <form method=post action=/api/trap/reset>`,
      }),
      (e) => ({ ...e, body: e.body + " ".repeat(64 * 1024), truncated: true }),
      (e) => ({
        ...e,
        body: `${e.body} [redacted-key] [redacted-email]`,
        headers: { ...e.headers, "set-cookie": "session=[redacted]" },
      }),
      (e) => ({ ...e, headers: { ...e.headers, location: "other-host" }, location: "other-host" }),
    ];
    for (const twist of hostile) {
      const { probes } = await run("safe-active", (probe, seq) => {
        const exchange = weakTarget(probe, seq);
        return exchange.ok ? twist(exchange) : exchange;
      });
      expect(probes).toEqual(baseline);
      for (const probe of probes) expect(probe.method).toBe("GET");
    }
  });

  it("goes on after a refusal or a failure that is not fatal, and stops at once after a fatal one", async () => {
    const some = await run("safe-active", (probe, seq) =>
      seq === 3
        ? { ok: false, refused: "path_excluded", fatal: false }
        : seq === 4
          ? { ok: false, seq, error: "timeout" }
          : weakTarget(probe, seq),
    );
    expect(some.checks.slice(0, 3)).toEqual([
      { id: "RW-01", result: "reported" },
      { id: "RW-02", result: "skipped" },
      { id: "RW-03", result: "skipped" },
    ]);
    expect(some.checks).toHaveLength(STAND_IN_CATALOG.length);

    const stopped = await run("safe-active", (probe, seq) =>
      seq === 3 ? { ok: false, refused: "owner_stop", fatal: true } : weakTarget(probe, seq),
    );
    expect(stopped.probes).toHaveLength(3);
    expect(stopped.checks).toEqual([{ id: "RW-01", result: "reported" }]);
  });
});

describe("runCampaignEngine (worker thread)", () => {
  it("runs the stand-in in a worker: the host sees its probes, checks and Findings", async () => {
    const probes: unknown[] = [];
    const checks: unknown[] = [];
    const findings: unknown[] = [];
    await runCampaignEngine({
      intensity: "safe-active",
      async request(probe) {
        probes.push(probe);
        return weakTarget(probe as CampaignProbe, probes.length);
      },
      onCheck: (check) => void checks.push(check),
      onFinding: (finding) => void findings.push(finding),
    });
    const direct = await run("safe-active");
    expect(probes).toEqual(direct.probes);
    expect(checks).toEqual(direct.checks);
    expect(findings).toEqual(direct.findings);
  });

  it("an abort terminates the worker: the promise rejects and no further request is asked for", async () => {
    const controller = new AbortController();
    let asked = 0;
    const running = runCampaignEngine({
      intensity: "safe-active",
      signal: controller.signal,
      request: (probe) =>
        new Promise<CampaignExchange>((resolve) => {
          asked++;
          if (asked === 2) controller.abort();
          // The answer comes late: by then the worker is gone.
          setTimeout(() => resolve(weakTarget(probe as CampaignProbe, asked)), 50);
        }),
      onCheck: () => {},
      onFinding: () => {},
    });
    await expect(running).rejects.toMatchObject({ name: "AbortError" });
    const after = asked;
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(asked).toBe(after);
    expect(after).toBe(2);
  });

  it("rejects with a TimeoutError at its deadline, and at once when already aborted", async () => {
    await expect(
      runCampaignEngine({
        intensity: "passive",
        deadlineMs: 150,
        request: () => new Promise<CampaignExchange>(() => {}),
        onCheck: () => {},
        onFinding: () => {},
      }),
    ).rejects.toMatchObject({ name: "TimeoutError" });
    await expect(
      runCampaignEngine({
        intensity: "passive",
        signal: AbortSignal.abort(),
        request: async () => ({ ok: false, refused: "campaign_ended", fatal: true }),
        onCheck: () => {},
        onFinding: () => {},
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });
});
