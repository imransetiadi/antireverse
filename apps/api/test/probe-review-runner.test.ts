import type { SloId } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createProbeConnect } from "../src/probe/connect.ts";
import { createProber, type ProberOptions, type ProbeTransport } from "../src/probe/runner.ts";
import type { ProbeTenant } from "../src/probe/tenant.ts";
import { captureLogger } from "./helpers.ts";

// Slice 18g, independent review: F4 (a cut cycle records nothing, the enforcement sample included), F5 (a logger or a
// clock that throws neither rejects the run nor loses it from the status), D-117 (a prober that cannot be set up
// counts as failing from its fourth failed cycle in a row) and F1 (the probe's Organization is provisioned once per
// process; only the transport is tried again).

const TRANSPORT: ProbeTransport = {
  publishBlock: async () => {},
  blocks: () => true,
  request: async () => 403,
  eventVisible: async () => true,
  close: async () => {},
};

function prober(overrides: Partial<ProberOptions> & { transport?: Partial<ProbeTransport> } = {}) {
  let clock = 0;
  const samples: { slo: SloId; good: boolean; ms: number }[] = [];
  const logger = captureLogger();
  const timers: { fn: () => void; ms: number }[] = [];
  const { transport, ...options } = overrides;
  const made = createProber({
    connect: async () => ({ ...TRANSPORT, ...transport }),
    slo: { record: (slo, good, ms) => samples.push({ slo, good, ms }) },
    logger,
    now: () => new Date(Date.UTC(2026, 10, 20, 8, 0, 0) + clock),
    monotonic: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    setTimer: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
    clearTimer: () => {},
    ...options,
  });
  return { prober: made, samples, logger, timers };
}

describe("F4: a cycle cut by stop records nothing", () => {
  it("records no SLO-06 sample when it is cut while it waits for the Event", async () => {
    let reads = 0;
    const h = prober({
      transport: {
        eventVisible: async () => {
          if (++reads === 3) void h.prober.stop();
          return false;
        },
      },
    });
    expect(await h.prober.runOnce()).toBeNull();
    expect(reads).toBe(3);
    expect(h.samples).toEqual([]);
    expect(h.prober.status()).toMatchObject({ runs: 0, failures: 0, enforcement: null });
  });

  it("records both samples together once the cycle has ended", async () => {
    const order: string[] = [];
    const h = prober({
      transport: {
        eventVisible: async () => {
          order.push("event");
          return true;
        },
      },
      slo: { record: (slo) => order.push(slo) },
    });
    await h.prober.runOnce();
    expect(order).toEqual(["event", "SLO-06", "SLO-04"]);
  });
});

describe("F5: a logger or a clock that throws", () => {
  it("does not reject the run, and the failed run still reaches the status", async () => {
    const h = prober({
      transport: { blocks: () => false },
      logger: {
        info: () => {
          throw new Error("logger down");
        },
        warn: () => {
          throw new Error("logger down");
        },
      },
    });
    await expect(h.prober.runOnce()).resolves.toMatchObject({ enforcement: { outcome: "timeout" } });
    expect(h.prober.status()).toMatchObject({ runs: 1, failures: 1, consecutive_failures: 1 });
    expect(h.samples).toEqual([{ slo: "SLO-06", good: false, ms: 60_001 }]);
  });

  it("keeps the run when the wall clock throws: the time of the run is left out, not the run", async () => {
    const h = prober({
      now: () => {
        throw new Error("no clock");
      },
    });
    await expect(h.prober.runOnce()).resolves.toMatchObject({ enforcement: { outcome: "good" } });
    expect(h.prober.status()).toMatchObject({ runs: 1, failures: 0, last_run_at: null });
    expect(h.samples).toHaveLength(2);
  });

  it("leaves no unhandled rejection on the timer path and schedules the next cycle", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      const h = prober({
        slo: {
          record: () => {
            throw new Error("sink down");
          },
        },
      });
      h.prober.start();
      h.timers[0]?.fn();
      await h.prober.idle();
      await new Promise((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
      expect(h.timers).toHaveLength(2);
      expect(h.prober.status()).toMatchObject({ runs: 1 });
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});

describe("D-117: a prober that cannot be set up", () => {
  it("records nothing for three failed set-ups in a row, then a bad SLO-06 sample at the give-up bound for each further one", async () => {
    let fail = true;
    const h = prober({
      connect: async () => {
        if (fail) throw new TypeError("cannot listen");
        return TRANSPORT;
      },
    });
    for (let i = 1; i <= 3; i++) {
      await h.prober.runOnce();
      expect(h.samples, `cycle ${i}`).toEqual([]);
      expect(h.prober.status()).toMatchObject({ setup_failures: i, consecutive_failures: i });
    }
    await h.prober.runOnce();
    await h.prober.runOnce();
    expect(h.samples).toEqual([
      { slo: "SLO-06", good: false, ms: 60_001 },
      { slo: "SLO-06", good: false, ms: 60_001 },
    ]);
    expect(h.prober.status()).toMatchObject({
      runs: 5,
      failures: 5,
      setup_failures: 5,
      enforcement: { outcome: "failed", ms: null },
      freshness: { outcome: "skipped", ms: null },
    });
    // The log names the cause, and says when the failure began to count.
    expect(h.logger.lines.filter((line) => line.includes("reason=setup"))).toHaveLength(5);
    expect(h.logger.lines.filter((line) => line.includes("counted=bad"))).toHaveLength(2);
    expect(h.logger.lines[0]).toBe(
      "probe failed leg=enforcement outcome=failed reason=setup error=TypeError setup_failures=1 counted=no",
    );

    // Set up again: the count starts over, and a single failure later records nothing.
    fail = false;
    await h.prober.runOnce();
    expect(h.prober.status()).toMatchObject({ setup_failures: 0, consecutive_failures: 0 });
    expect(h.samples).toHaveLength(4);
  });
});

describe("F1: the probe's Organization is provisioned once per process", () => {
  const TENANT: ProbeTenant = {
    organizationId: "org_0123456789abcdef01234567",
    appId: "app_0123456789abcdef01234567",
    adminKey: "admin",
    shieldKey: "shield",
  };

  it("tries only the transport again after it failed, and provisions again only when provisioning itself failed", async () => {
    let provisions = 0;
    let opens = 0;
    let provisionFails = 1;
    const registered: string[] = [];
    const connect = createProbeConnect({
      provision: async () => {
        provisions++;
        if (provisionFails-- > 0) throw new Error("database busy");
        return TENANT;
      },
      register: (organizationId) => registered.push(organizationId),
      open: async (tenant) => {
        expect(tenant).toBe(TENANT);
        if (++opens <= 10) throw new Error("no port");
        return TRANSPORT;
      },
    });
    const signal = new AbortController().signal;
    for (let i = 0; i < 11; i++) await expect(connect(signal)).rejects.toThrow();
    expect([provisions, opens]).toEqual([2, 10]);
    await expect(connect(signal)).resolves.toBe(TRANSPORT);
    expect([provisions, opens]).toEqual([2, 11]);
    // Known as a system Organization before its first request is sent.
    expect(registered).toEqual([TENANT.organizationId]);
  });
});
