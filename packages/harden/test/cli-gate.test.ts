// Slice 13 — the CI gate on the Reverse Resistance Score: `harden --register --assess <tier> --min-rrs <n>` and
// `antireverse gate --assessment <asm_id> --min-rrs <n>`. The wait loop polls GET /v1/assessments/:id with backoff
// (2 s doubling to 30 s) until the Assessment finishes or --wait runs out; exit 5 below the threshold, 6 with no score
// (unless --on-no-score pass), 4 (findings) wins over 5/6 and both gates are reported. The key is never printed.
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Assessment,
  AssessmentResponseSchema,
  EXAMPLE_ASSESSMENT,
  EXAMPLE_BUILD,
  type FindingsSummary,
  type ObjectiveResult,
  scoreAssessment,
  TIERS,
} from "@antireverse/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type CliIo, main } from "../src/cli.ts";
import { beaconHostModule } from "./helpers.ts";

const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const ENDPOINT = "https://api.example.test";
const ASM = EXAMPLE_ASSESSMENT.id;
const POLL_URL = `${ENDPOINT}/v1/assessments/${ASM}`;

const temps: string[] = [];
afterEach(() => {
  vi.unstubAllGlobals();
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function bundle(): string {
  const d = mkdtempSync(join(tmpdir(), "harden-cli13-"));
  temps.push(d);
  writeFileSync(join(d, "a.mjs"), beaconHostModule());
  return d;
}

// ---------------------------------------------------------------------------------------------------------------
// Fixtures: every Assessment is checked against the protocol's response schema, as the CLI parses it.

const evidence = { summary: "Verifier summary.", recovered: [], calls: [] };
const notAchieved = (objective: ObjectiveResult["objective"]): ObjectiveResult => ({
  objective,
  result: "not_achieved",
  cost: { calls: 10, seconds: 5 },
  evidence,
});
const achieved = (objective: ObjectiveResult["objective"], tier: "T1" | "T2" | "T3"): ObjectiveResult => ({
  objective,
  result: "achieved",
  tier,
  cost: { calls: 10, seconds: 5 },
  evidence,
});

/** A T3 run: W2 achieved at T1 (0), W4 achieved at T2 (0.4), the rest not achieved (1). */
const RESULTS: ObjectiveResult[] = [
  notAchieved("W1"),
  achieved("W2", "T1"),
  notAchieved("W3"),
  achieved("W4", "T2"),
  notAchieved("W5"),
];
const SCORE = scoreAssessment(RESULTS, "T3");
if (SCORE.status !== "scored") throw new Error("fixture must be scored");
const RRS = SCORE.rrs;

const T3 = { tier: "T3" as const, scope: { ...EXAMPLE_ASSESSMENT.scope, tier: "T3" as const } };

const QUEUED: Assessment = {
  ...EXAMPLE_ASSESSMENT,
  ...T3,
  build_id: EXAMPLE_BUILD.build_id,
  app_id: EXAMPLE_BUILD.app_id,
  status: "queued",
  results: [],
  rrs: null,
  inconclusive_reason: null,
  inconclusive_code: null,
  renormalised: false,
  started_at: null,
  finished_at: null,
  failure_reason: null,
};
const RUNNING: Assessment = { ...QUEUED, status: "running", started_at: "2026-11-13T08:00:01.000Z" };
const SCORED: Assessment = {
  ...RUNNING,
  status: "scored",
  results: RESULTS,
  rrs: RRS,
  finished_at: "2026-11-13T08:30:00.000Z",
};
const INCONCLUSIVE: Assessment = { ...EXAMPLE_ASSESSMENT };
const FAILED: Assessment = {
  ...RUNNING,
  status: "failed",
  finished_at: "2026-11-13T08:30:00.000Z",
  failure_reason: "The sandbox stopped unexpectedly.",
};
const T1_RUNNING: Assessment = {
  ...RUNNING,
  tier: "T1",
  scope: { ...RUNNING.scope, tier: "T1" },
};

for (const a of [QUEUED, RUNNING, SCORED, INCONCLUSIVE, FAILED, T1_RUNNING]) {
  AssessmentResponseSchema.parse({ assessment: a });
}

// ---------------------------------------------------------------------------------------------------------------
// A fake API: GET /v1/assessments/:id answers from a script (the last entry repeats); POST register / assess answer
// a Build and a queued Assessment. A fake clock: `sleep` advances `now`.

type Step =
  | Assessment
  | { status: number; body?: unknown; headers?: Record<string, string> }
  | { stalledBody: true }
  | Error;
type Call = { method: string; url: string; auth: string | null; signal: AbortSignal | null };

function fakeApi(poll: Step[], opts: { findings?: FindingsSummary; queued?: Assessment } = {}) {
  const calls: Call[] = [];
  let i = 0;
  const fetch = async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    calls.push({ method, url: String(url), auth: headers.get("authorization"), signal: init?.signal ?? null });
    const json = (status: number, body: unknown, extra: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...extra } });
    if (method === "POST" && String(url).endsWith("/builds")) {
      return json(201, { build: EXAMPLE_BUILD, ...(opts.findings ? { findings: opts.findings } : {}) });
    }
    if (method === "POST" && String(url).endsWith("/assessments")) {
      return json(202, { assessment: opts.queued ?? QUEUED });
    }
    const step = poll[Math.min(i, poll.length - 1)] as Step;
    i++;
    if (step instanceof Error) throw step;
    if ("id" in step) return json(200, { assessment: step });
    if ("stalledBody" in step) {
      // Headers arrive, then the body is aborted by the poll's timeout.
      const stream = new ReadableStream({
        start(controller) {
          controller.error(new DOMException("The operation timed out.", "TimeoutError"));
        },
      });
      return new Response(stream, { status: 200, headers: { "content-type": "application/json" } });
    }
    return json(step.status, step.body ?? {}, step.headers);
  };
  return { fetch, calls, polls: () => calls.filter((c) => c.method === "GET") };
}

const CLOCK_START = 1_000_000;

function fakeClock() {
  let t = CLOCK_START;
  const sleeps: number[] = [];
  /** Each poll's timeout, and the signal handed out for it. */
  const timeouts: Array<{ ms: number; signal: AbortSignal }> = [];
  return {
    now: () => t,
    sleep: async (ms: number) => {
      sleeps.push(ms);
      t += ms;
    },
    timeout: (ms: number) => {
      const signal = new AbortController().signal;
      timeouts.push({ ms, signal });
      return signal;
    },
    /** Advances the clock without a sleep: a poll that takes time to answer. */
    advance: (ms: number) => {
      t += ms;
    },
    sleeps,
    timeouts,
  };
}

async function run(
  argv: string[],
  api: ReturnType<typeof fakeApi>,
  opts: {
    env?: Record<string, string>;
    cwd?: string;
    global?: boolean;
    pollMs?: number;
    /** Replaces the fake sleep. */
    sleep?: (ms: number) => Promise<void>;
    /** Called before each fake sleep. */
    onSleep?: (ms: number) => void;
    /** Leaves `now` to the CLI's default clock. */
    defaultNow?: boolean;
  } = {},
) {
  const clock = fakeClock();
  const fetch = opts.pollMs
    ? async (url: string | URL, init?: RequestInit) => {
        const response = await api.fetch(url, init);
        if ((init?.method ?? "GET") === "GET") clock.advance(opts.pollMs as number);
        return response;
      }
    : api.fetch;
  let out = "";
  let err = "";
  if (opts.global) vi.stubGlobal("fetch", fetch);
  const io: CliIo = {
    env: opts.env ?? { AR_ADMIN_KEY: KEY },
    ...(opts.cwd ? { cwd: opts.cwd } : {}),
    stdout: (s) => {
      out += s;
    },
    stderr: (s) => {
      err += s;
    },
    ...(opts.defaultNow ? {} : { now: clock.now }),
    sleep:
      opts.sleep ??
      (async (ms: number) => {
        opts.onSleep?.(ms);
        await clock.sleep(ms);
      }),
    timeout: clock.timeout,
    ...(opts.global ? {} : { fetch: fetch as typeof globalThis.fetch }),
  };
  const code = await main(argv, io);
  // The key is never printed, whatever happened.
  expect(out + err).not.toContain(KEY);
  expect(out + err).not.toContain(KEY.slice(4, 20));
  return { code, out, err, sleeps: clock.sleeps, timeouts: clock.timeouts, elapsed: clock.now() - CLOCK_START };
}

const gate = (min: string, ...rest: string[]) => [
  "gate",
  "--assessment",
  ASM,
  "--min-rrs",
  min,
  "--endpoint",
  ENDPOINT,
  "--key-env",
  "AR_ADMIN_KEY",
  ...rest,
];

// ---------------------------------------------------------------------------------------------------------------

describe("antireverse gate", () => {
  it("passes (exit 0) above the threshold, polling with the admin key, and names the two weakest Objectives", async () => {
    const api = fakeApi([SCORED]);
    const r = await run(gate(String(RRS - 8)), api);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    expect(api.polls().map(({ signal: _signal, ...call }) => call)).toEqual([
      { method: "GET", url: POLL_URL, auth: `Bearer ${KEY}` },
    ]);
    expect(r.out).toContain(`✓ RRS ${RRS} meets --min-rrs ${RRS - 8}`);
    expect(r.out).toContain(`assessment ${ASM} scored (T3)`);
    expect(r.out).toContain("weakest: W2 Secrets (achieved at T1), W4 Tamper (achieved at T2)");
    // No evidence content.
    expect(r.out).not.toContain("Verifier summary");
  });

  it("equal to the threshold passes (exit 0)", async () => {
    const r = await run(gate(String(RRS)), fakeApi([SCORED]));
    expect(r.code).toBe(0);
  });

  it("below the threshold fails with exit 5, naming the score and the threshold", async () => {
    const r = await run(gate(String(RRS + 1)), fakeApi([SCORED]));
    expect(r.code).toBe(5);
    expect(r.out).toContain(`✗ RRS ${RRS} is below --min-rrs ${RRS + 1}`);
    expect(r.out).toContain("weakest: W2 Secrets (achieved at T1), W4 Tamper (achieved at T2)");
    expect(r.err).toContain(`gate: RRS gate failed: ${RRS} is below ${RRS + 1}`);
  });

  it("inconclusive exits 6 with the reason", async () => {
    const r = await run(gate("50"), fakeApi([INCONCLUSIVE]));
    expect(r.code).toBe(6);
    expect(r.out).toContain(`✗ no RRS for assessment ${ASM} (inconclusive): ${INCONCLUSIVE.inconclusive_reason}`);
    expect(r.err).toContain("gate: RRS gate has no score");
  });

  it("failed exits 6 with the failure reason", async () => {
    const r = await run(gate("50"), fakeApi([FAILED]));
    expect(r.code).toBe(6);
    expect(r.out).toContain(
      `✗ no RRS for assessment ${ASM} (failed): the Assessment failed: The sandbox stopped unexpectedly.`,
    );
  });

  it("polls queued → running → scored with backoff 2 s, 4 s", async () => {
    const api = fakeApi([QUEUED, RUNNING, SCORED]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(0);
    expect(api.polls().length).toBe(3);
    expect(r.sleeps).toEqual([2000, 4000]);
  });

  it("backs off 2 s doubling to 30 s, sleeps at most until the deadline, and exits 6 after a last poll there", async () => {
    const api = fakeApi([RUNNING]);
    const r = await run(gate("10", "--wait", "100"), api);
    expect(r.code).toBe(6);
    expect(r.sleeps).toEqual([2000, 4000, 8000, 16_000, 30_000, 30_000, 10_000]);
    expect(r.elapsed).toBe(100_000);
    expect(api.polls().length).toBe(8);
    expect(r.out).toContain(
      `✗ no RRS for assessment ${ASM} (running): the wait of 100 s ended before the Assessment finished`,
    );
  });

  it("without --wait waits the tier's seconds plus 5 minutes", async () => {
    const r = await run(gate("10"), fakeApi([T1_RUNNING]));
    expect(r.code).toBe(6);
    expect(r.sleeps.reduce((a, b) => a + b, 0)).toBe((TIERS.T1.seconds + 300) * 1000);
  });

  it("retries network errors, 429 and 5xx within the wait", async () => {
    const api = fakeApi([
      new TypeError("fetch failed", { cause: Object.assign(new Error("connect"), { code: "ECONNREFUSED" }) }),
      { status: 429, body: { title: "Too Many Requests" } },
      { status: 503 },
      SCORED,
    ]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(0);
    expect(api.polls().length).toBe(4);
    expect(r.sleeps).toEqual([2000, 4000, 8000]);
  });

  it("an API that stays unreachable until the wait ends exits 6", async () => {
    const api = fakeApi([
      new TypeError("fetch failed", { cause: Object.assign(new Error("x"), { code: "ECONNREFUSED" }) }),
    ]);
    const r = await run(gate("10", "--wait", "10"), api);
    expect(r.code).toBe(6);
    expect(r.out).toContain("the wait of 10 s ended before the Assessment finished");
  });

  it("each poll is aborted after min(15 s, max(time left, 2 s))", async () => {
    const api = fakeApi([RUNNING]);
    const r = await run(gate("10", "--wait", "100"), api);
    expect(r.code).toBe(6);
    // Polls at 0, 2, 6, 14, 30, 60, 90 and 100 s: 100, 98, 94, 86, 70, 40, 10 and 0 s left.
    expect(r.timeouts.map((t) => t.ms)).toEqual([15_000, 15_000, 15_000, 15_000, 15_000, 15_000, 10_000, 2000]);
    expect(api.polls().map((c) => c.signal)).toEqual(r.timeouts.map((t) => t.signal));
  });

  it.each([
    ["2", [2000], [2000, 2000]],
    ["7", [2000, 4000, 1000], [7000, 5000, 2000, 2000]],
  ])("a short --wait %s polls until the deadline and makes a last poll there", async (wait, sleeps, timeouts) => {
    const api = fakeApi([RUNNING]);
    const r = await run(gate("10", "--wait", wait), api);
    expect(r.code).toBe(6);
    expect(r.sleeps).toEqual(sleeps);
    expect(r.timeouts.map((t) => t.ms)).toEqual(timeouts);
    expect(api.polls().length).toBe(timeouts.length);
    expect(r.elapsed).toBe(Number(wait) * 1000);
  });

  it("polls that take time never end the wait before the deadline, and overrun it by at most 2 s", async () => {
    const api = fakeApi([RUNNING]);
    const r = await run(gate("10", "--wait", "7"), api, { pollMs: 1500 });
    expect(r.code).toBe(6);
    expect(r.elapsed).toBeGreaterThanOrEqual(7000);
    expect(r.elapsed).toBeLessThanOrEqual(9000);
  });

  it("a poll that times out is retried", async () => {
    const api = fakeApi([new DOMException("The operation timed out.", "TimeoutError"), SCORED]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(0);
    expect(api.polls().length).toBe(2);
    expect(r.sleeps).toEqual([2000]);
  });

  it("a body that times out after the headers is retried", async () => {
    const api = fakeApi([{ stalledBody: true }, SCORED]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(0);
    expect(api.polls().length).toBe(2);
  });

  it("a 200 carrying a different Assessment stops with exit 1", async () => {
    const other = { ...SCORED, id: "asm_ffffffffffffffffffffffff" };
    const api = fakeApi([other]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(1);
    expect(api.polls().length).toBe(1);
    expect(r.err).toContain("gate: cannot read the Assessment: the API returned a different Assessment");
  });

  it("prints a progress line to stderr every 60 s, never to stdout", async () => {
    const r = await run(gate("10", "--wait", "200", "--json"), fakeApi([RUNNING]));
    expect(r.code).toBe(6);
    const progress = r.err.split("\n").filter((line) => line.includes("waiting for assessment"));
    expect(progress).toEqual([
      `gate: waiting for assessment ${ASM}: running, 60 s elapsed`,
      `gate: waiting for assessment ${ASM}: running, 120 s elapsed`,
      `gate: waiting for assessment ${ASM}: running, 180 s elapsed`,
    ]);
    expect(r.out).not.toContain("waiting");
    expect(JSON.parse(r.out).gate.result).toBe("no_score");
  });

  it("a short wait prints no progress", async () => {
    const r = await run(gate("10"), fakeApi([QUEUED, RUNNING, SCORED]));
    expect(r.err).toBe("");
  });

  it("a 404 stops at once with exit 1", async () => {
    const api = fakeApi([
      { status: 404, body: { type: "about:blank", title: "Not Found", status: 404, detail: "No such Assessment." } },
    ]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(1);
    expect(api.polls().length).toBe(1);
    expect(r.sleeps).toEqual([]);
    expect(r.err).toContain("gate: cannot read the Assessment: No such Assessment.");
  });

  it("a 401 stops with exit 1", async () => {
    const r = await run(gate("10"), fakeApi([{ status: 401 }]));
    expect(r.code).toBe(1);
    expect(r.err).toContain("the API responded 401");
  });

  it("--on-no-score pass: inconclusive passes with a warning and the gate skipped", async () => {
    const r = await run(gate("50", "--on-no-score", "pass", "--json"), fakeApi([INCONCLUSIVE]));
    expect(r.code).toBe(0);
    expect(r.err).toContain("warning: RRS gate skipped (--on-no-score pass)");
    const report = JSON.parse(r.out);
    expect(report.gate.result).toBe("skipped");
    expect(report.gate.status).toBe("inconclusive");
    expect(report.gate.reason).toBe(INCONCLUSIVE.inconclusive_reason);
  });

  it("--on-no-score pass: a wait that runs out passes with a warning", async () => {
    const r = await run(gate("50", "--on-no-score", "pass", "--wait", "5"), fakeApi([RUNNING]));
    expect(r.code).toBe(0);
    expect(r.out).toContain("! RRS gate skipped (--on-no-score pass)");
    expect(r.err).toContain("warning: RRS gate skipped");
  });

  it("--on-no-score pass never passes a score below the threshold", async () => {
    const r = await run(gate(String(RRS + 1), "--on-no-score", "pass"), fakeApi([SCORED]));
    expect(r.code).toBe(5);
  });

  it("--json reports the gate and the Assessment", async () => {
    const r = await run(gate("60", "--json"), fakeApi([SCORED]));
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.assessment).toEqual({ id: ASM, status: "scored", tier: "T3", rrs: RRS });
    expect(report.gate).toEqual({
      result: "passed",
      rrs: RRS,
      threshold: 60,
      status: "scored",
      reason: null,
      weakest: [
        { objective: "W2", name: "Secrets", result: "achieved", tier: "T1" },
        { objective: "W4", name: "Tamper", result: "achieved", tier: "T2" },
      ],
    });
  });

  it("--json below the threshold reports failed; no score reports no_score", async () => {
    const below = await run(gate("99", "--json"), fakeApi([SCORED]));
    expect(below.code).toBe(5);
    expect(JSON.parse(below.out).gate.result).toBe("failed");
    const none = await run(gate("10", "--json", "--wait", "3"), fakeApi([RUNNING]));
    expect(none.code).toBe(6);
    const report = JSON.parse(none.out);
    expect(report.gate).toMatchObject({ result: "no_score", rrs: null, threshold: 10, status: "running" });
    expect(report.gate.reason).toContain("the wait of 3 s ended");
  });

  it.each([
    [
      "no --assessment",
      ["gate", "--min-rrs", "10", "--endpoint", ENDPOINT, "--key-env", "AR_ADMIN_KEY"],
      /--assessment/,
    ],
    [
      "a bad Assessment id",
      gate("10").map((a) => (a === ASM ? "asm_nope" : a)),
      /--assessment must be an Assessment id/,
    ],
    ["no --min-rrs", ["gate", "--assessment", ASM, "--endpoint", ENDPOINT, "--key-env", "AR_ADMIN_KEY"], /--min-rrs/],
    ["--min-rrs over 100", gate("101"), /--min-rrs must be an integer from 0 to 100/],
    ["--min-rrs below 0", gate("-1"), /--min-rrs must be an integer from 0 to 100/],
    ["--min-rrs not an integer", gate("50.5"), /--min-rrs must be an integer from 0 to 100/],
    ["--min-rrs not a number", gate("high"), /--min-rrs must be an integer from 0 to 100/],
    ["--wait 0", gate("10", "--wait", "0"), /--wait must be an integer from 1 to 86,400/],
    ["--wait over a day", gate("10", "--wait", "86401"), /--wait must be an integer from 1 to 86,400/],
    ["--on-no-score bogus", gate("10", "--on-no-score", "skip"), /--on-no-score must be fail or pass/],
    [
      "no --endpoint",
      gate("10").filter((a, i, all) => a !== "--endpoint" && all[i - 1] !== "--endpoint"),
      /--endpoint/,
    ],
    ["no --key-env", gate("10").filter((a, i, all) => a !== "--key-env" && all[i - 1] !== "--key-env"), /--key-env/],
  ])("%s exits 2 before any request", async (_name, argv, message) => {
    const api = fakeApi([SCORED]);
    const r = await run(argv, api);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(message);
    expect(api.calls.length).toBe(0);
  });

  it.each([
    ["the key itself (no dash)", KEY],
    ["the key itself (with a dash)", "aro_abcdefghijklmnopqrstuvwx-zABCDEFGHIJKLMNOPQ"],
    ["an empty value", ""],
    ["a name starting with a digit", "1KEY"],
  ])("--key-env given %s exits 2 without echoing it", async (_name, value) => {
    const api = fakeApi([SCORED]);
    const argv = gate("10").map((a, i, all) => (all[i - 1] === "--key-env" ? value : a));
    const r = await run(argv, api, { env: { AR_ADMIN_KEY: KEY, [value]: KEY } });
    expect(r.code).toBe(2);
    expect(r.err).toContain("gate: the --key-env value is not a valid variable name");
    if (value.length > 4) expect(r.out + r.err).not.toContain(value.slice(4));
    expect(api.calls.length).toBe(0);
  });

  it("a key that is not a valid header value exits 2 before any request, without echoing it", async () => {
    const api = fakeApi([SCORED]);
    const r = await run(gate("10"), api, { env: { AR_ADMIN_KEY: `${KEY}€` } });
    expect(r.code).toBe(2);
    expect(r.err).toContain("gate: the admin key in AR_ADMIN_KEY is not a valid header value");
    expect(api.calls.length).toBe(0);
  });

  it("an endpoint with credentials exits 2 before any request, without echoing them", async () => {
    const api = fakeApi([SCORED]);
    const argv = gate("10").map((a) => (a === ENDPOINT ? "https://zquser:zqpass@api.example.test" : a));
    const r = await run(argv, api);
    expect(r.code).toBe(2);
    expect(r.err).toContain("gate: --endpoint must not contain credentials");
    expect(r.out + r.err).not.toContain("zqpass");
    expect(api.calls.length).toBe(0);
  });

  it("a fetch TypeError with no cause code (a request that can never be made) stops with exit 1", async () => {
    const api = fakeApi([new TypeError(`Headers.append: "Bearer ${KEY}" is an invalid header value.`)]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(1);
    expect(api.polls().length).toBe(1);
    expect(r.sleeps).toEqual([]);
    expect(r.err).toContain("gate: cannot read the Assessment: the request could not be made (TypeError)");
  });

  it("retries 408", async () => {
    const api = fakeApi([{ status: 408 }, SCORED]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(0);
    expect(api.polls().length).toBe(2);
  });

  it.each([
    [429, "10", [10_000]],
    [503, "5", [5000]],
    [429, "1", [2000]],
  ])("honours Retry-After on %s (%s s), but never sleeps less than the backoff", async (status, after, sleeps) => {
    const api = fakeApi([{ status, headers: { "retry-after": after } }, SCORED]);
    const r = await run(gate("10"), api);
    expect(r.code).toBe(0);
    expect(r.sleeps).toEqual(sleeps);
  });

  it("a Retry-After beyond the wait sleeps only until the deadline, then polls there", async () => {
    const api = fakeApi([{ status: 429, headers: { "retry-after": "100" } }, RUNNING]);
    const r = await run(gate("10", "--wait", "7"), api);
    expect(r.code).toBe(6);
    expect(r.sleeps).toEqual([7000]);
    expect(api.polls().length).toBe(2);
  });

  it("the skipped line names the Assessment", async () => {
    const r = await run(gate("50", "--on-no-score", "pass"), fakeApi([INCONCLUSIVE]));
    expect(r.out).toContain(`! RRS gate skipped (--on-no-score pass): no RRS for assessment ${ASM} (inconclusive)`);
  });

  it("an unset key variable exits 2", async () => {
    const api = fakeApi([SCORED]);
    const r = await run(gate("10"), api, { env: {} });
    expect(r.code).toBe(2);
    expect(r.err).toContain("environment variable AR_ADMIN_KEY is not set");
    expect(api.calls.length).toBe(0);
  });

  it("the usage text documents the gate and exit codes 5 and 6", async () => {
    const r = await run(["--help"], fakeApi([SCORED]));
    expect(r.code).toBe(0);
    expect(r.out).toContain("antireverse gate --assessment <asm_id> --min-rrs <0-100>");
    expect(r.out).toContain("--on-no-score <fail|pass>");
    expect(r.out).toContain("5 RRS below --min-rrs");
    expect(r.out).toContain("6 no score");
  });
});

// ---------------------------------------------------------------------------------------------------------------

const register = [
  "--register",
  "--endpoint",
  ENDPOINT,
  "--key-env",
  "AR_ADMIN_KEY",
  "--app",
  EXAMPLE_BUILD.app_id,
  "--environment",
  "development",
  "--build-version",
  "1.0.0",
];

const FAILING_FINDINGS: FindingsSummary = {
  open: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
  items: [
    { advisory: "GHSA-aaaa-bbbb-cccc", package: "example-parser", version: "1.2.3", severity: "high", fixed: [] },
  ],
};
const CLEAN_FINDINGS: FindingsSummary = { open: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, items: [] };

describe("the wait follows a monotonic clock", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it.each([
    ["back 1 h", -3_600_000, "10"],
    ["forward 2 h", 7_200_000, "1800"],
  ])("a wall-clock jump %s does not change --wait", async (_name, jump, wait) => {
    vi.useFakeTimers({ toFake: ["Date", "performance"] });
    let jumped = false;
    const sleeps: number[] = [];
    const sleep = async (ms: number) => {
      sleeps.push(ms);
      if (!jumped) {
        jumped = true;
        vi.setSystemTime(Date.now() + jump);
      }
      vi.advanceTimersByTime(ms);
    };
    const api = fakeApi([RUNNING]);
    const r = await run(gate("10", "--wait", wait), api, { sleep, defaultNow: true });
    expect(r.code).toBe(6);
    expect(sleeps.reduce((a, b) => a + b, 0)).toBe(Number(wait) * 1000);
  });
});

describe("harden --min-rrs", () => {
  it.each([
    ["--min-rrs without --assess", ["--min-rrs", "50"], /--min-rrs needs --assess/],
    ["--min-rrs out of range", ["--assess", "T1", "--min-rrs", "101"], /--min-rrs must be an integer from 0 to 100/],
    ["--min-rrs not an integer", ["--assess", "T1", "--min-rrs", "7.5"], /--min-rrs must be an integer from 0 to 100/],
    ["--min-rrs with no value", ["--assess", "T1", "--min-rrs"], /--min-rrs must be an integer from 0 to 100/],
    ["--wait without --min-rrs", ["--assess", "T1", "--wait", "60"], /--wait needs --min-rrs/],
    ["--on-no-score without --min-rrs", ["--assess", "T1", "--on-no-score", "pass"], /--on-no-score needs --min-rrs/],
    ["--wait out of range", ["--assess", "T1", "--min-rrs", "5", "--wait", "0"], /--wait must be an integer/],
    ["--on-no-score bogus", ["--assess", "T1", "--min-rrs", "5", "--on-no-score", "x"], /--on-no-score must be/],
  ])("%s exits 2 before any work", async (_name, extra, message) => {
    const d = bundle();
    const api = fakeApi([SCORED]);
    const r = await run(["harden", d, "--seed", "1", ...register, ...extra], api, { cwd: d, global: true });
    expect(r.code).toBe(2);
    expect(r.err).toMatch(message);
    expect(api.calls.length).toBe(0);
  });

  it("--min-rrs without --register exits 2 (via --assess)", async () => {
    const d = bundle();
    const api = fakeApi([SCORED]);
    const r = await run(["harden", d, "--seed", "1", "--assess", "T1", "--min-rrs", "5"], api, {
      cwd: d,
      global: true,
    });
    expect(r.code).toBe(2);
    expect(api.calls.length).toBe(0);
  });

  it("waits for the queued Assessment and passes (exit 0) at or above the threshold", async () => {
    const d = bundle();
    const api = fakeApi([RUNNING, SCORED]);
    const r = await run(["harden", d, "--seed", "1", ...register, "--assess", "T3", "--min-rrs", String(RRS)], api, {
      cwd: d,
      global: true,
    });
    expect(r.code).toBe(0);
    expect(api.calls.map((c) => c.method)).toEqual(["POST", "POST", "GET", "GET"]);
    expect(api.polls()[0]?.url).toBe(POLL_URL);
    expect(r.sleeps).toEqual([2000]);
    expect(r.out).toContain(`✓ assessment ${ASM} queued (T3)`);
    expect(r.out).toContain(`✓ RRS ${RRS} meets --min-rrs ${RRS}`);
  });

  it("exits 5 below the threshold; the Build stays registered", async () => {
    const d = bundle();
    const r = await run(
      ["harden", d, "--seed", "1", ...register, "--assess", "T3", "--min-rrs", String(RRS + 1)],
      fakeApi([SCORED]),
      { cwd: d, global: true },
    );
    expect(r.code).toBe(5);
    expect(r.out).toContain(`registered: ${EXAMPLE_BUILD.build_id}`);
    expect(r.out).toContain(`✗ RRS ${RRS} is below --min-rrs ${RRS + 1}`);
    expect(r.err).toContain(`harden: RRS gate failed: ${RRS} is below ${RRS + 1}`);
  });

  it("exits 6 on no score and passes with --on-no-score pass", async () => {
    const d = bundle();
    const argv = ["harden", d, "--seed", "1", ...register, "--assess", "T3", "--min-rrs", "10"];
    const none = await run(argv, fakeApi([FAILED]), { cwd: d, global: true });
    expect(none.code).toBe(6);
    const pass = await run([...argv, "--on-no-score", "pass", "--json"], fakeApi([FAILED]), { cwd: d, global: true });
    expect(pass.code).toBe(0);
    expect(JSON.parse(pass.out).rrs_gate.result).toBe("skipped");
  });

  it("defaults --wait to the tier's seconds plus 5 minutes", async () => {
    const d = bundle();
    const r = await run(
      ["harden", d, "--seed", "1", ...register, "--assess", "T3", "--min-rrs", "10"],
      fakeApi([RUNNING]),
      { cwd: d, global: true },
    );
    expect(r.code).toBe(6);
    expect(r.sleeps.reduce((a, b) => a + b, 0)).toBe((TIERS.T3.seconds + 300) * 1000);
    expect(r.err).toContain("harden: waiting for assessment");
  });

  it("--json reports rrs_gate beside the findings gate and the final Assessment status", async () => {
    const d = bundle();
    const r = await run(
      ["harden", d, "--seed", "1", "--json", ...register, "--assess", "T3", "--min-rrs", "60"],
      fakeApi([SCORED]),
      { cwd: d, global: true },
    );
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.assessment).toEqual({ id: ASM, status: "scored" });
    expect(report.rrs_gate).toMatchObject({ result: "passed", rrs: RRS, threshold: 60, status: "scored" });
    expect(report.gate).toBeNull();
  });

  it.each([
    ["the key itself", KEY],
    ["an empty value", ""],
  ])("--key-env given %s exits 2 without echoing it", async (_name, value) => {
    const d = bundle();
    const api = fakeApi([SCORED]);
    const argv = ["harden", d, "--seed", "1", ...register].map((a, i, all) => (all[i - 1] === "--key-env" ? value : a));
    const r = await run(argv, api, { cwd: d, global: true, env: { AR_ADMIN_KEY: KEY, [value]: KEY } });
    expect(r.code).toBe(2);
    expect(r.err).toContain("harden: the --key-env value is not a valid variable name");
    expect(api.calls.length).toBe(0);
  });

  it("a key that is not a valid header value, or an endpoint with credentials, exits 2 before any work", async () => {
    const d = bundle();
    const api = fakeApi([SCORED]);
    const badKey = await run(["harden", d, "--seed", "1", ...register], api, {
      cwd: d,
      global: true,
      env: { AR_ADMIN_KEY: `${KEY} x` },
    });
    expect(badKey.code).toBe(2);
    expect(badKey.err).toContain("harden: the admin key in AR_ADMIN_KEY is not a valid header value");
    const creds = await run(
      ["harden", d, "--seed", "1", ...register].map((a) => (a === ENDPOINT ? "https://zquser:zqpass@api.test" : a)),
      api,
      { cwd: d, global: true },
    );
    expect(creds.code).toBe(2);
    expect(creds.err).toContain("harden: --endpoint must not contain credentials");
    expect(creds.out + creds.err).not.toContain("zqpass");
    expect(api.calls.length).toBe(0);
  });

  it("--json carries rrs_gate { result: error } when the Assessment was not queued, and exits 1", async () => {
    const d = bundle();
    vi.stubGlobal("fetch", async (url: string) =>
      String(url).endsWith("/builds")
        ? new Response(JSON.stringify({ build: EXAMPLE_BUILD }), { status: 201 })
        : new Response(JSON.stringify({ title: "Bad Request", detail: "The artifact does not match." }), {
            status: 400,
          }),
    );
    const r = await run(
      ["harden", d, "--seed", "1", "--json", ...register, "--assess", "T1", "--min-rrs", "10"],
      fakeApi([SCORED]),
      { cwd: d },
    );
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).rrs_gate).toEqual({
      result: "error",
      reason: "the Assessment was not queued: The artifact does not match.",
    });
  });

  it("--json carries rrs_gate { result: error } when a poll stops the wait", async () => {
    const d = bundle();
    const r = await run(
      ["harden", d, "--seed", "1", "--json", ...register, "--assess", "T3", "--min-rrs", "10"],
      fakeApi([{ status: 404 }]),
      { cwd: d, global: true },
    );
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).rrs_gate).toEqual({
      result: "error",
      reason: "cannot read the Assessment: the API responded 404",
    });
  });

  it("writes --out before waiting, so the files exist while waiting and when the gate fails or times out", async () => {
    const d = bundle();
    const out = join(d, "..", `${d.split("/").pop()}-out`);
    temps.push(out);
    const seen: boolean[] = [];
    const onSleep = () => {
      seen.push(existsSync(join(out, "a.mjs")));
    };
    const argv = ["harden", d, "--seed", "1", "--out", out, ...register, "--assess", "T3"];
    const timedOut = await run([...argv, "--min-rrs", "10", "--wait", "3"], fakeApi([RUNNING]), {
      cwd: d,
      global: true,
      onSleep,
    });
    expect(timedOut.code).toBe(6);
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every(Boolean)).toBe(true);
    rmSync(out, { recursive: true, force: true });
    const below = await run([...argv, "--min-rrs", String(RRS + 1)], fakeApi([SCORED]), { cwd: d, global: true });
    expect(below.code).toBe(5);
    expect(existsSync(join(out, "a.mjs"))).toBe(true);
  });

  it("a 404 while waiting exits 1; the Build stays registered", async () => {
    const d = bundle();
    const r = await run(
      ["harden", d, "--seed", "1", ...register, "--assess", "T3", "--min-rrs", "10"],
      fakeApi([{ status: 404 }]),
      { cwd: d, global: true },
    );
    expect(r.code).toBe(1);
    expect(r.err).toContain("harden: cannot read the Assessment: the API responded 404");
    expect(r.err).toContain(`the Build stays registered (${EXAMPLE_BUILD.build_id})`);
  });

  it("with --fail-on: findings (4) win over the RRS gate (5) and both gates are reported", async () => {
    const d = bundle();
    const r = await run(
      ["harden", d, "--seed", "1", ...register, "--fail-on", "high", "--assess", "T3", "--min-rrs", String(RRS + 1)],
      fakeApi([SCORED], { findings: FAILING_FINDINGS }),
      { cwd: d, global: true },
    );
    expect(r.code).toBe(4);
    expect(r.out).toContain("✗ 1 open finding at or above high");
    expect(r.out).toContain(`✗ RRS ${RRS} is below --min-rrs ${RRS + 1}`);
    expect(r.err).toContain("harden: findings gate failed");
    expect(r.err).toContain("harden: RRS gate failed");
  });

  it("with --fail-on: findings (4) win over no score (6); both in --json", async () => {
    const d = bundle();
    const r = await run(
      ["harden", d, "--seed", "1", "--json", ...register, "--fail-on", "high", "--assess", "T3", "--min-rrs", "10"],
      fakeApi([INCONCLUSIVE], { findings: FAILING_FINDINGS }),
      { cwd: d, global: true },
    );
    expect(r.code).toBe(4);
    const report = JSON.parse(r.out);
    expect(report.gate.passed).toBe(false);
    expect(report.rrs_gate.result).toBe("no_score");
  });

  it("with --fail-on passing, the RRS gate decides (exit 5)", async () => {
    const d = bundle();
    const r = await run(
      ["harden", d, "--seed", "1", ...register, "--fail-on", "high", "--assess", "T3", "--min-rrs", String(RRS + 1)],
      fakeApi([SCORED], { findings: CLEAN_FINDINGS }),
      { cwd: d, global: true },
    );
    expect(r.code).toBe(5);
    expect(r.out).toContain("✓ no open findings at or above high");
  });
});
