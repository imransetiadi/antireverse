// @vitest-environment node
import {
  EXAMPLE_POLICY,
  EXAMPLE_SIMULATION_RESULT,
  type Policy,
  type PolicyRule,
  type PolicyRuleInput,
  type SimulationResult,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The simulation action (slice 11) through its interface, with the API client, the session, the cache and the
// navigation replaced by fakes. It reads the Policy and asks for an estimate; it never publishes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  getPolicy: vi.fn(),
  publishPolicy: vi.fn(),
  rollbackPolicy: vi.fn(),
  simulatePolicy: vi.fn(),
}));
vi.mock("@/lib/session.ts", () => ({
  SESSION_COOKIE: "ar_admin",
  readSession: vi.fn(),
  writeSession: vi.fn(),
  clearSession: vi.fn(),
}));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import { revalidatePath } from "next/cache";
import { simulatePolicyAction } from "@/app/actions.ts";
import { ruleFingerprint } from "@/features/policy/simulation.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const appId = EXAMPLE_POLICY.app_id;
const [enforced, monitored] = EXAMPLE_POLICY.rules as [PolicyRule, PolicyRule];
const READ = 4;
const SHOWN = { appId, environment: "development", expectedVersion: String(READ) };

const STALE = "This Policy changed since the page was loaded, so nothing was simulated. Reload the page and try again.";
const DOWN = "The Airverse API did not answer, so nothing was simulated. Check that it is running, then try again.";
const FAILED = "The Airverse API reported a problem, so nothing was simulated. Try again in a moment.";

function form(fields: Record<string, string | string[]>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) {
    for (const entry of Array.isArray(value) ? value : [value]) data.append(name, entry);
  }
  return data;
}
function policy(overrides: Partial<Policy> = {}): Policy {
  return { ...EXAMPLE_POLICY, version: READ, ...overrides };
}
/** A result with one row per Rule sent, as the API answers. */
function resultFor(count: number): SimulationResult {
  const [row] = EXAMPLE_SIMULATION_RESULT.rules;
  if (!row) throw new Error("no row");
  const { id: _id, ...plain } = row;
  return {
    ...EXAMPLE_SIMULATION_RESULT,
    rules: Array.from({ length: count }, (_, index) => ({ ...plain, index })),
    totals: { would_refuse: 40, clients_affected: 3, unknown_client_events: 0 },
  };
}
function signedIn(current: Policy = policy()): void {
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(api.getPolicy).mockResolvedValue({ policy: current });
  vi.mocked(api.simulatePolicy).mockImplementation(async (_key, _app, _environment, rules) => ({
    simulation: resultFor(rules.length),
  }));
}
const draft = { ...SHOWN, simulate: "draft", name: "  Login  ", path: " /login ", methods: ["POST", "GET"] };

beforeEach(() => {
  vi.mocked(api.getPolicy).mockReset();
  vi.mocked(api.publishPolicy).mockReset();
  vi.mocked(api.rollbackPolicy).mockReset();
  vi.mocked(api.simulatePolicy).mockReset();
  vi.mocked(session.readSession).mockReset();
  vi.mocked(revalidatePath).mockReset();
});

describe("simulatePolicyAction", () => {
  it("simulates the Rules of the Policy as the page showed them, and publishes nothing", async () => {
    signedIn();
    const state = await simulatePolicyAction(null, form(SHOWN));
    expect(api.getPolicy).toHaveBeenCalledWith(admin.key, appId, "development");
    expect(api.simulatePolicy).toHaveBeenCalledTimes(1);
    expect(api.simulatePolicy).toHaveBeenCalledWith(admin.key, appId, "development", [enforced, monitored]);
    expect(state).toEqual({
      ok: true,
      withDraft: false,
      simulation: resultFor(2),
      // What was simulated, Rule by Rule: the page shows a Rule's figures only while the Rule is the same.
      rules: [ruleFingerprint(enforced), ruleFingerprint(monitored)],
    });
    expect(api.publishPolicy).not.toHaveBeenCalled();
    expect(api.rollbackPolicy).not.toHaveBeenCalled();
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("simulates the current Rules plus the Rule being typed, in Monitor mode and without an id", async () => {
    signedIn();
    const state = await simulatePolicyAction(null, form(draft));
    const typed: PolicyRuleInput = {
      name: "Login",
      path: "/login",
      methods: ["GET", "POST"],
      action: "block",
      mode: "monitor",
    };
    expect(api.simulatePolicy).toHaveBeenCalledWith(admin.key, appId, "development", [enforced, monitored, typed]);
    expect(state).toEqual({
      ok: true,
      withDraft: true,
      simulation: resultFor(3),
      rules: [ruleFingerprint(enforced), ruleFingerprint(monitored), ruleFingerprint(typed)],
      // What was typed goes back, so that the form still holds it.
      values: { name: "Login", path: "/login", methods: ["GET", "POST"], requires: false },
    });
    expect(api.publishPolicy).not.toHaveBeenCalled();
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("simulates a typed Rule with a requirement, and one with a limit", async () => {
    signedIn();
    await simulatePolicyAction(null, form({ ...draft, requires: "signature" }));
    expect(vi.mocked(api.simulatePolicy).mock.calls.at(-1)?.[3].at(-1)).toEqual({
      name: "Login",
      path: "/login",
      methods: ["GET", "POST"],
      action: "block",
      mode: "monitor",
      requires: "signature",
    });
    const limited = { limitRequests: "10", limitWindow: "300", limitKey: "ip", limitCount: "failures" };
    const state = await simulatePolicyAction(null, form({ ...draft, action: "throttle", ...limited }));
    expect(vi.mocked(api.simulatePolicy).mock.calls.at(-1)?.[3].at(-1)).toEqual({
      name: "Login",
      path: "/login",
      methods: ["GET", "POST"],
      action: "throttle",
      mode: "monitor",
      limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
    });
    expect(state?.values).toEqual({
      name: "Login",
      path: "/login",
      methods: ["GET", "POST"],
      requires: false,
      action: "throttle",
      limit: { requests: "10", window: "300", key: "ip", count: "failures" },
    });
  });

  it("refuses a typed Rule the form would refuse, below its fields, and asks the API nothing", async () => {
    signedIn();
    const state = await simulatePolicyAction(null, form({ ...draft, name: " ", path: "login" }));
    expect(state).toEqual({
      ok: false,
      withDraft: true,
      errors: [
        { path: "name", message: "Enter a name." },
        {
          path: "path",
          message:
            "Start with / and use only letters, digits and . _ ~ - in a segment. * stands for one whole segment; ** is allowed only at the end.",
        },
      ],
      values: { name: "", path: "login", methods: ["GET", "POST"], requires: false },
    });
    expect(api.getPolicy).not.toHaveBeenCalled();
    expect(api.simulatePolicy).not.toHaveBeenCalled();
  });

  it("does not simulate a 51st Rule", async () => {
    const full = Array.from({ length: 50 }, (_, n) => ({ ...monitored, id: `rul_${String(n).padStart(24, "0")}` }));
    signedIn(policy({ rules: full }));
    const state = await simulatePolicyAction(null, form(draft));
    expect(state?.ok).toBe(false);
    expect(state?.ok === false && state.errors).toEqual([
      { path: "", message: "A Policy holds at most 50 Rules. Remove one before adding another." },
    ]);
    expect(api.simulatePolicy).not.toHaveBeenCalled();
  });

  it("simulates nothing when the Policy is no longer the version the page showed", async () => {
    signedIn(policy({ version: READ + 1 }));
    expect(await simulatePolicyAction(null, form(SHOWN))).toEqual({
      ok: false,
      withDraft: false,
      errors: [{ path: "", message: STALE }],
    });
    expect(api.simulatePolicy).not.toHaveBeenCalled();
  });

  it.each([
    ["no App", { ...SHOWN, appId: "nope" }],
    ["an unknown Environment", { ...SHOWN, environment: "moon" }],
    ["no version", { appId, environment: "development" }],
    ["a simulate value this screen never sends", { ...SHOWN, simulate: "everything" }],
  ])("simulates nothing for a form with %s", async (_name, fields) => {
    signedIn();
    const state = await simulatePolicyAction(null, form(fields));
    expect(state?.ok === false && state.errors).toEqual([{ path: "", message: STALE }]);
    expect(api.getPolicy).not.toHaveBeenCalled();
    expect(api.simulatePolicy).not.toHaveBeenCalled();
  });

  it("says how long to wait when there were too many simulations", async () => {
    signedIn();
    vi.mocked(api.simulatePolicy).mockRejectedValue(new api.RateLimitedError("limited", 42));
    expect(await simulatePolicyAction(null, form(SHOWN))).toEqual({
      ok: false,
      withDraft: false,
      errors: [{ path: "", message: "Too many simulations. Try again in 42 s." }],
    });
    vi.mocked(api.simulatePolicy).mockRejectedValue(new api.RateLimitedError("limited", undefined));
    const state = await simulatePolicyAction(null, form(SHOWN));
    expect(state?.ok === false && state.errors).toEqual([
      { path: "", message: "Too many simulations. Try again in a moment." },
    ]);
  });

  it("puts a refusal of the typed Rule below its field, and never shows the API's own words", async () => {
    signedIn();
    vi.mocked(api.simulatePolicy).mockRejectedValue(
      new api.ValidationError("refused", [
        { path: "rules.2.path", message: "secret words of the API" },
        { path: "rules.0.path", message: "about another Rule" },
      ]),
    );
    const state = await simulatePolicyAction(null, form(draft));
    expect(state?.ok === false && state.errors).toEqual([
      {
        path: "path",
        message:
          "Start with / and use only letters, digits and . _ ~ - in a segment. * stands for one whole segment; ** is allowed only at the end.",
      },
    ]);
    // A refusal that is about nothing the form shows is a failure of the simulation as a whole.
    vi.mocked(api.simulatePolicy).mockRejectedValue(
      new api.ValidationError("refused", [{ path: "rules.0.path", message: "about another Rule" }]),
    );
    const other = await simulatePolicyAction(null, form(SHOWN));
    expect(other?.ok === false && other.errors).toEqual([{ path: "", message: FAILED }]);
  });

  it("says that nothing was simulated when the API is down, fails, or no longer has the App", async () => {
    signedIn();
    vi.mocked(api.simulatePolicy).mockRejectedValue(new api.ApiError("down", 0));
    const down = await simulatePolicyAction(null, form(SHOWN));
    expect(down?.ok === false && down.errors).toEqual([{ path: "", message: DOWN }]);
    vi.mocked(api.simulatePolicy).mockRejectedValue(new api.ApiError("boom", 500));
    const failed = await simulatePolicyAction(null, form(SHOWN));
    expect(failed?.ok === false && failed.errors).toEqual([{ path: "", message: FAILED }]);
    vi.mocked(api.simulatePolicy).mockRejectedValue(new api.NotFoundError("gone"));
    const gone = await simulatePolicyAction(null, form(SHOWN));
    expect(gone?.ok === false && gone.errors).toEqual([{ path: "", message: STALE }]);
    vi.mocked(api.getPolicy).mockRejectedValue(new api.ApiError("down", 0));
    const unread = await simulatePolicyAction(null, form(SHOWN));
    expect(unread?.ok === false && unread.errors).toEqual([{ path: "", message: DOWN }]);
  });

  it("goes to sign-in when the session ended, and home without one", async () => {
    signedIn();
    vi.mocked(api.simulatePolicy).mockRejectedValue(new api.UnauthorizedError("expired"));
    await expect(simulatePolicyAction(null, form(SHOWN))).rejects.toThrow("REDIRECT /sign-in?reason=expired");
    vi.mocked(session.readSession).mockResolvedValue(undefined);
    vi.mocked(api.simulatePolicy).mockClear();
    await expect(simulatePolicyAction(null, form(SHOWN))).rejects.toThrow("REDIRECT /");
    expect(api.simulatePolicy).not.toHaveBeenCalled();
  });

  it("rethrows what is not an answer of the API: a defect is not turned into a message", async () => {
    signedIn();
    vi.mocked(api.simulatePolicy).mockRejectedValue(new TypeError("defect"));
    await expect(simulatePolicyAction(null, form(SHOWN))).rejects.toThrow("defect");
  });
});
