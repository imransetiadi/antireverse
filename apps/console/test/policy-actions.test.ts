// @vitest-environment node
import { EXAMPLE_POLICY, type Policy, type PolicyRule } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The Policy actions are exercised through their interface with the API client, the session, the cache
// and the navigation replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  getPolicy: vi.fn(),
  getPolicyVersion: vi.fn(),
  publishPolicy: vi.fn(),
  rollbackPolicy: vi.fn(),
}));
vi.mock("@/lib/session.ts", () => ({
  SESSION_COOKIE: "ar_admin",
  readSession: vi.fn(),
  writeSession: vi.fn(),
  clearSession: vi.fn(),
}));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
// redirect() never returns: the real one throws a control-flow signal, and so does this one.
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import { revalidatePath } from "next/cache";
import { publishRuleAction, removeRuleAction, rollbackPolicyAction, setRuleModeAction } from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const appId = EXAMPLE_POLICY.app_id;
const [enforced, monitored] = EXAMPLE_POLICY.rules as [PolicyRule, PolicyRule];
const PAGE = `/apps/${appId}/policy`;
/** The version the page showed and the API holds by default: it goes back as the `expected_version`. */
const READ = 4;
/** What every Policy form carries: the version the page showed. */
const SHOWN = { expectedVersion: String(READ) };

const GUARDRAIL = "A Rule that blocks every request cannot be enforced.";
const BROAD_UNCONFIRMED =
  "This pattern matches most of the App's requests and needs the stronger confirmation. Nothing was published. Reload the page and confirm again.";
const typedMismatch = (environment: string) =>
  `Nothing was published. Type ${environment} exactly as shown to confirm.`;
const STALE = "This Policy changed while you were editing it, so nothing was saved. Reload the page and try again.";
const UNCONFIRMED = "Nothing was published. Confirm the change first.";
const API_DOWN = "The Anti Reverse API did not answer, so nothing was saved. Check that it is running, then try again.";
const API_FAILED = "The Anti Reverse API reported a problem, so nothing was saved. Try again in a moment.";

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
function signedIn(current: Policy = policy()): void {
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(api.getPolicy).mockResolvedValue({ policy: current });
  vi.mocked(api.publishPolicy).mockResolvedValue({ policy: { ...current, version: current.version + 1 } });
  vi.mocked(api.rollbackPolicy).mockResolvedValue({ policy: { ...current, version: current.version + 1 } });
  // The version a rollback brings back: by default the same Rules, nothing broad.
  vi.mocked(api.getPolicyVersion).mockImplementation(async (_key, _app, _environment, version) => ({
    policy: { ...current, version },
  }));
}

beforeEach(() => {
  vi.mocked(api.getPolicy).mockReset();
  vi.mocked(api.getPolicyVersion).mockReset();
  vi.mocked(api.publishPolicy).mockReset();
  vi.mocked(api.rollbackPolicy).mockReset();
  vi.mocked(session.readSession).mockReset();
  vi.mocked(revalidatePath).mockReset();
});

describe("publishRuleAction", () => {
  const fields = {
    appId,
    environment: "development",
    name: "  Login  ",
    path: " /login ",
    methods: ["POST", "GET"],
    ...SHOWN,
  };

  it("appends the Rule in Monitor mode, publishes the full Rule list and goes back to the Policy", async () => {
    signedIn();
    await expect(publishRuleAction(null, form(fields))).rejects.toThrow(`REDIRECT ${PAGE}?environment=development`);
    expect(api.getPolicy).toHaveBeenCalledWith(admin.key, appId, "development");
    expect(api.publishPolicy).toHaveBeenCalledTimes(1);
    // The existing Rules travel unchanged, id included, so that the API keeps them; the new one has no id.
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "development",
      [
        enforced,
        monitored,
        { name: "Login", path: "/login", methods: ["GET", "POST"], action: "block", mode: "monitor" },
      ],
      READ,
    );
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
  });

  it("means every method when none is checked", async () => {
    signedIn(policy({ environment: "production", rules: [] }));
    const { methods: _none, ...rest } = fields;
    await expect(publishRuleAction(null, form({ ...rest, environment: "production" }))).rejects.toThrow(
      `REDIRECT ${PAGE}?environment=production`,
    );
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "production",
      [{ name: "Login", path: "/login", methods: [], action: "block", mode: "monitor" }],
      READ,
    );
  });

  it("starts a Rule in Monitor mode whatever the form claims", async () => {
    signedIn(policy({ rules: [] }));
    await expect(publishRuleAction(null, form({ ...fields, mode: "enforce", confirm: "development" }))).rejects.toThrow(
      "REDIRECT",
    );
    expect(vi.mocked(api.publishPolicy).mock.calls[0]?.[3]).toMatchObject([{ mode: "monitor" }]);
  });

  it("passes Require a signed request through as requires: signature, still a block Rule in Monitor mode", async () => {
    signedIn();
    await expect(publishRuleAction(null, form({ ...fields, requires: "signature" }))).rejects.toThrow(
      `REDIRECT ${PAGE}?environment=development`,
    );
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "development",
      [
        enforced,
        monitored,
        {
          name: "Login",
          path: "/login",
          methods: ["GET", "POST"],
          action: "block",
          mode: "monitor",
          requires: "signature",
        },
      ],
      READ,
    );
  });

  it("sends no requires at all when the box is not checked", async () => {
    signedIn(policy({ rules: [] }));
    await expect(publishRuleAction(null, form(fields))).rejects.toThrow("REDIRECT");
    const [rule] = vi.mocked(api.publishPolicy).mock.calls[0]?.[3] ?? [];
    expect(rule && "requires" in rule).toBe(false);
  });

  it("refuses a requirement this screen does not offer, as a stale form, without calling the API", async () => {
    signedIn();
    const state = await publishRuleAction(null, form({ ...fields, requires: "captcha" }));
    expect(state).toMatchObject({ ok: false, errors: [{ path: "", message: STALE }] });
    expect(api.getPolicy).not.toHaveBeenCalled();
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("gives the requirement back with a refusal, so the box stays checked", async () => {
    signedIn();
    const state = await publishRuleAction(null, form({ ...fields, path: "", requires: "signature" }));
    expect(state).toMatchObject({ ok: false, values: { requires: true } });
    const plain = await publishRuleAction(null, form({ ...fields, path: "" }));
    expect(plain).toMatchObject({ ok: false, values: { requires: false } });
  });

  it("requires a session: without one it goes to / and never calls the API", async () => {
    vi.mocked(session.readSession).mockResolvedValue(undefined);
    await expect(publishRuleAction(null, form(fields))).rejects.toThrow("REDIRECT /");
    expect(api.getPolicy).not.toHaveBeenCalled();
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("goes to sign-in when the API no longer accepts the session's key", async () => {
    signedIn();
    vi.mocked(api.getPolicy).mockRejectedValue(new api.UnauthorizedError("no"));
    await expect(publishRuleAction(null, form(fields))).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });

  it.each([
    ["an empty name", { name: " " }, { path: "name", message: "Enter a name." }],
    ["a name of 81 characters", { name: "n".repeat(81) }, { path: "name", message: "Use 80 characters or fewer." }],
    ["an empty path pattern", { path: "" }, { path: "path", message: "Enter a path pattern." }],
    ["a pattern without a leading slash", { path: "api/admin" }, { path: "path" }],
    ["a pattern with ** in the middle", { path: "/a/**/b" }, { path: "path" }],
    ["a pattern with a query string", { path: "/a?x=1" }, { path: "path" }],
    ["a method outside the five", { methods: ["GET", "TRACE"] }, { path: "methods" }],
  ])("refuses %s next to its field without calling the API", async (_label, change, expected) => {
    signedIn();
    const state = await publishRuleAction(null, form({ ...fields, ...change }));
    expect(state).toMatchObject({ ok: false, errors: [expected] });
    expect(state?.errors).toHaveLength(1);
    expect(api.getPolicy).not.toHaveBeenCalled();
    expect(api.publishPolicy).not.toHaveBeenCalled();
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("gives the typed values back with a refusal", async () => {
    signedIn();
    const state = await publishRuleAction(null, form({ ...fields, path: "api/admin" }));
    expect(state).toMatchObject({ ok: false, values: { name: "Login", path: "api/admin", methods: ["GET", "POST"] } });
  });

  it("reports what the API refused next to the field of the new Rule", async () => {
    signedIn();
    vi.mocked(api.publishPolicy).mockRejectedValue(
      new api.ValidationError("refused", [
        { path: "rules.2.path", message: "Must be a path pattern" },
        { path: "rules.2.name", message: "Too big" },
        { path: "rules.2.methods.0", message: "Invalid" },
      ]),
    );
    const state = await publishRuleAction(null, form(fields));
    expect(state).toMatchObject({ ok: false, values: { name: "Login", path: "/login" } });
    expect(state?.errors.map((error) => error.path)).toEqual(["path", "name", "methods"]);
    // The API's own words are never shown: every message comes from the catalog.
    expect(JSON.stringify(state)).not.toContain("Must be a path pattern");
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("does not blame a field for a refusal about another Rule", async () => {
    signedIn();
    vi.mocked(api.publishPolicy).mockRejectedValue(
      new api.ValidationError("refused", [{ path: "rules.0.path", message: "Must be a path pattern" }]),
    );
    const state = await publishRuleAction(null, form(fields));
    expect(state?.errors).toEqual([{ path: "", message: API_FAILED }]);
  });

  it("refuses a 51st Rule without publishing", async () => {
    const rules = Array.from({ length: 50 }, (_unused, n) => ({
      ...monitored,
      id: `rul_${n.toString(16).padStart(24, "0")}`,
    }));
    signedIn(policy({ rules }));
    const state = await publishRuleAction(null, form(fields));
    expect(state?.errors).toEqual([
      { path: "", message: "A Policy holds at most 50 Rules. Remove one before adding another." },
    ]);
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("says what failed and what to do when the API does not answer", async () => {
    signedIn();
    vi.mocked(api.publishPolicy).mockRejectedValue(new api.ApiError("unreachable", 0));
    const state = await publishRuleAction(null, form(fields));
    expect(state?.errors).toEqual([{ path: "", message: API_DOWN }]);
  });

  it.each([
    ["an unknown Environment", { environment: "moon" }],
    ["a value that is not an App identifier", { appId: "app_1/../x" }],
  ])("refuses %s without calling the API", async (_label, change) => {
    signedIn();
    const state = await publishRuleAction(null, form({ ...fields, ...change }));
    expect(state?.errors).toEqual([{ path: "", message: STALE }]);
    expect(api.getPolicy).not.toHaveBeenCalled();
  });
});

describe("setRuleModeAction", () => {
  const promote = { appId, environment: "development", ruleId: monitored.id, mode: "enforce", ...SHOWN };
  const demote = { appId, environment: "development", ruleId: enforced.id, mode: "monitor", ...SHOWN };

  it("promotes only that Rule when the confirmation names the Environment, and publishes", async () => {
    signedIn();
    await expect(setRuleModeAction(null, form({ ...promote, confirm: "development" }))).rejects.toThrow(
      `REDIRECT ${PAGE}?environment=development`,
    );
    expect(api.publishPolicy).toHaveBeenCalledTimes(1);
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "development",
      [enforced, { ...monitored, mode: "enforce" }],
      READ,
    );
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
  });

  it("keeps the requirement of a Rule when it is promoted or put back to Monitor", async () => {
    const signedOnly: PolicyRule = { ...monitored, requires: "signature" };
    signedIn(policy({ rules: [enforced, signedOnly] }));
    await expect(setRuleModeAction(null, form({ ...promote, confirm: "development" }))).rejects.toThrow("REDIRECT");
    expect(vi.mocked(api.publishPolicy).mock.calls[0]?.[3]).toEqual([enforced, { ...signedOnly, mode: "enforce" }]);

    vi.mocked(api.publishPolicy).mockClear();
    const enforcedSigned: PolicyRule = { ...enforced, requires: "signature" };
    signedIn(policy({ rules: [enforcedSigned, monitored] }));
    await expect(setRuleModeAction(null, form(demote))).rejects.toThrow("REDIRECT");
    expect(vi.mocked(api.publishPolicy).mock.calls[0]?.[3]).toEqual([
      { ...enforcedSigned, mode: "monitor" },
      monitored,
    ]);
  });

  it.each([
    ["no confirmation", {}],
    ["an empty confirmation", { confirm: "" }],
    ["the confirmation of another Environment", { confirm: "production" }],
    ["a confirmation that is not an Environment", { confirm: "yes" }],
  ])("refuses to promote with %s and never calls the API", async (_label, confirmation) => {
    signedIn();
    const state = await setRuleModeAction(null, form({ ...promote, ...confirmation }));
    expect(state).toEqual({ ok: false, errors: [{ path: "confirm", message: UNCONFIRMED }] });
    expect(api.getPolicy).not.toHaveBeenCalled();
    expect(api.publishPolicy).not.toHaveBeenCalled();
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("puts a Rule back to Monitor without a confirmation: that reduces enforcement", async () => {
    signedIn();
    await expect(setRuleModeAction(null, form(demote))).rejects.toThrow(`REDIRECT ${PAGE}?environment=development`);
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "development",
      [{ ...enforced, mode: "monitor" }, monitored],
      READ,
    );
  });

  it("shows the guardrail when the API refuses to enforce the Rule", async () => {
    signedIn();
    vi.mocked(api.publishPolicy).mockRejectedValue(
      new api.ValidationError("refused", [{ path: "rules.1.mode", message: "Would block every request" }]),
    );
    const state = await setRuleModeAction(null, form({ ...promote, confirm: "development" }));
    expect(state).toEqual({ ok: false, errors: [{ path: "mode", message: GUARDRAIL }] });
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("shows the guardrail for a Rule on /** without asking the API to publish it", async () => {
    signedIn(policy({ rules: [enforced, { ...monitored, path: "/**" }] }));
    const state = await setRuleModeAction(null, form({ ...promote, confirm: "development" }));
    expect(state).toEqual({ ok: false, errors: [{ path: "mode", message: GUARDRAIL }] });
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("publishes nothing when the Rule already has that mode", async () => {
    signedIn();
    await expect(setRuleModeAction(null, form({ ...demote, ruleId: monitored.id }))).rejects.toThrow(
      `REDIRECT ${PAGE}?environment=development`,
    );
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("says the Policy changed when the Rule is no longer part of it", async () => {
    signedIn(policy({ rules: [enforced] }));
    const state = await setRuleModeAction(null, form({ ...promote, confirm: "development" }));
    expect(state).toEqual({ ok: false, errors: [{ path: "", message: STALE }] });
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it.each([
    ["a mode that does not exist", { mode: "block" }],
    ["a value that is not a Rule identifier", { ruleId: "rul_1" }],
    ["an unknown Environment", { environment: "moon", confirm: "moon" }],
  ])("refuses %s without calling the API", async (_label, change) => {
    signedIn();
    const state = await setRuleModeAction(null, form({ ...promote, confirm: "development", ...change }));
    expect(state).toEqual({ ok: false, errors: [{ path: "", message: STALE }] });
    expect(api.getPolicy).not.toHaveBeenCalled();
  });

  it("requires a session", async () => {
    vi.mocked(session.readSession).mockResolvedValue(undefined);
    await expect(setRuleModeAction(null, form({ ...promote, confirm: "development" }))).rejects.toThrow("REDIRECT /");
    expect(api.getPolicy).not.toHaveBeenCalled();
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("goes to sign-in when the API no longer accepts the session's key", async () => {
    signedIn();
    vi.mocked(api.publishPolicy).mockRejectedValue(new api.UnauthorizedError("no"));
    await expect(setRuleModeAction(null, form(demote))).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });

  it("says what failed when the API does not answer or the App is not the caller's", async () => {
    signedIn();
    vi.mocked(api.getPolicy).mockRejectedValueOnce(new api.ApiError("unreachable", 0));
    expect(await setRuleModeAction(null, form(demote))).toEqual({
      ok: false,
      errors: [{ path: "", message: API_DOWN }],
    });
    vi.mocked(api.getPolicy).mockRejectedValueOnce(new api.NotFoundError("no"));
    expect(await setRuleModeAction(null, form(demote))).toEqual({ ok: false, errors: [{ path: "", message: STALE }] });
  });
});

describe("removeRuleAction", () => {
  const fields = { appId, environment: "development", ruleId: enforced.id, ...SHOWN };

  it("removes only that Rule and publishes the rest, without a confirmation", async () => {
    signedIn();
    await expect(removeRuleAction(null, form(fields))).rejects.toThrow(`REDIRECT ${PAGE}?environment=development`);
    expect(api.publishPolicy).toHaveBeenCalledTimes(1);
    expect(api.publishPolicy).toHaveBeenCalledWith(admin.key, appId, "development", [monitored], READ);
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
  });

  it("publishes nothing when the Rule is already gone", async () => {
    signedIn(policy({ rules: [monitored] }));
    await expect(removeRuleAction(null, form(fields))).rejects.toThrow(`REDIRECT ${PAGE}?environment=development`);
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("requires a session", async () => {
    vi.mocked(session.readSession).mockResolvedValue(undefined);
    await expect(removeRuleAction(null, form(fields))).rejects.toThrow("REDIRECT /");
    expect(api.getPolicy).not.toHaveBeenCalled();
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("says what failed and what to do when the API does not answer", async () => {
    signedIn();
    vi.mocked(api.publishPolicy).mockRejectedValue(new api.ApiError("boom", 500));
    expect(await removeRuleAction(null, form(fields))).toEqual({
      ok: false,
      errors: [{ path: "", message: API_FAILED }],
    });
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("refuses a value that is not a Rule identifier without calling the API", async () => {
    signedIn();
    expect(await removeRuleAction(null, form({ ...fields, ruleId: "" }))).toEqual({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
    expect(api.getPolicy).not.toHaveBeenCalled();
  });
});

describe("rollbackPolicyAction", () => {
  const fields = { appId, environment: "production", version: "3", confirm: "production", ...SHOWN };

  it("rolls back to the named version when the confirmation names the Environment", async () => {
    signedIn();
    await expect(rollbackPolicyAction(null, form(fields))).rejects.toThrow(`REDIRECT ${PAGE}?environment=production`);
    expect(api.rollbackPolicy).toHaveBeenCalledTimes(1);
    expect(api.getPolicy).toHaveBeenCalledWith(admin.key, appId, "production");
    expect(api.getPolicyVersion).toHaveBeenCalledWith(admin.key, appId, "production", 3);
    // Nothing broad comes back: no acknowledgement is sent.
    expect(api.rollbackPolicy).toHaveBeenCalledWith(admin.key, appId, "production", 3, READ);
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
  });

  it.each([
    ["no confirmation", { confirm: [] as string[] }],
    ["the confirmation of another Environment", { confirm: "development" }],
  ])("refuses to roll back with %s and never calls the API", async (_label, confirmation) => {
    signedIn();
    const state = await rollbackPolicyAction(null, form({ ...fields, ...confirmation }));
    expect(state).toEqual({ ok: false, errors: [{ path: "confirm", message: UNCONFIRMED }] });
    expect(api.rollbackPolicy).not.toHaveBeenCalled();
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it("says the Policy changed when the API does not know the version", async () => {
    signedIn();
    vi.mocked(api.rollbackPolicy).mockRejectedValue(new api.NotFoundError("no"));
    expect(await rollbackPolicyAction(null, form(fields))).toEqual({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
  });

  it.each(["0", "-1", "1.5", "abc", "", "1e3", "99999999999999999999"])(
    "refuses the version %j without calling the API",
    async (version) => {
      signedIn();
      expect(await rollbackPolicyAction(null, form({ ...fields, version }))).toEqual({
        ok: false,
        errors: [{ path: "", message: STALE }],
      });
      expect(api.rollbackPolicy).not.toHaveBeenCalled();
    },
  );

  it("requires a session", async () => {
    vi.mocked(session.readSession).mockResolvedValue(undefined);
    await expect(rollbackPolicyAction(null, form(fields))).rejects.toThrow("REDIRECT /");
    expect(api.rollbackPolicy).not.toHaveBeenCalled();
  });

  it("goes to sign-in when the API no longer accepts the session's key", async () => {
    signedIn();
    vi.mocked(api.rollbackPolicy).mockRejectedValue(new api.UnauthorizedError("no"));
    await expect(rollbackPolicyAction(null, form(fields))).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });

  it("says what failed and what to do when the API does not answer", async () => {
    signedIn();
    vi.mocked(api.rollbackPolicy).mockRejectedValue(new api.ApiError("unreachable", 0));
    expect(await rollbackPolicyAction(null, form(fields))).toEqual({
      ok: false,
      errors: [{ path: "", message: API_DOWN }],
    });
  });
});

describe("a Policy published by someone else in the meantime", () => {
  const conflict = () => new api.ConflictError("PUT /v1/apps/x/policies/development failed with status 409");
  /** The API call an action ends with: what it was called with, and a way to make it fail. */
  interface Sent {
    calls(): unknown[][];
    reject(error: Error): void;
  }
  const publishing: Sent = {
    calls: () => vi.mocked(api.publishPolicy).mock.calls,
    reject: (error) => vi.mocked(api.publishPolicy).mockRejectedValue(error),
  };
  const rollingBack: Sent = {
    calls: () => vi.mocked(api.rollbackPolicy).mock.calls,
    reject: (error) => vi.mocked(api.rollbackPolicy).mockRejectedValue(error),
  };
  const base = { appId, environment: "development", ...SHOWN };
  type Run = (extra?: Record<string, string | string[]>) => Promise<unknown>;
  const cases: Array<[string, Run, Sent]> = [
    [
      "publishRuleAction",
      (extra) => publishRuleAction(null, form({ ...base, name: "Login", path: "/login", ...extra })),
      publishing,
    ],
    [
      "setRuleModeAction",
      (extra) =>
        setRuleModeAction(
          null,
          form({ ...base, ruleId: monitored.id, mode: "enforce", confirm: "development", ...extra }),
        ),
      publishing,
    ],
    [
      "removeRuleAction",
      (extra) => removeRuleAction(null, form({ ...base, ruleId: enforced.id, ...extra })),
      publishing,
    ],
    [
      "rollbackPolicyAction",
      (extra) => rollbackPolicyAction(null, form({ ...base, version: "1", confirm: "development", ...extra })),
      rollingBack,
    ],
  ];

  it.each(cases)("%s sends the version the page showed as the expected version", async (_name, run, call) => {
    signedIn(policy({ version: 17 }));
    await expect(run({ expectedVersion: "17" })).rejects.toThrow(`REDIRECT ${PAGE}?environment=development`);
    expect(call.calls()).toHaveLength(1);
    expect(call.calls()[0]?.[4]).toBe(17);
  });

  it.each(cases)("%s publishes nothing when the Policy moved on since the page showed it", async (_name, run, call) => {
    signedIn(policy({ version: 17 }));
    expect(await run({ expectedVersion: "16" })).toMatchObject({ ok: false, errors: [{ path: "", message: STALE }] });
    expect(call.calls()).toHaveLength(0);
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it.each(cases)(
    "%s refuses a form without a valid shown version, without calling the API",
    async (_name, run, call) => {
      // An empty list leaves the field out of the form altogether.
      for (const expectedVersion of [[], "", "-1", "1.5", "abc", "01", "1e3", "99999999999999999999"]) {
        signedIn();
        expect(await run({ expectedVersion }), String(expectedVersion)).toMatchObject({
          ok: false,
          errors: [{ path: "", message: STALE }],
        });
      }
      expect(call.calls()).toHaveLength(0);
      expect(api.getPolicy).not.toHaveBeenCalled();
    },
  );

  it.each(cases)(
    "%s shows that the Policy changed on a 409, and neither retries nor goes on",
    async (_name, run, call) => {
      signedIn();
      call.reject(conflict());
      const state = await run();
      expect(state).toMatchObject({ ok: false, errors: [{ path: "", message: STALE }] });
      expect(call.calls()).toHaveLength(1);
      expect(api.getPolicy).toHaveBeenCalledTimes(1);
      expect(revalidatePath).not.toHaveBeenCalled();
    },
  );
});

describe("broad Enforce Rules", () => {
  /** A Rule in Monitor mode whose first segment is a wildcard: enforced, it blocks most of the App. */
  const broad: PolicyRule = { ...monitored, path: "/*/export" };
  const promote = {
    appId,
    environment: "production",
    ruleId: broad.id,
    mode: "enforce",
    confirm: "production",
    ...SHOWN,
  };

  it("does not promote a broad Rule without the typed Environment", async () => {
    signedIn(policy({ environment: "production", rules: [enforced, broad] }));
    const state = await setRuleModeAction(null, form(promote));
    expect(state).toEqual({ ok: false, errors: [{ path: "typedEnvironment", message: typedMismatch("production") }] });
    expect(api.publishPolicy).not.toHaveBeenCalled();
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it.each(["Production", " production", "production ", "staging", "prod", "production\n"])(
    "does not promote a broad Rule when %j was typed: the match is exact",
    async (typed) => {
      signedIn(policy({ environment: "production", rules: [enforced, broad] }));
      const state = await setRuleModeAction(null, form({ ...promote, typedEnvironment: typed }));
      expect(state).toEqual({
        ok: false,
        errors: [{ path: "typedEnvironment", message: typedMismatch("production") }],
      });
      expect(api.publishPolicy).not.toHaveBeenCalled();
    },
  );

  it("promotes a broad Rule with the typed Environment, and only then sends allow_broad", async () => {
    signedIn(policy({ environment: "production", rules: [enforced, broad] }));
    await expect(setRuleModeAction(null, form({ ...promote, typedEnvironment: "production" }))).rejects.toThrow(
      `REDIRECT ${PAGE}?environment=production`,
    );
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "production",
      [enforced, { ...broad, mode: "enforce" }],
      READ,
      { allowBroad: true },
    );
  });

  it("never sends allow_broad for a Rule that is not broad, even with a typed Environment", async () => {
    signedIn(policy({ environment: "production" }));
    await expect(
      setRuleModeAction(null, form({ ...promote, ruleId: monitored.id, typedEnvironment: "production" })),
    ).rejects.toThrow("REDIRECT");
    expect(vi.mocked(api.publishPolicy).mock.calls[0]).toHaveLength(5);
  });

  it("adds a broad Rule in Monitor mode with nothing extra", async () => {
    signedIn(policy({ rules: [] }));
    await expect(
      publishRuleAction(null, form({ appId, environment: "development", name: "All", path: "/*", ...SHOWN })),
    ).rejects.toThrow("REDIRECT");
    expect(vi.mocked(api.publishPolicy).mock.calls[0]).toEqual([
      admin.key,
      appId,
      "development",
      [{ name: "All", path: "/*", methods: [], action: "block", mode: "monitor" }],
      READ,
    ]);
  });

  it("keeps a broad Rule that is enforced already: other changes send it on with its earlier acknowledgement", async () => {
    const acknowledged: PolicyRule = { ...broad, mode: "enforce" };
    signedIn(policy({ rules: [enforced, acknowledged] }));
    await expect(
      setRuleModeAction(
        null,
        form({ appId, environment: "development", ruleId: enforced.id, mode: "monitor", ...SHOWN }),
      ),
    ).rejects.toThrow("REDIRECT");
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "development",
      [{ ...enforced, mode: "monitor" }, acknowledged],
      READ,
      { allowBroad: true },
    );
  });

  it("shows the API's refusal of a broad Rule next to the mode of the Rule", async () => {
    signedIn(policy({ environment: "production", rules: [enforced, broad] }));
    vi.mocked(api.publishPolicy).mockRejectedValue(
      new api.ValidationError("refused", [{ path: "rules.1.mode", message: "needs allow_broad" }]),
    );
    const state = await setRuleModeAction(null, form({ ...promote, typedEnvironment: "production" }));
    expect(state).toEqual({ ok: false, errors: [{ path: "mode", message: BROAD_UNCONFIRMED }] });
  });

  describe("rollback", () => {
    const fields = { appId, environment: "production", version: "2", confirm: "production", ...SHOWN };
    function withVersion(rules: PolicyRule[]): void {
      signedIn(policy({ environment: "production", rules: [enforced] }));
      vi.mocked(api.getPolicyVersion).mockResolvedValue({
        policy: policy({ environment: "production", version: 2, rules }),
      });
    }

    it("refuses to bring back a broad Enforce Rule without the typed Environment, or with a wrong one", async () => {
      withVersion([enforced, { ...broad, mode: "enforce" }]);
      for (const typed of [[], "", "Production", "staging"]) {
        expect(await rollbackPolicyAction(null, form({ ...fields, typedEnvironment: typed }))).toEqual({
          ok: false,
          errors: [{ path: "typedEnvironment", message: typedMismatch("production") }],
        });
      }
      expect(api.rollbackPolicy).not.toHaveBeenCalled();
    });

    it("brings back a broad Enforce Rule with the typed Environment, sending allow_broad", async () => {
      withVersion([enforced, { ...broad, mode: "enforce" }]);
      await expect(rollbackPolicyAction(null, form({ ...fields, typedEnvironment: "production" }))).rejects.toThrow(
        `REDIRECT ${PAGE}?environment=production`,
      );
      expect(api.rollbackPolicy).toHaveBeenCalledWith(admin.key, appId, "production", 2, READ, { allowBroad: true });
    });

    it("needs nothing typed for a version whose broad Rules are in Monitor mode", async () => {
      withVersion([enforced, broad]);
      await expect(rollbackPolicyAction(null, form(fields))).rejects.toThrow("REDIRECT");
      expect(api.rollbackPolicy).toHaveBeenCalledWith(admin.key, appId, "production", 2, READ);
    });

    it("shows the API's refusal of a broad Rule next to the mode", async () => {
      withVersion([{ ...broad, mode: "enforce" }]);
      vi.mocked(api.rollbackPolicy).mockRejectedValue(
        new api.ValidationError("refused", [{ path: "rules.0.mode", message: "needs allow_broad" }]),
      );
      expect(await rollbackPolicyAction(null, form({ ...fields, typedEnvironment: "production" }))).toEqual({
        ok: false,
        errors: [{ path: "mode", message: BROAD_UNCONFIRMED }],
      });
    });

    it("says the Policy changed when the version to bring back is not there", async () => {
      withVersion([]);
      vi.mocked(api.getPolicyVersion).mockRejectedValue(new api.NotFoundError("no"));
      expect(await rollbackPolicyAction(null, form(fields))).toEqual({
        ok: false,
        errors: [{ path: "", message: STALE }],
      });
      expect(api.rollbackPolicy).not.toHaveBeenCalled();
    });
  });
});
