// @vitest-environment node
import {
  EXAMPLE_AUDIT_ENTRY,
  EXAMPLE_POLICY,
  EXAMPLE_SIGNED_AUDIT_HEAD,
  EXAMPLE_TARGET,
  type Policy,
  type PolicyRule,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { loadAuditPage } from "@/features/audit/load.ts";
import { dropReason } from "./helpers/reason.ts";

// Slice 18a: the reason of a sensitive change. Every sensitive action asks for it before anything is sent,
// forwards it to the API client (which sends it as the encoded header), and explains the API's reason-required.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  getPolicy: vi.fn(),
  getPolicyVersion: vi.fn(),
  publishPolicy: vi.fn(),
  rollbackPolicy: vi.fn(),
  setPatchMode: vi.fn(),
  createContainment: vi.fn(),
  deleteTarget: vi.fn(),
  signRulesOfEngagement: vi.fn(),
  listAudit: vi.fn(),
  verifyAudit: vi.fn(),
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

import {
  createContainmentAction,
  deleteTargetAction,
  loadMoreAuditAction,
  rollbackPolicyAction,
  setPatchModeAction,
  setRuleModeAction,
  signRulesOfEngagementAction,
  verifyAuditChainAction,
} from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const appId = EXAMPLE_POLICY.app_id;
const [enforced, monitored] = EXAMPLE_POLICY.rules as [PolicyRule, PolicyRule];
const READ = 4;
const REASON = "Credential stuffing on /login since 08:40";

const REQUIRED = "Nothing was saved. Give a reason for this change; it is recorded in the audit log.";
const LONG = "Nothing was saved. Keep the reason to 500 characters or fewer.";
const INVALID = "Nothing was saved. The reason must be one line, without control, direction or zero width characters.";
const SECRET = "Nothing was saved. The reason must not contain a key, a token, a secret or an email address.";
const REFUSED = "The API did not accept this reason, so nothing was saved. Use 1 to 500 characters on one line.";

function form(fields: Record<string, string | string[]>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) {
    for (const one of Array.isArray(value) ? value : [value]) data.append(name, one);
  }
  return data;
}
const policy = (overrides: Partial<Policy> = {}): Policy => ({ ...EXAMPLE_POLICY, version: READ, ...overrides });
const missing = () => new api.ReasonRequiredError("POST failed with status 400: Reason required");
const refusedHeader = () =>
  new api.ValidationError("400", [{ path: "headers.x-airverse-reason", message: "Invalid encoding" }]);

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(api.getPolicy).mockResolvedValue({ policy: policy() });
  vi.mocked(api.publishPolicy).mockResolvedValue({ policy: policy({ version: READ + 1 }) });
  vi.mocked(api.rollbackPolicy).mockResolvedValue({ policy: policy({ version: READ + 1 }) });
});

describe("setRuleModeAction — reason", () => {
  const promote = {
    appId,
    environment: "development",
    ruleId: monitored.id,
    mode: "enforce",
    expectedVersion: String(READ),
    confirm: "development",
  };

  it("forwards the trimmed reason with the promotion", async () => {
    await expect(setRuleModeAction(null, form({ ...promote, reason: `  ${REASON}  ` }))).rejects.toThrow("REDIRECT");
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "development",
      [enforced, { ...monitored, mode: "enforce" }],
      READ,
      { reason: REASON },
    );
  });

  it.each([
    ["no reason", {}, REQUIRED],
    ["a blank reason", { reason: "   " }, REQUIRED],
    ["a reason over 500 characters", { reason: "x".repeat(501) }, LONG],
    ["a reason with a line break", { reason: "one\ntwo" }, INVALID],
    ["a reason with a bidi override", { reason: "evil \u202Etxt.exe" }, INVALID],
    ["a reason with a zero-width space", { reason: "zero\u200Bwidth" }, INVALID],
    // The protocol's `holdsSecretShape`, the API's own check.
    ["a reason with an email address", { reason: "asked by ops@acme-shop.io" }, SECRET],
    ["a reason with an admin key", { reason: `key ${admin.key}` }, SECRET],
    ["a reason with a token-like run", { reason: "a".repeat(43) }, SECRET],
  ])("refuses a promotion with %s before calling the API", async (_label, extra, message) => {
    expect(dropReason(await setRuleModeAction(null, form({ ...promote, ...extra })))).toEqual({
      ok: false,
      errors: [{ path: "reason", message }],
    });
    expect(api.publishPolicy).not.toHaveBeenCalled();
  });

  it("accepts a reason of exactly 500 characters", async () => {
    await expect(setRuleModeAction(null, form({ ...promote, reason: `${"ab ".repeat(166)}ab` }))).rejects.toThrow(
      "REDIRECT",
    );
    expect(api.publishPolicy).toHaveBeenCalledTimes(1);
  });

  it("needs no reason to go back to monitor", async () => {
    const demote = { ...promote, ruleId: enforced.id, mode: "monitor" };
    await expect(setRuleModeAction(null, form(demote))).rejects.toThrow("REDIRECT");
    expect(api.publishPolicy).toHaveBeenCalledWith(
      admin.key,
      appId,
      "development",
      [{ ...enforced, mode: "monitor" }, monitored],
      READ,
    );
  });

  it("explains the API's reason-required and its refusal of the header below the reason", async () => {
    vi.mocked(api.publishPolicy).mockRejectedValueOnce(missing());
    expect(dropReason(await setRuleModeAction(null, form({ ...promote, reason: REASON })))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
    vi.mocked(api.publishPolicy).mockRejectedValueOnce(refusedHeader());
    expect(dropReason(await setRuleModeAction(null, form({ ...promote, reason: REASON })))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REFUSED }],
    });
    // The API's refusals of a reason, in the Console's words, by their code (never by the API's text).
    const byCode: Array<[string, string]> = [
      ["reason-holds-secret", SECRET],
      ["reason-too-long", LONG],
      ["reason-unsafe-characters", INVALID],
      ["reason-empty", REQUIRED],
      ["reason-not-ascii", REFUSED],
      ["reason-bad-encoding", REFUSED],
    ];
    for (const [code, message] of byCode) {
      vi.mocked(api.publishPolicy).mockRejectedValueOnce(
        new api.ValidationError(
          "400",
          [{ path: "headers.x-airverse-reason", message: "whatever the API says" }],
          code as api.ValidationError["code"],
        ),
      );
      expect(dropReason(await setRuleModeAction(null, form({ ...promote, reason: REASON })))).toEqual({
        ok: false,
        errors: [{ path: "reason", message }],
      });
    }
  });
});

describe("rollbackPolicyAction — reason", () => {
  const fields = {
    appId,
    environment: "production",
    version: "3",
    confirm: "production",
    expectedVersion: String(READ),
  };
  // Version 3 enforces the Rule that is in monitor now: rolling back promotes it.
  const promoting = () =>
    vi.mocked(api.getPolicyVersion).mockResolvedValue({
      policy: policy({ version: 3, rules: [enforced, { ...monitored, mode: "enforce" }] }),
    });
  const same = () => vi.mocked(api.getPolicyVersion).mockResolvedValue({ policy: policy({ version: 3 }) });

  it("requires a reason when the rollback enforces a Rule that is not enforced now", async () => {
    promoting();
    expect(dropReason(await rollbackPolicyAction(null, form(fields)))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
    expect(api.rollbackPolicy).not.toHaveBeenCalled();
    await expect(rollbackPolicyAction(null, form({ ...fields, reason: REASON }))).rejects.toThrow("REDIRECT");
    expect(api.rollbackPolicy).toHaveBeenCalledWith(admin.key, appId, "production", 3, READ, { reason: REASON });
  });

  it("requires a reason when an enforced Rule comes back changed: other traffic is enforced (as the API counts it)", async () => {
    const changes: Array<Partial<PolicyRule>> = [
      { path: "/elsewhere" },
      { methods: ["DELETE"] },
      { requires: "signature" },
      { action: "throttle", limit: { requests: 5, window_s: 60, key: "ip", count: "requests" } },
    ];
    for (const change of changes) {
      vi.mocked(api.getPolicyVersion).mockResolvedValue({
        policy: policy({ version: 3, rules: [{ ...enforced, ...change }, monitored] }),
      });
      expect(dropReason(await rollbackPolicyAction(null, form(fields)))).toEqual({
        ok: false,
        errors: [{ path: "reason", message: REQUIRED }],
      });
    }
    // The same Rule with its methods in another order enforces the same traffic.
    vi.mocked(api.getPolicyVersion).mockResolvedValue({
      policy: policy({ version: 3, rules: [{ ...enforced, methods: [...enforced.methods].reverse() }, monitored] }),
    });
    await expect(rollbackPolicyAction(null, form(fields))).rejects.toThrow("REDIRECT");
  });

  it("takes an optional reason when the rollback enforces nothing new", async () => {
    same();
    await expect(rollbackPolicyAction(null, form(fields))).rejects.toThrow("REDIRECT");
    expect(api.rollbackPolicy).toHaveBeenLastCalledWith(admin.key, appId, "production", 3, READ);
    await expect(rollbackPolicyAction(null, form({ ...fields, reason: REASON }))).rejects.toThrow("REDIRECT");
    expect(api.rollbackPolicy).toHaveBeenLastCalledWith(admin.key, appId, "production", 3, READ, { reason: REASON });
  });

  it("refuses a malformed optional reason before calling the API", async () => {
    same();
    expect(dropReason(await rollbackPolicyAction(null, form({ ...fields, reason: "a\tb" })))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: INVALID }],
    });
    expect(api.rollbackPolicy).not.toHaveBeenCalled();
  });

  it("explains the API's reason-required", async () => {
    same();
    vi.mocked(api.rollbackPolicy).mockRejectedValueOnce(missing());
    expect(dropReason(await rollbackPolicyAction(null, form(fields)))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
  });
});

describe("setPatchModeAction — reason", () => {
  const fields = {
    appId,
    environment: "production",
    patchId: "vp_qs_proto_pollution",
    findingId: "fnd_0123456789abcdef01234567",
    mode: "enforce",
    confirm: "vp_qs_proto_pollution",
  };

  it("requires a reason to enforce and forwards it", async () => {
    expect(dropReason(await setPatchModeAction(null, form(fields)))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
    expect(api.setPatchMode).not.toHaveBeenCalled();
    await expect(setPatchModeAction(null, form({ ...fields, reason: REASON }))).rejects.toThrow("REDIRECT");
    expect(api.setPatchMode).toHaveBeenCalledWith(
      admin.key,
      appId,
      fields.patchId,
      { environment: "production", mode: "enforce", confirm: fields.patchId },
      { reason: REASON },
    );
  });

  it("needs no reason to go back to monitor", async () => {
    const { confirm: _confirm, ...rest } = fields;
    await expect(setPatchModeAction(null, form({ ...rest, mode: "monitor" }))).rejects.toThrow("REDIRECT");
    expect(api.setPatchMode).toHaveBeenCalledWith(admin.key, appId, fields.patchId, {
      environment: "production",
      mode: "monitor",
    });
  });

  it("explains the API's reason-required", async () => {
    vi.mocked(api.setPatchMode).mockRejectedValueOnce(missing());
    expect(dropReason(await setPatchModeAction(null, form({ ...fields, reason: REASON })))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
  });
});

describe("createContainmentAction — reason", () => {
  const ipHash = `iph_${"a".repeat(32)}`;
  const fields = {
    incidentId: "inc_0123456789abcdef01234567",
    environment: "production",
    kind: "actor",
    ipHash,
    ttl: "3600",
    confirm: ipHash,
  };

  it("requires a reason and forwards it", async () => {
    expect(dropReason(await createContainmentAction(null, form(fields)))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
    expect(api.createContainment).not.toHaveBeenCalled();
    vi.mocked(api.createContainment).mockResolvedValue({
      containment: { app_id: appId } as Awaited<ReturnType<typeof api.createContainment>>["containment"],
    });
    await expect(createContainmentAction(null, form({ ...fields, reason: REASON }))).rejects.toThrow("REDIRECT");
    expect(api.createContainment).toHaveBeenCalledWith(
      admin.key,
      fields.incidentId,
      { target: { kind: "actor", ip_hash: ipHash }, ttl_s: 3600 },
      { reason: REASON },
    );
  });

  it("explains the API's reason-required instead of calling the Incident stale", async () => {
    vi.mocked(api.createContainment).mockRejectedValueOnce(missing());
    expect(dropReason(await createContainmentAction(null, form({ ...fields, reason: REASON })))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
  });
});

describe("deleteTargetAction — reason", () => {
  const fields = { targetId: EXAMPLE_TARGET.id, confirm: EXAMPLE_TARGET.id };

  it("requires a reason and forwards it", async () => {
    expect(dropReason(await deleteTargetAction(null, form(fields)))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
    expect(api.deleteTarget).not.toHaveBeenCalled();
    await expect(deleteTargetAction(null, form({ ...fields, reason: REASON }))).rejects.toThrow("REDIRECT");
    expect(api.deleteTarget).toHaveBeenCalledWith(admin.key, EXAMPLE_TARGET.id, { reason: REASON });
  });

  it("explains the API's reason-required", async () => {
    vi.mocked(api.deleteTarget).mockRejectedValueOnce(missing());
    expect(dropReason(await deleteTargetAction(null, form({ ...fields, reason: REASON })))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REQUIRED }],
    });
  });
});

describe("signRulesOfEngagementAction — reason", () => {
  const fields = {
    scope: [EXAMPLE_TARGET.id],
    exclusions: "",
    intensity: "passive",
    days: ["mon"],
    from: "09:00",
    to: "17:00",
    contacts: "security@acme-shop.io",
    confirm: "I authorise passive testing",
  };

  it("requires a reason, listed after the phrase, and forwards it", async () => {
    const state = dropReason(await signRulesOfEngagementAction(null, form(fields)));
    expect(state?.errors).toEqual([{ path: "reason", message: REQUIRED }]);
    expect(api.signRulesOfEngagement).not.toHaveBeenCalled();
    await expect(signRulesOfEngagementAction(null, form({ ...fields, reason: REASON }))).rejects.toThrow("REDIRECT");
    expect(vi.mocked(api.signRulesOfEngagement).mock.calls[0]?.[2]).toEqual({ reason: REASON });
  });

  it("explains the API's reason-required", async () => {
    vi.mocked(api.signRulesOfEngagement).mockRejectedValueOnce(missing());
    const state = dropReason(await signRulesOfEngagementAction(null, form({ ...fields, reason: REASON })));
    expect(state?.errors).toEqual([{ path: "reason", message: REQUIRED }]);
  });
});

describe("loadMoreAuditAction", () => {
  const query = { action: "policy.rule.promote", app: appId, from: "2026-11-01", to: "2026-11-13" } as const;

  it("reads the next page with the filters of the page and the cursor", async () => {
    vi.mocked(api.listAudit).mockResolvedValue({ entries: [EXAMPLE_AUDIT_ENTRY], next_cursor: null });
    expect(await loadMoreAuditAction(query, "17")).toEqual({
      ok: true,
      entries: [EXAMPLE_AUDIT_ENTRY],
      nextCursor: null,
    });
    expect(api.listAudit).toHaveBeenCalledWith(admin.key, {
      action: "policy.rule.promote",
      appId,
      from: "2026-11-01T00:00:00.000Z",
      to: "2026-11-14T00:00:00.000Z",
      cursor: "17",
    });
  });

  it("refuses a cursor that is not one and says when the API fails", async () => {
    expect(await loadMoreAuditAction({}, "abc")).toEqual({ ok: false, message: expect.any(String) });
    expect(api.listAudit).not.toHaveBeenCalled();
    vi.mocked(api.listAudit).mockRejectedValue(new api.ApiError("down", 0));
    expect(await loadMoreAuditAction({}, "5")).toEqual({
      ok: false,
      message: "The audit log could not be read. Try again in a moment.",
    });
  });

  it("ignores a filter value it does not know", async () => {
    vi.mocked(api.listAudit).mockResolvedValue({ entries: [], next_cursor: null });
    await loadMoreAuditAction({ action: "nope", app: "x", from: "2026-13-40" }, "5");
    expect(api.listAudit).toHaveBeenCalledWith(admin.key, { cursor: "5" });
  });
});

describe("review findings (slice 18a)", () => {
  const promote = {
    appId,
    environment: "development",
    ruleId: monitored.id,
    mode: "enforce",
    expectedVersion: String(READ),
    confirm: "development",
  };

  it("F4: leaves the check for secrets to the API: a reason that merely looks like a key prefix is sent", async () => {
    await expect(setRuleModeAction(null, form({ ...promote, reason: "ticket aro_123456" }))).rejects.toThrow(
      "REDIRECT",
    );
    expect(vi.mocked(api.publishPolicy).mock.calls[0]?.[5]).toEqual({ reason: "ticket aro_123456" });
  });

  it("F2: gives the typed reason back, trimmed, with any refusal of a sensitive change", async () => {
    vi.mocked(api.publishPolicy).mockRejectedValueOnce(refusedHeader());
    expect(await setRuleModeAction(null, form({ ...promote, reason: `  ${REASON} ` }))).toEqual({
      ok: false,
      errors: [{ path: "reason", message: REFUSED }],
      reason: REASON,
    });
    expect(await setRuleModeAction(null, form({ ...promote, confirm: "", reason: REASON }))).toMatchObject({
      reason: REASON,
    });
    vi.mocked(api.deleteTarget).mockRejectedValueOnce(missing());
    expect(
      await deleteTargetAction(null, form({ targetId: EXAMPLE_TARGET.id, confirm: EXAMPLE_TARGET.id, reason: REASON })),
    ).toMatchObject({ reason: REASON });
    const state = await signRulesOfEngagementAction(null, form({ scope: [], reason: REASON }));
    expect(state).toMatchObject({ reason: REASON });
    // Nothing typed, nothing given back.
    expect(await setRuleModeAction(null, form(promote))).not.toHaveProperty("reason");
  });

  it("verifies the chain on demand, and explains a 429 and a failure", async () => {
    const result = {
      verify: { valid: true, entries: 1, last_seq: 1, first_broken_seq: null },
      signed_head: EXAMPLE_SIGNED_AUDIT_HEAD,
    };
    vi.mocked(api.verifyAudit).mockResolvedValueOnce(result);
    expect(await verifyAuditChainAction()).toEqual({ ok: true, result });
    vi.mocked(api.verifyAudit).mockRejectedValueOnce(new api.RateLimitedError("429", 12));
    expect(await verifyAuditChainAction()).toEqual({ ok: false, limited: { retryAfter: 12 } });
    vi.mocked(api.verifyAudit).mockRejectedValueOnce(new api.ApiError("down", 0));
    expect(await verifyAuditChainAction()).toEqual({ ok: false });
  });
});

describe("loadAuditPage (F1, and verify only on the unfiltered view)", () => {
  const empty = { entries: [], next_cursor: null };

  it("lists without the filters when the API refuses them, and says so", async () => {
    vi.mocked(api.listAudit).mockRejectedValueOnce(new api.ValidationError("400", [{ path: "from", message: "x" }]));
    vi.mocked(api.listAudit).mockResolvedValueOnce(empty);
    const loaded = await loadAuditPage(admin.key, { from: "2026-11-01" }, false);
    expect(loaded).toMatchObject({ page: empty, filtersApplied: false });
    expect(vi.mocked(api.listAudit).mock.calls.map((call) => call[1])).toEqual([
      { from: "2026-11-01T00:00:00.000Z" },
      {},
    ]);
  });

  it("verifies the chain on the unfiltered view only", async () => {
    vi.mocked(api.listAudit).mockResolvedValue(empty);
    const result = {
      verify: { valid: true, entries: 0, last_seq: 0, first_broken_seq: null },
      signed_head: EXAMPLE_SIGNED_AUDIT_HEAD,
    };
    vi.mocked(api.verifyAudit).mockResolvedValue(result);
    expect(await loadAuditPage(admin.key, {}, true)).toMatchObject({ chain: { result }, filtersApplied: true });
    expect(await loadAuditPage(admin.key, { action: "app.create" }, true)).toMatchObject({ chain: null });
    expect(await loadAuditPage(admin.key, {}, false)).toMatchObject({ chain: null });
    expect(api.verifyAudit).toHaveBeenCalledTimes(1);
  });
});
