// @vitest-environment node
import { type Assessment, EXAMPLE_ASSESSMENT } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

// "Assess again" (slice 12a): the action asks the API to assess the Build's kept artifact again with the tier alone,
// exercised with the API client, the session, the cache and the navigation replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  createAssessment: vi.fn(),
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
import { assessAgainAction } from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const appId = EXAMPLE_ASSESSMENT.app_id;
const buildId = EXAMPLE_ASSESSMENT.build_id;
const PAGE = `/apps/${appId}/builds/${buildId}`;

const queued: Assessment = {
  ...EXAMPLE_ASSESSMENT,
  id: "asm_eeeeeeeeeeeeeeeeeeeeeeee",
  tier: "T2",
  status: "queued",
  results: [],
  rrs: null,
  inconclusive_reason: null,
  inconclusive_code: null,
  scope: { ...EXAMPLE_ASSESSMENT.scope, tier: "T2" },
  started_at: null,
  finished_at: null,
};

const NOT_KEPT = "The uploaded bundle is no longer kept. Run Harden with --assess to upload it again.";
const STALE =
  "This Build changed since the page was loaded, so no Assessment was requested. Reload the page and try again.";
const TIER = "Choose tier T1, T2 or T3.";
const API_DOWN = "The Airverse API did not answer, so nothing was saved. Check that it is running, then try again.";

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.append(name, value);
  return data;
}
const assessForm = (overrides: Record<string, string> = {}) => form({ appId, buildId, tier: "T2", ...overrides });

beforeEach(() => {
  vi.mocked(api.createAssessment).mockReset();
  vi.mocked(api.createAssessment).mockResolvedValue({ assessment: queued });
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(revalidatePath).mockReset();
});

describe("assessAgainAction", () => {
  it("sends the tier alone, refreshes the Build page and returns the queued Assessment", async () => {
    expect(await assessAgainAction(null, assessForm())).toEqual({ ok: true, assessment: queued });
    expect(api.createAssessment).toHaveBeenCalledWith(admin.key, appId, buildId, { tier: "T2" });
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
  });

  it("refuses an unknown tier next to its field, and malformed ids as stale, without calling the API", async () => {
    expect(await assessAgainAction(null, assessForm({ tier: "T4" }))).toEqual({
      ok: false,
      errors: [{ path: "tier", message: TIER }],
    });
    for (const overrides of [{ appId: "app_x" }, { buildId: "bld_x" }] as Record<string, string>[]) {
      expect(await assessAgainAction(null, assessForm(overrides))).toEqual({
        ok: false,
        errors: [{ path: "", message: STALE }],
      });
    }
    expect(api.createAssessment).not.toHaveBeenCalled();
  });

  it("says the bundle is no longer kept on 409 artifact-required", async () => {
    vi.mocked(api.createAssessment).mockRejectedValueOnce(new api.ConflictError("409", "artifact-required"));
    expect(await assessAgainAction(null, assessForm())).toEqual({
      ok: false,
      errors: [{ path: "", message: NOT_KEPT }],
    });
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
  });

  it("says the Build changed on a 404 or another 409, and names an unreachable API", async () => {
    vi.mocked(api.createAssessment).mockRejectedValueOnce(new api.NotFoundError("404"));
    expect(await assessAgainAction(null, assessForm())).toEqual({ ok: false, errors: [{ path: "", message: STALE }] });
    vi.mocked(api.createAssessment).mockRejectedValueOnce(new api.ConflictError("409"));
    expect(await assessAgainAction(null, assessForm())).toEqual({ ok: false, errors: [{ path: "", message: STALE }] });
    vi.mocked(api.createAssessment).mockRejectedValueOnce(new api.ApiError("failed: unreachable", 0));
    expect(await assessAgainAction(null, assessForm())).toEqual({
      ok: false,
      errors: [{ path: "", message: API_DOWN }],
    });
    vi.mocked(api.createAssessment).mockRejectedValueOnce(
      new api.ValidationError("400", [{ path: "tier", message: "Invalid option" }]),
    );
    expect(await assessAgainAction(null, assessForm())).toEqual({
      ok: false,
      errors: [{ path: "tier", message: TIER }],
    });
  });

  it("sends a person whose key is no longer accepted to sign in, and one without a session home", async () => {
    vi.mocked(api.createAssessment).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(assessAgainAction(null, assessForm())).rejects.toThrow("REDIRECT /sign-in?reason=expired");
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(assessAgainAction(null, assessForm())).rejects.toThrow("REDIRECT /");
  });
});
