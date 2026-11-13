// @vitest-environment node
import { EXAMPLE_FINDING, EXAMPLE_VIRTUAL_PATCH } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { dropReason } from "./helpers/reason.ts";

// The patch mode action (slice 20), exercised through its interface with the API client, the session, the cache
// and the navigation replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  setPatchMode: vi.fn(),
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
import { setPatchModeAction } from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const patchId = EXAMPLE_VIRTUAL_PATCH.id;
const appId = EXAMPLE_FINDING.app_id;
const findingId = EXAMPLE_FINDING.id;
const PAGE = `/findings/${findingId}`;

const STALE = "This patch changed since the page was loaded, so nothing was saved. Reload the page and try again.";
const MISMATCH = `Type ${patchId} exactly to confirm.`;
const API_DOWN = "The Airverse API did not answer, so nothing was saved. Check that it is running, then try again.";

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.append(name, value);
  return data;
}
/** Slice 18a: enforcing carries a reason. */
const REASON = "Exploit attempts seen; monitor showed no false positives";
const modeForm = (overrides: Record<string, string> = {}) =>
  form({
    appId,
    environment: "production",
    patchId,
    findingId,
    mode: "enforce",
    confirm: patchId,
    reason: REASON,
    ...overrides,
  });

beforeEach(() => {
  vi.mocked(api.setPatchMode).mockReset();
  vi.mocked(api.setPatchMode).mockResolvedValue(undefined);
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(revalidatePath).mockReset();
});

describe("setPatchModeAction", () => {
  it("enforces with the typed patch id as the confirmation, then goes back to the Finding", async () => {
    await expect(setPatchModeAction(null, modeForm())).rejects.toThrow(`REDIRECT ${PAGE}`);
    expect(api.setPatchMode).toHaveBeenCalledWith(
      admin.key,
      appId,
      patchId,
      {
        environment: "production",
        mode: "enforce",
        confirm: patchId,
      },
      { reason: REASON },
    );
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
    expect(revalidatePath).toHaveBeenCalledWith(`/apps/${appId}/policy`);
  });

  it("goes back to monitor at once, without a confirmation", async () => {
    await expect(setPatchModeAction(null, modeForm({ mode: "monitor", confirm: "", reason: "" }))).rejects.toThrow(
      `REDIRECT ${PAGE}`,
    );
    expect(api.setPatchMode).toHaveBeenCalledWith(admin.key, appId, patchId, {
      environment: "production",
      mode: "monitor",
    });
  });

  it("refuses to enforce unless the patch id was typed exactly, and never calls the API", async () => {
    for (const confirm of ["", ` ${patchId}`, patchId.toUpperCase(), "vp_other_patch"]) {
      expect(dropReason(await setPatchModeAction(null, modeForm({ confirm })))).toEqual({
        ok: false,
        errors: [{ path: "confirm", message: MISMATCH }],
      });
    }
    expect(api.setPatchMode).not.toHaveBeenCalled();
  });

  it("says the patch changed for a malformed field, a 404 or a 409", async () => {
    const malformed: Record<string, string>[] = [
      { patchId: "vp_X" },
      { appId: "app_x" },
      { findingId: "fnd_x" },
      { environment: "prod" },
      { mode: "block" },
    ];
    for (const overrides of malformed) {
      expect(dropReason(await setPatchModeAction(null, modeForm(overrides)))).toEqual({
        ok: false,
        errors: [{ path: "", message: STALE }],
      });
    }
    expect(api.setPatchMode).not.toHaveBeenCalled();
    vi.mocked(api.setPatchMode).mockRejectedValueOnce(new api.NotFoundError("404"));
    expect(dropReason(await setPatchModeAction(null, modeForm()))).toEqual({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
    vi.mocked(api.setPatchMode).mockRejectedValueOnce(new api.ConflictError("409"));
    expect(dropReason(await setPatchModeAction(null, modeForm()))).toEqual({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
  });

  it("puts a refused confirmation next to its field and an unreachable API in the summary", async () => {
    vi.mocked(api.setPatchMode).mockRejectedValueOnce(
      new api.ValidationError("400", [{ path: "confirm", message: "must equal the patch id" }]),
    );
    expect(dropReason(await setPatchModeAction(null, modeForm()))).toEqual({
      ok: false,
      errors: [{ path: "confirm", message: MISMATCH }],
    });
    vi.mocked(api.setPatchMode).mockRejectedValueOnce(new api.ApiError("failed: unreachable", 0));
    expect(dropReason(await setPatchModeAction(null, modeForm()))).toEqual({
      ok: false,
      errors: [{ path: "", message: API_DOWN }],
    });
  });

  it("sends a person whose key is no longer accepted to sign in, and one without a session home", async () => {
    vi.mocked(api.setPatchMode).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(setPatchModeAction(null, modeForm())).rejects.toThrow("REDIRECT /sign-in?reason=expired");
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(setPatchModeAction(null, modeForm())).rejects.toThrow("REDIRECT /");
  });
});
