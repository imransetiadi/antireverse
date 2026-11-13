// @vitest-environment node
import {
  type Containment,
  EXAMPLE_ALLOWLIST_ENTRY,
  EXAMPLE_CONTAINMENT,
  EXAMPLE_INCIDENT,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { dropReason } from "./helpers/reason.ts";

// The containment and never-block actions, exercised through their interface with the API client, the
// session, the cache and the navigation replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  createContainment: vi.fn(),
  liftContainment: vi.fn(),
  listContainments: vi.fn(),
  getIncident: vi.fn(),
  listAllowlist: vi.fn(),
  createAllowlistEntry: vi.fn(),
  deleteAllowlistEntry: vi.fn(),
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
import {
  createAllowlistEntryAction,
  createContainmentAction,
  deleteAllowlistEntryAction,
  liftContainmentAction,
} from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const incidentId = EXAMPLE_INCIDENT.id;
const appId = EXAMPLE_INCIDENT.app_id;
const HASH = "iph_2932b22cf89905dbc929c64247ddad3e";
// The network of EXAMPLE_INCIDENT (nullable in the protocol since slice 10; set for this rule).
const PREFIX = "203.0.113.0/24";
const PAGE = `/incidents/${incidentId}`;
const containmentId = EXAMPLE_CONTAINMENT.id;
const entryId = EXAMPLE_ALLOWLIST_ENTRY.id;

const CONFIRM_REQUIRED = "Nothing was blocked. Confirm the block first.";
const TYPED_MISMATCH = `Nothing was blocked. Type ${PREFIX} exactly as shown.`;
const STALE =
  "This Incident or its blocks changed since the page was loaded, so nothing was blocked. Reload the page and try again.";
const RESOLVED = "This Incident is resolved, so nothing was blocked.";
const OVERLAP = "This network overlaps your never block list.";
const CAP_DEV = "This App already has 150 active blocks in development. Lift one first.";
// Slice 10: a clone Incident, or any Incident without a network prefix, cannot be contained.
const NOT_APPLICABLE = "Containment does not apply to this Incident.";
const LIFT_REQUIRED = "Nothing was lifted. Confirm the change first.";
const ENDED = "This block already ended — it expired or was lifted. Reload the page to see its status.";
const REMOVE_REQUIRED = "Nothing was removed. Confirm the change first.";
const API_DOWN = "The Airverse API did not answer, so nothing was saved. Check that it is running, then try again.";

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.append(name, value);
  return data;
}

const lifted: Containment = {
  ...EXAMPLE_CONTAINMENT,
  status: "lifted",
  lifted_at: "2026-11-10T08:40:00.000Z",
  lifted_by: "key_0123456789abcdef01234567",
};

const ALL = [
  api.createContainment,
  api.liftContainment,
  api.listContainments,
  api.getIncident,
  api.listAllowlist,
  api.createAllowlistEntry,
  api.deleteAllowlistEntry,
];

beforeEach(() => {
  for (const fn of ALL) vi.mocked(fn).mockReset();
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(revalidatePath).mockReset();
});

const REASON = "Credential stuffing from this network";
const blockActor = (extra: Record<string, string> = {}) =>
  form({
    incidentId,
    environment: EXAMPLE_INCIDENT.environment,
    kind: "actor",
    ipHash: HASH,
    ttl: "3600",
    confirm: HASH,
    // Slice 18a: a block carries a reason.
    reason: REASON,
    ...extra,
  });
const blockNetwork = (extra: Record<string, string> = {}) =>
  form({
    incidentId,
    environment: EXAMPLE_INCIDENT.environment,
    kind: "prefix",
    ttl: "900",
    confirm: PREFIX,
    typedPrefix: PREFIX,
    reason: REASON,
    ...extra,
  });

describe("createContainmentAction", () => {
  it("blocks the Actor named in the confirmation and goes back to the Incident", async () => {
    vi.mocked(api.createContainment).mockResolvedValue({ containment: EXAMPLE_CONTAINMENT });
    await expect(createContainmentAction(null, blockActor())).rejects.toThrow(`REDIRECT ${PAGE}`);
    expect(api.createContainment).toHaveBeenCalledWith(
      admin.key,
      incidentId,
      {
        target: { kind: "actor", ip_hash: HASH },
        ttl_s: 3600,
      },
      { reason: REASON },
    );
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
    expect(revalidatePath).toHaveBeenCalledWith("/incidents");
    expect(revalidatePath).toHaveBeenCalledWith(`/apps/${EXAMPLE_CONTAINMENT.app_id}/containment`);
  });

  it("refuses an Actor block without the confirmation, or confirmed for another Actor; the API is never called", async () => {
    for (const confirm of ["", "yes", "iph_00000000000000000000000000000000"]) {
      expect(dropReason(await createContainmentAction(null, blockActor({ confirm })))).toEqual({
        ok: false,
        errors: [{ path: "confirm", message: CONFIRM_REQUIRED }],
      });
    }
    expect(api.createContainment).not.toHaveBeenCalled();
  });

  it("blocks the network when the prefix was typed exactly, sending it as confirm_prefix", async () => {
    vi.mocked(api.createContainment).mockResolvedValue({
      containment: { ...EXAMPLE_CONTAINMENT, target: { kind: "prefix", ip_prefix: PREFIX } },
    });
    await expect(createContainmentAction(null, blockNetwork())).rejects.toThrow(`REDIRECT ${PAGE}`);
    expect(api.createContainment).toHaveBeenCalledWith(
      admin.key,
      incidentId,
      {
        target: { kind: "prefix" },
        ttl_s: 900,
        confirm_prefix: PREFIX,
      },
      { reason: REASON },
    );
  });

  it("refuses a mistyped, padded, partial or missing prefix — the API is never called", async () => {
    for (const typedPrefix of ["203.0.113.0/23", ` ${PREFIX}`, `${PREFIX} `, "203.0.113.0", "", "203.0.113.0/24x"]) {
      expect(dropReason(await createContainmentAction(null, blockNetwork({ typedPrefix })))).toEqual({
        ok: false,
        errors: [{ path: "typedPrefix", message: TYPED_MISMATCH }],
      });
    }
    const withoutTyped = form({ incidentId, environment: "development", kind: "prefix", ttl: "900", confirm: PREFIX });
    expect(dropReason(await createContainmentAction(null, withoutTyped))).toEqual({
      ok: false,
      errors: [{ path: "typedPrefix", message: TYPED_MISMATCH }],
    });
    expect(api.createContainment).not.toHaveBeenCalled();
  });

  it("refuses a form this screen does not send", async () => {
    const forms: Array<Record<string, string>> = [
      { incidentId: "inc_nope" },
      { environment: "" },
      { environment: "qa" },
      { kind: "account" },
      { ttl: "60" },
      { ttl: "" },
      { ipHash: "203.0.113.7", confirm: "203.0.113.7" },
    ];
    for (const fields of forms) {
      expect(dropReason(await createContainmentAction(null, blockActor(fields)))).toEqual({
        ok: false,
        errors: [{ path: "", message: STALE }],
      });
    }
    // A network confirmation that is not an Event prefix (a full address) is refused too.
    expect(
      dropReason(
        await createContainmentAction(null, blockNetwork({ confirm: "203.0.113.7", typedPrefix: "203.0.113.7" })),
      ),
    ).toEqual({ ok: false, errors: [{ path: "", message: STALE }] });
    expect(api.createContainment).not.toHaveBeenCalled();
  });

  it.each([
    ["incident-resolved", RESOLVED, blockActor],
    ["prefix-allowlisted", OVERLAP, blockNetwork],
    ["containment-limit", CAP_DEV, blockActor],
    ["containment-not-applicable", NOT_APPLICABLE, blockActor],
    ["containment-not-applicable", NOT_APPLICABLE, blockNetwork],
    ["actor-unknown", STALE, blockActor],
    [undefined, STALE, blockActor],
  ] as const)(
    "explains a 409 with reason %s from the reason alone, calling the API once",
    async (reason, message, build) => {
      vi.mocked(api.createContainment).mockRejectedValueOnce(new api.ConflictError("409", reason));
      expect(dropReason(await createContainmentAction(null, build()))).toEqual({
        ok: false,
        errors: [{ path: "", message }],
      });
      expect(api.createContainment).toHaveBeenCalledTimes(1);
      // Nothing is read again to guess the cause.
      expect(api.getIncident).not.toHaveBeenCalled();
      expect(api.listAllowlist).not.toHaveBeenCalled();
      expect(api.listContainments).not.toHaveBeenCalled();
      expect(revalidatePath).not.toHaveBeenCalled();
    },
  );

  it("names the Incident's Environment in the cap message", async () => {
    vi.mocked(api.createContainment).mockRejectedValueOnce(new api.ConflictError("409", "containment-limit"));
    expect(dropReason(await createContainmentAction(null, blockActor({ environment: "production" })))).toEqual({
      ok: false,
      errors: [{ path: "", message: "This App already has 150 active blocks in production. Lift one first." }],
    });
  });

  it("says the Incident changed for a 404 or a 400", async () => {
    for (const error of [
      new api.NotFoundError("404"),
      new api.ValidationError("400", [{ path: "target.ip_hash", message: "Not in this Incident" }]),
    ]) {
      vi.mocked(api.createContainment).mockRejectedValueOnce(error);
      expect(dropReason(await createContainmentAction(null, blockActor()))).toEqual({
        ok: false,
        errors: [{ path: "", message: STALE }],
      });
    }
  });

  it("says the API did not answer, and signs out on 401", async () => {
    vi.mocked(api.createContainment).mockRejectedValueOnce(new api.ApiError("down", 0));
    expect(dropReason(await createContainmentAction(null, blockActor()))).toEqual({
      ok: false,
      errors: [{ path: "", message: API_DOWN }],
    });
    vi.mocked(api.createContainment).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(createContainmentAction(null, blockActor())).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });

  it("goes to the start page without a session", async () => {
    vi.mocked(session.readSession).mockResolvedValue(undefined);
    await expect(createContainmentAction(null, blockActor())).rejects.toThrow("REDIRECT /");
    expect(api.createContainment).not.toHaveBeenCalled();
  });
});

describe("liftContainmentAction", () => {
  it("lifts with the confirmation and goes back to the Incident it came from", async () => {
    vi.mocked(api.liftContainment).mockResolvedValue({ containment: lifted });
    await expect(
      liftContainmentAction(null, form({ containmentId, confirm: containmentId, incidentId })),
    ).rejects.toThrow(`REDIRECT ${PAGE}`);
    expect(api.liftContainment).toHaveBeenCalledWith(admin.key, containmentId);
    expect(revalidatePath).toHaveBeenCalledWith(`/incidents/${lifted.incident_id}`);
    expect(revalidatePath).toHaveBeenCalledWith("/incidents");
    expect(revalidatePath).toHaveBeenCalledWith(`/apps/${lifted.app_id}/containment`);
  });

  it("goes back to the App's containment page when it came from there", async () => {
    vi.mocked(api.liftContainment).mockResolvedValue({ containment: lifted });
    await expect(liftContainmentAction(null, form({ containmentId, confirm: containmentId, appId }))).rejects.toThrow(
      `REDIRECT /apps/${appId}/containment`,
    );
  });

  it("refuses without the confirmation; the API is never called", async () => {
    for (const confirm of ["", "yes", "cnt_ffffffffffffffffffffffff"]) {
      expect(await liftContainmentAction(null, form({ containmentId, confirm, incidentId }))).toEqual({
        ok: false,
        errors: [{ path: "confirm", message: LIFT_REQUIRED }],
      });
    }
    expect(api.liftContainment).not.toHaveBeenCalled();
  });

  it("refuses a form without a valid block or a valid way back", async () => {
    const forms: Array<Record<string, string>> = [
      { containmentId: "cnt_nope", confirm: "cnt_nope", incidentId },
      { containmentId, confirm: containmentId },
      { containmentId, confirm: containmentId, incidentId: "https://evil.example" },
      { containmentId, confirm: containmentId, appId: "../../x" },
    ];
    for (const fields of forms) {
      expect(await liftContainmentAction(null, form(fields))).toEqual({
        ok: false,
        errors: [{ path: "", message: ENDED }],
      });
    }
    expect(api.liftContainment).not.toHaveBeenCalled();
  });

  it("says the block already ended on 409 (with or without its reason) or 404, calling the API once each", async () => {
    for (const error of [
      new api.ConflictError("409", "containment-ended"),
      new api.ConflictError("409"),
      new api.NotFoundError("404"),
    ]) {
      vi.mocked(api.liftContainment).mockRejectedValueOnce(error);
      expect(await liftContainmentAction(null, form({ containmentId, confirm: containmentId, incidentId }))).toEqual({
        ok: false,
        errors: [{ path: "", message: ENDED }],
      });
    }
    expect(api.liftContainment).toHaveBeenCalledTimes(3);
    expect(revalidatePath).not.toHaveBeenCalled();
  });
});

describe("createAllowlistEntryAction", () => {
  it("adds a range with its trimmed note and returns it", async () => {
    vi.mocked(api.createAllowlistEntry).mockResolvedValue({ entry: EXAMPLE_ALLOWLIST_ENTRY });
    expect(
      await createAllowlistEntryAction(null, form({ cidr: " 198.51.100.0/24 ", note: "  Office network " })),
    ).toEqual({ ok: true, entry: EXAMPLE_ALLOWLIST_ENTRY });
    expect(api.createAllowlistEntry).toHaveBeenCalledWith(admin.key, {
      cidr: "198.51.100.0/24",
      note: "Office network",
    });
    expect(revalidatePath).toHaveBeenCalledWith("/settings/allowlist");
  });

  it("asks for a range when the field is empty", async () => {
    expect(await createAllowlistEntryAction(null, form({ cidr: "", note: "" }))).toEqual({
      ok: false,
      errors: [{ path: "cidr", message: "Enter a range, for example 203.0.113.0/24." }],
      values: { cidr: "", note: "" },
    });
  });

  it.each([
    ["203.0.113.7/24", "203.0.113.0/24"],
    ["2001:DB8::/32", "2001:db8::/32"],
    ["2001:0db8:0000:0000:0000:0000:0000:0000/32", "2001:db8::/32"],
    ["2001:db8::1/48", "2001:db8::/48"],
  ])("refuses the non-canonical %s and shows the canonical %s", async (cidr, canonical) => {
    expect(await createAllowlistEntryAction(null, form({ cidr, note: "" }))).toEqual({
      ok: false,
      errors: [
        { path: "cidr", message: `Write this range as ${canonical}: the network address with its host bits zero.` },
      ],
      values: { cidr, note: "" },
    });
    expect(api.createAllowlistEntry).not.toHaveBeenCalled();
  });

  it.each(["203.0.113.7", "203.0.113.0/33", "10.0.0.0/7", "2001:db8::/15", "office", "::ffff:203.0.113.0/120"])(
    "refuses %s with the CIDR rules",
    async (cidr) => {
      expect(await createAllowlistEntryAction(null, form({ cidr, note: "" }))).toEqual({
        ok: false,
        errors: [
          {
            path: "cidr",
            message: "Enter a range in CIDR form: IPv4 /8 to /32 or IPv6 /16 to /128, for example 203.0.113.0/24.",
          },
        ],
        values: { cidr, note: "" },
      });
    },
  );

  it("refuses a note longer than 80 characters", async () => {
    const note = "n".repeat(81);
    expect(await createAllowlistEntryAction(null, form({ cidr: "198.51.100.0/24", note }))).toEqual({
      ok: false,
      errors: [{ path: "note", message: "Use 80 characters or fewer." }],
      values: { cidr: "198.51.100.0/24", note },
    });
  });

  it.each([
    ["allowlist-duplicate", { path: "cidr", message: "This range is already on the never block list." }],
    [
      "allowlist-limit",
      { path: "", message: "The never block list holds at most 100 ranges. Remove one before adding another." },
    ],
    [
      undefined,
      {
        path: "",
        message:
          "The never block list changed since the page was loaded, so nothing was added. Reload the page and try again.",
      },
    ],
  ] as const)("explains a 409 with reason %s from the reason alone, calling the API once", async (reason, error) => {
    vi.mocked(api.createAllowlistEntry).mockRejectedValueOnce(new api.ConflictError("409", reason));
    expect(await createAllowlistEntryAction(null, form({ cidr: "198.51.100.0/24", note: "" }))).toEqual({
      ok: false,
      errors: [error],
      values: { cidr: "198.51.100.0/24", note: "" },
    });
    expect(api.createAllowlistEntry).toHaveBeenCalledTimes(1);
    expect(api.listAllowlist).not.toHaveBeenCalled();
  });

  it("shows a 400 at cidr below the field", async () => {
    vi.mocked(api.createAllowlistEntry).mockRejectedValue(
      new api.ValidationError("400", [{ path: "cidr", message: "x" }]),
    );
    const state = await createAllowlistEntryAction(null, form({ cidr: "198.51.100.0/24", note: "" }));
    expect(state).toEqual({
      ok: false,
      errors: [
        {
          path: "cidr",
          message: "Enter a range in CIDR form: IPv4 /8 to /32 or IPv6 /16 to /128, for example 203.0.113.0/24.",
        },
      ],
      values: { cidr: "198.51.100.0/24", note: "" },
    });
  });
});

describe("deleteAllowlistEntryAction", () => {
  it("removes with the confirmation and goes back to the list", async () => {
    vi.mocked(api.deleteAllowlistEntry).mockResolvedValue(undefined);
    await expect(deleteAllowlistEntryAction(null, form({ entryId, confirm: entryId }))).rejects.toThrow(
      "REDIRECT /settings/allowlist",
    );
    expect(api.deleteAllowlistEntry).toHaveBeenCalledWith(admin.key, entryId);
    expect(revalidatePath).toHaveBeenCalledWith("/settings/allowlist");
  });

  it("refuses without the confirmation; the API is never called", async () => {
    for (const confirm of ["", "yes", "alw_ffffffffffffffffffffffff"]) {
      expect(await deleteAllowlistEntryAction(null, form({ entryId, confirm }))).toEqual({
        ok: false,
        errors: [{ path: "confirm", message: REMOVE_REQUIRED }],
      });
    }
    expect(api.deleteAllowlistEntry).not.toHaveBeenCalled();
  });

  it("treats a range that is already gone as removed", async () => {
    vi.mocked(api.deleteAllowlistEntry).mockRejectedValue(new api.NotFoundError("404"));
    await expect(deleteAllowlistEntryAction(null, form({ entryId, confirm: entryId }))).rejects.toThrow(
      "REDIRECT /settings/allowlist",
    );
  });
});
