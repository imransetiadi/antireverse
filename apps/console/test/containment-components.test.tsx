import {
  type AllowlistEntry,
  type Containment,
  EXAMPLE_ALLOWLIST_ENTRY,
  EXAMPLE_CONTAINMENT,
  EXAMPLE_INCIDENT,
  type Incident,
  type IncidentDetailResponse,
} from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Slice 09, contract P4: the containment bar, the Actors, the blocks with Lift, the Contained marker, the
// App's containment page and the never-block list — rendered with the Server Actions replaced by fakes.
vi.mock("@/app/actions.ts", () => ({
  updateIncidentAction: vi.fn(),
  createContainmentAction: vi.fn(),
  liftContainmentAction: vi.fn(),
  createAllowlistEntryAction: vi.fn(),
  deleteAllowlistEntryAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import * as actions from "@/app/actions.ts";
import { AppNav } from "@/components/app-nav.tsx";
import { AppShell } from "@/components/app-shell.tsx";
import { AddRangeForm } from "@/features/allowlist/add-range-form.tsx";
import { AllowlistTable } from "@/features/allowlist/allowlist-table.tsx";
import { AppContainment } from "@/features/containment/app-containment.tsx";
import { BlockList } from "@/features/containment/block-list.tsx";
import { expiryText, shortHash, shortId, suggestCidr } from "@/features/containment/format.ts";
import { blockRequestFrom, liftFrom } from "@/features/containment/query.ts";
import { IncidentDetail } from "@/features/incidents/incident-detail.tsx";
import { IncidentList } from "@/features/incidents/incident-list.tsx";
import { ROUTES } from "@/lib/routes.ts";

const HASH_A = "iph_2932b22cf89905dbc929c64247ddad3e";
const HASH_B = "iph_d78c52b682710159027de8721a764da9";
// The network of EXAMPLE_INCIDENT (nullable in the protocol since slice 10; set for this rule).
const PREFIX = "203.0.113.0/24";
const incidentId = EXAMPLE_INCIDENT.id;
const appId = EXAMPLE_INCIDENT.app_id;
const PAGE = `/incidents/${incidentId}`;
/** 2026-11-10 13:05:00 UTC */
const NOW = Date.UTC(2026, 10, 10, 13, 5, 0);
const production: Incident = { ...EXAMPLE_INCIDENT, environment: "production" };
const actors: IncidentDetailResponse["actors"] = [
  { ip_hash: HASH_B, events: 5 },
  { ip_hash: HASH_A, events: 42 },
];

const activeBlock: Containment = { ...EXAMPLE_CONTAINMENT, environment: "production" };
const expiredBlock: Containment = {
  ...EXAMPLE_CONTAINMENT,
  id: "cnt_aaaaaaaaaaaaaaaaaaaaaaaa",
  environment: "production",
  target: { kind: "prefix", ip_prefix: PREFIX },
  status: "expired",
  created_at: "2026-11-10T07:00:00.000Z",
  expires_at: "2026-11-10T07:15:00.000Z",
};
const liftedBlock: Containment = {
  ...EXAMPLE_CONTAINMENT,
  id: "cnt_bbbbbbbbbbbbbbbbbbbbbbbb",
  environment: "production",
  target: { kind: "actor", ip_hash: HASH_B },
  status: "lifted",
  lifted_at: "2026-11-10T08:40:00.000Z",
  lifted_by: "key_fedcba9876543210fedcba98",
};

const fieldsOf = (data: FormData): Record<string, string[]> => {
  const values: Record<string, string[]> = {};
  for (const [name, value] of data.entries()) values[name] = [...(values[name] ?? []), String(value)];
  return values;
};
const sent = (action: unknown): Record<string, string[]> => {
  const data = vi.mocked(action as (previous: unknown, data: FormData) => unknown).mock.calls.at(-1)?.[1];
  if (!data) throw new Error("the action was not called");
  return fieldsOf(data);
};
/** Slice 18a: the reason a sensitive confirmation requires, typed (when still empty) before it is sent. */
const REASON = "Reviewed with the on-call team";
const submit = async (control: HTMLElement): Promise<void> => {
  const reason = control.closest("form")?.querySelector<HTMLInputElement>('input[name="reason"]');
  if (reason?.required && reason.value === "") fireEvent.change(reason, { target: { value: REASON } });
  await act(async () => {
    fireEvent.click(control);
  });
};

beforeEach(() => {
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
});

interface ShowOptions {
  incident?: Incident;
  actors?: IncidentDetailResponse["actors"];
  containments?: Containment[];
  block?: ReturnType<typeof blockRequestFrom>;
  confirmLiftId?: string;
  confirmResolve?: boolean;
}

function show(options: ShowOptions = {}) {
  render(
    <IncidentDetail
      incident={options.incident ?? production}
      detections={[]}
      evidence={[]}
      actors={options.actors ?? actors}
      containments={options.containments ?? []}
      appName="shop-web"
      confirmResolve={options.confirmResolve ?? false}
      now={NOW}
      block={options.block ?? null}
      confirmLiftId={options.confirmLiftId}
    />,
  );
}

describe("formatting helpers", () => {
  it("shortens an actor hash and an id, keeping the prefix", () => {
    expect(shortHash(HASH_A)).toBe("iph_2932b22c…");
    expect(shortId("key_0123456789abcdef01234567")).toBe("key_01234567…");
  });

  it("states the expiry as a UTC clock time, with the date when it falls on another day", () => {
    expect(expiryText(NOW, 3600)).toBe("14:05 UTC");
    expect(expiryText(NOW, 900)).toBe("13:20 UTC");
    expect(expiryText(NOW, 86_400)).toBe("2026-11-11 13:05 UTC");
  });

  it("suggests the canonical form of a CIDR when one exists", () => {
    expect(suggestCidr("203.0.113.7/24")).toBe("203.0.113.0/24");
    expect(suggestCidr("2001:DB8::/32")).toBe("2001:db8::/32");
    expect(suggestCidr("2001:db8::1/48")).toBe("2001:db8::/48");
    expect(suggestCidr("203.0.113.0/24")).toBeNull();
    expect(suggestCidr("203.0.113.7")).toBeNull();
    expect(suggestCidr("203.0.113.0/40")).toBeNull();
    expect(suggestCidr("10.0.0.0/7")).toBeNull();
    expect(suggestCidr("office")).toBeNull();
  });
});

describe("addresses of the containment steps", () => {
  it("builds the Incident's block, lift and plain addresses", () => {
    expect(ROUTES.incident(incidentId, { block: { kind: "actor", ipHash: HASH_A, ttl: 3600 } })).toBe(
      `${PAGE}?contain=actor&actor=${HASH_A}&ttl=3600`,
    );
    expect(ROUTES.incident(incidentId, { block: { kind: "prefix", ttl: 900 } })).toBe(`${PAGE}?contain=prefix&ttl=900`);
    expect(ROUTES.incident(incidentId, { lift: EXAMPLE_CONTAINMENT.id })).toBe(
      `${PAGE}?lift=${EXAMPLE_CONTAINMENT.id}`,
    );
    expect(ROUTES.containment(appId)).toBe(`/apps/${appId}/containment`);
    expect(ROUTES.containment(appId, { lift: EXAMPLE_CONTAINMENT.id })).toBe(
      `/apps/${appId}/containment?lift=${EXAMPLE_CONTAINMENT.id}`,
    );
    expect(ROUTES.allowlist()).toBe("/settings/allowlist");
    expect(ROUTES.allowlist({ remove: EXAMPLE_ALLOWLIST_ENTRY.id })).toBe(
      `/settings/allowlist?remove=${EXAMPLE_ALLOWLIST_ENTRY.id}`,
    );
  });

  it("reads a block step only for a listed Actor and a known duration; no duration means 1 hour", () => {
    expect(blockRequestFrom({ contain: "actor", actor: HASH_A, ttl: "900" }, actors)).toEqual({
      kind: "actor",
      ipHash: HASH_A,
      ttl: 900,
    });
    expect(blockRequestFrom({ contain: "actor", actor: HASH_A }, actors)).toEqual({
      kind: "actor",
      ipHash: HASH_A,
      ttl: 3600,
    });
    expect(blockRequestFrom({ contain: "prefix", ttl: "86400" }, actors)).toEqual({ kind: "prefix", ttl: 86_400 });
    expect(blockRequestFrom({ contain: "actor", actor: "iph_00000000000000000000000000000000" }, actors)).toBeNull();
    expect(blockRequestFrom({ contain: "actor", actor: HASH_A, ttl: "60" }, actors)).toBeNull();
    expect(blockRequestFrom({ contain: "prefix", ttl: ["900", "3600"] }, actors)).toBeNull();
    expect(blockRequestFrom({ contain: "network" }, actors)).toBeNull();
    expect(blockRequestFrom({}, actors)).toBeNull();
  });

  it("reads a lift step only for an active block in the list", () => {
    const listed = [activeBlock, expiredBlock];
    expect(liftFrom(activeBlock.id, listed)).toBe(activeBlock.id);
    expect(liftFrom(expiredBlock.id, listed)).toBeUndefined();
    expect(liftFrom("cnt_ffffffffffffffffffffffff", listed)).toBeUndefined();
    expect(liftFrom([activeBlock.id], listed)).toBeUndefined();
    expect(liftFrom(undefined, listed)).toBeUndefined();
  });
});

describe("containment bar", () => {
  it("comes first among the actions: Block actor (top Actor, 1 hour) before Block network", () => {
    show();
    const bar = screen.getByTestId("containment-bar");
    const status = screen.getByRole("heading", { name: "Status" });
    // The bar precedes the status actions in reading order.
    expect(bar.compareDocumentPosition(status) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    const actor = within(bar).getByLabelText("Actor") as HTMLSelectElement;
    expect(actor.getAttribute("data-testid")).toBe("containment-actor");
    // The Actor with the most requests is chosen, whatever the order of the list.
    expect(actor.value).toBe(HASH_A);
    expect([...actor.options].map((option) => option.textContent)).toEqual([
      "iph_2932b22c… · 42 requests",
      "iph_d78c52b6… · 5 requests",
    ]);
    expect([...actor.options].map((option) => option.title)).toEqual([HASH_A, HASH_B]);

    const duration = within(bar).getByLabelText("Duration") as HTMLSelectElement;
    expect(duration.getAttribute("data-testid")).toBe("containment-duration");
    expect(duration.value).toBe("3600");
    expect([...duration.options].map((option) => [option.value, option.textContent])).toEqual([
      ["900", "15 minutes"],
      ["3600", "1 hour"],
      ["86400", "24 hours"],
    ]);

    const buttons = within(bar).getAllByRole("button");
    expect(buttons.map((button) => button.textContent)).toEqual(["Block actor", "Block network"]);
    expect(buttons[0]?.getAttribute("data-testid")).toBe("containment-block-actor");
    expect(buttons[1]?.getAttribute("data-testid")).toBe("containment-block-network");
    expect(buttons.map((button) => [button.getAttribute("name"), button.getAttribute("value")])).toEqual([
      ["contain", "actor"],
      ["contain", "prefix"],
    ]);
    // The bar only opens the confirmation step: a GET to the Incident's own address.
    const form = buttons[0]?.closest("form");
    expect(form?.getAttribute("method")).toBe("get");
    expect(form?.getAttribute("action")).toBe(PAGE);
    // It states the scope and that blocks end on their own.
    expect(bar.textContent).toContain(
      "Blocks apply to shop-web in production only, are enforced by its Shields within 30 seconds and end on their own.",
    );
  });

  it("disables Block actor with the reason when no Actor is known, and keeps Block network", () => {
    show({ actors: [] });
    const bar = screen.getByTestId("containment-bar");
    expect(within(bar).queryByTestId("containment-actor")).toBeNull();
    const blockActor = screen.getByTestId("containment-block-actor") as HTMLButtonElement;
    expect(blockActor.disabled).toBe(true);
    const reason = screen.getByTestId("containment-no-actor");
    expect(reason.textContent).toBe(
      "No Actors to block: Shield sends Actor identities only when an actor key is configured (AR_ACTOR_KEY). You can still block the network.",
    );
    expect(blockActor.getAttribute("aria-describedby")).toBe(reason.id);
    expect((screen.getByTestId("containment-block-network") as HTMLButtonElement).disabled).toBe(false);
  });

  it("is not offered for a resolved Incident, which says why", () => {
    show({
      incident: { ...production, status: "resolved" },
      block: { kind: "actor", ipHash: HASH_A, ttl: 3600 },
    });
    expect(screen.queryByTestId("containment-block-actor")).toBeNull();
    expect(screen.queryByTestId("containment-block-network")).toBeNull();
    expect(screen.queryByTestId("containment-confirm")).toBeNull();
    expect(screen.getByTestId("containment-resolved-note").textContent).toBe(
      "This Incident is resolved, so it can no longer be contained. Earlier blocks are listed below.",
    );
  });

  it("asks before blocking the Actor, stating target, App, Environment, duration and expiry", async () => {
    show({ block: { kind: "actor", ipHash: HASH_A, ttl: 3600 } });
    const dialog = screen.getByTestId("containment-confirm");
    expect(dialog.getAttribute("role")).toBe("alertdialog");
    expect(document.activeElement).toBe(dialog);
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Blocks 1 Actor (iph_2932b22c…) in production of shop-web for 1 hour, until 14:05 UTC.",
    );
    expect(dialog.textContent).toContain(
      "Shields enforce it within 30 seconds. It ends on its own at expiry, or earlier when you lift it. Addresses on the never block list are never blocked.",
    );
    expect(within(dialog).getByTestId("confirm-cancel").getAttribute("href")).toBe(PAGE);
    // No typed confirmation for one Actor.
    expect(within(dialog).queryByTestId("confirm-typed")).toBeNull();
    // The bar keeps the choice that opened the step.
    expect((screen.getByTestId("containment-actor") as HTMLSelectElement).value).toBe(HASH_A);

    const confirm = within(dialog).getByTestId("confirm-submit");
    expect(confirm.textContent).toBe("Block actor");
    await submit(confirm);
    expect(sent(actions.createContainmentAction)).toEqual({
      reason: [REASON],
      incidentId: [incidentId],
      environment: ["production"],
      kind: ["actor"],
      ipHash: [HASH_A],
      ttl: ["3600"],
      confirm: [HASH_A],
    });
  });

  it("states the date of an expiry 24 hours away", () => {
    show({ block: { kind: "actor", ipHash: HASH_B, ttl: 86_400 } });
    expect(screen.getByTestId("confirm-question").textContent).toBe(
      "Blocks 1 Actor (iph_d78c52b6…) in production of shop-web for 24 hours, until 2026-11-11 13:05 UTC.",
    );
    expect((screen.getByTestId("containment-duration") as HTMLSelectElement).value).toBe("86400");
  });

  it("asks more strongly before blocking the network: every client of the prefix, typed to confirm", async () => {
    show({ block: { kind: "prefix", ttl: 900 } });
    const dialog = screen.getByTestId("containment-confirm");
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Blocks every client in 203.0.113.0/24 in production of shop-web for 15 minutes, until 13:20 UTC.",
    );
    expect(within(dialog).getByTestId("confirm-broad").textContent).toBe(
      "This blocks everyone who shares 203.0.113.0/24, not only the attacker — an office, a mobile carrier or a proxy may sit behind it.",
    );
    const typed = within(dialog).getByLabelText("Type 203.0.113.0/24 to confirm") as HTMLInputElement;
    expect(typed.getAttribute("name")).toBe("typedPrefix");
    expect(typed.getAttribute("data-testid")).toBe("confirm-typed");
    expect(typed.required).toBe(true);

    fireEvent.change(typed, { target: { value: PREFIX } });
    const confirm = within(dialog).getByTestId("confirm-submit");
    expect(confirm.textContent).toBe("Block network");
    await submit(confirm);
    expect(sent(actions.createContainmentAction)).toEqual({
      reason: [REASON],
      incidentId: [incidentId],
      environment: ["production"],
      kind: ["prefix"],
      ttl: ["900"],
      confirm: [PREFIX],
      typedPrefix: [PREFIX],
    });
  });

  it("shows a refused block in the error summary, and a mistyped prefix below the field", async () => {
    const CAP = "This App already has 150 active blocks in production. Lift one first.";
    vi.mocked(actions.createContainmentAction).mockResolvedValueOnce({
      ok: false,
      errors: [{ path: "", message: CAP }],
    });
    show({ block: { kind: "actor", ipHash: HASH_A, ttl: 3600 } });
    await submit(screen.getByTestId("confirm-submit"));
    expect(screen.getByTestId("error-summary").textContent).toContain(CAP);
  });

  it("shows the typed-prefix refusal below the typed field", async () => {
    const MISTYPED = "Nothing was blocked. Type 203.0.113.0/24 exactly as shown.";
    vi.mocked(actions.createContainmentAction).mockResolvedValueOnce({
      ok: false,
      errors: [{ path: "typedPrefix", message: MISTYPED }],
    });
    show({ block: { kind: "prefix", ttl: 3600 } });
    // The browser holds back a mismatch itself; the Server Action checks again and alone decides.
    expect(screen.getByTestId("confirm-typed").getAttribute("pattern")).toBe("203\\.0\\.113\\.0\\/24");
    fireEvent.change(screen.getByTestId("confirm-typed"), { target: { value: PREFIX } });
    await submit(screen.getByTestId("confirm-submit"));
    expect(screen.getByTestId("confirm-typed-error").textContent).toBe(MISTYPED);
  });
});

describe("Actors card", () => {
  it("lists each Actor by short hash, with the full hash in its title and name, and its request count", () => {
    show();
    const card = screen.getByTestId("incident-actors");
    const rows = within(card).getAllByTestId("actor-row");
    // Most requests first.
    expect(rows.map((row) => row.getAttribute("data-actor"))).toEqual([HASH_A, HASH_B]);
    const hash = within(rows[0] as HTMLElement).getByTestId("actor-hash");
    expect(hash.textContent).toBe("iph_2932b22c…");
    expect(hash.getAttribute("title")).toBe(HASH_A);
    // The short form is for the eye; assistive technology reads the full hash.
    expect(hash.getAttribute("aria-hidden")).toBe("true");
    expect(within(rows[0] as HTMLElement).getByTestId("actor-hash-full").textContent).toBe(`Actor ${HASH_A}`);
    expect(within(rows[0] as HTMLElement).getByRole("rowheader").textContent).toContain(HASH_A);
    expect(within(rows[0] as HTMLElement).getByTestId("actor-requests").textContent).toBe("42");
  });

  it("says why there is no Actor", () => {
    show({ actors: [] });
    expect(screen.getByTestId("actors-empty").textContent).toBe(
      "No Actors for this Incident. Shield sends Actor identities only when an actor key is configured (AR_ACTOR_KEY); the key stays on your servers.",
    );
  });
});

describe("blocks list", () => {
  it("shows target, status as word and shape, end time and who created each block", () => {
    show({ containments: [activeBlock, expiredBlock, liftedBlock] });
    const list = screen.getByTestId("block-list");
    const rows = within(list).getAllByTestId("block-row");
    expect(rows.map((row) => row.getAttribute("data-status"))).toEqual(["active", "expired", "lifted"]);
    const cells = rows.map((row) => within(row as HTMLElement));

    expect(cells[0]?.getByTestId("block-target").textContent).toBe("Actor iph_2932b22c…");
    expect(cells[0]?.getByTestId("block-target").getAttribute("title")).toBe(HASH_A);
    expect(cells[1]?.getByTestId("block-target").textContent).toBe("Network 203.0.113.0/24");

    const statuses = cells.map((cell) => cell.getByTestId("block-status"));
    expect(statuses.map((status) => status.textContent)).toEqual(["Active", "Expired", "Lifted"]);
    // Never colour alone: each status has its own shape.
    const shapes = statuses.map((status) => status.querySelector("svg")?.getAttribute("data-shape"));
    expect(new Set(shapes).size).toBe(3);
    for (const status of statuses) expect(status.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");

    expect(cells[0]?.getByTestId("block-ends").textContent).toBe("Expires 2026-11-10 09:21:00");
    expect(cells[1]?.getByTestId("block-ends").textContent).toBe("Expired 2026-11-10 07:15:00");
    expect(cells[2]?.getByTestId("block-ends").textContent).toBe("Lifted 2026-11-10 08:40:00");
    expect(cells[0]?.getByTestId("block-created-by").textContent).toBe("key_01234567…");
    expect(cells[0]?.getByTestId("block-created-by").getAttribute("title")).toBe(EXAMPLE_CONTAINMENT.created_by);

    // Lift is offered for the active block only, as a link to the confirmation step.
    const lift = cells[0]?.getByRole("link", { name: "Lift" });
    expect(lift?.getAttribute("data-testid")).toBe("block-lift");
    expect(lift?.getAttribute("href")).toBe(`${PAGE}?lift=${activeBlock.id}`);
    expect(cells[1]?.queryByTestId("block-lift")).toBeNull();
    expect(cells[2]?.queryByTestId("block-lift")).toBeNull();
    expect(screen.queryByRole("button", { name: "Lift" })).toBeNull();
  });

  it("says what will appear when the Incident has no block", () => {
    show({ containments: [] });
    expect(screen.getByTestId("blocks-empty").textContent).toBe(
      "No blocks yet. A block created with the bar above is listed here until it ends, and stays on record after.",
    );
  });

  it("asks before lifting, naming the target, App and Environment, and sends the confirmation", async () => {
    show({ containments: [activeBlock], confirmLiftId: activeBlock.id });
    const dialog = screen.getByTestId("lift-confirm");
    expect(document.activeElement).toBe(dialog);
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Lift the block of Actor iph_2932b22c… in production of shop-web? Its requests pass again within 30 seconds.",
    );
    expect(dialog.textContent).toContain("The block stays on record as Lifted, with who lifted it and when.");
    expect(within(dialog).getByTestId("confirm-cancel").getAttribute("href")).toBe(PAGE);
    expect(screen.queryByTestId("block-lift")).toBeNull();
    await submit(within(dialog).getByTestId("confirm-submit"));
    expect(sent(actions.liftContainmentAction)).toEqual({
      containmentId: [activeBlock.id],
      confirm: [activeBlock.id],
      incidentId: [incidentId],
    });
  });

  it("names the network when lifting a network block, and shows a refusal", async () => {
    const network = { ...expiredBlock, status: "active" as const, expires_at: "2026-11-10T14:05:00.000Z" };
    vi.mocked(actions.liftContainmentAction).mockResolvedValueOnce({
      ok: false,
      errors: [
        {
          path: "",
          message: "This block already ended — it expired or was lifted. Reload the page to see its status.",
        },
      ],
    });
    render(
      <BlockList
        containments={[network]}
        appName="shop-web"
        caption="Blocks"
        empty="none"
        base={PAGE}
        returnTo={{ incidentId }}
        confirmLiftId={network.id}
      />,
    );
    expect(screen.getByTestId("confirm-question").textContent).toBe(
      "Lift the block of 203.0.113.0/24 in production of shop-web? Every client in it passes again within 30 seconds.",
    );
    await submit(screen.getByTestId("confirm-submit"));
    expect(screen.getByTestId("error-summary").textContent).toContain("This block already ended");
  });

  it("marks the Incident Contained in its header while a block is active", () => {
    show({ containments: [activeBlock] });
    expect(screen.getByTestId("incident-contained").textContent).toBe("Contained");
  });
});

describe("Contained marker in the Incident list", () => {
  it("marks only the Incidents with an active block, as a word with a shape", () => {
    const other = { ...EXAMPLE_INCIDENT, id: "inc_aaaaaaaaaaaaaaaaaaaaaaaa" };
    render(
      <IncidentList
        incidents={[EXAMPLE_INCIDENT, other]}
        appNames={new Map([[appId, "shop-web"]])}
        status={undefined}
        contained={new Set([EXAMPLE_INCIDENT.id])}
      />,
    );
    const rows = screen.getAllByTestId("incident-row");
    const marker = within(rows[0] as HTMLElement).getByTestId("incident-contained");
    expect(marker.textContent).toBe("Contained");
    expect(marker.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
    expect(rows[0]?.getAttribute("data-contained")).toBe("true");
    expect(within(rows[1] as HTMLElement).queryByTestId("incident-contained")).toBeNull();
    expect(rows[1]?.getAttribute("data-contained")).toBe("false");
  });

  it("says when the containment state could not be loaded instead of showing no marker silently", () => {
    render(<IncidentList incidents={[EXAMPLE_INCIDENT]} appNames={new Map()} status={undefined} contained={null} />);
    expect(screen.getByTestId("incidents-contained-unknown").textContent).toBe(
      "Blocks could not be loaded, so Incidents are shown without the Contained marker. Reload the page to try again.",
    );
  });
});

describe("App containment section", () => {
  const staging = { ...activeBlock, id: "cnt_cccccccccccccccccccccccc", environment: "staging" as const };

  it("lists the active blocks of each Environment with a count and Lift", () => {
    render(
      <AppContainment
        appId={appId}
        appName="shop-web"
        containments={[activeBlock, staging]}
        confirmLiftId={undefined}
      />,
    );
    const sections = screen.getAllByTestId("containment-environment");
    expect(sections.map((section) => section.getAttribute("data-environment"))).toEqual([
      "production",
      "staging",
      "development",
    ]);
    const [prod, stg, dev] = sections.map((section) => within(section as HTMLElement));
    expect(prod?.getByTestId("containment-count").textContent).toBe("1 of 150 active blocks");
    expect(prod?.getAllByTestId("block-row")).toHaveLength(1);
    expect(prod?.getByTestId("block-lift").getAttribute("href")).toBe(
      `/apps/${appId}/containment?lift=${activeBlock.id}`,
    );
    expect(stg?.getAllByTestId("block-row").map((row) => row.getAttribute("data-block-id"))).toEqual([staging.id]);
    expect(dev?.getByTestId("blocks-empty").textContent).toBe(
      "No active blocks in development. Blocks are created from an Incident.",
    );
    expect(dev?.getByTestId("containment-count").textContent).toBe("0 of 150 active blocks");
  });

  it("asks before lifting and sends the App as the way back", async () => {
    render(
      <AppContainment appId={appId} appName="shop-web" containments={[activeBlock]} confirmLiftId={activeBlock.id} />,
    );
    const dialog = screen.getByTestId("lift-confirm");
    expect(within(dialog).getByTestId("confirm-cancel").getAttribute("href")).toBe(`/apps/${appId}/containment`);
    await submit(within(dialog).getByTestId("confirm-submit"));
    expect(sent(actions.liftContainmentAction)).toEqual({
      containmentId: [activeBlock.id],
      confirm: [activeBlock.id],
      appId: [appId],
    });
  });
});

describe("never block list", () => {
  const second: AllowlistEntry = {
    ...EXAMPLE_ALLOWLIST_ENTRY,
    id: "alw_aaaaaaaaaaaaaaaaaaaaaaaa",
    cidr: "2001:db8::/32",
    note: "",
  };

  it("lists range, note, added time and who added it, with the count of 100", () => {
    render(<AllowlistTable entries={[EXAMPLE_ALLOWLIST_ENTRY, second]} confirmRemoveId={undefined} />);
    expect(screen.getByTestId("allowlist-count").textContent).toBe("2 of 100 ranges");
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Range",
      "Note",
      "Added UTC",
      "Added by",
      "Actions",
    ]);
    const rows = screen.getAllByTestId("allowlist-row");
    expect(rows.map((row) => row.getAttribute("data-entry-id"))).toEqual([EXAMPLE_ALLOWLIST_ENTRY.id, second.id]);
    const first = within(rows[0] as HTMLElement);
    expect(first.getByTestId("allowlist-cidr").textContent).toBe("198.51.100.0/24");
    expect(first.getByTestId("allowlist-note").textContent).toBe("Office network");
    expect(first.getByTestId("allowlist-added").textContent).toBe("2026-11-10 08:00:00");
    expect(first.getByTestId("allowlist-added-by").textContent).toBe("key_01234567…");
    const remove = first.getByRole("link", { name: "Remove" });
    expect(remove.getAttribute("data-testid")).toBe("allowlist-remove");
    expect(remove.getAttribute("href")).toBe(`/settings/allowlist?remove=${EXAMPLE_ALLOWLIST_ENTRY.id}`);
    // An empty note is shown as "no note", not as a blank cell.
    expect(within(rows[1] as HTMLElement).getByTestId("allowlist-note").textContent).toBe("No note");
  });

  it("says what will appear when the list is empty", () => {
    render(<AllowlistTable entries={[]} confirmRemoveId={undefined} />);
    expect(screen.getByTestId("allowlist-count").textContent).toBe("0 of 100 ranges");
    expect(screen.getByTestId("allowlist-empty").textContent).toBe(
      "No ranges yet. Add the networks that must never be blocked, such as your office or your monitoring.",
    );
  });

  it("asks before removing, naming the range, and sends the confirmation", async () => {
    render(<AllowlistTable entries={[EXAMPLE_ALLOWLIST_ENTRY]} confirmRemoveId={EXAMPLE_ALLOWLIST_ENTRY.id} />);
    const dialog = screen.getByTestId("allowlist-confirm");
    expect(document.activeElement).toBe(dialog);
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Remove 198.51.100.0/24 from the never block list? Containment blocks can then apply to it.",
    );
    expect(within(dialog).getByTestId("confirm-cancel").getAttribute("href")).toBe("/settings/allowlist");
    await submit(within(dialog).getByTestId("confirm-submit"));
    expect(sent(actions.deleteAllowlistEntryAction)).toEqual({
      entryId: [EXAMPLE_ALLOWLIST_ENTRY.id],
      confirm: [EXAMPLE_ALLOWLIST_ENTRY.id],
    });
  });

  it("has labelled fields for the range and the note, and sends them", async () => {
    vi.mocked(actions.createAllowlistEntryAction).mockResolvedValueOnce({ ok: true, entry: EXAMPLE_ALLOWLIST_ENTRY });
    render(<AddRangeForm />);
    const cidr = screen.getByLabelText("Range (CIDR)") as HTMLInputElement;
    expect(cidr.getAttribute("data-testid")).toBe("allowlist-cidr-input");
    const note = screen.getByLabelText("Note") as HTMLInputElement;
    expect(note.getAttribute("data-testid")).toBe("allowlist-note-input");
    expect(note.maxLength).toBe(80);
    fireEvent.change(cidr, { target: { value: "198.51.100.0/24" } });
    fireEvent.change(note, { target: { value: "Office network" } });
    await submit(screen.getByTestId("allowlist-add"));
    expect(sent(actions.createAllowlistEntryAction)).toEqual({ cidr: ["198.51.100.0/24"], note: ["Office network"] });
    expect(screen.getByTestId("allowlist-added-status").textContent).toBe("198.51.100.0/24 was added");
  });

  it("shows a non-canonical range below the field with the canonical form, keeping what was typed", async () => {
    const message = "Write this range as 203.0.113.0/24: the network address with its host bits zero.";
    vi.mocked(actions.createAllowlistEntryAction).mockResolvedValueOnce({
      ok: false,
      errors: [{ path: "cidr", message }],
      values: { cidr: "203.0.113.7/24", note: "VPN" },
    });
    render(<AddRangeForm />);
    await submit(screen.getByTestId("allowlist-add"));
    expect(screen.getByTestId("allowlist-cidr-error").textContent).toBe(message);
    expect((screen.getByTestId("allowlist-cidr-input") as HTMLInputElement).value).toBe("203.0.113.7/24");
    expect((screen.getByTestId("allowlist-note-input") as HTMLInputElement).value).toBe("VPN");
    expect(screen.getByTestId("error-summary").textContent).toContain(message);
    expect(document.activeElement).toBe(screen.getByTestId("error-summary"));
  });
});

describe("navigation", () => {
  const organization = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-10T08:00:00.000Z" };

  it("has Never block in the settings navigation, marked on its page", () => {
    render(
      <AppShell organization={organization} current="allowlist">
        <p>content</p>
      </AppShell>,
    );
    const settings = screen.getByRole("navigation", { name: "Settings" });
    expect(
      within(settings)
        .getAllByRole("link")
        .map((link) => [link.textContent, link.getAttribute("href")]),
    ).toEqual([
      ["Alerts", "/settings/alerts"],
      ["Never block", "/settings/allowlist"],
      // Slice 18a.
      ["Audit log", "/settings/audit"],
    ]);
    expect(screen.getByTestId("nav-allowlist").getAttribute("aria-current")).toBe("page");
  });

  it("has a Containment screen among the App's screens", () => {
    render(<AppNav appId={appId} current="containment" />);
    const link = screen.getByRole("link", { name: "Containment" });
    expect(link.getAttribute("href")).toBe(`/apps/${appId}/containment`);
    expect(link.getAttribute("data-testid")).toBe("app-nav-containment");
    expect(link.getAttribute("aria-current")).toBe("page");
  });
});
