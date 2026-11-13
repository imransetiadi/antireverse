import {
  EXAMPLE_ADVISORY,
  EXAMPLE_BUILD,
  EXAMPLE_FINDING,
  EXAMPLE_FINDING_INCIDENT,
  EXAMPLE_VIRTUAL_PATCH,
  type Incident,
  type StoredEvent,
} from "@antireverse/protocol";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Slice 20: virtual patches in the Console — the Finding page's section, the Policy page's list, the patch on an
// Event and the Exploit attempt Incident. The Server Actions are replaced by fakes: what a form sends is the
// contract.
vi.mock("@/app/actions.ts", () => ({
  ignoreFindingAction: vi.fn(),
  reopenFindingAction: vi.fn(),
  setPatchModeAction: vi.fn(),
  updateIncidentAction: vi.fn(),
  createContainmentAction: vi.fn(),
  liftContainmentAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import type { PatchSummary } from "@antireverse/protocol";
import * as actions from "@/app/actions.ts";
import { FindingDetail } from "@/features/findings/finding-detail.tsx";
import { IncidentDetail } from "@/features/incidents/incident-detail.tsx";
import { EventRow } from "@/features/live-feed/event-row.tsx";
import { PatchModeChip } from "@/features/patches/mode-chip.tsx";
import { PolicyPatches } from "@/features/patches/policy-patches.tsx";
import { confirmEnforceFrom, patchForFinding } from "@/features/patches/query.ts";
import { eventAt } from "./helpers/events.ts";

const NOW = Date.UTC(2026, 10, 11, 15, 30);
const MONO = /\bcode-[1-3]\b/;
const NOTE = "A patch blocks known exploit requests. Upgrading is the fix.";

const PATCH: PatchSummary = {
  id: EXAMPLE_VIRTUAL_PATCH.id,
  title: EXAMPLE_VIRTUAL_PATCH.title,
  advisories: [...EXAMPLE_VIRTUAL_PATCH.advisories],
  package: EXAMPLE_VIRTUAL_PATCH.package,
  mode: "monitor",
  active: true,
  shipped: true,
  findings: [EXAMPLE_FINDING.id],
  hits_24h: 12,
  last_hit: "2026-11-11T14:05:00.000Z",
};
const patch = (overrides: Partial<PatchSummary>): PatchSummary => ({ ...PATCH, ...overrides });

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
  cleanup();
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
});

describe("patch query helpers", () => {
  it("opens the enforce step only for exactly ?confirm=enforce", () => {
    expect(confirmEnforceFrom("enforce")).toBe(true);
    expect(confirmEnforceFrom("ignore")).toBe(false);
    expect(confirmEnforceFrom(["enforce", "enforce"])).toBe(false);
    expect(confirmEnforceFrom(undefined)).toBe(false);
  });

  it("finds the patch of a Finding by its id, else by its advisory or an alias in the same package", () => {
    const other = patch({ id: "vp_other_patch", advisories: ["GHSA-zzzz-zzzz-zzzz"], findings: [] });
    expect(patchForFinding([other, PATCH], EXAMPLE_FINDING)?.id).toBe(PATCH.id);
    const byAlias = patch({ advisories: ["CVE-2026-10001"], findings: [], active: false });
    expect(patchForFinding([byAlias], EXAMPLE_FINDING)?.id).toBe(PATCH.id);
    expect(patchForFinding([patch({ findings: [], package: "another-package" })], EXAMPLE_FINDING)).toBeNull();
    expect(patchForFinding([other], EXAMPLE_FINDING)).toBeNull();
  });
});

describe("PatchModeChip", () => {
  it("draws Monitor and Enforce each with its own glyph, word and colour, monitor dashed and enforce solid", () => {
    const { unmount } = render(<PatchModeChip mode="monitor" />);
    const monitor = screen.getByTestId("patch-mode");
    expect(monitor.textContent).toBe("Monitor");
    expect(monitor.getAttribute("data-mode")).toBe("monitor");
    expect(monitor.querySelector("svg")?.getAttribute("data-shape")).toBe("eye");
    expect(monitor.className).toContain("border-dashed");
    expect(monitor.className).toContain("text-dec-monitor");
    unmount();
    render(<PatchModeChip mode="enforce" />);
    const enforce = screen.getByTestId("patch-mode");
    expect(enforce.textContent).toBe("Enforce");
    expect(enforce.querySelector("svg")?.getAttribute("data-shape")).toBe("shield-check");
    expect(enforce.className).toContain("border-solid");
    expect(enforce.className).toContain("text-dec-block");
    expect(enforce.outerHTML).not.toMatch(/#[0-9a-fA-F]{3,8}\b|rgb\(/);
  });
});

describe("FindingDetail — Virtual patch", () => {
  function show(patches: readonly PatchSummary[] | null, options: { confirmEnforce?: boolean } = {}): void {
    render(
      <FindingDetail
        finding={EXAMPLE_FINDING}
        advisory={EXAMPLE_ADVISORY}
        appName="shop-web"
        build={EXAMPLE_BUILD}
        confirmIgnore={false}
        patches={patches}
        confirmEnforce={options.confirmEnforce ?? false}
        now={NOW}
      />,
    );
  }
  const section = () => within(screen.getByTestId("finding-patch"));

  it("says when no patch is available, with the note that upgrading is the fix", () => {
    show([]);
    expect(screen.getByRole("heading", { name: "Virtual patch" })).toBeTruthy();
    expect(section().getByTestId("patch-none").textContent).toBe("No virtual patch is available for this advisory.");
    expect(section().getByTestId("patch-note").textContent).toBe(NOTE);
    expect(section().queryByTestId("patch-enforce")).toBeNull();
  });

  it("says when the patches could not be read", () => {
    show(null);
    expect(section().getByTestId("patch-unavailable").textContent).toBe(
      "Virtual patches could not be loaded. Reload the page to try again.",
    );
  });

  it("shows the patch's title, id, mode, hits in 24 h and last hit", () => {
    show([PATCH]);
    expect(section().getByTestId("patch-title").textContent).toBe(PATCH.title);
    const id = section().getByTestId("patch-id");
    expect(id.textContent).toBe(PATCH.id);
    expect(id.className).toMatch(MONO);
    expect(section().getByTestId("patch-mode").textContent).toBe("Monitor");
    expect(section().getByTestId("patch-hits").textContent).toBe("12");
    const last = section().getByTestId("patch-last-hit");
    expect(last.textContent).toBe("2026-11-11 14:05:00 UTC");
    expect(last.getAttribute("dateTime")).toBe("2026-11-11T14:05:00.000Z");
    expect(section().queryByTestId("patch-not-shipped")).toBeNull();
  });

  it("says None when the patch never matched", () => {
    show([patch({ hits_24h: 0, last_hit: null })]);
    expect(section().getByTestId("patch-hits").textContent).toBe("0");
    expect(section().getByTestId("patch-last-hit").textContent).toBe("None");
  });

  it("says Not shipped: bundle budget when the patch is active but left out of the bundle", () => {
    show([patch({ shipped: false })]);
    const tag = section().getByTestId("patch-not-shipped");
    expect(tag.textContent).toBe("Not shipped: bundle budget");
    expect(tag.querySelector("svg")?.getAttribute("data-shape")).toBe("warning");
  });

  it("offers Enforce as a link to the confirmation step; nothing is sent from the page itself", () => {
    show([PATCH]);
    const enforce = section().getByTestId("patch-enforce");
    expect(enforce.tagName).toBe("A");
    expect(enforce.textContent).toBe("Enforce");
    expect(enforce.getAttribute("href")).toBe(`/findings/${EXAMPLE_FINDING.id}?confirm=enforce`);
    expect(screen.queryByTestId("patch-confirm")).toBeNull();
    expect(section().queryByTestId("patch-monitor")).toBeNull();
  });

  it("asks before enforcing with the patch id typed, and sends the typed id as the confirmation", async () => {
    show([PATCH], { confirmEnforce: true });
    const step = within(screen.getByTestId("patch-confirm"));
    expect(step.getByTestId("confirm-question").textContent).toBe(
      `Enforce ${PATCH.title} for shop-web (${EXAMPLE_FINDING.environment})? Shield will refuse requests that match it.`,
    );
    expect(step.getByTestId("confirm-typed-label").textContent).toContain(`Type ${PATCH.id} to confirm`);
    expect(step.getByTestId("confirm-cancel").getAttribute("href")).toBe(`/findings/${EXAMPLE_FINDING.id}`);
    expect(section().queryByTestId("patch-enforce")).toBeNull();
    fireEvent.change(step.getByTestId("confirm-typed"), { target: { value: PATCH.id } });
    await submit(step.getByTestId("confirm-submit"));
    expect(sent(actions.setPatchModeAction)).toEqual({
      reason: [REASON],
      appId: [EXAMPLE_FINDING.app_id],
      environment: [EXAMPLE_FINDING.environment],
      patchId: [PATCH.id],
      findingId: [EXAMPLE_FINDING.id],
      mode: ["enforce"],
      confirm: [PATCH.id],
    });
  });

  it("goes back to monitor in one action, without a confirmation", async () => {
    show([patch({ mode: "enforce" })]);
    expect(section().getByTestId("patch-mode").textContent).toBe("Enforce");
    expect(section().queryByTestId("patch-enforce")).toBeNull();
    const back = section().getByTestId("patch-monitor");
    expect(back.textContent).toBe("Back to monitor");
    await submit(back);
    expect(sent(actions.setPatchModeAction)).toEqual({
      appId: [EXAMPLE_FINDING.app_id],
      environment: [EXAMPLE_FINDING.environment],
      patchId: [PATCH.id],
      findingId: [EXAMPLE_FINDING.id],
      mode: ["monitor"],
    });
  });

  it("offers no action for a patch that is not active, and says why", () => {
    show([patch({ active: false, findings: [] })], { confirmEnforce: true });
    expect(section().getByTestId("patch-inactive").textContent).toBe(
      "Not active: a patch ships only while a Finding for its advisory is open or ignored.",
    );
    expect(section().queryByTestId("patch-enforce")).toBeNull();
    expect(section().queryByTestId("patch-monitor")).toBeNull();
    expect(screen.queryByTestId("patch-confirm")).toBeNull();
  });
});

describe("PolicyPatches", () => {
  it("lists the active patches with mode, hits and a link to the Finding", () => {
    const enforced = patch({
      id: "vp_second_patch",
      title: "Second patch",
      mode: "enforce",
      hits_24h: 3,
      shipped: false,
      findings: ["fnd_aaaaaaaaaaaaaaaaaaaaaaaa"],
    });
    const inactive = patch({ id: "vp_inactive_patch", title: "Inactive", active: false, findings: [] });
    render(<PolicyPatches environment="production" patches={[PATCH, inactive, enforced]} />);
    const rows = screen.getAllByTestId("policy-patch-row");
    expect(rows.map((row) => row.getAttribute("data-patch-id"))).toEqual([PATCH.id, "vp_second_patch"]);
    const first = within(rows[0] as HTMLElement);
    expect(first.getByTestId("patch-title").textContent).toBe(PATCH.title);
    expect(first.getByTestId("patch-mode").textContent).toBe("Monitor");
    expect(first.getByTestId("patch-hits").textContent).toBe("12");
    const link = first.getByTestId("patch-finding-link");
    expect(link.getAttribute("href")).toBe(`/findings/${EXAMPLE_FINDING.id}`);
    expect(link.textContent).toBe("View Finding");
    const second = within(rows[1] as HTMLElement);
    expect(second.getByTestId("patch-mode").textContent).toBe("Enforce");
    expect(second.getByTestId("patch-not-shipped").textContent).toBe("Not shipped: bundle budget");
  });

  it("says when no patch is active and when the patches could not be read", () => {
    const { unmount } = render(<PolicyPatches environment="staging" patches={[]} />);
    expect(screen.getByTestId("policy-patches-none").textContent).toBe("No virtual patch is active in staging.");
    unmount();
    render(<PolicyPatches environment="staging" patches={null} />);
    expect(screen.getByTestId("policy-patches-unavailable")).toBeTruthy();
  });
});

describe("EventRow — patch decisions", () => {
  const patchEvent = (decision: Partial<StoredEvent["decision"]>): StoredEvent =>
    eventAt(1_000, {
      request: { method: "GET", route: "/search", status: 403, latency_ms: 0.4 },
      decision: {
        action: "block",
        mode: "enforce",
        rule_id: null,
        policy_version: 3,
        containment_id: null,
        patch_id: PATCH.id,
        patch_body: "checked",
        ...decision,
      },
    });
  const row = (event: StoredEvent, titles?: Readonly<Record<string, string>>) =>
    render(
      <table>
        <tbody>
          <EventRow event={event} patchTitles={titles} />
        </tbody>
      </table>,
    );

  it("names the patch by its title when known, by its id otherwise", () => {
    const { unmount } = row(patchEvent({}), { [PATCH.id]: PATCH.title });
    expect(screen.getByTestId("event-patch").textContent).toBe(`Patch: ${PATCH.title}`);
    expect(screen.queryByTestId("event-patch-unchecked")).toBeNull();
    unmount();
    row(patchEvent({}));
    expect(screen.getByTestId("event-patch").textContent).toBe(`Patch: ${PATCH.id}`);
  });

  it("says body not checked when the patch's body condition could not be checked", () => {
    row(patchEvent({ action: "block", mode: "monitor", patch_body: "unchecked" }));
    expect(screen.getByTestId("event-patch-unchecked").textContent).toBe("body not checked");
  });

  it("says body in an unreadable character set when the body could not be decoded", () => {
    row(patchEvent({ action: "block", mode: "enforce", patch_body: "undecodable" }));
    expect(screen.getByTestId("event-patch-undecodable").textContent).toBe("body in an unreadable character set");
    expect(screen.queryByTestId("event-patch-unchecked")).toBeNull();
  });

  it("renders an older Event without the patch fields as before", () => {
    const older = eventAt(1_000);
    const { patch_id: _id, patch_body: _body, ...decision } = older.decision;
    row({ ...older, decision: decision as StoredEvent["decision"] });
    expect(screen.queryByTestId("event-patch")).toBeNull();
    expect(screen.queryByTestId("event-patch-unchecked")).toBeNull();
    expect(screen.getByTestId("decision-chip")).toBeTruthy();
  });
});

describe("IncidentDetail — exploit attempt", () => {
  const EXPLOIT: Incident = {
    ...EXAMPLE_FINDING_INCIDENT,
    id: "inc_aabbccddeeff001122334455",
    rule: "exploit-attempt",
    title: "Exploit attempt",
    ip_prefix: "203.0.113.0/24",
    build_id: null,
  };

  it("links the advisory to the Finding list narrowed to it and names the patch in the evidence", () => {
    const evidence = eventAt(1_000, {
      decision: {
        action: "block",
        mode: "monitor",
        rule_id: null,
        policy_version: 2,
        containment_id: null,
        patch_id: PATCH.id,
        patch_body: "unchecked",
      },
    });
    render(
      <IncidentDetail
        incident={EXPLOIT}
        detections={[]}
        evidence={[evidence]}
        appName="shop-web"
        confirmResolve={false}
        actors={[]}
        containments={[]}
        now={NOW}
        patchTitles={{ [PATCH.id]: PATCH.title }}
      />,
    );
    expect(screen.getByTestId("fact-rule").textContent).toBe("Exploit attempt");
    const link = screen.getByTestId("fact-advisory-link");
    expect(link.textContent).toBe(EXAMPLE_FINDING_INCIDENT.advisory_id);
    expect(link.getAttribute("href")).toBe(`/findings?advisory=${EXAMPLE_FINDING_INCIDENT.advisory_id}`);
    const evidenceRow = within(screen.getByTestId("incident-evidence"));
    expect(evidenceRow.getByTestId("event-patch").textContent).toBe(`Patch: ${PATCH.title}`);
    expect(evidenceRow.getByTestId("event-patch-unchecked").textContent).toBe("body not checked");
  });

  it("says body in an unreadable character set in the evidence of an Incident", () => {
    const evidence = eventAt(1_000, {
      decision: {
        action: "block",
        mode: "enforce",
        rule_id: null,
        policy_version: 2,
        containment_id: null,
        patch_id: PATCH.id,
        patch_body: "undecodable",
      },
    });
    render(
      <IncidentDetail
        incident={EXPLOIT}
        detections={[]}
        evidence={[evidence]}
        appName="shop-web"
        confirmResolve={false}
        actors={[]}
        containments={[]}
        now={NOW}
        patchTitles={{ [PATCH.id]: PATCH.title }}
      />,
    );
    const evidenceRow = within(screen.getByTestId("incident-evidence"));
    expect(evidenceRow.getByTestId("event-patch-undecodable").textContent).toBe("body in an unreadable character set");
    expect(evidenceRow.queryByTestId("event-patch-unchecked")).toBeNull();
  });
});
