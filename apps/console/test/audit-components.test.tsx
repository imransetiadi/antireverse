import {
  AUDIT_ACTIONS,
  AUDIT_TARGET_KINDS,
  type AuditEntry,
  type AuditVerifyResponse,
  EXAMPLE_AUDIT_ENTRY,
  EXAMPLE_POLICY,
  EXAMPLE_SIGNED_AUDIT_HEAD,
  type PolicyRule,
} from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { useActionState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Slice 18a: Settings → Audit log (SCR-13) and the reason field of the sensitive confirmation steps, rendered with
// the Server Actions replaced by fakes.
vi.mock("@/app/actions.ts", () => ({
  loadMoreAuditAction: vi.fn(),
  verifyAuditChainAction: vi.fn(),
  signRulesOfEngagementAction: vi.fn(),
  setRuleModeAction: vi.fn(),
  removeRuleAction: vi.fn(),
  rollbackPolicyAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import * as actions from "@/app/actions.ts";
import { AppShell } from "@/components/app-shell.tsx";
import { ConfirmPanel } from "@/components/confirm-panel.tsx";
import { AuditFilters } from "@/features/audit/audit-filters.tsx";
import { AuditLog } from "@/features/audit/audit-log.tsx";
import { AuditPublicKey } from "@/features/audit/audit-public-key.tsx";
import { ChainCheck } from "@/features/audit/chain-check.tsx";
import { ChainStatus } from "@/features/audit/chain-status.tsx";
import { ExportNotice, exportNoticeFrom } from "@/features/audit/export-notice.tsx";
import { ACTION_LABEL, TARGET_LABEL } from "@/features/audit/labels.ts";
import { auditFilterFrom, auditQueryFrom, rangeReversed } from "@/features/audit/query.ts";
import { RuleList } from "@/features/policy/rule-list.tsx";
import { VersionHistory } from "@/features/policy/version-history.tsx";
import { RoeForm } from "@/features/prove/roe-form.tsx";
import { t } from "@/lib/t.ts";

const MONO = /\bcode-[1-3]\b/;
const appId = EXAMPLE_AUDIT_ENTRY.app_id as string;
const apps = [{ id: appId, name: "shop-web" }];
const organization = { id: EXAMPLE_AUDIT_ENTRY.organization_id, name: "Acme", created_at: "2026-11-01T00:00:00.000Z" };

const second: AuditEntry = {
  ...EXAMPLE_AUDIT_ENTRY,
  id: "aud_aaaaaaaaaaaaaaaaaaaaaaaa",
  seq: 2,
  at: "2026-11-13T10:15:30.000Z",
  action: "target.create",
  target: { kind: "target", id: "tgt_0123456789abcdef01234567" },
  summary: "Added shop.acme-shop.io.",
  prev_hash: EXAMPLE_AUDIT_ENTRY.hash,
  hash: "1".repeat(64),
};
const { reason: _reason, app_id: _app, ...withoutReason } = second;
const orgWide: AuditEntry = withoutReason as AuditEntry;

beforeEach(() => {
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
});

describe("audit query", () => {
  it("keeps only the filters it knows, as they were written", () => {
    expect(auditQueryFrom({ action: "policy.rule.promote", app: appId, from: "2026-11-01", to: "2026-11-13" })).toEqual(
      { action: "policy.rule.promote", app: appId, from: "2026-11-01", to: "2026-11-13" },
    );
    expect(
      auditQueryFrom({ action: "nope", app: "app_x", from: "2026-02-30", to: ["2026-11-01", "2026-11-02"] }),
    ).toEqual({});
  });

  it("turns the days into an inclusive start and an exclusive end, in UTC", () => {
    expect(auditFilterFrom({ action: "containment.create", app: appId, from: "2026-11-01", to: "2026-11-13" })).toEqual(
      {
        action: "containment.create",
        appId,
        from: "2026-11-01T00:00:00.000Z",
        to: "2026-11-14T00:00:00.000Z",
      },
    );
    expect(auditFilterFrom({ to: "2026-12-31" })).toEqual({ to: "2027-01-01T00:00:00.000Z" });
  });

  it("applies no range when the first day comes after the last", () => {
    const query = { from: "2026-11-13", to: "2026-11-01" };
    expect(rangeReversed(query)).toBe(true);
    expect(auditFilterFrom(query)).toEqual({});
  });

  it("names every action of the protocol in readable words", () => {
    for (const action of AUDIT_ACTIONS) {
      const label = t(ACTION_LABEL[action]);
      expect(label).not.toContain(".");
      expect(label).not.toMatch(/_/);
    }
    expect(t(ACTION_LABEL["policy.rule.promote"])).toBe("Rule promoted to enforce");
  });

  it("names the Campaign actions and the Campaign target kind (slice 15a)", () => {
    expect(t(ACTION_LABEL["campaign.create"])).toBe("Campaign created");
    expect(t(ACTION_LABEL["campaign.stop"])).toBe("Campaign stopped");
    expect(t(ACTION_LABEL["campaign.start"])).toBe("Campaign started");
    expect(t(ACTION_LABEL["campaign.end"])).toBe("Campaign ended");
    expect(t(ACTION_LABEL["campaign.refuse"])).toBe("Campaign refused");
    expect(t(ACTION_LABEL["campaign.operator_kill"])).toBe("Campaigns stopped by the operator");
    expect(t(ACTION_LABEL["campaign.operator_suspend"])).toBe("Campaigns suspended by the operator");
    expect(t(ACTION_LABEL["campaign.operator_resume"])).toBe("Campaign suspension lifted by the operator");
    for (const kind of AUDIT_TARGET_KINDS) expect(t(TARGET_LABEL[kind]).length).toBeGreaterThan(0);
    expect(t(TARGET_LABEL.campaign)).toBe("Campaign");
  });
});

describe("AuditLog", () => {
  it("lists time, readable action, App, target, actor key id, reason and summary, newest first", () => {
    render(
      <AuditLog entries={[second, EXAMPLE_AUDIT_ENTRY]} nextCursor={null} query={{}} apps={apps} filtered={false} />,
    );
    const table = screen.getByRole("table", { name: "Audit log entries, newest first" });
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((cell) => cell.textContent);
    expect(headers).toEqual(["Time UTC", "Details", "Action", "App", "Target", "Actor", "Reason", "Summary"]);
    const rows = screen.getAllByTestId("audit-row");
    expect(rows.map((row) => row.getAttribute("data-seq"))).toEqual(["2", "1"]);
    const first = rows[1] as HTMLElement;
    expect(within(first).getByTestId("audit-time").textContent).toBe("2026-11-13 09:00:00");
    expect(within(first).getByTestId("audit-action").textContent).toBe("Rule promoted to enforce");
    expect(within(first).getByTestId("audit-app").textContent).toBe("shop-web");
    expect(within(first).getByTestId("audit-target").textContent).toContain("Policy");
    expect(within(first).getByTestId("audit-target").textContent).toContain(`${appId}/production`);
    const actor = within(first).getByTestId("audit-actor");
    expect(actor.textContent).toBe(EXAMPLE_AUDIT_ENTRY.actor.key_id);
    expect(actor.className).toMatch(MONO);
    expect(within(first).getByTestId("audit-reason").textContent).toBe(EXAMPLE_AUDIT_ENTRY.reason);
    expect(within(first).getByTestId("audit-summary").textContent).toBe(EXAMPLE_AUDIT_ENTRY.summary);
  });

  it("says when an entry has no reason, and names the Organization for an entry without an App", () => {
    render(<AuditLog entries={[orgWide]} nextCursor={null} query={{}} apps={apps} filtered={false} />);
    expect(screen.getByTestId("audit-reason").textContent).toBe("None given");
    expect(screen.getByTestId("audit-app").textContent).toBe("Organization");
  });

  it("names the system and the operator as actors in words, without a key id (slice 15a)", () => {
    const { reason: _r, app_id: _a, ...base } = EXAMPLE_AUDIT_ENTRY;
    const system = {
      ...base,
      id: "aud_bbbbbbbbbbbbbbbbbbbbbbbb",
      seq: 3,
      actor: { kind: "system" },
      action: "campaign.end",
      target: { kind: "campaign", id: "cmp_0123456789abcdef01234567" },
      summary: "The Campaign ended: checks_complete.",
    } as AuditEntry;
    const operator = {
      ...base,
      id: "aud_cccccccccccccccccccccccc",
      seq: 4,
      actor: { kind: "operator" },
      action: "campaign.operator_kill",
      target: { kind: "campaign", id: "cmp_0123456789abcdef01234567" },
      reason: "Incident 42",
      summary: "The operator stopped all Campaigns.",
    } as AuditEntry;
    render(
      <AuditLog
        entries={[operator, system, EXAMPLE_AUDIT_ENTRY]}
        nextCursor={null}
        query={{}}
        apps={apps}
        filtered={false}
      />,
    );
    const rows = screen.getAllByTestId("audit-row");
    const cell = (row: HTMLElement | undefined) => within(row as HTMLElement).getByTestId("audit-actor");
    expect(cell(rows[0]).textContent).toBe("Operator");
    expect(cell(rows[0]).getAttribute("data-actor-kind")).toBe("operator");
    expect(cell(rows[1]).textContent).toBe("System");
    expect(cell(rows[1]).className).not.toMatch(MONO);
    // No "Admin key" prefix and no "undefined" where there is no key.
    expect((cell(rows[1]).parentElement as HTMLElement).textContent).toBe("System");
    expect((cell(rows[2]).parentElement as HTMLElement).textContent).toBe(
      `Admin key ${EXAMPLE_AUDIT_ENTRY.actor.key_id}`,
    );
    expect(within(rows[1] as HTMLElement).getByTestId("audit-action").textContent).toBe("Campaign ended");
    expect(within(rows[1] as HTMLElement).getByTestId("audit-target").textContent).toContain("Campaign");
    fireEvent.click(within(rows[1] as HTMLElement).getByRole("button", { name: "Show details" }));
    const details = screen.getByTestId("audit-details");
    expect(within(details).getByTestId("audit-detail-actor").textContent).toBe("System");
    expect(details.textContent).not.toContain("undefined");
  });

  it("names an App that is no longer listed by its id", () => {
    render(<AuditLog entries={[EXAMPLE_AUDIT_ENTRY]} nextCursor={null} query={{}} apps={[]} filtered={false} />);
    expect(screen.getByTestId("audit-app").textContent).toBe(appId);
  });

  it("shows an entry's sequence and hashes on demand, as a disclosure", () => {
    render(<AuditLog entries={[EXAMPLE_AUDIT_ENTRY]} nextCursor={null} query={{}} apps={apps} filtered={false} />);
    const toggle = screen.getByRole("button", { name: "Show details" });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByTestId("audit-details")).toBeNull();
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(toggle.textContent).toBe("Hide details");
    const details = screen.getByTestId("audit-details");
    expect(toggle.getAttribute("aria-controls")).toBe(details.id);
    expect(within(details).getByRole("heading", { name: "Entry 1" })).toBeTruthy();
    expect(within(details).getByTestId("audit-detail-seq").textContent).toBe("1");
    const hash = within(details).getByTestId("audit-detail-hash");
    expect(hash.textContent).toBe(EXAMPLE_AUDIT_ENTRY.hash);
    expect(hash.className).toMatch(MONO);
    expect(within(details).getByTestId("audit-detail-prev").textContent).toBe(EXAMPLE_AUDIT_ENTRY.prev_hash);
    expect(within(details).getByTestId("audit-detail-request").textContent).toBe(EXAMPLE_AUDIT_ENTRY.request_id);
    expect(within(details).getByTestId("audit-detail-id").textContent).toBe(EXAMPLE_AUDIT_ENTRY.id);
    fireEvent.click(toggle);
    expect(screen.queryByTestId("audit-details")).toBeNull();
  });

  it("loads the next page with the page's filters and the cursor, and appends it", async () => {
    vi.mocked(actions.loadMoreAuditAction).mockResolvedValue({
      ok: true,
      entries: [EXAMPLE_AUDIT_ENTRY],
      nextCursor: null,
    });
    const query = { action: "target.create" as const, app: appId };
    render(<AuditLog entries={[second]} nextCursor="2" query={query} apps={apps} filtered />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    });
    expect(actions.loadMoreAuditAction).toHaveBeenCalledWith(query, "2");
    expect(screen.getAllByTestId("audit-row").map((row) => row.getAttribute("data-seq"))).toEqual(["2", "1"]);
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
    expect(screen.getByTestId("audit-end").textContent).toBe("This is the oldest entry.");
  });

  it("says when the next page could not be read, and keeps Load more", async () => {
    vi.mocked(actions.loadMoreAuditAction).mockResolvedValue({
      ok: false,
      message: "The audit log could not be read. Try again in a moment.",
    });
    render(<AuditLog entries={[second]} nextCursor="2" query={{}} apps={apps} filtered={false} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    });
    expect(screen.getByRole("alert").textContent).toBe("The audit log could not be read. Try again in a moment.");
    expect(screen.getByRole("button", { name: "Load more" })).toBeTruthy();
  });

  it("explains an empty log, and an empty filtered one", () => {
    const { rerender } = render(<AuditLog entries={[]} nextCursor={null} query={{}} apps={apps} filtered={false} />);
    expect(screen.getByTestId("audit-empty").textContent).toBe(
      "No entries yet. Every change made with an admin key will be listed here.",
    );
    rerender(<AuditLog entries={[]} nextCursor={null} query={{}} apps={apps} filtered />);
    expect(screen.getByTestId("audit-empty").textContent).toBe("No entries match these filters.");
  });
});

describe("ChainStatus", () => {
  const signed = (seq: number) => ({ ...EXAMPLE_SIGNED_AUDIT_HEAD, head: { ...EXAMPLE_SIGNED_AUDIT_HEAD.head, seq } });
  const result = (verify: AuditVerifyResponse["verify"]): AuditVerifyResponse => ({
    verify,
    signed_head: signed(verify.last_seq),
  });

  it("says the chain is verified with its count, as a status, beside the signed head", () => {
    render(<ChainStatus result={result({ valid: true, entries: 12, last_seq: 12, first_broken_seq: null })} />);
    const status = screen.getByTestId("audit-chain");
    expect(status.getAttribute("role")).toBe("status");
    expect(status.getAttribute("data-valid")).toBe("true");
    expect(within(status).getByTestId("audit-chain-text").textContent).toBe("Chain verified: 12 entries");
    const head = screen.getByTestId("audit-signed-head");
    expect(head.textContent).toBe(`Head signed at entry 12 with audit key ${EXAMPLE_SIGNED_AUDIT_HEAD.key_id}`);
    expect(within(head).getByText(EXAMPLE_SIGNED_AUDIT_HEAD.key_id).className).toMatch(MONO);
  });

  it("uses the singular for one entry and says when there is none", () => {
    const { rerender } = render(
      <ChainStatus result={result({ valid: true, entries: 1, last_seq: 1, first_broken_seq: null })} />,
    );
    expect(screen.getByTestId("audit-chain-text").textContent).toBe("Chain verified: 1 entry");
    rerender(<ChainStatus result={result({ valid: true, entries: 0, last_seq: 0, first_broken_seq: null })} />);
    expect(screen.getByTestId("audit-chain-text").textContent).toBe("Chain verified: no entries yet");
  });

  it("names the first broken entry, as an alert in the destructive style, with what to do", () => {
    render(<ChainStatus result={result({ valid: false, entries: 9, last_seq: 9, first_broken_seq: 4 })} />);
    const status = screen.getByTestId("audit-chain");
    expect(status.getAttribute("role")).toBe("alert");
    expect(status.getAttribute("data-valid")).toBe("false");
    expect(within(status).getByTestId("audit-chain-text").textContent).toBe("Chain broken at entry 4");
    expect(status.textContent).toContain("Export the log and keep it as evidence.");
    expect(status.className).toContain("border-destructive");
    expect(screen.getByTestId("audit-signed-head").textContent).toContain("entry 9");
  });

  it("says when the chain could not be checked, and when it was checked too often", () => {
    const { rerender } = render(<ChainStatus result={null} />);
    expect(screen.getByTestId("audit-chain").textContent).toBe(
      "The chain could not be checked just now. Reload the page to try again.",
    );
    expect(screen.queryByTestId("audit-signed-head")).toBeNull();
    rerender(<ChainStatus result={null} limited={{ retryAfter: 42 }} />);
    expect(screen.getByTestId("audit-chain").textContent).toBe(
      "The chain was checked too often just now. Reload the page in 42 seconds to check it again.",
    );
    rerender(<ChainStatus result={null} limited={{ retryAfter: undefined }} />);
    expect(screen.getByTestId("audit-chain").textContent).toBe(
      "The chain was checked too often just now. Reload the page in a minute to check it again.",
    );
  });
});

describe("AuditPublicKey", () => {
  it("shows the audit key's id and public key, in Geist Mono, with Copy, and how to use it", () => {
    render(
      <AuditPublicKey publicKey={{ key_id: "0123456789abcdef", algorithm: "Ed25519", public_key: "A".repeat(43) }} />,
    );
    const section = screen.getByRole("region", { name: "Verify an export" });
    expect(within(section).getByTestId("audit-key-id").textContent).toBe("0123456789abcdef");
    const key = within(section).getByTestId("audit-public-key");
    expect(key.textContent).toBe("A".repeat(43));
    expect(key.className).toMatch(MONO);
    expect(within(section).getByRole("button", { name: "Copy" })).toBeTruthy();
    expect(section.textContent).toContain("Ed25519");
  });

  it("says when the key could not be read", () => {
    render(<AuditPublicKey publicKey={null} />);
    expect(screen.getByTestId("audit-public-key-missing").textContent).toBe(
      "The audit public key could not be read just now. Reload the page to try again.",
    );
  });
});

describe("export notice", () => {
  it("explains an export that was refused for being asked too often, or that failed", () => {
    const { rerender } = render(<ExportNotice notice={{ kind: "limited", retryAfter: 30 }} />);
    expect(screen.getByRole("alert").textContent).toBe("The export was asked for too often. Try again in 30 seconds.");
    rerender(<ExportNotice notice={{ kind: "limited", retryAfter: undefined }} />);
    expect(screen.getByRole("alert").textContent).toBe("The export was asked for too often. Try again in a minute.");
    rerender(<ExportNotice notice={{ kind: "failed" }} />);
    expect(screen.getByRole("alert").textContent).toBe("The export could not be made. Try again in a moment.");
    rerender(<ExportNotice notice={null} />);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("reads the notice from the address", () => {
    expect(exportNoticeFrom({ export: "limited", retry: "30" })).toEqual({ kind: "limited", retryAfter: 30 });
    expect(exportNoticeFrom({ export: "limited", retry: "x" })).toEqual({ kind: "limited", retryAfter: undefined });
    expect(exportNoticeFrom({ export: "failed" })).toEqual({ kind: "failed" });
    expect(exportNoticeFrom({ export: "other" })).toBeNull();
    expect(exportNoticeFrom({})).toBeNull();
  });
});

describe("AuditFilters", () => {
  it("is a GET form of the page with labelled action, App and day fields, holding the address's values", () => {
    render(
      <AuditFilters
        query={{ action: "policy.rule.promote", app: appId, from: "2026-11-01", to: "2026-11-13" }}
        apps={apps}
      />,
    );
    // A <search> landmark (its implicit role is search), named by its label.
    const form = screen.getByTestId("audit-filters");
    const landmark = form.parentElement as HTMLElement;
    expect(landmark.tagName).toBe("SEARCH");
    expect(landmark.getAttribute("aria-label")).toBe("Filter");
    expect(form.getAttribute("method")).toBe("get");
    expect(form.getAttribute("action")).toBe("/settings/audit");
    const action = screen.getByLabelText("Action") as HTMLSelectElement;
    expect(action.name).toBe("action");
    expect(action.value).toBe("policy.rule.promote");
    expect(within(action).getAllByRole("option")).toHaveLength(AUDIT_ACTIONS.length + 1);
    expect(within(action).getByRole("option", { name: "Rule promoted to enforce" })).toBeTruthy();
    const app = screen.getByLabelText("App") as HTMLSelectElement;
    expect(app.name).toBe("app");
    expect(app.value).toBe(appId);
    const from = screen.getByLabelText("From (UTC)") as HTMLInputElement;
    expect([from.name, from.type, from.value]).toEqual(["from", "date", "2026-11-01"]);
    const to = screen.getByLabelText("To (UTC, included)") as HTMLInputElement;
    expect([to.name, to.type, to.value]).toEqual(["to", "date", "2026-11-13"]);
    expect(screen.getByRole("button", { name: "Apply filters" }).getAttribute("type")).toBe("submit");
    expect(screen.getByRole("link", { name: "Clear filters" }).getAttribute("href")).toBe("/settings/audit");
  });

  it("warns that a reversed range is not applied", () => {
    render(<AuditFilters query={{ from: "2026-11-13", to: "2026-11-01" }} apps={apps} />);
    expect(screen.getByTestId("audit-range-reversed").textContent).toBe(
      "The From date is after the To date, so no time range is applied.",
    );
  });

  it("offers no Clear link without filters", () => {
    render(<AuditFilters query={{}} apps={apps} />);
    expect(screen.queryByRole("link", { name: "Clear filters" })).toBeNull();
  });
});

describe("Settings navigation", () => {
  it("links the Audit log, marked as current on its page", () => {
    render(
      <AppShell organization={organization} current="audit">
        <p>content</p>
      </AppShell>,
    );
    const settings = screen.getByRole("navigation", { name: "Settings" });
    const link = within(settings).getByRole("link", { name: "Audit log" });
    expect(link.getAttribute("href")).toBe("/settings/audit");
    expect(link.getAttribute("aria-current")).toBe("page");
  });
});

describe("the reason field of a confirmation step", () => {
  it("is a labelled, required, one-line field of at most 500 characters, with help and error linked", () => {
    render(
      <ConfirmPanel
        question="Remove it?"
        confirmLabel="Remove"
        cancelHref="/"
        action={vi.fn()}
        reason={{
          required: true,
          error: "Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
        }}
      >
        <input type="hidden" name="x" value="y" />
      </ConfirmPanel>,
    );
    const field = screen.getByLabelText("Reason") as HTMLInputElement;
    expect(field.name).toBe("reason");
    expect(field.type).toBe("text");
    expect(field.required).toBe(true);
    expect(field.maxLength).toBe(500);
    expect(field.getAttribute("aria-invalid")).toBe("true");
    const described = (field.getAttribute("aria-describedby") ?? "").split(" ");
    expect(described).toContain(screen.getByTestId("confirm-reason-error").id);
    expect(screen.getByText(t("reason.help")).id).toBe(described[1]);
    // In the form that sends the change.
    expect(field.closest("form")).toBe(screen.getByTestId("confirm-submit").closest("form"));
  });

  it("is optional when the change is not sensitive, and absent without the prop", () => {
    const { rerender } = render(
      <ConfirmPanel question="Q?" confirmLabel="Go" cancelHref="/" action={vi.fn()} reason={{ required: false }}>
        {null}
      </ConfirmPanel>,
    );
    const field = screen.getByLabelText("Reason (optional)") as HTMLInputElement;
    expect(field.required).toBe(false);
    rerender(
      <ConfirmPanel question="Q?" confirmLabel="Go" cancelHref="/" action={vi.fn()}>
        {null}
      </ConfirmPanel>,
    );
    expect(screen.queryByTestId("confirm-reason")).toBeNull();
  });

  it("is required when promoting a Rule, and its refusal is linked from the summary", async () => {
    const [enforced, monitored] = EXAMPLE_POLICY.rules as [PolicyRule, PolicyRule];
    vi.mocked(actions.setRuleModeAction).mockResolvedValue({
      ok: false,
      errors: [
        {
          path: "reason",
          message: "Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
        },
      ],
    });
    render(
      <RuleList
        version={3}
        appId={EXAMPLE_POLICY.app_id}
        appName="shop-web"
        environment="production"
        rules={[enforced, monitored]}
        confirmRuleId={monitored.id}
      />,
    );
    const field = within(screen.getByRole("alertdialog")).getByLabelText("Reason") as HTMLInputElement;
    expect(field.required).toBe(true);
    fireEvent.change(field, { target: { value: "x" } });
    await act(async () => {
      fireEvent.click(screen.getByTestId("confirm-submit"));
    });
    const link = within(screen.getByTestId("error-summary")).getByRole("link", {
      name: "Reason: Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
    });
    expect(link.getAttribute("href")).toBe(`#${screen.getByTestId("confirm-reason").id}`);
  });

  it("is required on a rollback that enforces a Rule anew, optional on any other", () => {
    const versions = [
      { version: 3, published_at: "2026-11-10T10:30:05.000Z", rule_count: 2, enforced_count: 1 },
      { version: 2, published_at: "2026-11-10T09:00:00.000Z", rule_count: 2, enforced_count: 2 },
    ];
    const props = {
      appId: EXAMPLE_POLICY.app_id,
      appName: "shop-web",
      environment: "production" as const,
      currentVersion: 3,
      versions,
      confirmVersion: 2,
    };
    const { rerender } = render(<VersionHistory {...props} confirmPromotes />);
    expect((screen.getByLabelText("Reason") as HTMLInputElement).required).toBe(true);
    rerender(<VersionHistory {...props} />);
    expect((screen.getByLabelText("Reason (optional)") as HTMLInputElement).required).toBe(false);
  });
});

/** A confirmation step whose action always refuses and gives the reason back, as the sensitive actions do. */
function ReasonHost() {
  const [state, action] = useActionState(
    async (_previous: { reason: string } | null, data: FormData) => ({ reason: String(data.get("reason")).trim() }),
    null,
  );
  return (
    <ConfirmPanel
      question="Block?"
      confirmLabel="Block"
      cancelHref="/"
      action={action}
      reason={{ required: true, error: state ? "refused" : undefined, value: state?.reason }}
    >
      <input type="hidden" name="x" value="y" />
    </ConfirmPanel>
  );
}

describe("review findings (slice 18a)", () => {
  it("F1: drops days the API cannot take (outside 2000-01-01 to 2099-12-30) and bounds the date fields", () => {
    expect(auditQueryFrom({ from: "1999-12-31", to: "2099-12-31" })).toEqual({});
    expect(auditQueryFrom({ from: "2000-01-01", to: "2099-12-30" })).toEqual({ from: "2000-01-01", to: "2099-12-30" });
    expect(auditFilterFrom({ from: "2000-01-01", to: "2099-12-30" })).toEqual({
      from: "2000-01-01T00:00:00.000Z",
      to: "2099-12-31T00:00:00.000Z",
    });
    render(<AuditFilters query={{}} apps={apps} />);
    for (const label of ["From (UTC)", "To (UTC, included)"]) {
      const field = screen.getByLabelText(label) as HTMLInputElement;
      expect([field.min, field.max]).toEqual(["2000-01-01", "2099-12-30"]);
    }
  });

  it("F1: says when the filters were not applied", () => {
    render(<AuditFilters query={{ action: "app.create" }} apps={apps} notApplied />);
    expect(screen.getByTestId("audit-filters-not-applied").textContent).toBe(
      "The API did not accept these filters, so every entry is listed. Change the filters and apply them again.",
    );
  });

  it("F3: moves the focus to the first new row after Load more, also after the last page", async () => {
    vi.mocked(actions.loadMoreAuditAction).mockResolvedValue({
      ok: true,
      entries: [EXAMPLE_AUDIT_ENTRY],
      nextCursor: null,
    });
    render(<AuditLog entries={[second]} nextCursor="2" query={{}} apps={apps} filtered={false} />);
    const more = screen.getByTestId("audit-more");
    more.focus();
    await act(async () => {
      fireEvent.click(more);
    });
    const rows = screen.getAllByTestId("audit-row");
    const header = within(rows[1] as HTMLElement).getByRole("rowheader");
    expect(document.activeElement).toBe(header);
    expect(header.getAttribute("tabindex")).toBe("-1");
  });

  it("F2: keeps the typed reason after a refusal through a real action state (React resets the form)", async () => {
    render(<ReasonHost />);
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: " Credential stuffing from one network " } });
    await act(async () => {
      fireEvent.click(screen.getByTestId("confirm-submit"));
    });
    expect((screen.getByLabelText("Reason") as HTMLInputElement).value).toBe("Credential stuffing from one network");
  });

  it("F2: keeps the typed reason in the Rules of Engagement form after a refusal", async () => {
    vi.mocked(actions.signRulesOfEngagementAction).mockResolvedValueOnce({
      ok: false,
      errors: [{ path: "confirm", message: "Type the phrase." }],
      values: {
        scope: [],
        exclusions: "",
        intensity: "passive",
        days: [],
        allDay: false,
        from: "",
        to: "",
        contacts: "",
      },
      reason: "Quarterly pentest approved",
    });
    render(<RoeForm targets={[]} />);
    fireEvent.change(screen.getByTestId("roe-reason"), { target: { value: "Quarterly pentest approved" } });
    await act(async () => {
      fireEvent.click(screen.getByTestId("roe-sign"));
    });
    expect((screen.getByTestId("roe-reason") as HTMLInputElement).value).toBe("Quarterly pentest approved");
  });

  it("F2: keeps the typed reason in the confirmation step after a refusal", () => {
    render(
      <ConfirmPanel
        question="Q?"
        confirmLabel="Go"
        cancelHref="/"
        action={vi.fn()}
        reason={{ required: true, error: "refused", value: "Credential stuffing from one network" }}
      >
        {null}
      </ConfirmPanel>,
    );
    expect((screen.getByLabelText("Reason") as HTMLInputElement).value).toBe("Credential stuffing from one network");
  });
});

describe("ChainCheck (verify on demand in a filtered view)", () => {
  it("verifies when asked and shows the result in place", async () => {
    vi.mocked(actions.verifyAuditChainAction).mockResolvedValue({
      ok: true,
      result: {
        verify: { valid: true, entries: 3, last_seq: 3, first_broken_seq: null },
        signed_head: EXAMPLE_SIGNED_AUDIT_HEAD,
      },
    });
    render(<ChainCheck />);
    expect(screen.queryByTestId("audit-chain")).toBeNull();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Verify chain" }));
    });
    expect(actions.verifyAuditChainAction).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("audit-chain-text").textContent).toBe("Chain verified: 3 entries");
  });

  it("explains a check refused for being asked too often", async () => {
    vi.mocked(actions.verifyAuditChainAction).mockResolvedValue({ ok: false, limited: { retryAfter: 12 } });
    render(<ChainCheck />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Verify chain" }));
    });
    expect(screen.getByTestId("audit-chain").textContent).toBe(
      "The chain was checked too often just now. Reload the page in 12 seconds to check it again.",
    );
  });
});
