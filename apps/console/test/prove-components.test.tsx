import {
  AUTHORIZE_REASONS,
  DNS_VERIFY_FAILURES,
  EXAMPLE_RULES_OF_ENGAGEMENT,
  EXAMPLE_TARGET,
  FILE_VERIFY_FAILURES,
  type RulesOfEngagementVersion,
  type Target,
  verificationInstructions,
} from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Slice 14: the Prove screens — targets, one target with its instructions and Verify, the Rules of Engagement
// with history, the form that writes and signs a version, and the dry "Check a test" form — rendered with the
// Server Actions replaced by fakes.
vi.mock("@/app/actions.ts", () => ({
  createTargetAction: vi.fn(),
  verifyTargetAction: vi.fn(),
  deleteTargetAction: vi.fn(),
  signRulesOfEngagementAction: vi.fn(),
  checkAuthorizationAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import * as actions from "@/app/actions.ts";
import { AppShell } from "@/components/app-shell.tsx";
import { AddTargetForm } from "@/features/prove/add-target-form.tsx";
import { CheckTestForm } from "@/features/prove/check-test-form.tsx";
import { AUTHORIZE_REASON_LABEL, DNS_FAILURE_LABEL, FILE_FAILURE_LABEL, windowText } from "@/features/prove/labels.ts";
import { RoeForm } from "@/features/prove/roe-form.tsx";
import { RoeHistory } from "@/features/prove/roe-history.tsx";
import { RoeVersionCard } from "@/features/prove/roe-version.tsx";
import { TargetDetail, TargetView } from "@/features/prove/target-detail.tsx";
import { TargetList } from "@/features/prove/target-list.tsx";
import { TargetStatusChip } from "@/features/prove/target-status.tsx";
import { t } from "@/lib/t.ts";

const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE";
const shop: Target = EXAMPLE_TARGET;
const api: Target = {
  ...EXAMPLE_TARGET,
  id: "tgt_aaaaaaaaaaaaaaaaaaaaaaaa",
  host: "api.acme-shop.io",
  method: "file",
  verified_at: "2026-11-12T07:00:00.000Z",
  last_checked_at: "2026-11-12T07:00:00.000Z",
};
const legacy: Target = {
  ...EXAMPLE_TARGET,
  id: "tgt_bbbbbbbbbbbbbbbbbbbbbbbb",
  host: "legacy.acme-shop.io",
  status: "lapsed",
  lapsed_reason: "The daily check found no TXT record and the file answered with status 404.",
  last_checked_at: "2026-11-12T06:00:00.000Z",
};
const staging: Target = {
  ...EXAMPLE_TARGET,
  id: "tgt_cccccccccccccccccccccccc",
  host: "staging.acme-shop.io",
  status: "pending",
  method: null,
  verified_at: null,
  last_checked_at: null,
};
const targets = [shop, api, legacy, staging];
const current: RulesOfEngagementVersion = {
  ...EXAMPLE_RULES_OF_ENGAGEMENT,
  scope: [shop.id, api.id],
  contacts: ["security@acme-shop.io", "oncall@acme-shop.io"],
};
const older: RulesOfEngagementVersion = {
  ...EXAMPLE_RULES_OF_ENGAGEMENT,
  id: "roe_aaaaaaaaaaaaaaaaaaaaaaaa",
  intensity: "passive",
  exclusions: [],
  window: { days: ["sat", "sun"], from: "22:00", to: "06:00" },
  signed_at: "2026-11-08T08:10:00.000Z",
  content_sha256: "a".repeat(64),
};

const writeText = vi.fn<(text: string) => Promise<void>>();
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
const submit = async (control: HTMLElement): Promise<void> => {
  await act(async () => {
    fireEvent.click(control);
  });
};

beforeEach(() => {
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
  writeText.mockReset();
  writeText.mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
});

describe("navigation", () => {
  const organization = { id: "org_0123456789abcdef01234567", name: "Acme", created_at: "2026-11-10T08:00:00.000Z" };

  it("has a Prove group with Targets and Rules of Engagement, the current one marked", () => {
    render(
      <AppShell organization={organization} current="rules">
        <p>content</p>
      </AppShell>,
    );
    const prove = screen.getByRole("navigation", { name: "Prove" });
    expect(
      within(prove)
        .getAllByRole("link")
        .map((link) => [link.textContent, link.getAttribute("href")]),
    ).toEqual([
      ["Targets", "/prove/targets"],
      ["Rules of Engagement", "/prove/rules-of-engagement"],
    ]);
    expect(screen.getByTestId("nav-rules").getAttribute("aria-current")).toBe("page");
    expect(screen.getByTestId("nav-targets").getAttribute("aria-current")).toBeNull();
  });
});

describe("target status", () => {
  it("shows each status with its own glyph, word and colour", () => {
    const shapes: Record<string, [string | null, string]> = {};
    for (const status of ["pending", "verified", "lapsed"] as const) {
      const { unmount } = render(<TargetStatusChip status={status} />);
      const chip = screen.getByTestId("target-status");
      shapes[status] = [chip.querySelector("svg")?.getAttribute("data-shape") ?? null, chip.textContent ?? ""];
      expect(chip.getAttribute("data-status")).toBe(status);
      unmount();
    }
    expect(shapes).toEqual({
      pending: ["hourglass-medium", "Pending"],
      verified: ["check-circle", "Verified"],
      lapsed: ["warning-circle", "Lapsed"],
    });
  });
});

describe("target list", () => {
  it("lists host, status, method and the last successful check; a lapsed target shows its reason", () => {
    render(<TargetList targets={targets} />);
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Host",
      "Status",
      "Method",
      "Last successful check UTC",
      "Last check UTC",
    ]);
    const rows = screen.getAllByTestId("target-row");
    const read = (row: HTMLElement) => {
      const cells = within(row);
      return [
        cells.getByTestId("target-host").textContent,
        cells.getByTestId("target-status").textContent,
        cells.getByTestId("target-method").textContent,
        cells.getByTestId("target-verified-at").textContent,
      ];
    };
    expect(rows.map(read)).toEqual([
      ["shop.acme-shop.io", "Verified", "DNS record", "2026-11-12 08:05:00"],
      ["api.acme-shop.io", "Verified", "File", "2026-11-12 07:00:00"],
      ["legacy.acme-shop.io", "Lapsed", "DNS record", "2026-11-12 08:05:00"],
      ["staging.acme-shop.io", "Pending", "Not yet", "Never"],
    ]);
    expect(
      within(rows[0] as HTMLElement)
        .getByRole("link", { name: "shop.acme-shop.io" })
        .getAttribute("href"),
    ).toBe(`/prove/targets/${shop.id}`);
    expect(within(rows[2] as HTMLElement).getByTestId("target-lapsed-reason").textContent).toBe(
      `Lapsed: ${legacy.lapsed_reason}`,
    );
    expect(within(rows[0] as HTMLElement).queryByTestId("target-lapsed-reason")).toBeNull();
  });

  it("says what will appear when there is no target", () => {
    render(<TargetList targets={[]} />);
    expect(screen.getByTestId("targets-empty").textContent).toBe(
      "No targets yet. Add a host you own, then prove it with a DNS record or a file.",
    );
  });
});

describe("add a host", () => {
  it("has a labelled host field and sends it", async () => {
    vi.mocked(actions.createTargetAction).mockResolvedValueOnce(null);
    render(<AddTargetForm />);
    const host = screen.getByLabelText("Host") as HTMLInputElement;
    fireEvent.change(host, { target: { value: "shop.acme-shop.io" } });
    await submit(screen.getByRole("button", { name: "Add host" }));
    expect(sent(actions.createTargetAction)).toEqual({ host: ["shop.acme-shop.io"] });
  });

  it("shows the API's field error below the field, keeping what was typed", async () => {
    vi.mocked(actions.createTargetAction).mockResolvedValueOnce({
      ok: false,
      errors: [{ path: "host", message: "The API did not accept this host." }],
      values: { host: "shop.acme-shop.io" },
    });
    render(<AddTargetForm />);
    await submit(screen.getByRole("button", { name: "Add host" }));
    expect(screen.getByTestId("target-host-input-error").textContent).toBe("The API did not accept this host.");
    expect((screen.getByLabelText("Host") as HTMLInputElement).value).toBe("shop.acme-shop.io");
    expect(document.activeElement).toBe(screen.getByTestId("error-summary"));
  });
});

describe("one target", () => {
  const verification = verificationInstructions(staging.host, TOKEN);
  const show = (target: Target, options: { inScope?: boolean; confirmRemove?: boolean } = {}) =>
    render(
      <TargetDetail
        target={target}
        verification={verificationInstructions(target.host, TOKEN)}
        inScope={options.inScope ?? false}
        confirmRemove={options.confirmRemove ?? false}
      />,
    );

  it("shows both ways to prove ownership, each value with a copy button", async () => {
    show(staging);
    const dns = screen.getByTestId("prove-dns");
    expect(within(dns).getByTestId("prove-dns-name").textContent).toBe(verification.dns_name);
    expect(within(dns).getByTestId("prove-dns-type").textContent).toBe("TXT");
    expect(within(dns).getByTestId("prove-dns-value").textContent).toBe(verification.dns_value);
    const file = screen.getByTestId("prove-file");
    expect(within(file).getByTestId("prove-file-url").textContent).toBe(verification.file_url);
    expect(within(file).getByTestId("prove-file-content").textContent).toBe(TOKEN);
    const copies = [
      ...within(dns).getAllByRole("button", { name: /Copy/ }),
      ...within(file).getAllByRole("button", { name: /Copy/ }),
    ];
    expect(copies).toHaveLength(4);
    for (const button of copies) {
      await act(async () => {
        fireEvent.click(button);
      });
    }
    expect(writeText.mock.calls.map(([value]) => value)).toEqual([
      verification.dns_name,
      verification.dns_value,
      verification.file_url,
      TOKEN,
    ]);
  });

  it("verifies and says which method passed", async () => {
    vi.mocked(actions.verifyTargetAction).mockResolvedValueOnce({
      ok: true,
      result: { verified: true, method: "file", checked_at: "2026-11-12T08:05:00.000Z" },
    });
    show(staging);
    await submit(screen.getByRole("button", { name: "Verify now" }));
    expect(sent(actions.verifyTargetAction)).toEqual({ targetId: [staging.id] });
    expect(screen.getByTestId("verify-result").textContent).toBe(
      "Verified through the file at 2026-11-12 08:05:00 UTC.",
    );
  });

  it("explains in plain words why each method failed", async () => {
    vi.mocked(actions.verifyTargetAction).mockResolvedValueOnce({
      ok: true,
      result: { verified: false, dns: "mismatch", file: "redirect", checked_at: "2026-11-12T08:05:00.000Z" },
    });
    show(staging);
    await submit(screen.getByRole("button", { name: "Verify now" }));
    const result = screen.getByTestId("verify-result");
    expect(within(result).getByTestId("verify-headline").textContent).toBe(
      "Not verified. Checked at 2026-11-12 08:05:00 UTC.",
    );
    expect(within(result).getByTestId("verify-dns").textContent).toBe(`DNS record: ${t(DNS_FAILURE_LABEL.mismatch)}`);
    expect(within(result).getByTestId("verify-file").textContent).toBe(`File: ${t(FILE_FAILURE_LABEL.redirect)}`);
  });

  it("shows a refused check as an alert", async () => {
    vi.mocked(actions.verifyTargetAction).mockResolvedValueOnce({ ok: false, message: "Try again later." });
    show(staging);
    await submit(screen.getByRole("button", { name: "Verify now" }));
    expect(screen.getByTestId("verify-error").textContent).toBe("Try again later.");
  });

  it("has a plain sentence for every DNS and file failure reason, and every refusal of authorize", () => {
    const texts = [
      ...DNS_VERIFY_FAILURES.map((reason) => t(DNS_FAILURE_LABEL[reason])),
      ...FILE_VERIFY_FAILURES.map((reason) => t(FILE_FAILURE_LABEL[reason])),
      ...AUTHORIZE_REASONS.map((reason) => t(AUTHORIZE_REASON_LABEL[reason])),
    ];
    for (const text of texts) expect(text).toMatch(/^[A-Z][^_]*\.$/);
    expect(new Set(texts).size).toBe(texts.length);
  });

  it("shows a lapsed target's reason", () => {
    show(legacy);
    expect(screen.getByTestId("target-lapsed-reason").textContent).toBe(`Lapsed: ${legacy.lapsed_reason}`);
  });

  it("asks before removing, naming the host, and sends the confirmation", async () => {
    show(staging, { confirmRemove: true });
    const dialog = screen.getByTestId("target-confirm");
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Remove staging.acme-shop.io? Tests can no longer be pointed at it until it is added and verified again.",
    );
    expect(within(dialog).getByTestId("confirm-cancel").getAttribute("href")).toBe(`/prove/targets/${staging.id}`);
    await submit(within(dialog).getByTestId("confirm-submit"));
    expect(sent(actions.deleteTargetAction)).toEqual({ targetId: [staging.id], confirm: [staging.id] });
  });

  it("offers Remove as a link to the confirmation, or explains why a target in scope cannot be removed", () => {
    const { unmount } = show(staging);
    expect(screen.getByRole("link", { name: "Remove" }).getAttribute("href")).toBe(
      `/prove/targets/${staging.id}?confirm=remove`,
    );
    unmount();
    show(shop, { inScope: true, confirmRemove: true });
    expect(screen.queryByRole("link", { name: "Remove" })).toBeNull();
    expect(screen.queryByTestId("target-confirm")).toBeNull();
    expect(screen.getByTestId("target-in-scope").textContent).toBe(
      "This host is in the current Rules of Engagement, so it cannot be removed. Sign a new version without it first.",
    );
  });
});

describe("target page after a check", () => {
  it("keeps the verify result on screen when the page revalidates with the changed target", async () => {
    vi.mocked(actions.verifyTargetAction).mockResolvedValueOnce({
      ok: true,
      result: { verified: true, method: "dns", checked_at: "2026-11-12T08:05:00.000Z" },
    });
    const props = { verification: verificationInstructions(staging.host, TOKEN), inScope: false };
    const { rerender } = render(<TargetView target={staging} confirmRemove={false} {...props} />);
    await submit(screen.getByRole("button", { name: "Verify now" }));
    expect(screen.getByTestId("verify-result").textContent).toBe(
      "Verified through the DNS record at 2026-11-12 08:05:00 UTC.",
    );
    // What revalidatePath sends back: the same page with the target as the check left it.
    const checked: Target = {
      ...staging,
      status: "verified",
      method: "dns",
      verified_at: "2026-11-12T08:05:00.000Z",
      last_checked_at: "2026-11-12T08:05:00.000Z",
    };
    rerender(<TargetView target={checked} confirmRemove={false} {...props} />);
    expect(screen.getByTestId("target-status").textContent).toBe("Verified");
    expect(screen.getByTestId("verify-result").textContent).toBe(
      "Verified through the DNS record at 2026-11-12 08:05:00 UTC.",
    );
    // Opening the removal step starts the actions afresh.
    rerender(<TargetView target={checked} confirmRemove={true} {...props} />);
    expect(screen.queryByTestId("verify-result")).toBeNull();
  });
});

describe("Rules of Engagement", () => {
  it("shows the current version: scope hosts, exclusions, intensity, window, contacts, signer, time and hash", () => {
    render(<RoeVersionCard version={current} targets={targets} />);
    const card = screen.getByTestId("roe-current");
    const field = (id: string) => within(card).getByTestId(id).textContent;
    expect(
      within(card)
        .getAllByTestId("roe-scope-host")
        .map((host) => host.textContent),
    ).toEqual(["shop.acme-shop.io", "api.acme-shop.io"]);
    expect(
      within(card)
        .getAllByTestId("roe-exclusion")
        .map((path) => path.textContent),
    ).toEqual(["/admin", "/checkout"]);
    expect(field("roe-intensity")).toBe("safe-active");
    expect(field("roe-window")).toBe("Mon, Tue, Wed, Thu, Fri, 09:00 to 17:00 UTC");
    expect(
      within(card)
        .getAllByTestId("roe-contact")
        .map((contact) => contact.textContent),
    ).toEqual(["security@acme-shop.io", "oncall@acme-shop.io"]);
    expect(field("roe-signed-by")).toBe("key_01234567…");
    expect(field("roe-signed-at")).toBe("2026-11-12 08:10:00");
    expect(field("roe-hash")).toBe("fb90b621f043…");
    expect(within(card).getByTestId("roe-hash").getAttribute("title")).toBe(current.content_sha256);
    expect(field("roe-immutable")).toBe("A signed version cannot be changed. To change anything, sign a new version.");
  });

  it("names a removed target by its id and says when nothing is excluded", () => {
    render(
      <RoeVersionCard
        version={{ ...current, exclusions: [], scope: ["tgt_dddddddddddddddddddddddd"] }}
        targets={targets}
      />,
    );
    expect(screen.getByTestId("roe-scope-host").textContent).toBe("tgt_dddddddddddddddddddddddd (removed)");
    expect(screen.getByTestId("roe-exclusions-none").textContent).toBe("No path is excluded.");
  });

  it("writes windows in words: all day and across midnight", () => {
    expect(windowText({ days: ["sat", "sun"], from: "22:00", to: "06:00" })).toBe(
      "Sat, Sun, 22:00 to 06:00 the next day UTC",
    );
    expect(windowText({ days: ["mon"], from: "00:00", to: "24:00" })).toBe("Mon, all day UTC");
  });

  it("lists the history newest first, marking the current version", () => {
    render(<RoeHistory versions={[current, older]} targets={targets} />);
    const rows = screen.getAllByTestId("roe-row");
    expect(rows.map((row) => row.getAttribute("data-roe-id"))).toEqual([current.id, older.id]);
    expect(within(rows[0] as HTMLElement).getByTestId("roe-row-current").textContent).toBe("Current");
    expect(within(rows[1] as HTMLElement).queryByTestId("roe-row-current")).toBeNull();
    expect(within(rows[1] as HTMLElement).getByTestId("roe-row-window").textContent).toBe(
      "Sat, Sun, 22:00 to 06:00 the next day UTC",
    );
    expect(within(rows[1] as HTMLElement).getByTestId("roe-row-scope").textContent).toBe("shop.acme-shop.io");
  });
});

describe("write and sign a version", () => {
  it("offers only verified targets in the scope and explains each intensity", () => {
    render(<RoeForm targets={targets} />);
    const scope = screen.getByRole("group", { name: "Scope" });
    const boxes = within(scope).getAllByRole("checkbox") as HTMLInputElement[];
    expect(boxes.map((box) => [box.value, box.disabled])).toEqual([
      [shop.id, false],
      [api.id, false],
      [legacy.id, true],
      [staging.id, true],
    ]);
    const intensity = screen.getByRole("group", { name: "Intensity" });
    expect((within(intensity).getAllByRole("radio") as HTMLInputElement[]).map((radio) => radio.value)).toEqual([
      "passive",
      "safe-active",
      "full",
    ]);
    for (const level of ["passive", "safe-active", "full"])
      expect(screen.getByTestId(`roe-intensity-help-${level}`).textContent).toMatch(/^[A-Z].+\.$/);
  });

  it("shows the phrase to type for the chosen intensity exactly and sends the whole version", async () => {
    vi.mocked(actions.signRulesOfEngagementAction).mockResolvedValueOnce(null);
    render(<RoeForm targets={targets} />);
    expect(screen.getByTestId("roe-phrase").textContent).toBe("I authorise passive testing");
    fireEvent.click(screen.getByLabelText("safe-active"));
    expect(screen.getByTestId("roe-phrase").textContent).toBe("I authorise safe-active testing");
    fireEvent.click(screen.getByLabelText("shop.acme-shop.io"));
    fireEvent.change(screen.getByLabelText("Excluded paths"), { target: { value: "/admin" } });
    fireEvent.click(screen.getByLabelText("Mon"));
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "09:00" } });
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "17:00" } });
    fireEvent.change(screen.getByLabelText("Contacts"), { target: { value: "security@acme-shop.io" } });
    fireEvent.change(screen.getByLabelText("Type the phrase to sign"), {
      target: { value: "I authorise safe-active testing" },
    });
    expect(screen.getByTestId("roe-immutable-note").textContent).toBe(
      "A signed version cannot be changed. To change anything, sign a new version.",
    );
    await submit(screen.getByRole("button", { name: "Sign version" }));
    expect(sent(actions.signRulesOfEngagementAction)).toEqual({
      scope: [shop.id],
      exclusions: ["/admin"],
      intensity: ["safe-active"],
      days: ["mon"],
      from: ["09:00"],
      to: ["17:00"],
      contacts: ["security@acme-shop.io"],
      confirm: ["I authorise safe-active testing"],
    });
  });

  it("sends All day instead of the hours", async () => {
    vi.mocked(actions.signRulesOfEngagementAction).mockResolvedValueOnce(null);
    render(<RoeForm targets={targets} />);
    fireEvent.click(screen.getByLabelText("All day"));
    expect((screen.getByLabelText("From") as HTMLInputElement).disabled).toBe(true);
    await submit(screen.getByRole("button", { name: "Sign version" }));
    const fields = sent(actions.signRulesOfEngagementAction);
    expect(fields.allDay).toEqual(["on"]);
    expect(fields.from).toBeUndefined();
  });

  it("refills what was written after a refusal and shows each error below its field", async () => {
    vi.mocked(actions.signRulesOfEngagementAction).mockResolvedValueOnce({
      ok: false,
      errors: [
        { path: "days", message: "Choose at least one day." },
        { path: "confirm", message: "Nothing was signed. Type the phrase exactly as shown." },
      ],
      values: {
        scope: [api.id],
        exclusions: "/admin",
        intensity: "full",
        days: [],
        allDay: false,
        from: "09:00",
        to: "17:00",
        contacts: "security@acme-shop.io",
      },
    });
    render(<RoeForm targets={targets} />);
    await submit(screen.getByRole("button", { name: "Sign version" }));
    expect((screen.getByLabelText("api.acme-shop.io") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText("full") as HTMLInputElement).checked).toBe(true);
    expect(screen.getByTestId("roe-phrase").textContent).toBe("I authorise full testing");
    expect((screen.getByLabelText("Excluded paths") as HTMLTextAreaElement).value).toBe("/admin");
    expect(screen.getByTestId("roe-days-error").textContent).toBe("Choose at least one day.");
    expect(screen.getByTestId("roe-confirm-error").textContent).toBe(
      "Nothing was signed. Type the phrase exactly as shown.",
    );
    expect((screen.getByLabelText("Type the phrase to sign") as HTMLInputElement).value).toBe("");
  });
});

describe("check a test", () => {
  it("defaults the time to the one given and shows Allowed with the version", async () => {
    vi.mocked(actions.checkAuthorizationAction).mockResolvedValueOnce({
      ok: true,
      result: { allowed: true, roe_id: current.id },
      values: { host: "shop.acme-shop.io", path: "/", intensity: "passive", at: "2026-11-12T10:30" },
    });
    render(<CheckTestForm defaultAt="2026-11-12T10:30" hosts={["shop.acme-shop.io"]} />);
    expect((screen.getByLabelText("Time (UTC)") as HTMLInputElement).value).toBe("2026-11-12T10:30");
    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "shop.acme-shop.io" } });
    await submit(screen.getByRole("button", { name: "Check" }));
    expect(sent(actions.checkAuthorizationAction)).toEqual({
      host: ["shop.acme-shop.io"],
      path: ["/"],
      intensity: ["passive"],
      at: ["2026-11-12T10:30"],
    });
    expect(screen.getByTestId("check-result").textContent).toBe(
      `Allowed. The current Rules of Engagement (${current.id}) permit this test. Nothing was started.`,
    );
  });

  it("shows the refusal reason in plain words", async () => {
    vi.mocked(actions.checkAuthorizationAction).mockResolvedValueOnce({
      ok: true,
      result: { allowed: false, reason: "outside_window" },
      values: { host: "shop.acme-shop.io", path: "/", intensity: "passive", at: "2026-11-12T20:30" },
    });
    render(<CheckTestForm defaultAt="2026-11-12T10:30" hosts={[]} />);
    await submit(screen.getByRole("button", { name: "Check" }));
    expect(screen.getByTestId("check-result").textContent).toBe(`Refused. ${t(AUTHORIZE_REASON_LABEL.outside_window)}`);
    expect((screen.getByLabelText("Time (UTC)") as HTMLInputElement).value).toBe("2026-11-12T20:30");
  });
});
