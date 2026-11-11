import { EXAMPLE_POLICY, type PolicyRule, type PolicyVersionSummary } from "@antireverse/protocol";
import { generateKey, newId } from "@antireverse/protocol/server";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The screens are rendered with the Server Actions replaced by fakes: what a form sends is the contract.

// The monospace named text styles (UIUX.md §4.3): identifiers, hashes, routes and data are set in Geist Mono.
const MONO = /\bcode-[1-3]\b/;

vi.mock("@/app/actions.ts", () => ({
  createAppAction: vi.fn(),
  publishRuleAction: vi.fn(),
  setRuleModeAction: vi.fn(),
  removeRuleAction: vi.fn(),
  rollbackPolicyAction: vi.fn(),
  signOutAction: vi.fn(),
}));

import * as actions from "@/app/actions.ts";
import { AppNav } from "@/components/app-nav.tsx";
import { Button } from "@/components/button.tsx";
import { CreateAppForm } from "@/features/apps/create-app-form.tsx";
import { policyKeyLine, shieldExpressSnippet } from "@/features/apps/shield-snippet.ts";
import { AddRuleForm } from "@/features/policy/add-rule-form.tsx";
import { EnvironmentSwitch } from "@/features/policy/environment-switch.tsx";
import { PolicyKeySnippet } from "@/features/policy/policy-key-snippet.tsx";
import { confirmationFrom, environmentFrom } from "@/features/policy/query.ts";
import { RuleList } from "@/features/policy/rule-list.tsx";
import { VersionHistory } from "@/features/policy/version-history.tsx";
import { ROUTES } from "@/lib/routes.ts";

const appId = EXAMPLE_POLICY.app_id;
const [enforced, monitored] = EXAMPLE_POLICY.rules as [PolicyRule, PolicyRule];
const rules = [enforced, monitored];
const PAGE = `/apps/${appId}/policy`;
const PUBLIC_KEY = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXU";
const versions: PolicyVersionSummary[] = [
  { version: 3, published_at: "2026-11-10T10:30:05.000Z", rule_count: 2, enforced_count: 1 },
  { version: 2, published_at: "2026-11-10T09:00:00.000Z", rule_count: 2, enforced_count: 0 },
  { version: 1, published_at: "2026-11-09T23:59:59.000Z", rule_count: 1, enforced_count: 0 },
];

const writeText = vi.fn<(text: string) => Promise<void>>();

beforeEach(() => {
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
  writeText.mockReset();
  writeText.mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
});

const row = (ruleId: string): HTMLElement => {
  const found = screen.getAllByTestId("rule-row").find((element) => element.getAttribute("data-rule-id") === ruleId);
  if (!found) throw new Error(`no row for ${ruleId}`);
  return found;
};
/** Every field of a form's data, by name. */
const fieldsOf = (data: FormData): Record<string, string[]> => {
  const values: Record<string, string[]> = {};
  for (const [name, value] of data.entries()) values[name] = [...(values[name] ?? []), String(value)];
  return values;
};
const formValues = (form: HTMLFormElement | null): Record<string, string[]> => {
  if (!form) throw new Error("no form");
  return fieldsOf(new FormData(form));
};
/** What the fake action received when the form was submitted. */
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

describe("RuleList", () => {
  it("shows name, pattern, methods and the mode mark of every Rule, in order", () => {
    render(<RuleList version={3} appId={appId} appName="shop-web" environment="production" rules={rules} />);
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Rule name",
      "Path pattern",
      "Methods",
      "Mode",
      "Actions",
    ]);
    expect(screen.getAllByTestId("rule-row").map((element) => element.getAttribute("data-rule-id"))).toEqual([
      enforced.id,
      monitored.id,
    ]);

    const first = within(row(enforced.id));
    expect(first.getByRole("rowheader").textContent).toBe("Admin area");
    expect(first.getByTestId("rule-path").textContent).toBe("/api/admin/**");
    expect(first.getByTestId("rule-path").className).toMatch(MONO);
    // No method listed means every method.
    expect(first.getByTestId("rule-methods").textContent).toBe("All methods");

    const second = within(row(monitored.id));
    expect(second.getByRole("rowheader").textContent).toBe("User export");
    expect(second.getByTestId("rule-path").textContent).toBe("/api/users/*/export");
    expect(second.getByTestId("rule-methods").textContent).toBe("GET, POST");
  });

  it("marks Monitor dashed and hollow and Enforce solid: the mode never depends on colour alone", () => {
    render(<RuleList version={3} appId={appId} appName="shop-web" environment="production" rules={rules} />);
    const enforce = within(row(enforced.id)).getByTestId("mode-tag");
    expect(enforce.textContent).toBe("Enforce");
    expect(enforce.getAttribute("data-mode")).toBe("enforce");
    expect(enforce.className).toContain("border-solid");
    expect(enforce.className).not.toContain("border-dashed");
    expect(row(enforced.id).getAttribute("data-mode")).toBe("enforce");

    const monitor = within(row(monitored.id)).getByTestId("mode-tag");
    expect(monitor.textContent).toBe("Monitor");
    expect(monitor.className).toContain("border-dashed");
    expect(monitor.className).toContain("bg-transparent");
    expect(monitor.className).not.toContain("border-solid");
    expect(row(monitored.id).getAttribute("data-mode")).toBe("monitor");
  });

  it("tags a Rule that requires a signed request with an icon and the words, and only that Rule", () => {
    const signedOnly: PolicyRule = { ...monitored, id: newId("rul"), name: "Checkout", requires: "signature" };
    render(
      <RuleList version={3} appId={appId} appName="shop-web" environment="production" rules={[enforced, signedOnly]} />,
    );
    const tag = within(row(signedOnly.id)).getByTestId("rule-requires");
    expect(tag.textContent).toBe("Signed requests required");
    expect(tag.getAttribute("data-requires")).toBe("signature");
    expect(tag.querySelector("svg")?.getAttribute("data-shape")).toBe("signature");
    expect(tag.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
    expect(row(signedOnly.id).getAttribute("data-requires")).toBe("signature");
    expect(within(row(enforced.id)).queryByTestId("rule-requires")).toBeNull();
    expect(row(enforced.id).getAttribute("data-requires")).toBeNull();
    // The requirement changes nothing about promotion: still a link to the confirmation step.
    expect(within(row(signedOnly.id)).getByTestId("rule-promote").getAttribute("href")).toBe(
      ROUTES.policy(appId, "production", { promote: signedOnly.id }),
    );
  });

  it("reads policy.none when there is no Rule, and shows no table", () => {
    render(<RuleList version={3} appId={appId} appName="shop-web" environment="development" rules={[]} />);
    expect(screen.getByTestId("policy-empty").textContent).toBe(
      "No Rules yet. Shield observes every request and blocks nothing.",
    );
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("offers Promote to enforce as a link to the confirmation step — never as a one-click change", () => {
    render(<RuleList version={3} appId={appId} appName="shop-web" environment="production" rules={rules} />);
    const monitor = within(row(monitored.id));
    const promote = monitor.getByRole("link", { name: "Promote to enforce" });
    expect(promote.getAttribute("href")).toBe(`${PAGE}?environment=production&promote=${monitored.id}`);
    expect(promote.getAttribute("data-testid")).toBe("rule-promote");
    // Nothing on the row itself can publish Enforce mode.
    for (const form of Array.from(row(monitored.id).querySelectorAll("form"))) {
      expect(formValues(form).mode ?? []).not.toContain("enforce");
    }
    expect(screen.queryByRole("alertdialog")).toBeNull();
    // A Rule that is enforced already has nothing to promote.
    expect(within(row(enforced.id)).queryByRole("link", { name: "Promote to enforce" })).toBeNull();
  });

  it("opens a confirmation that names the Environment and the pattern, and sends the confirmation", async () => {
    render(
      <RuleList
        version={3}
        appId={appId}
        appName="shop-web"
        environment="production"
        rules={rules}
        confirmRuleId={monitored.id}
      />,
    );
    const dialog = screen.getByRole("alertdialog");
    expect(dialog.getAttribute("data-testid")).toBe("policy-confirm");
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Promote to enforce in production? Requests matching /api/users/*/export will be blocked.",
    );
    // The question is the dialog's accessible name.
    expect(dialog.getAttribute("aria-labelledby")).toBe(within(dialog).getByTestId("confirm-question").id);
    // It takes the focus when it appears, so a keyboard user lands on it.
    expect(document.activeElement).toBe(dialog);

    const confirm = within(dialog).getByRole("button", { name: "Promote to enforce" });
    expect(confirm.getAttribute("type")).toBe("submit");
    // Black text on the destructive colour (UIUX.md §8).
    expect(confirm.className).toContain("bg-destructive");
    expect(confirm.className).toContain("text-on-destructive");
    const cancel = within(dialog).getByRole("link", { name: "Cancel" });
    expect(cancel.getAttribute("href")).toBe(`${PAGE}?environment=production`);

    await submit(confirm);
    expect(actions.setRuleModeAction).toHaveBeenCalledTimes(1);
    expect(sent(actions.setRuleModeAction)).toEqual({
      appId: [appId],
      environment: ["production"],
      ruleId: [monitored.id],
      mode: ["enforce"],
      confirm: ["production"],
      expectedVersion: ["3"],
    });
  });

  it("asks nothing for a Rule that is not in Monitor mode or not part of the Policy", () => {
    const { rerender } = render(
      <RuleList
        version={3}
        appId={appId}
        appName="shop-web"
        environment="production"
        rules={rules}
        confirmRuleId={enforced.id}
      />,
    );
    expect(screen.queryByRole("alertdialog")).toBeNull();
    rerender(
      <RuleList
        version={3}
        appId={appId}
        appName="shop-web"
        environment="production"
        rules={rules}
        confirmRuleId="rul_ffffffffffffffffffffffff"
      />,
    );
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("puts a Rule back to Monitor with one button and no confirmation", async () => {
    render(<RuleList version={3} appId={appId} appName="shop-web" environment="staging" rules={rules} />);
    const demote = within(row(enforced.id)).getByRole("button", { name: "Back to monitor" });
    expect(within(row(monitored.id)).queryByRole("button", { name: "Back to monitor" })).toBeNull();
    await submit(demote);
    expect(sent(actions.setRuleModeAction)).toEqual({
      appId: [appId],
      environment: ["staging"],
      ruleId: [enforced.id],
      expectedVersion: ["3"],
      mode: ["monitor"],
    });
  });

  it("removes a Rule with one button and no confirmation", async () => {
    render(<RuleList version={3} appId={appId} appName="shop-web" environment="staging" rules={rules} />);
    await submit(within(row(monitored.id)).getByRole("button", { name: "Remove" }));
    expect(actions.removeRuleAction).toHaveBeenCalledTimes(1);
    expect(sent(actions.removeRuleAction)).toEqual({
      appId: [appId],
      environment: ["staging"],
      ruleId: [monitored.id],
      expectedVersion: ["3"],
    });
    expect(actions.setRuleModeAction).not.toHaveBeenCalled();
  });

  it("names the Rule a control belongs to without changing the control's own name", () => {
    render(<RuleList version={3} appId={appId} appName="shop-web" environment="staging" rules={rules} />);
    const remove = within(row(monitored.id)).getByRole("button", { name: "Remove" });
    const described = document.getElementById(remove.getAttribute("aria-describedby") ?? "");
    expect(described?.textContent).toBe("User export");
  });

  it("shows why a change was refused, as an alert, and keeps the Rules", async () => {
    vi.mocked(actions.setRuleModeAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "mode", message: "A Rule that blocks every request cannot be enforced." }],
    });
    render(
      <RuleList
        version={3}
        appId={appId}
        appName="shop-web"
        environment="production"
        rules={rules}
        confirmRuleId={monitored.id}
      />,
    );
    await submit(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Promote to enforce" }));
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("A Rule that blocks every request cannot be enforced.");
    expect(document.activeElement).toBe(alert);
    expect(screen.getAllByTestId("rule-row")).toHaveLength(2);
  });
});

describe("stronger confirmation of a broad pattern", () => {
  const BROAD_WARNING =
    "This pattern matches most of the App's requests. Enforcing it can take the App offline for its users.";
  const broad: PolicyRule = { ...monitored, path: "/*/export" };

  it("asks for the typed Environment, with a warning, only when the pattern is broad", async () => {
    const { rerender } = render(
      <RuleList
        version={3}
        appId={appId}
        appName="shop-web"
        environment="production"
        rules={[enforced, monitored]}
        confirmRuleId={monitored.id}
      />,
    );
    expect(screen.queryByTestId("confirm-broad")).toBeNull();
    expect(screen.queryByTestId("confirm-typed")).toBeNull();

    rerender(
      <RuleList
        version={3}
        appId={appId}
        appName="shop-web"
        environment="production"
        rules={[enforced, broad]}
        confirmRuleId={broad.id}
      />,
    );
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Promote to enforce in production? Requests matching /*/export will be blocked.",
    );
    const warning = within(dialog).getByTestId("confirm-broad");
    expect(warning.textContent).toBe(BROAD_WARNING);
    expect(warning.className).toContain("border-destructive");
    // Read with the question: the dialog is described by the warning.
    expect((dialog.getAttribute("aria-describedby") ?? "").split(" ")).toContain(warning.id);

    const typed = within(dialog).getByLabelText("Type production to confirm") as HTMLInputElement;
    expect(typed.getAttribute("data-testid")).toBe("confirm-typed");
    expect(typed.name).toBe("typedEnvironment");
    expect(typed.type).toBe("text");
    expect(typed.value).toBe("");
    // Without JavaScript the browser itself holds the submit back until the Environment is typed.
    expect(typed.required).toBe(true);
    expect(typed.getAttribute("pattern")).toBe("production");
    expect(typed.getAttribute("autocomplete")).toBe("off");
    expect(within(dialog).getByTestId("confirm-typed-label").textContent).toBe("Type production to confirm");

    fireEvent.change(typed, { target: { value: "production" } });
    await submit(within(dialog).getByTestId("confirm-submit"));
    expect(sent(actions.setRuleModeAction)).toEqual({
      appId: [appId],
      environment: ["production"],
      ruleId: [broad.id],
      mode: ["enforce"],
      confirm: ["production"],
      expectedVersion: ["3"],
      typedEnvironment: ["production"],
    });
  });

  it("shows a wrong typed Environment below the field, linked to it and to the summary", async () => {
    vi.mocked(actions.setRuleModeAction).mockResolvedValue({
      ok: false,
      errors: [
        { path: "typedEnvironment", message: "Nothing was published. Type production exactly as shown to confirm." },
      ],
    });
    render(
      <RuleList
        version={3}
        appId={appId}
        appName="shop-web"
        environment="production"
        rules={[enforced, broad]}
        confirmRuleId={broad.id}
      />,
    );
    fireEvent.change(screen.getByTestId("confirm-typed"), { target: { value: "production" } });
    await submit(screen.getByTestId("confirm-submit"));

    const error = screen.getByTestId("confirm-typed-error");
    expect(error.textContent).toBe("Nothing was published. Type production exactly as shown to confirm.");
    const field = screen.getByTestId("confirm-typed");
    expect(field.getAttribute("aria-invalid")).toBe("true");
    expect((field.getAttribute("aria-describedby") ?? "").split(" ")).toContain(error.id);
    const link = within(screen.getByTestId("error-summary")).getByRole("link", {
      name: "Type production to confirm: Nothing was published. Type production exactly as shown to confirm.",
    });
    expect(link.getAttribute("href")).toBe(`#${field.id}`);
  });

  it("asks for the typed Environment before a rollback that enforces a broad pattern", async () => {
    const { rerender } = render(
      <VersionHistory
        appId={appId}
        appName="shop-web"
        environment="staging"
        currentVersion={3}
        versions={versions}
        confirmVersion={2}
      />,
    );
    expect(screen.queryByTestId("confirm-typed")).toBeNull();
    rerender(
      <VersionHistory
        appId={appId}
        appName="shop-web"
        environment="staging"
        currentVersion={3}
        versions={versions}
        confirmVersion={2}
        confirmBroad
      />,
    );
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByTestId("confirm-broad").textContent).toBe(
      "This version enforces a pattern that matches most of the App's requests. Rolling back can take the App offline for its users.",
    );
    const typed = within(dialog).getByLabelText("Type staging to confirm");
    fireEvent.change(typed, { target: { value: "staging" } });
    await submit(within(dialog).getByTestId("confirm-submit"));
    expect(sent(actions.rollbackPolicyAction)).toEqual({
      appId: [appId],
      environment: ["staging"],
      version: ["2"],
      confirm: ["staging"],
      expectedVersion: ["3"],
      typedEnvironment: ["staging"],
    });
  });
});

describe("VersionHistory", () => {
  it("lists the versions newest first with when they were published and what they hold", () => {
    render(
      <VersionHistory
        appId={appId}
        appName="shop-web"
        environment="production"
        currentVersion={3}
        versions={versions}
      />,
    );
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Version",
      "Published UTC",
      "Rules",
      "Enforce",
      "Actions",
    ]);
    const cells = screen.getAllByTestId("version-row").map((element) =>
      within(element)
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    );
    expect(cells.map((line) => line.slice(0, 3))).toEqual([
      ["2026-11-10 10:30:05", "2", "1"],
      ["2026-11-10 09:00:00", "2", "0"],
      ["2026-11-09 23:59:59", "1", "0"],
    ]);
    expect(screen.getAllByRole("rowheader").map((header) => header.textContent)).toEqual([
      "Version 3Current",
      "Version 2",
      "Version 1",
    ]);
    expect(screen.getAllByTestId("version-row")[0]?.querySelector("time")?.getAttribute("dateTime")).toBe(
      "2026-11-10T10:30:05.000Z",
    );
  });

  it("offers Roll back for every version but the current one, as a link to the confirmation step", () => {
    render(
      <VersionHistory
        appId={appId}
        appName="shop-web"
        environment="production"
        currentVersion={3}
        versions={versions}
      />,
    );
    const links = screen.getAllByRole("link", { name: "Roll back" });
    expect(links.map((link) => link.getAttribute("href"))).toEqual([
      `${PAGE}?environment=production&rollback=2`,
      `${PAGE}?environment=production&rollback=1`,
    ]);
    expect(links[0]?.getAttribute("data-testid")).toBe("version-rollback");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    // Nothing rolls back with one click.
    expect(document.querySelector("form")).toBeNull();
  });

  it("opens a confirmation that names the Environment and the version, and sends the confirmation", async () => {
    render(
      <VersionHistory
        appId={appId}
        appName="shop-web"
        environment="production"
        currentVersion={3}
        versions={versions}
        confirmVersion={1}
      />,
    );
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByTestId("confirm-question").textContent).toBe(
      "Roll back production to the Rules of version 1?",
    );
    expect(document.activeElement).toBe(dialog);
    const confirm = within(dialog).getByRole("button", { name: "Roll back" });
    expect(confirm.className).toContain("bg-destructive");
    expect(within(dialog).getByRole("link", { name: "Cancel" }).getAttribute("href")).toBe(
      `${PAGE}?environment=production`,
    );

    await submit(confirm);
    expect(actions.rollbackPolicyAction).toHaveBeenCalledTimes(1);
    expect(sent(actions.rollbackPolicyAction)).toEqual({
      appId: [appId],
      environment: ["production"],
      version: ["1"],
      confirm: ["production"],
      expectedVersion: ["3"],
    });
  });

  it("asks nothing for the current version or a version that is not listed", () => {
    const { rerender } = render(
      <VersionHistory
        appId={appId}
        appName="shop-web"
        environment="production"
        currentVersion={3}
        versions={versions}
        confirmVersion={3}
      />,
    );
    expect(screen.queryByRole("alertdialog")).toBeNull();
    rerender(
      <VersionHistory
        appId={appId}
        appName="shop-web"
        environment="production"
        currentVersion={3}
        versions={versions}
        confirmVersion={9}
      />,
    );
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("says that nothing was published yet when there is no version", () => {
    render(
      <VersionHistory appId={appId} appName="shop-web" environment="development" currentVersion={0} versions={[]} />,
    );
    expect(screen.getByText("No version has been published yet.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("shows why a rollback was refused, as an alert", async () => {
    vi.mocked(actions.rollbackPolicyAction).mockResolvedValue({
      ok: false,
      errors: [
        {
          path: "",
          message:
            "This Policy changed while you were editing it, so nothing was saved. Reload the page and try again.",
        },
      ],
    });
    render(
      <VersionHistory
        appId={appId}
        appName="shop-web"
        environment="production"
        currentVersion={3}
        versions={versions}
        confirmVersion={2}
      />,
    );
    await submit(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Roll back" }));
    expect(screen.getByRole("alert").textContent).toContain(
      "This Policy changed while you were editing it, so nothing was saved.",
    );
  });
});

describe("AddRuleForm", () => {
  it("asks for a name, a path pattern with its help text, and the five methods — none checked", () => {
    render(<AddRuleForm version={3} appId={appId} environment="staging" />);
    expect(screen.getByLabelText("Rule name").getAttribute("name")).toBe("name");
    const path = screen.getByLabelText("Path pattern");
    expect(path.getAttribute("name")).toBe("path");
    expect(path.className).toMatch(MONO);
    const help = document.getElementById(path.getAttribute("aria-describedby") ?? "");
    expect(help?.textContent).toBe("For example /api/admin/** — * is one segment, ** is everything below.");

    const group = screen.getByRole("group", { name: "Methods" });
    const boxes = within(group).getAllByRole("checkbox") as HTMLInputElement[];
    expect(boxes.map((box) => box.value)).toEqual(["GET", "POST", "PUT", "PATCH", "DELETE"]);
    expect(boxes.every((box) => box.name === "methods" && !box.checked)).toBe(true);
    for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE"]) {
      expect(within(group).getByLabelText(method)).toBeTruthy();
    }
    expect(screen.getByRole("button", { name: "Add Rule" }).getAttribute("type")).toBe("submit");
  });

  it("offers Require a signed request, unchecked, with its help text", () => {
    render(<AddRuleForm version={3} appId={appId} environment="staging" />);
    const box = screen.getByLabelText("Require a signed request") as HTMLInputElement;
    expect(box.type).toBe("checkbox");
    expect(box.name).toBe("requires");
    expect(box.value).toBe("signature");
    expect(box.checked).toBe(false);
    expect(box.getAttribute("data-testid")).toBe("rule-requires-signature");
    const help = (box.getAttribute("aria-describedby") ?? "").split(" ").map((id) => document.getElementById(id));
    expect(help.map((element) => element?.textContent)).toContain(
      "Requests on this route must come from Guard with a valid signature. For routes that take a body, add shield.verifyBody to your body parser.",
    );
  });

  it("sends requires=signature when the box is checked, and nothing about it otherwise", async () => {
    render(<AddRuleForm version={3} appId={appId} environment="staging" />);
    fireEvent.change(screen.getByLabelText("Rule name"), { target: { value: "Checkout" } });
    fireEvent.change(screen.getByLabelText("Path pattern"), { target: { value: "/api/checkout" } });
    fireEvent.click(screen.getByLabelText("Require a signed request"));
    await submit(screen.getByRole("button", { name: "Add Rule" }));
    expect(sent(actions.publishRuleAction)).toEqual({
      appId: [appId],
      environment: ["staging"],
      name: ["Checkout"],
      path: ["/api/checkout"],
      requires: ["signature"],
      expectedVersion: ["3"],
    });
  });

  it("keeps the box checked after a refusal", async () => {
    vi.mocked(actions.publishRuleAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "path", message: "Enter a path pattern." }],
      values: { name: "Checkout", path: "", methods: [], requires: true },
    });
    render(<AddRuleForm version={3} appId={appId} environment="staging" />);
    await submit(screen.getByRole("button", { name: "Add Rule" }));
    expect((screen.getByLabelText("Require a signed request") as HTMLInputElement).checked).toBe(true);
  });

  it("sends the Rule with the App and the Environment — and no mode: a new Rule starts in Monitor", async () => {
    render(<AddRuleForm version={3} appId={appId} environment="staging" />);
    fireEvent.change(screen.getByLabelText("Rule name"), { target: { value: "Admin area" } });
    fireEvent.change(screen.getByLabelText("Path pattern"), { target: { value: "/api/admin/**" } });
    fireEvent.click(screen.getByLabelText("POST"));
    fireEvent.click(screen.getByLabelText("DELETE"));
    await submit(screen.getByRole("button", { name: "Add Rule" }));
    expect(actions.publishRuleAction).toHaveBeenCalledTimes(1);
    expect(sent(actions.publishRuleAction)).toEqual({
      appId: [appId],
      environment: ["staging"],
      name: ["Admin area"],
      path: ["/api/admin/**"],
      methods: ["POST", "DELETE"],
      expectedVersion: ["3"],
    });
  });

  it("shows a refusal in a summary and below its field, linked to the field, and keeps what was typed", async () => {
    vi.mocked(actions.publishRuleAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "path", message: "Enter a path pattern." }],
      values: { name: "Admin area", path: "", methods: ["PUT"] },
    });
    render(<AddRuleForm version={3} appId={appId} environment="staging" />);
    await submit(screen.getByRole("button", { name: "Add Rule" }));

    const summary = screen.getByTestId("error-summary");
    expect(document.activeElement).toBe(summary);
    const link = within(summary).getByRole("link", { name: "Path pattern: Enter a path pattern." });
    const path = screen.getByLabelText("Path pattern");
    expect(link.getAttribute("href")).toBe(`#${path.id}`);
    expect(path.getAttribute("aria-invalid")).toBe("true");
    const described = (path.getAttribute("aria-describedby") ?? "").split(" ");
    expect(described.map((id) => document.getElementById(id)?.textContent)).toContain("Enter a path pattern.");

    expect((screen.getByLabelText("Rule name") as HTMLInputElement).value).toBe("Admin area");
    expect((screen.getByLabelText("PUT") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText("GET") as HTMLInputElement).checked).toBe(false);
  });

  it("links a refusal of the methods to the group", async () => {
    vi.mocked(actions.publishRuleAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "methods", message: "Choose from GET, POST, PUT, PATCH and DELETE." }],
      values: { name: "Admin area", path: "/x", methods: [] },
    });
    render(<AddRuleForm version={3} appId={appId} environment="staging" />);
    await submit(screen.getByRole("button", { name: "Add Rule" }));
    const group = screen.getByRole("group", { name: "Methods" });
    const described = (group.getAttribute("aria-describedby") ?? "").split(" ");
    expect(described.map((id) => document.getElementById(id)?.textContent)).toContain(
      "Choose from GET, POST, PUT, PATCH and DELETE.",
    );
  });
});

describe("PolicyKeySnippet", () => {
  it("shows the public key as the AR_POLICY_PUBLIC_KEY line and copies exactly that line", async () => {
    render(<PolicyKeySnippet publicKey={PUBLIC_KEY} />);
    expect(screen.getByTestId("policy-public-key").textContent).toBe(PUBLIC_KEY);
    expect(screen.getByRole("figure").querySelector("code")?.textContent).toBe(
      `export AR_POLICY_PUBLIC_KEY="${PUBLIC_KEY}"`,
    );
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    });
    expect(writeText).toHaveBeenCalledWith(`export AR_POLICY_PUBLIC_KEY="${PUBLIC_KEY}"`);
    expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy();
  });

  it("builds the line and the middleware set-up that reads it", () => {
    expect(policyKeyLine(PUBLIC_KEY)).toBe(`export AR_POLICY_PUBLIC_KEY="${PUBLIC_KEY}"`);
    const snippet = shieldExpressSnippet("http://127.0.0.1:8787");
    expect(snippet).toContain("policyPublicKey: process.env.AR_POLICY_PUBLIC_KEY");
    expect(snippet).toContain("key: process.env.AR_SHIELD_KEY");
    expect(snippet).toContain('endpoint: "http://127.0.0.1:8787"');
    expect(snippet).toContain("app.use(shield.express());");
  });
});

describe("App-created screen", () => {
  const app = { id: newId("app"), name: "shop-web", created_at: "2026-11-10T08:01:00.000Z" };
  const shieldKey = generateKey("shield", "production").key;

  async function create(policyPublicKey: string | null): Promise<void> {
    vi.mocked(actions.createAppAction).mockResolvedValue({ ok: true, app, shieldKey, environment: "production" });
    render(<CreateAppForm apiUrl="http://127.0.0.1:8787" policyPublicKey={policyPublicKey} />);
    await submit(screen.getByRole("button", { name: "Create App" }));
  }

  it("shows the policy public key as the AR_POLICY_PUBLIC_KEY line in the set-up", async () => {
    await create(PUBLIC_KEY);
    expect(screen.getByTestId("shield-key").textContent).toBe(shieldKey);
    expect(screen.getByTestId("policy-public-key").textContent).toBe(PUBLIC_KEY);
    const setup = screen.getByRole("region", { name: "Add Shield to your Express server" });
    const code = Array.from(setup.querySelectorAll("code")).map((element) => element.textContent);
    expect(code).toContain(`export AR_SHIELD_KEY="${shieldKey}"`);
    expect(code).toContain(`export AR_POLICY_PUBLIC_KEY="${PUBLIC_KEY}"`);
    expect(within(setup).getByText("Shield accepts only Policies signed with this key.")).toBeTruthy();
    // The App's Policy is one step away.
    expect(screen.getByRole("link", { name: "Policy" }).getAttribute("href")).toBe(
      `/apps/${app.id}/policy?environment=production`,
    );
  });

  it("says so when the policy public key could not be loaded, and still shows the Shield key", async () => {
    await create(null);
    expect(screen.getByTestId("shield-key").textContent).toBe(shieldKey);
    expect(screen.queryByTestId("policy-public-key")).toBeNull();
    expect(screen.getByText("The policy public key could not be loaded. Reload this page to see it.")).toBeTruthy();
  });
});

describe("EnvironmentSwitch", () => {
  it("links to the same screen for each Environment and marks the current one", () => {
    render(<EnvironmentSwitch appId={appId} current="staging" />);
    const nav = screen.getByRole("navigation", { name: "Environment" });
    expect(nav.getAttribute("data-testid")).toBe("environment-switch");
    const links = within(nav).getAllByRole("link");
    expect(links.map((link) => [link.textContent, link.getAttribute("href")])).toEqual([
      ["Production", `${PAGE}?environment=production`],
      ["Staging", `${PAGE}?environment=staging`],
      ["Development", `${PAGE}?environment=development`],
    ]);
    expect(links.map((link) => link.getAttribute("aria-current"))).toEqual([null, "true", null]);
    expect(links.map((link) => link.getAttribute("data-environment"))).toEqual([
      "production",
      "staging",
      "development",
    ]);
  });
});

describe("AppNav", () => {
  it("links Live and Policy of the App and marks the current screen", () => {
    const { rerender } = render(<AppNav appId={appId} current="policy" />);
    const nav = screen.getByTestId("app-nav");
    expect(nav.tagName).toBe("NAV");
    const live = within(nav).getByRole("link", { name: "Live" });
    const policy = within(nav).getByRole("link", { name: "Policy" });
    expect(live.getAttribute("href")).toBe(`/apps/${appId}/live`);
    expect(policy.getAttribute("href")).toBe(PAGE);
    expect(policy.getAttribute("aria-current")).toBe("page");
    expect(live.getAttribute("aria-current")).toBeNull();

    rerender(<AppNav appId={appId} current="live" />);
    expect(within(nav).getByRole("link", { name: "Live" }).getAttribute("aria-current")).toBe("page");
    expect(within(nav).getByRole("link", { name: "Policy" }).getAttribute("aria-current")).toBeNull();
  });
});

describe("Button", () => {
  it("draws a destructive action with black text on the destructive colour", () => {
    render(<Button variant="destructive">Roll back</Button>);
    const button = screen.getByRole("button", { name: "Roll back" });
    expect(button.className).toContain("bg-destructive");
    expect(button.className).toContain("text-on-destructive");
  });
});

describe("Policy addresses", () => {
  it("builds the address of the Policy screen, its Environment and its confirmation step", () => {
    expect(ROUTES.policy(appId)).toBe(PAGE);
    expect(ROUTES.policy(appId, "staging")).toBe(`${PAGE}?environment=staging`);
    expect(ROUTES.policy(appId, "production", { promote: monitored.id })).toBe(
      `${PAGE}?environment=production&promote=${monitored.id}`,
    );
    expect(ROUTES.policy(appId, "production", { rollback: 4 })).toBe(`${PAGE}?environment=production&rollback=4`);
  });

  it("reads the Environment from the address: development by default and for an unknown value", () => {
    expect(environmentFrom("production")).toBe("production");
    expect(environmentFrom("staging")).toBe("staging");
    expect(environmentFrom("development")).toBe("development");
    expect(environmentFrom(undefined)).toBe("development");
    expect(environmentFrom("")).toBe("development");
    expect(environmentFrom("moon")).toBe("development");
    expect(environmentFrom("Production")).toBe("development");
    expect(environmentFrom(["production", "staging"])).toBe("development");
    expect(environmentFrom("__proto__")).toBe("development");
  });

  it("reads the confirmation step from the address only when it names something that can be confirmed", () => {
    const policy = { ...EXAMPLE_POLICY, version: 3 };
    expect(confirmationFrom({}, policy, versions)).toEqual({});
    expect(confirmationFrom({ promote: monitored.id }, policy, versions)).toEqual({ promote: monitored.id });
    // Enforced already, unknown, malformed or repeated: no confirmation.
    expect(confirmationFrom({ promote: enforced.id }, policy, versions)).toEqual({});
    expect(confirmationFrom({ promote: "rul_ffffffffffffffffffffffff" }, policy, versions)).toEqual({});
    expect(confirmationFrom({ promote: "x" }, policy, versions)).toEqual({});
    expect(confirmationFrom({ promote: [monitored.id, monitored.id] }, policy, versions)).toEqual({});

    expect(confirmationFrom({ rollback: "2" }, policy, versions)).toEqual({ rollback: 2 });
    // The current version, an unlisted one and a value that is not a version: no confirmation.
    expect(confirmationFrom({ rollback: "3" }, policy, versions)).toEqual({});
    expect(confirmationFrom({ rollback: "9" }, policy, versions)).toEqual({});
    expect(confirmationFrom({ rollback: "2.0" }, policy, versions)).toEqual({});
    expect(confirmationFrom({ rollback: "02" }, policy, versions)).toEqual({});
    // One confirmation at a time: a promotion comes first.
    expect(confirmationFrom({ promote: monitored.id, rollback: "2" }, policy, versions)).toEqual({
      promote: monitored.id,
    });
  });
});
