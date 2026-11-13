import {
  EXAMPLE_POLICY,
  EXAMPLE_SIMULATION_RESULT,
  type PolicyRule,
  type SimulationResult,
} from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Policy simulation on the Policy screen (slice 11), rendered with the Server Actions replaced by fakes: what a
// form sends is the contract, and what the action answers is what the screen shows, for this view only.

vi.mock("@/app/actions.ts", () => ({
  publishRuleAction: vi.fn(),
  setRuleModeAction: vi.fn(),
  removeRuleAction: vi.fn(),
  simulatePolicyAction: vi.fn(),
}));

import type { SimulationState } from "@/app/actions.ts";
import * as actions from "@/app/actions.ts";
import { AddRuleForm } from "@/features/policy/add-rule-form.tsx";
import { RuleList } from "@/features/policy/rule-list.tsx";
import { ruleFingerprint } from "@/features/policy/simulation.ts";
import { PolicySimulation } from "@/features/policy/simulation-context.tsx";
import { SimulationPanel } from "@/features/policy/simulation-panel.tsx";

const appId = EXAMPLE_POLICY.app_id;
const [enforced, monitored] = EXAMPLE_POLICY.rules as [PolicyRule, PolicyRule];
const rules = [enforced, monitored];
const MONO = /\bcode-[1-3]\b/;

/** A result for the two Rules of the Policy: the enforced one blocks 40, the monitored one would block 1,260. */
function result(overrides: Partial<SimulationResult> = {}): SimulationResult {
  const [first] = EXAMPLE_SIMULATION_RESULT.rules;
  if (!first) throw new Error("no row");
  return {
    ...EXAMPLE_SIMULATION_RESULT,
    rules: [
      first,
      {
        index: 1,
        id: monitored.id,
        name: monitored.name,
        matched: 1_300,
        would_block: 1_260,
        would_fail_signature: 0,
        would_throttle: 0,
        already_refused: 0,
        undecidable: 325,
        clients_affected: 12,
        unknown_client_events: 0,
        // Promoted alone it refuses more than with every Rule enforced.
        if_promoted: { would_refuse: 1_300, clients_affected: 14, unknown_client_events: 0, undecidable: 330 },
        sample_routes: [{ route: "/api/users/:id/export", method: "GET", count: 1_260 }],
      },
    ],
    totals: { would_refuse: 1_300, clients_affected: 15, unknown_client_events: 0 },
    ...overrides,
  };
}
const ran = (simulation: SimulationResult = result(), simulated: readonly PolicyRule[] = rules): SimulationState => ({
  ok: true,
  withDraft: false,
  simulation,
  rules: simulated.map(ruleFingerprint),
});
const answers = (state: SimulationState): void => {
  vi.mocked(actions.simulatePolicyAction).mockResolvedValue(state);
};

beforeEach(() => {
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
});

const fieldsOf = (data: FormData): Record<string, string[]> => {
  const values: Record<string, string[]> = {};
  for (const [name, value] of data.entries()) values[name] = [...(values[name] ?? []), String(value)];
  return values;
};
const sent = (): Record<string, string[]> => {
  const data = vi.mocked(actions.simulatePolicyAction).mock.calls.at(-1)?.[1];
  if (!data) throw new Error("the action was not called");
  return fieldsOf(data);
};
const submit = async (control: HTMLElement): Promise<void> => {
  await act(async () => {
    fireEvent.click(control);
  });
};
const texts = (testId: string, within_: HTMLElement = document.body): (string | null)[] =>
  within(within_)
    .queryAllByTestId(testId)
    .map((element) => element.textContent);

function Screen({ current = rules, confirmRuleId }: { current?: readonly PolicyRule[]; confirmRuleId?: string }) {
  return (
    <PolicySimulation>
      <RuleList
        version={3}
        appId={appId}
        appName="shop-web"
        environment="production"
        rules={current}
        confirmRuleId={confirmRuleId}
      />
      <SimulationPanel appId={appId} environment="production" version={3} ruleCount={current.length} />
      <AddRuleForm version={3} appId={appId} environment="production" />
    </PolicySimulation>
  );
}
const simulate = (): Promise<void> => submit(screen.getByRole("button", { name: "Simulate" }));

describe("SimulationPanel", () => {
  it("offers Simulate with what it does, and shows no result before one ran", () => {
    render(<Screen />);
    const button = screen.getByRole("button", { name: "Simulate" });
    expect(button.getAttribute("type")).toBe("submit");
    const help = document.getElementById(button.getAttribute("aria-describedby") ?? "");
    expect(help?.textContent).toBe(
      "Replays the last 24 hours of recorded requests against these Rules as if every Rule were enforced. Nothing is published.",
    );
    expect(screen.queryByTestId("simulation-result")).toBeNull();
    expect(screen.queryByTestId("simulation-error")).toBeNull();
  });

  it("offers nothing to simulate while the Policy has no Rule", () => {
    render(<Screen current={[]} />);
    expect(screen.queryByRole("button", { name: "Simulate" })).toBeNull();
  });

  it("sends the App, the Environment and the version the page showed, and nothing else", async () => {
    answers(ran());
    render(<Screen />);
    await simulate();
    expect(actions.simulatePolicyAction).toHaveBeenCalledTimes(1);
    expect(sent()).toEqual({ appId: [appId], environment: ["production"], expectedVersion: ["3"] });
  });

  it("shows the result as an estimate with its period and the requests replayed, and takes the focus", async () => {
    answers(ran());
    render(<Screen />);
    await simulate();
    const panel = screen.getByTestId("simulation-result");
    expect(document.activeElement).toBe(panel);
    expect(within(panel).getByRole("heading", { level: 3 }).textContent).toBe("Simulation");
    expect(panel.getAttribute("aria-labelledby")).toBe(within(panel).getByRole("heading", { level: 3 }).id);
    expect(within(panel).getByTestId("simulation-caption").textContent).toBe(
      "Estimate from the last 24 hours of recorded requests",
    );
    // The promise, in one line beside the caption.
    expect(within(panel).getByTestId("simulation-promise").textContent).toBe(
      "Never claims a refusal Shield would not make for the recorded traffic, within the limits listed below.",
    );
    expect(within(panel).getByTestId("simulation-period").textContent).toBe(
      "2026-11-10 09:00:00 to 2026-11-11 09:00:00 UTC",
    );
    expect(within(panel).getByTestId("simulation-period").className).toMatch(MONO);
    expect(within(panel).getByTestId("simulation-events").textContent).toBe("18,452 requests replayed");
    // When it ran: a figure read later is dated.
    expect(within(panel).getByTestId("simulation-ran").textContent).toBe("Simulated at 2026-11-11 09:00:00 UTC");
  });

  it("shows per Rule what it would refuse, by kind when not zero, the clients, what could not be judged and what Shield refused", async () => {
    const [block, signature, limit] = EXAMPLE_SIMULATION_RESULT.rules;
    if (!block || !signature || !limit) throw new Error("the example has three rows");
    const mixed = { ...limit, matched: 600, would_block: 3, would_fail_signature: 1, would_throttle: 1_180 };
    const simulation = { ...EXAMPLE_SIMULATION_RESULT, rules: [block, signature, { ...mixed, clients_affected: 1 }] };
    answers({ ok: true, withDraft: false, simulation, rules: ["a", "b", "c"] });
    render(<Screen />);
    await simulate();
    const panel = screen.getByTestId("simulation-result");
    expect(
      within(panel)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual([
      "Rule",
      "Would refuse",
      "Clients affected",
      "Could not be judged",
      "Already refused by Shield",
      "Routes refused most",
    ]);
    const rows = within(panel).getAllByTestId("simulation-row");
    expect(rows.map((row) => within(row).getByRole("rowheader").textContent)).toEqual([
      "Admin area",
      "Signed checkout",
      "Login protection",
    ]);
    const [first, second, third] = rows as [HTMLElement, HTMLElement, HTMLElement];
    expect(within(first).getByTestId("simulation-refuse").textContent).toBe("40");
    expect(texts("simulation-kind", first)).toEqual(["40 blocked"]);
    expect(within(first).getByTestId("simulation-clients").textContent).toBe("3");
    expect(within(first).getByTestId("simulation-undecidable").textContent).toBe("310");
    expect(within(first).getByTestId("simulation-already").textContent).toBe("2");

    expect(within(second).getByTestId("simulation-refuse").textContent).toBe("96");
    expect(texts("simulation-kind", second)).toEqual(["96 without a valid signature"]);
    expect(within(second).getByTestId("simulation-already").textContent).toBe("0");

    // The sum, thousands grouped, and each kind that is not zero.
    expect(within(third).getByTestId("simulation-refuse").textContent).toBe("1,184");
    expect(texts("simulation-kind", third)).toEqual(["3 blocked", "1 without a valid signature", "1,180 throttled"]);
    for (const cell of ["simulation-refuse", "simulation-clients", "simulation-undecidable", "simulation-already"]) {
      expect(within(third).getByTestId(cell).className).toMatch(MONO);
    }
  });

  it("lists the routes a Rule would refuse most with method and count, in the order of the result", async () => {
    answers(ran(EXAMPLE_SIMULATION_RESULT, []));
    render(<Screen />);
    await simulate();
    const [first, second] = screen.getAllByTestId("simulation-row") as [HTMLElement, HTMLElement];
    expect(texts("simulation-route", first)).toEqual([
      "DELETE /api/admin/users/:id 17",
      "GET /api/admin/export 13",
      "GET /api/admin/users 10",
    ]);
    expect(texts("simulation-route", second)).toEqual(["POST /api/checkout 96"]);
    for (const route of within(first).getAllByTestId("simulation-route")) expect(route.className).toMatch(MONO);
  });

  it("says so when a Rule would refuse nothing: then it has no routes", async () => {
    const [first] = EXAMPLE_SIMULATION_RESULT.rules;
    if (!first) throw new Error("no row");
    const idle = {
      ...first,
      matched: 0,
      would_block: 0,
      already_refused: 0,
      clients_affected: 0,
      sample_routes: [],
    };
    answers(
      ran({
        ...EXAMPLE_SIMULATION_RESULT,
        rules: [idle],
        totals: { would_refuse: 0, clients_affected: 0, unknown_client_events: 0 },
      }),
    );
    render(<Screen />);
    await simulate();
    const row = screen.getByTestId("simulation-row");
    expect(within(row).getByTestId("simulation-refuse").textContent).toBe("0");
    expect(texts("simulation-kind", row)).toEqual([]);
    expect(within(row).getByTestId("simulation-routes").textContent).toBe("No requests would be refused");
  });

  it("gives the totals, and what could not be judged against at least one Rule", async () => {
    answers(ran());
    render(<Screen />);
    await simulate();
    expect(screen.getByTestId("simulation-totals").textContent).toBe(
      "In total these Rules would refuse 1,300 requests from 15 clients.",
    );
    expect(screen.getByTestId("simulation-undecidable-events").textContent).toBe(
      "325 requests could not be judged against at least one Rule.",
    );
  });

  it("says the totals in the singular, and nothing about judging when every request could be judged", async () => {
    answers(
      ran(
        result({ undecidable_events: 0, totals: { would_refuse: 1, clients_affected: 1, unknown_client_events: 0 } }),
      ),
    );
    render(<Screen />);
    await simulate();
    expect(screen.getByTestId("simulation-totals").textContent).toBe(
      "In total these Rules would refuse 1 request from 1 client.",
    );
    expect(screen.queryByTestId("simulation-undecidable-events")).toBeNull();
  });

  it("explains on one line each what the simulation leaves out, and nothing about the period when it is whole", async () => {
    answers(ran());
    render(<Screen />);
    await simulate();
    expect(texts("simulation-note")).toEqual([
      "Virtual patches are not simulated.",
      "Blocks on individual clients are not simulated.",
      "Requests whose path Shield decodes or resolves differently may be missed.",
      "Limits per device are a lower bound: recorded requests carry no device.",
      "Whether Shield checks request bodies on your routes is not known to the simulation.",
      "Requests Shield could not deliver, or that were still open when the simulation ran, are not included.",
      "Shield may forget counters when it holds too many clients; the simulation does not.",
      "If Shield uses your own counter store, its counting may differ.",
      "Clock changes or pauses on your server can shift counts by a few milliseconds.",
    ]);
  });

  it("notes a period that was cut short, and shows what it does not know of not_simulated as it came", async () => {
    answers(ran(result({ truncated: true, not_simulated: ["patches", "canaries"] })));
    render(<Screen />);
    await simulate();
    expect(texts("simulation-note")).toEqual([
      "The period was cut short: only the most recent requests were replayed.",
      "Virtual patches are not simulated.",
      "Not simulated: canaries",
    ]);
  });

  it("says for how many refused requests the clients are unknown, per Rule and in total, and why", async () => {
    const simulation = result({ not_simulated: [] });
    const [first, second] = simulation.rules;
    if (!first || !second) throw new Error("two rows");
    answers(
      ran({
        ...simulation,
        rules: [first, { ...second, clients_affected: 0, unknown_client_events: 1_260 }],
        totals: { would_refuse: 1_300, clients_affected: 3, unknown_client_events: 1_260 },
      }),
    );
    render(<Screen />);
    await simulate();
    const [known, unknown] = screen.getAllByTestId("simulation-row") as [HTMLElement, HTMLElement];
    expect(within(known).queryByTestId("simulation-unknown")).toBeNull();
    expect(within(unknown).getByTestId("simulation-clients").textContent).toBe("0");
    expect(within(unknown).getByTestId("simulation-unknown").textContent).toBe("Clients unknown for 1,260 requests");
    expect(screen.getByTestId("simulation-totals").textContent).toBe(
      "In total these Rules would refuse 1,300 requests from 3 clients.",
    );
    expect(screen.getByTestId("simulation-unknown-total").textContent).toBe("Clients unknown for 1,260 requests.");
    expect(texts("simulation-note")).toEqual(["Shield has no actor key, so clients cannot be told apart."]);
  });

  it("says nothing about unknown clients when every refused request has one", async () => {
    answers(ran(result({ not_simulated: [] })));
    render(<Screen />);
    await simulate();
    expect(screen.queryByTestId("simulation-unknown")).toBeNull();
    expect(screen.queryByTestId("simulation-unknown-total")).toBeNull();
    expect(texts("simulation-note")).toEqual([]);
  });

  it("shows an empty state, and no table, when no request was recorded", async () => {
    answers(
      ran(
        result({
          events: 0,
          undecidable_events: 0,
          rules: result().rules.map((row) => ({
            ...row,
            matched: 0,
            would_block: 0,
            already_refused: 0,
            undecidable: 0,
            clients_affected: 0,
            sample_routes: [],
          })),
          totals: { would_refuse: 0, clients_affected: 0, unknown_client_events: 0 },
        }),
      ),
    );
    render(<Screen />);
    await simulate();
    const panel = screen.getByTestId("simulation-result");
    expect(within(panel).getByTestId("simulation-empty").textContent).toBe(
      "No requests were recorded in the last 24 hours, so there is nothing to estimate. Send requests through Shield, then simulate again.",
    );
    expect(within(panel).queryByRole("table")).toBeNull();
    expect(within(panel).queryByTestId("simulation-totals")).toBeNull();
    expect(within(panel).getByTestId("simulation-caption")).toBeTruthy();
    // The promise points at limits listed below the figures: with no figures it is not shown.
    expect(within(panel).queryByTestId("simulation-promise")).toBeNull();
  });

  it("says clearly when there were too many simulations, as an alert, and shows no figures", async () => {
    answers({
      ok: false,
      withDraft: false,
      errors: [{ path: "", message: "Too many simulations. Try again in 42 s." }],
    });
    render(<Screen />);
    await simulate();
    const error = screen.getByTestId("simulation-error");
    expect(error.getAttribute("role")).toBe("alert");
    expect(error.textContent).toBe("Too many simulations. Try again in 42 s.");
    expect(screen.queryByRole("table", { name: /Simulation/ })).toBeNull();
    expect(screen.queryByTestId("simulation-caption")).toBeNull();
    expect(document.activeElement).toBe(screen.getByTestId("simulation-result"));
  });

  it("keeps the last successful result after a later failure, with the error above it", async () => {
    answers(ran());
    render(<Screen />);
    await simulate();
    expect(screen.getAllByTestId("simulation-row")).toHaveLength(2);
    answers({
      ok: false,
      withDraft: false,
      errors: [{ path: "", message: "Too many simulations. Try again in 9 s." }],
    });
    await simulate();
    const panel = screen.getByTestId("simulation-result");
    expect(document.activeElement).toBe(panel);
    const error = within(panel).getByTestId("simulation-error");
    expect(error.textContent).toBe("Too many simulations. Try again in 9 s.");
    expect(within(panel).getAllByTestId("simulation-row")).toHaveLength(2);
    const caption = within(panel).getByTestId("simulation-caption");
    // The error comes first: it is read before the figures of the earlier run.
    expect(error.compareDocumentPosition(caption) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(panel).getByTestId("simulation-totals").textContent).toBe(
      "In total these Rules would refuse 1,300 requests from 15 clients.",
    );
  });

  it("drops the error again with the next successful simulation", async () => {
    answers({
      ok: false,
      withDraft: false,
      errors: [{ path: "", message: "Too many simulations. Try again in 9 s." }],
    });
    render(<Screen />);
    await simulate();
    answers(ran());
    await simulate();
    expect(screen.queryByTestId("simulation-error")).toBeNull();
    expect(screen.getAllByTestId("simulation-row")).toHaveLength(2);
  });
});

describe("Simulate with this Rule", () => {
  const typed = { name: "Login", path: "/login", methods: ["POST"], requires: false };

  it("sends the Rule being typed with simulate=draft to the simulation, and never to the publish", async () => {
    answers(ran());
    render(<Screen />);
    fireEvent.change(screen.getByLabelText("Rule name"), { target: { value: "Login" } });
    fireEvent.change(screen.getByLabelText("Path pattern"), { target: { value: "/login" } });
    fireEvent.click(screen.getByLabelText("POST"));
    const button = screen.getByRole("button", { name: "Simulate with this Rule" });
    expect(document.getElementById(button.getAttribute("aria-describedby") ?? "")?.textContent).toBe(
      "Replays the current Rules plus this one. Nothing is published.",
    );
    await submit(button);
    expect(actions.publishRuleAction).not.toHaveBeenCalled();
    expect(actions.simulatePolicyAction).toHaveBeenCalledTimes(1);
    expect(sent()).toEqual({
      appId: [appId],
      environment: ["production"],
      expectedVersion: ["3"],
      name: ["Login"],
      path: ["/login"],
      methods: ["POST"],
      action: ["block"],
      simulate: ["draft"],
    });
  });

  it("still adds the Rule with Add Rule, without the simulate field", async () => {
    render(<Screen />);
    await submit(screen.getByRole("button", { name: "Add Rule" }));
    expect(actions.simulatePolicyAction).not.toHaveBeenCalled();
    const data = vi.mocked(actions.publishRuleAction).mock.calls.at(-1)?.[1];
    expect(data && fieldsOf(data).simulate).toBeUndefined();
  });

  it("shows the result with the typed Rule marked as not published, and keeps what was typed", async () => {
    const [first] = EXAMPLE_SIMULATION_RESULT.rules;
    if (!first) throw new Error("no row");
    const { id: _id, ...plain } = first;
    const simulation = result();
    const withDraft = { ...simulation, rules: [...simulation.rules, { ...plain, index: 2, name: "Login" }] };
    answers({ ok: true, withDraft: true, simulation: withDraft, rules: ["a", "b", "c"], values: typed });
    render(<Screen />);
    await submit(screen.getByRole("button", { name: "Simulate with this Rule" }));
    const rows = screen.getAllByTestId("simulation-row");
    expect(rows).toHaveLength(3);
    expect(rows.map((row) => within(row).queryByTestId("simulation-draft")?.textContent ?? null)).toEqual([
      null,
      null,
      "Not published",
    ]);
    expect(document.activeElement).toBe(screen.getByTestId("simulation-result"));
    expect((screen.getByLabelText("Rule name") as HTMLInputElement).value).toBe("Login");
    expect((screen.getByLabelText("Path pattern") as HTMLInputElement).value).toBe("/login");
    expect((screen.getByLabelText("POST") as HTMLInputElement).checked).toBe(true);
    expect(screen.queryByTestId("error-summary")).toBeNull();
  });

  it("shows a refusal of the typed Rule in the form's summary and below its field, and no result", async () => {
    answers({
      ok: false,
      withDraft: true,
      errors: [{ path: "path", message: "Enter a path pattern." }],
      values: { ...typed, path: "" },
    });
    render(<Screen />);
    await submit(screen.getByRole("button", { name: "Simulate with this Rule" }));
    const summary = screen.getByTestId("error-summary");
    expect(document.activeElement).toBe(summary);
    expect(within(summary).getByRole("link", { name: "Path pattern: Enter a path pattern." })).toBeTruthy();
    expect(screen.getByLabelText("Path pattern").getAttribute("aria-invalid")).toBe("true");
    expect((screen.getByLabelText("Rule name") as HTMLInputElement).value).toBe("Login");
    expect(screen.queryByTestId("simulation-result")).toBeNull();
  });

  it("shows a failure of the simulation itself in the result panel, not as a problem of the form", async () => {
    answers({
      ok: false,
      withDraft: true,
      errors: [{ path: "", message: "Too many simulations. Try again in 42 s." }],
      values: typed,
    });
    render(<Screen />);
    await submit(screen.getByRole("button", { name: "Simulate with this Rule" }));
    expect(screen.getByTestId("simulation-error").textContent).toBe("Too many simulations. Try again in 42 s.");
    expect(screen.queryByTestId("error-summary")).toBeNull();
    expect((screen.getByLabelText("Rule name") as HTMLInputElement).value).toBe("Login");
  });

  it("offers no simulation where the screen keeps none", () => {
    render(<AddRuleForm version={3} appId={appId} environment="production" />);
    expect(screen.queryByRole("button", { name: "Simulate with this Rule" })).toBeNull();
    expect(screen.getByRole("button", { name: "Add Rule" })).toBeTruthy();
  });
});

describe("the promote confirmation after a simulation", () => {
  it("shows that Rule's figures from the latest simulation of this page view", async () => {
    answers(ran());
    const { rerender } = render(<Screen />);
    await simulate();
    // The address now asks for the confirmation step: the same view, rendered again.
    rerender(<Screen confirmRuleId={monitored.id} />);
    const dialog = screen.getByRole("alertdialog");
    const estimate = within(dialog).getByTestId("confirm-estimate");
    expect(estimate.textContent).toBe(
      "Estimate from 09:00 UTC: promoting this Rule would refuse 1,300 requests from 14 clients in the last 24 hours; 330 could not be judged.",
    );
    // It is part of what the dialog is described by.
    expect((dialog.getAttribute("aria-describedby") ?? "").split(" ")).toContain(estimate.id);
  });

  it("shows nothing for a Rule the simulation says nothing about promoting", async () => {
    const simulation = result();
    const rows = simulation.rules.map(({ if_promoted: _dropped, ...row }) => row);
    answers(ran({ ...simulation, rules: rows }));
    const { rerender } = render(<Screen />);
    await simulate();
    rerender(<Screen confirmRuleId={monitored.id} />);
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(screen.queryByTestId("confirm-estimate")).toBeNull();
  });

  it("adds for how many requests the clients are unknown", async () => {
    const simulation = result();
    const rows = simulation.rules.map((row) =>
      row.if_promoted
        ? { ...row, if_promoted: { ...row.if_promoted, clients_affected: 2, unknown_client_events: 40 } }
        : row,
    );
    answers(ran({ ...simulation, rules: rows }));
    const { rerender } = render(<Screen />);
    await simulate();
    rerender(<Screen confirmRuleId={monitored.id} />);
    expect(screen.getByTestId("confirm-estimate").textContent).toBe(
      "Estimate from 09:00 UTC: promoting this Rule would refuse 1,300 requests from 2 clients in the last 24 hours; 330 could not be judged. Clients unknown for 40 requests.",
    );
  });

  it("shows nothing when no simulation ran", () => {
    render(<Screen confirmRuleId={monitored.id} />);
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(screen.queryByTestId("confirm-estimate")).toBeNull();
  });

  it("shows nothing when the Rule changed since the simulation", async () => {
    answers(ran());
    const { rerender } = render(<Screen />);
    await simulate();
    const changed = { ...monitored, path: "/api/users/**" };
    rerender(<Screen current={[enforced, changed]} confirmRuleId={monitored.id} />);
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(screen.queryByTestId("confirm-estimate")).toBeNull();
  });

  it("shows nothing after a simulation that failed", async () => {
    answers({
      ok: false,
      withDraft: false,
      errors: [{ path: "", message: "Too many simulations. Try again in 42 s." }],
    });
    const { rerender } = render(<Screen />);
    await simulate();
    rerender(<Screen confirmRuleId={monitored.id} />);
    expect(screen.queryByTestId("confirm-estimate")).toBeNull();
  });

  it("keeps showing the estimate of the last successful simulation after a later one failed", async () => {
    answers(ran());
    const { rerender } = render(<Screen />);
    await simulate();
    answers({
      ok: false,
      withDraft: false,
      errors: [{ path: "", message: "Too many simulations. Try again in 42 s." }],
    });
    await simulate();
    rerender(<Screen confirmRuleId={monitored.id} />);
    expect(screen.getByTestId("confirm-estimate").textContent).toBe(
      "Estimate from 09:00 UTC: promoting this Rule would refuse 1,300 requests from 14 clients in the last 24 hours; 330 could not be judged.",
    );
  });

  it("shows nothing from a simulation with the Rule being typed: only one of exactly the current Rules counts", async () => {
    const [first] = EXAMPLE_SIMULATION_RESULT.rules;
    if (!first) throw new Error("no row");
    const { id: _id, ...plain } = first;
    const simulation = result();
    answers({
      ok: true,
      withDraft: true,
      simulation: { ...simulation, rules: [...simulation.rules, { ...plain, index: 2, name: "Login" }] },
      rules: [...rules.map(ruleFingerprint), ruleFingerprint({ name: "Login", path: "/login", methods: ["POST"] })],
      values: { name: "Login", path: "/login", methods: ["POST"], requires: false },
    });
    const { rerender } = render(<Screen />);
    await submit(screen.getByRole("button", { name: "Simulate with this Rule" }));
    expect(screen.getAllByTestId("simulation-row")).toHaveLength(3);
    rerender(<Screen confirmRuleId={monitored.id} />);
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(screen.queryByTestId("confirm-estimate")).toBeNull();
  });

  it("shows nothing when another Rule of the Policy changed since the simulation", async () => {
    answers(ran());
    const { rerender } = render(<Screen />);
    await simulate();
    rerender(<Screen current={[{ ...enforced, path: "/api/other/**" }, monitored]} confirmRuleId={monitored.id} />);
    expect(screen.queryByTestId("confirm-estimate")).toBeNull();
  });

  it("says so in the estimate when the period was cut short", async () => {
    answers(ran(result({ truncated: true })));
    const { rerender } = render(<Screen />);
    await simulate();
    rerender(<Screen confirmRuleId={monitored.id} />);
    expect(screen.getByTestId("confirm-estimate").textContent).toBe(
      "Estimate from 09:00 UTC: promoting this Rule would refuse 1,300 requests from 14 clients in the last 24 hours; 330 could not be judged. The period was cut short: only the most recent requests were replayed.",
    );
  });

  it("shows no estimate outside a screen that keeps a simulation", () => {
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
    expect(screen.queryByTestId("confirm-estimate")).toBeNull();
  });
});
