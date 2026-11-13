import {
  type Assessment,
  EXAMPLE_ASSESSMENT,
  EXAMPLE_BUILD,
  OBJECTIVES,
  type ObjectiveResult,
} from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/app/actions.ts", () => ({ assessAgainAction: vi.fn(), signOutAction: vi.fn() }));

import * as actions from "@/app/actions.ts";
import { ReverseResistance } from "@/features/assessments/reverse-resistance.tsx";
import { BuildDetail } from "@/features/builds/build-detail.tsx";

// Slice 12a, UIUX SCR-07: the Build page's "Reverse resistance" section — the latest Assessment as an RRS meter
// with its scope line, or "Inconclusive: <reason>" and never a number; its Objective rows; and the history.

const MONO = /\bcode-[1-3]\b/;
const STAND_IN_NOTE =
  "Scored by a scripted stand in, not an AI adversary. It checks the pipeline, not real resistance.";

// The protocol's example: an inconclusive T1 run of the stand-in agent (W2 achieved, W3/W4 not supported).
const inconclusive: Assessment = EXAMPLE_ASSESSMENT;

// A scored, renormalised T2 run of a model agent: W1 achieved within T2 limits, W4 not attempted; RRS 64.
const scoredResults: ObjectiveResult[] = [
  {
    objective: "W1",
    result: "achieved",
    tier: "T2",
    cost: { calls: 412, seconds: 1830 },
    evidence: {
      summary: "Recovered 14 route templates from the router table.",
      recovered: [{ kind: "routes", matched: 7, submitted: 14, inventory: 8 }],
      calls: [118],
    },
  },
  {
    objective: "W2",
    result: "not_achieved",
    cost: { calls: 1500, seconds: 6900 },
    evidence: {
      summary: "Submitted one string the leak scan had reported.",
      recovered: [{ kind: "leak", rule: "aws-access-key", fingerprint: "9f2c4e7a1b3d5f60718293a4b5c6d7e8" }],
      calls: [],
    },
  },
  {
    objective: "W3",
    result: "not_achieved",
    cost: { calls: 1500, seconds: 6900 },
    evidence: { summary: "The lifted function gave different answers.", recovered: [], calls: [] },
  },
  {
    objective: "W4",
    result: "not_attempted",
    reason: "tool_failure",
    evidence: { summary: "The code runner failed before the attempt.", recovered: [], calls: [] },
  },
  {
    objective: "W5",
    result: "not_achieved",
    cost: { calls: 1500, seconds: 6900 },
    evidence: {
      summary: "Replayed POST /api/checkout; the replica refused it.",
      recovered: [{ kind: "replay", status: 403 }],
      calls: [],
    },
  },
];
const scored: Assessment = {
  ...EXAMPLE_ASSESSMENT,
  id: "asm_aaaaaaaaaaaaaaaaaaaaaaaa",
  tier: "T2",
  status: "scored",
  results: scoredResults,
  rrs: 64,
  inconclusive_reason: null,
  inconclusive_code: null,
  renormalised: true,
  scope: { agent: { name: "adversary", version: "0.2.0" }, model: "example-model-1", toolbelt: "0.1.0", tier: "T2" },
  created_at: "2026-11-12T08:00:00.000Z",
  started_at: "2026-11-12T08:00:01.000Z",
  finished_at: "2026-11-12T10:00:00.000Z",
};
const pending = {
  ...EXAMPLE_ASSESSMENT,
  results: [],
  rrs: null,
  inconclusive_reason: null,
  inconclusive_code: null,
  renormalised: false,
  finished_at: null,
} satisfies Assessment;
const queued: Assessment = { ...pending, id: "asm_bbbbbbbbbbbbbbbbbbbbbbbb", status: "queued", started_at: null };
const running: Assessment = { ...pending, id: "asm_cccccccccccccccccccccccc", status: "running" };
const failed: Assessment = {
  ...pending,
  id: "asm_dddddddddddddddddddddddd",
  status: "failed",
  results: EXAMPLE_ASSESSMENT.results.filter((result) => result.objective === "W2"),
  finished_at: "2026-11-13T08:00:41.000Z",
  failure_reason: "The code runner stopped: the worker ran out of memory.",
};

const row = (objective: string): HTMLElement => {
  const found = screen
    .getAllByTestId("objective-row")
    .find((element) => element.getAttribute("data-objective") === objective);
  if (!found) throw new Error(`no row for ${objective}`);
  return found;
};

describe("ReverseResistance — score", () => {
  it("shows the RRS as a bullet meter on 0 to 100 with no threshold marker, and the scope line beneath", () => {
    render(<ReverseResistance assessments={[scored, inconclusive]} />);
    const section = screen.getByRole("region", { name: "Reverse resistance" });
    const meter = within(section).getByTestId("rrs-meter");
    expect(within(meter).getByTestId("rrs-value").textContent).toBe("64");
    expect(within(meter).getByTestId("rrs-value").className).toMatch(MONO);
    expect(within(meter).getByTestId("rrs-fill").style.width).toBe("64%");
    expect(within(meter).queryByTestId("rrs-threshold")).toBeNull();
    expect(within(meter).getByTestId("rrs-scale").textContent).toBe("0100");
    expect(within(section).getByTestId("rrs-summary").textContent).toBe("This Build scored 64 of 100 at tier T2.");
    expect(within(section).getByTestId("assessment-scope").textContent).toBe(
      "Measured by adversary 0.2.0 · model example-model-1 · toolbelt 0.1.0 · tier T2",
    );
    expect(within(section).getByTestId("assessment-renormalised").textContent).toBe(
      "Renormalised: the Objectives not attempted are left out and the weights of the others scaled to sum to 1.",
    );
    // A model agent: no stand-in note.
    expect(within(section).queryByTestId("assessment-stand-in")).toBeNull();
    expect(within(section).queryByTestId("assessment-inconclusive")).toBeNull();
  });

  it("leaves the renormalised note out when every Objective was attempted", () => {
    render(<ReverseResistance assessments={[{ ...scored, renormalised: false }]} />);
    expect(screen.queryByTestId("assessment-renormalised")).toBeNull();
  });

  it("says Inconclusive with the reason and never shows a number", () => {
    render(<ReverseResistance assessments={[inconclusive]} />);
    expect(screen.getByTestId("assessment-inconclusive").textContent).toBe(
      `Inconclusive: ${inconclusive.inconclusive_reason}`,
    );
    expect(screen.queryByTestId("rrs-meter")).toBeNull();
    expect(screen.queryByTestId("rrs-value")).toBeNull();
    expect(screen.queryByTestId("rrs-summary")).toBeNull();
    // The scope line is still shown: the reason belongs to this agent and tier.
    expect(screen.getByTestId("assessment-scope").textContent).toBe(
      "Measured by stand-in 0.1.0 · model stand-in · toolbelt 0.1.0 · tier T1",
    );
  });

  it("says plainly when the stand-in agent scored it", () => {
    render(<ReverseResistance assessments={[inconclusive]} />);
    expect(screen.getByTestId("assessment-stand-in").textContent).toBe(STAND_IN_NOTE);
  });

  it("shows a queued or running Assessment by its status and time, with no rows and no number", () => {
    const { unmount } = render(<ReverseResistance assessments={[queued]} />);
    expect(screen.getByTestId("assessment-progress").textContent).toBe("Queued since 2026-11-13 08:00:00 UTC");
    expect(screen.queryByTestId("objective-row")).toBeNull();
    expect(screen.queryByTestId("rrs-meter")).toBeNull();
    unmount();
    render(<ReverseResistance assessments={[running]} />);
    expect(screen.getByTestId("assessment-progress").textContent).toBe("Running since 2026-11-13 08:00:01 UTC");
    expect(screen.getByTestId("assessment-progress").getAttribute("data-status")).toBe("running");
  });

  it("shows a failed Assessment's reason and the results it reached, never a number", () => {
    render(<ReverseResistance assessments={[failed]} />);
    expect(screen.getByTestId("assessment-failed").textContent).toBe(
      "Failed: The code runner stopped: the worker ran out of memory.",
    );
    expect(screen.getByTestId("assessment-partial").textContent).toBe("Results reached before the failure");
    expect(screen.getAllByTestId("objective-row").map((element) => element.getAttribute("data-objective"))).toEqual([
      "W2",
    ]);
    expect(screen.queryByTestId("rrs-meter")).toBeNull();
  });

  it("explains an empty section and an unreadable one", () => {
    const { unmount } = render(<ReverseResistance assessments={[]} />);
    expect(screen.getByTestId("assessment-empty").textContent).toBe(
      "No Assessment of this Build yet. Run Harden with --register --assess to measure how it resists reverse engineering.",
    );
    unmount();
    render(<ReverseResistance assessments={null} />);
    expect(screen.getByTestId("assessment-unavailable").textContent).toBe(
      "The Assessments could not be loaded. Reload the page to try again.",
    );
  });
});

describe("ReverseResistance — Objective rows", () => {
  it("lists the Objectives in order with name, weight, result, cost and evidence", () => {
    render(<ReverseResistance assessments={[scored]} />);
    const table = screen.getByRole("table", { name: "Objectives of the latest Assessment" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual(["Objective", "Result", "Cost", "Evidence"]);
    expect(screen.getAllByTestId("objective-row").map((element) => element.getAttribute("data-objective"))).toEqual(
      OBJECTIVES.map((objective) => objective.id),
    );
    const map = within(row("W1"));
    expect(map.getByTestId("objective-name").textContent).toBe("Map");
    expect(map.getByTestId("objective-weight").textContent).toBe("W1 · weight 15");
    expect(map.getByTestId("objective-cost").textContent).toBe("412 calls · 30.5 min");
    expect(map.getByTestId("objective-summary").textContent).toBe(
      "Recovered 14 route templates from the router table.",
    );
    expect(within(row("W2")).getByTestId("objective-cost").textContent).toBe("1,500 calls · 1.9 h");
    expect(within(row("W4")).getByTestId("objective-cost").textContent).toBe("—");
  });

  it("marks an achieved Objective in the warning style with its tier: the attacker got it", () => {
    render(<ReverseResistance assessments={[scored]} />);
    const chip = within(row("W1")).getByTestId("objective-result");
    expect(chip.textContent).toBe("Achieved at T2");
    expect(chip.getAttribute("data-result")).toBe("achieved");
    expect(chip.className).toMatch(/text-sev-high/);
    expect(chip.querySelector("svg")).not.toBeNull();
    const held = within(row("W3")).getByTestId("objective-result");
    expect(held.textContent).toBe("Not achieved");
    expect(held.className).toMatch(/text-primary/);
    const skipped = within(row("W4")).getByTestId("objective-result");
    expect(skipped.textContent).toBe("Not attempted: tool failure");
    expect(skipped.className).toMatch(/text-fg-muted/);
  });

  it("gives the reason of every Objective not attempted", () => {
    render(<ReverseResistance assessments={[inconclusive]} />);
    expect(within(row("W3")).getByTestId("objective-result").textContent).toBe(
      "Not attempted: not supported in this version",
    );
  });

  it("names what was recovered by id, shortened fingerprint, counts and status, never a value", () => {
    const { unmount } = render(<ReverseResistance assessments={[scored]} />);
    expect(within(row("W1")).getByTestId("recovered-item").textContent).toBe("Routes matched 7 of 8");
    const leak = within(row("W2")).getByTestId("recovered-item");
    expect(leak.textContent).toBe("Leak aws-access-key 9f2c4e7a1b3d");
    expect(leak.className).toMatch(MONO);
    expect(within(row("W5")).getByTestId("recovered-item").textContent).toBe("Replica answered 403");
    unmount();
    render(<ReverseResistance assessments={[inconclusive]} />);
    expect(within(row("W2")).getByTestId("recovered-item").textContent).toBe("Canary cny_33d265fca16c848eb2f23f43");
    expect(document.body.textContent).not.toMatch(/ak_live_/);
  });

  it("suggests the Objective's fix only where it was achieved", () => {
    render(<ReverseResistance assessments={[scored]} />);
    const fix = OBJECTIVES.find((objective) => objective.id === "W1")?.fix;
    expect(within(row("W1")).getByTestId("objective-fix").textContent).toBe(`Fix: ${fix}`);
    for (const id of ["W2", "W3", "W4", "W5"]) expect(within(row(id)).queryByTestId("objective-fix")).toBeNull();
  });
});

describe("ReverseResistance — history", () => {
  it("lists every Assessment of the Build, newest first, with status, tier, score and date", () => {
    render(<ReverseResistance assessments={[running, scored, inconclusive, failed]} />);
    const table = screen.getByRole("table", { name: "Assessments of this Build, newest first" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual(["Created", "Tier", "Status", "Score"]);
    const rows = within(table).getAllByTestId("history-row");
    expect(
      rows.map((element) => [
        within(element).getByTestId("history-created").textContent,
        within(element).getByTestId("history-tier").textContent,
        within(element).getByTestId("history-status").textContent,
        within(element).getByTestId("history-score").textContent,
      ]),
    ).toEqual([
      ["2026-11-13 08:00:00", "T1", "Running", "—"],
      ["2026-11-12 08:00:00", "T2", "Scored", "64"],
      ["2026-11-13 08:00:00", "T1", "Inconclusive", "Inconclusive"],
      ["2026-11-13 08:00:00", "T1", "Failed", "—"],
    ]);
  });
});

describe("BuildDetail — Reverse resistance", () => {
  it("shows the section when the Assessments were loaded, and leaves it out otherwise", () => {
    const build = { ...EXAMPLE_BUILD };
    const { unmount } = render(<BuildDetail build={build} appName="shop-web" assessments={[inconclusive]} />);
    expect(screen.getByRole("region", { name: "Reverse resistance" })).toBeTruthy();
    unmount();
    render(<BuildDetail build={build} appName="shop-web" />);
    expect(screen.queryByRole("region", { name: "Reverse resistance" })).toBeNull();
  });
});

describe("ReverseResistance — Assess again", () => {
  // The example's artifact is kept until 2026-12-13 08:02:00 UTC.
  const BEFORE = Date.parse("2026-11-13T10:00:00.000Z");
  const AFTER = Date.parse("2026-12-14T00:00:00.000Z");
  const queuedAgain: Assessment = {
    ...queued,
    id: "asm_ffffffffffffffffffffffff",
    tier: "T2",
    scope: { ...queued.scope, tier: "T2" },
  };

  beforeEach(() => vi.mocked(actions.assessAgainAction).mockReset());

  const submit = async (): Promise<void> => {
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Assess again" }));
    });
  };
  const sent = (): Record<string, string> => {
    const data = vi.mocked(actions.assessAgainAction).mock.calls.at(-1)?.[1];
    if (!data) throw new Error("the action was not called");
    return Object.fromEntries([...data.entries()].map(([name, value]) => [name, String(value)]));
  };

  it("offers a tier choice with each tier's budget while the latest artifact is kept", () => {
    render(<ReverseResistance assessments={[inconclusive]} now={BEFORE} />);
    const tier = screen.getByLabelText("Tier") as HTMLSelectElement;
    expect([...tier.options].map((option) => [option.value, option.textContent])).toEqual([
      ["T1", "T1 · 150 calls · 15 min"],
      ["T2", "T2 · 1,500 calls · 2 h"],
      ["T3", "T3 · 6,000 calls · 8 h"],
    ]);
    expect(tier.value).toBe("T1");
    expect(screen.getByTestId("assess-again").textContent).toContain(
      "The bundle uploaded for this Build is assessed again; it is kept until 2026-12-13 08:02:00 UTC. A higher tier gives the attacker a larger budget.",
    );
  });

  it("does not offer it while the latest Assessment is queued or running", () => {
    for (const active of [queued, running]) {
      const { unmount } = render(<ReverseResistance assessments={[active, inconclusive]} now={BEFORE} />);
      expect(Date.parse(active.artifact_kept_until ?? "")).toBeGreaterThan(BEFORE);
      expect(screen.queryByRole("button", { name: "Assess again" })).toBeNull();
      unmount();
    }
  });

  it("does not offer it once the artifact's date has passed or it was deleted", () => {
    const { unmount } = render(<ReverseResistance assessments={[inconclusive]} now={AFTER} />);
    expect(screen.queryByRole("button", { name: "Assess again" })).toBeNull();
    unmount();
    render(<ReverseResistance assessments={[{ ...inconclusive, artifact_kept_until: null }, scored]} now={BEFORE} />);
    expect(screen.queryByRole("button", { name: "Assess again" })).toBeNull();
  });

  it("sends the Build and the chosen tier, then shows the queued Assessment", async () => {
    vi.mocked(actions.assessAgainAction).mockResolvedValueOnce({ ok: true, assessment: queuedAgain });
    render(<ReverseResistance assessments={[inconclusive]} now={BEFORE} />);
    fireEvent.change(screen.getByLabelText("Tier"), { target: { value: "T2" } });
    await submit();
    expect(sent()).toEqual({ appId: inconclusive.app_id, buildId: inconclusive.build_id, tier: "T2" });
    expect(screen.getByTestId("assess-again-queued").textContent).toBe(
      "Assessment asm_ffffffffffffffffffffffff is queued at tier T2.",
    );
  });

  it("says the bundle is no longer kept when the API refuses with artifact-required", async () => {
    const message = "The uploaded bundle is no longer kept. Run Harden with --assess to upload it again.";
    vi.mocked(actions.assessAgainAction).mockResolvedValueOnce({ ok: false, errors: [{ path: "", message }] });
    render(<ReverseResistance assessments={[inconclusive]} now={BEFORE} />);
    await submit();
    expect(screen.getByTestId("error-summary").textContent).toContain(message);
    expect(screen.queryByTestId("assess-again-queued")).toBeNull();
  });
});

// Slice 12b: W3 Logic and W4 Tamper are decided, so a stand-in run is scored. A T1 run with every Objective
// attempted: W2 and W4 achieved within T1 limits, the rest held — RRS 24, not renormalised.
const decided: ObjectiveResult[] = [
  ...EXAMPLE_ASSESSMENT.results.filter((result) => result.objective === "W1" || result.objective === "W2"),
  {
    objective: "W3",
    result: "not_achieved",
    cost: { calls: 150, seconds: 840 },
    evidence: {
      summary: "Submitted a reimplementation of price-total; 2 of 40 hidden vectors passed.",
      recovered: [],
      calls: [88, 120],
    },
  },
  {
    objective: "W4",
    result: "achieved",
    tier: "T1",
    cost: { calls: 31, seconds: 9.5 },
    evidence: {
      summary: "Edited dist/index.js; the edited file ran and set the marker.",
      recovered: [],
      calls: [30],
    },
  },
  ...EXAMPLE_ASSESSMENT.results.filter((result) => result.objective === "W5"),
];
const scoredStandIn: Assessment = {
  ...EXAMPLE_ASSESSMENT,
  id: "asm_121212121212121212121212",
  status: "scored",
  results: decided,
  rrs: 24,
  inconclusive_reason: null,
  inconclusive_code: null,
  renormalised: false,
};
const W3_HINT = "Designate a protected function with Harden's --logic file to assess Logic.";

describe("ReverseResistance — slice 12b, Logic and Tamper", () => {
  it("shows a scored stand-in run with the meter, the scope line, the stand-in note and all five rows", () => {
    render(<ReverseResistance assessments={[scoredStandIn]} />);
    expect(screen.getByTestId("rrs-value").textContent).toBe("24");
    expect(screen.getByTestId("assessment-scope").textContent).toBe(
      "Measured by stand-in 0.1.0 · model stand-in · toolbelt 0.1.0 · tier T1",
    );
    expect(screen.getByTestId("assessment-stand-in")).toBeTruthy();
    expect(screen.queryByTestId("assessment-renormalised")).toBeNull();
    expect(screen.getAllByTestId("objective-row").map((element) => element.getAttribute("data-objective"))).toEqual([
      "W1",
      "W2",
      "W3",
      "W4",
      "W5",
    ]);
    expect(within(row("W3")).getByTestId("objective-result").textContent).toBe("Not achieved");
    expect(within(row("W4")).getByTestId("objective-result").textContent).toBe("Achieved at T1");
  });

  it("names the edited file as W4's evidence, and nothing else", () => {
    render(<ReverseResistance assessments={[scoredStandIn]} />);
    const tamper = within(row("W4"));
    expect(tamper.getByTestId("objective-summary").textContent).toBe(
      "Edited dist/index.js; the edited file ran and set the marker.",
    );
    expect(tamper.queryByTestId("recovered-item")).toBeNull();
  });

  it("suggests the Logic and Tamper fixes where they were achieved", () => {
    const logicAchieved: ObjectiveResult = {
      objective: "W3",
      result: "achieved",
      tier: "T1",
      cost: { calls: 120, seconds: 600 },
      evidence: { summary: "Reimplemented price-total; 40 of 40 hidden vectors passed.", recovered: [], calls: [119] },
    };
    const results = decided.map((result) => (result.objective === "W3" ? logicAchieved : result));
    render(<ReverseResistance assessments={[{ ...scoredStandIn, results, rrs: 14 }]} />);
    // One source of truth: the protocol's fix text, as for every Objective.
    for (const id of ["W3", "W4"]) {
      const fix = OBJECTIVES.find((objective) => objective.id === id)?.fix;
      expect(within(row(id)).getByTestId("objective-fix").textContent).toBe(`Fix: ${fix}`);
    }
  });

  it("names a missing JavaScript file when Tamper was not attempted for want of one", () => {
    const noRunnable: ObjectiveResult = {
      objective: "W4",
      result: "not_attempted",
      reason: "no_runnable_file",
      evidence: { summary: "The artifact has no JavaScript file to run.", recovered: [], calls: [] },
    };
    const results = decided.map((result) => (result.objective === "W4" ? noRunnable : result));
    render(<ReverseResistance assessments={[{ ...scoredStandIn, results }]} />);
    expect(within(row("W4")).getByTestId("objective-result").textContent).toBe(
      "Not attempted: no JavaScript file to run",
    );
  });

  it("tells how to designate a protected function when Logic was not attempted for want of one", () => {
    const notDesignated: ObjectiveResult = {
      objective: "W3",
      result: "not_attempted",
      reason: "not_designated",
      evidence: { summary: "No protected function was designated for this Build.", recovered: [], calls: [] },
    };
    const results = decided.map((result) => (result.objective === "W3" ? notDesignated : result));
    render(
      <ReverseResistance
        assessments={[
          {
            ...scoredStandIn,
            status: "inconclusive",
            results,
            rrs: null,
            inconclusive_code: "excluded_over_limit",
            inconclusive_reason:
              "25% of the Objective weight was not attempted (W3 Logic: no protected function was designated (add --logic to Harden)); a score needs at most 20%.",
          },
        ]}
      />,
    );
    const logic = within(row("W3"));
    expect(logic.getByTestId("objective-result").textContent).toBe("Not attempted: no protected function designated");
    expect(logic.getByTestId("objective-hint").textContent).toBe(W3_HINT);
    expect(logic.getByTestId("objective-hint").querySelector("code")?.textContent).toBe("--logic");
    // Only W3's want of a designated function gets the hint.
    for (const id of ["W1", "W2", "W4", "W5"]) expect(within(row(id)).queryByTestId("objective-hint")).toBeNull();
  });
});
