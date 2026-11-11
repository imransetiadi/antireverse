import { EXAMPLE_STORED_EVENT } from "@antireverse/protocol";
import { act, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RENDER_INTERVAL_MS } from "@/features/live-feed/feed-state.ts";
import { LiveFeed } from "@/features/live-feed/live-feed.tsx";
import { RECONNECT_DELAY_MS } from "@/features/live-feed/use-event-stream.ts";
import { BASE_MS, eventAt } from "./helpers/events.ts";
import { FakeEventSource } from "./helpers/fake-event-source.ts";

const APP_ID = EXAMPLE_STORED_EVENT.app_id;

const fetchMock = vi.fn<typeof fetch>();
const listResponse = (events: unknown[], status = 200): Response =>
  new Response(JSON.stringify({ events }), { status, headers: { "content-type": "application/json" } });
/** Lets the promise of the list request settle under fake timers. */
const settle = async (ms = 0): Promise<void> => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
};

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  fetchMock.mockReset();
  fetchMock.mockImplementation(async () => listResponse([]));
  vi.stubGlobal("fetch", fetchMock);
  vi.useFakeTimers();
  vi.setSystemTime(BASE_MS);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const rows = (): HTMLElement[] => screen.queryAllByTestId("event-row");
const indicator = (): string | null => screen.getByTestId("live-indicator").textContent;
const tick = (ms: number): void => {
  act(() => {
    vi.advanceTimersByTime(ms);
  });
};

function renderFeed(initial = [eventAt(1_000), eventAt(2_000)]) {
  const view = render(<LiveFeed appId={APP_ID} appName="shop-web" initialEvents={initial} />);
  return { ...view, source: FakeEventSource.latest() };
}

describe("LiveFeed — what it shows", () => {
  it("renders the initial Events as rows, newest first, under the nine columns", () => {
    renderFeed([
      eventAt(1_000, { request: { method: "POST", route: "/api/login", status: 401, latency_ms: 0.4 } }),
      eventAt(2_000, { request: { method: "GET", route: "/api/products/:id", status: 200, latency_ms: 3.25 } }),
    ]);
    expect(screen.getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Time UTC",
      "Decision",
      "Client",
      "Signature",
      "Method",
      "Route",
      "Status",
      "Latency",
      "Network",
    ]);
    expect(rows()).toHaveLength(2);
    const [newest, older] = rows().map((row) =>
      within(row)
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    );
    expect(newest).toEqual([
      "08:00:02",
      "AllowedMonitor",
      "Not reported",
      "Not reported",
      "GET",
      "/api/products/:id",
      "200",
      "3 ms",
      "203.0.113.0/24",
    ]);
    expect(older).toEqual([
      "08:00:01",
      "AllowedMonitor",
      "Not reported",
      "Not reported",
      "POST",
      "/api/login",
      "401",
      "<1 ms",
      "203.0.113.0/24",
    ]);
  });

  it("shows the attestation Shield verified for each request in the Client column, with its risk", () => {
    renderFeed([
      eventAt(1_000, { attestation: { status: "missing", verdict: null, risk: null } }),
      eventAt(2_000, { attestation: { status: "valid", verdict: "suspect", risk: 70 } }),
      eventAt(3_000, { attestation: null }),
    ]);
    const chips = rows().map((row) => within(row).getByTestId("attestation-chip"));
    expect(chips.map((c) => c.getAttribute("data-attestation"))).toEqual(["unreported", "suspect", "missing"]);
    expect(chips.map((c) => c.textContent)).toEqual(["Not reported", "Suspect", "No token"]);
    const suspect = within(rows()[1] as HTMLElement);
    expect(suspect.getByTestId("attestation-risk").textContent).toBe("risk 70");
    // The chip sits in the column headed Client.
    const headers = screen.getAllByRole("columnheader").map((header) => header.textContent);
    const cells = within(rows()[1] as HTMLElement).getAllByRole("cell");
    expect(cells[headers.indexOf("Client")]?.textContent).toBe("Suspectrisk 70");
  });

  it("shows the request signature Shield verified in the Signature column, right after Client", () => {
    renderFeed([
      eventAt(1_000, { signature: { status: "replayed", body: "checked" } }),
      eventAt(2_000, { signature: { status: "invalid", body: "mismatch" } }),
      eventAt(3_000, { signature: { status: "valid", body: "unchecked" } }),
      eventAt(4_000, { signature: null }),
    ]);
    const headers = screen.getAllByRole("columnheader").map((header) => header.textContent);
    expect(headers.indexOf("Signature")).toBe(headers.indexOf("Client") + 1);
    const chips = rows().map((row) => within(row).getByTestId("signature-chip"));
    expect(chips.map((c) => c.getAttribute("data-signature"))).toEqual([
      "unreported",
      "unchecked",
      "mismatch",
      "replayed",
    ]);
    const cells = within(rows()[2] as HTMLElement).getAllByRole("cell");
    expect(cells[headers.indexOf("Signature")]?.textContent).toBe("Invalid · body changed");
  });

  it("says what the Client column is, and that it is evidence, not proof", () => {
    renderFeed();
    expect(screen.getByTestId("client-note").textContent).toBe(
      "Client shows the Guard attestation Shield verified for each request. It is evidence, not proof.",
    );
  });

  it("keeps the exact instant of an Event available on its time", () => {
    renderFeed([eventAt(2_000)]);
    const time = rows()[0]?.querySelector("time");
    expect(time?.getAttribute("dateTime")).toBe("2026-11-10T08:00:02.000Z");
    expect(time?.getAttribute("title")).toBe("2026-11-10T08:00:02.000Z");
  });

  it("reads the Decision as Allowed with a Monitor tag, both dashed: monitor is never solid", () => {
    renderFeed([eventAt(1_000)]);
    const row = within(rows()[0] as HTMLElement);
    const chip = row.getByText("Allowed").closest("[data-decision]");
    expect(chip?.getAttribute("data-mode")).toBe("monitor");
    expect(chip?.className).toContain("border-dashed");
    const tag = row.getByText("Monitor");
    expect(tag.getAttribute("data-mode")).toBe("monitor");
    expect(tag.className).toContain("border-dashed");
  });

  it("marks the status class and says Unknown for an unknown network", () => {
    renderFeed([
      eventAt(1_000, { request: { method: "GET", route: "/boom", status: 503, latency_ms: 1200 } }),
      eventAt(2_000, { actor: { ip_prefix: null, ip_hash: null } }),
    ]);
    const [newest, older] = rows();
    expect(within(newest as HTMLElement).getByText("Unknown")).toBeTruthy();
    expect(
      within(older as HTMLElement)
        .getByText("503")
        .getAttribute("data-status"),
    ).toBe("server");
    expect(within(older as HTMLElement).getByText("1.2 s")).toBeTruthy();
  });

  it("with no Events, waits for the first one and names the App", () => {
    renderFeed([]);
    expect(rows()).toHaveLength(0);
    expect(screen.getByTestId("feed-waiting").textContent).toBe("Waiting for the first event from shop-web…");
    expect(screen.queryByTestId("environment-tag")).toBeNull();
  });

  it("shows the Environment of the newest Event", () => {
    renderFeed([eventAt(1_000, { environment: "development" }), eventAt(2_000, { environment: "production" })]);
    expect(screen.getByTestId("environment-tag").textContent).toBe("Production");
  });

  it("is not a live region: only the connection indicator announces itself", () => {
    const { container } = renderFeed();
    expect(container.querySelector("[aria-live]")).toBeNull();
    expect(container.querySelectorAll("[role='status'], [role='alert'], [role='log']")).toHaveLength(1);
    expect(screen.getByRole("status")).toBe(screen.getByTestId("live-indicator"));
    expect(screen.getByRole("table").closest("[role='status']")).toBeNull();
  });
});

describe("LiveFeed — Blocked and enforced Decisions", () => {
  const RULE_ID = "rul_0123456789abcdef01234567";
  const decisionCell = (row: HTMLElement | undefined) => {
    const cell = within(row as HTMLElement).getAllByRole("cell")[1] as HTMLElement;
    return {
      text: cell.textContent,
      chip: within(cell).getByTestId("decision-chip"),
      mark: within(cell).queryByTestId("mode-tag"),
    };
  };

  it("draws a request blocked in Enforce mode as a solid Blocked chip in the critical colour, without a Monitor mark", () => {
    renderFeed([
      eventAt(1_000, {
        request: { method: "GET", route: "/api/admin/**", status: 403, latency_ms: 0.2 },
        decision: {
          action: "block",
          mode: "enforce",
          rule_id: RULE_ID,
          policy_version: 3,
          containment_id: null,
          patch_id: null,
          patch_body: null,
        },
      }),
    ]);
    const { text, chip, mark } = decisionCell(rows()[0]);
    expect(text).toBe("Blocked");
    expect(chip.getAttribute("data-decision")).toBe("block");
    expect(chip.getAttribute("data-mode")).toBe("enforce");
    expect(chip.className).toContain("border-solid");
    expect(chip.className).not.toContain("border-dashed");
    expect(chip.className).toContain("text-dec-block");
    // The prohibit icon: the Decision is never carried by colour alone.
    expect(chip.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
    expect(chip.querySelector("svg")?.getAttribute("data-shape")).toBe("prohibit");
    expect(mark).toBeNull();
    expect(within(rows()[0] as HTMLElement).queryByText("Monitor")).toBeNull();
  });

  it("shows the Rule's pattern as the route of a blocked request, with its 403", () => {
    renderFeed([
      eventAt(1_000, {
        request: { method: "GET", route: "/api/admin/**", status: 403, latency_ms: 0.2 },
        decision: {
          action: "block",
          mode: "enforce",
          rule_id: RULE_ID,
          policy_version: 3,
          containment_id: null,
          patch_id: null,
          patch_body: null,
        },
      }),
    ]);
    const cells = within(rows()[0] as HTMLElement)
      .getAllByRole("cell")
      .map((cell) => cell.textContent);
    expect(cells).toEqual([
      "08:00:01",
      "Blocked",
      "Not reported",
      "Not reported",
      "GET",
      "/api/admin/**",
      "403",
      "<1 ms",
      "203.0.113.0/24",
    ]);
  });

  it("draws a request a Monitor Rule would have blocked as a dashed Blocked chip plus the Monitor mark", () => {
    renderFeed([
      eventAt(1_000, {
        request: { method: "GET", route: "/api/products/:id", status: 200, latency_ms: 2 },
        decision: {
          action: "block",
          mode: "monitor",
          rule_id: RULE_ID,
          policy_version: 3,
          containment_id: null,
          patch_id: null,
          patch_body: null,
        },
      }),
    ]);
    const { text, chip, mark } = decisionCell(rows()[0]);
    expect(text).toBe("BlockedMonitor");
    expect(chip.getAttribute("data-decision")).toBe("block");
    expect(chip.getAttribute("data-mode")).toBe("monitor");
    expect(chip.className).toContain("border-dashed");
    expect(chip.className).toContain("bg-transparent");
    expect(chip.className).not.toContain("border-solid");
    expect(mark?.textContent).toBe("Monitor");
    expect(mark?.className).toContain("border-dashed");
  });

  it("draws Allowed under a published Policy without the Monitor mark", () => {
    renderFeed([
      eventAt(1_000, {
        decision: {
          action: "allow",
          mode: "enforce",
          rule_id: null,
          policy_version: 1,
          containment_id: null,
          patch_id: null,
          patch_body: null,
        },
      }),
      // Even if a Shield still says monitor: under a published Policy an allowed request has no Monitor mark.
      eventAt(2_000, {
        decision: {
          action: "allow",
          mode: "monitor",
          rule_id: null,
          policy_version: 7,
          containment_id: null,
          patch_id: null,
          patch_body: null,
        },
      }),
    ]);
    for (const row of rows()) {
      const { text, chip, mark } = decisionCell(row);
      expect(text).toBe("Allowed");
      expect(chip.getAttribute("data-decision")).toBe("allow");
      expect(mark).toBeNull();
    }
    expect(decisionCell(rows()[1]).chip.className).toContain("border-solid");
  });

  it("keeps the Monitor mark on Allowed while no Policy is published", () => {
    renderFeed([
      eventAt(1_000, {
        decision: {
          action: "allow",
          mode: "monitor",
          rule_id: null,
          policy_version: 0,
          containment_id: null,
          patch_id: null,
          patch_body: null,
        },
      }),
    ]);
    const { text, chip, mark } = decisionCell(rows()[0]);
    expect(text).toBe("AllowedMonitor");
    expect(chip.className).toContain("border-dashed");
    expect(mark?.getAttribute("data-mode")).toBe("monitor");
  });

  it("tells the three states apart as they arrive on the stream", () => {
    const { source } = renderFeed([]);
    act(() => {
      source.emit(
        "security-event",
        eventAt(3_000, {
          request: { method: "GET", route: "/api/admin/**", status: 403, latency_ms: 0.1 },
          decision: {
            action: "block",
            mode: "enforce",
            rule_id: RULE_ID,
            policy_version: 2,
            containment_id: null,
            patch_id: null,
            patch_body: null,
          },
        }),
      );
      source.emit(
        "security-event",
        eventAt(2_000, {
          decision: {
            action: "block",
            mode: "monitor",
            rule_id: RULE_ID,
            policy_version: 2,
            containment_id: null,
            patch_id: null,
            patch_body: null,
          },
        }),
      );
      source.emit(
        "security-event",
        eventAt(1_000, {
          decision: {
            action: "allow",
            mode: "enforce",
            rule_id: null,
            policy_version: 2,
            containment_id: null,
            patch_id: null,
            patch_body: null,
          },
        }),
      );
    });
    tick(RENDER_INTERVAL_MS);
    expect(rows().map((row) => decisionCell(row).text)).toEqual(["Blocked", "BlockedMonitor", "Allowed"]);
  });
});

describe("LiveFeed — Throttled Decisions (slice 08)", () => {
  const RULE_ID = "rul_fedcba9876543210fedcba98";
  const throttled = (mode: "enforce" | "monitor", status: number) =>
    eventAt(1_000, {
      request: { method: "POST", route: "/login", status, latency_ms: 0.3 },
      decision: {
        action: "throttle",
        mode,
        rule_id: RULE_ID,
        policy_version: 3,
        containment_id: null,
        patch_id: null,
        patch_body: null,
      },
    });
  const decisionCell = (row: HTMLElement | undefined) =>
    within(row as HTMLElement).getAllByRole("cell")[1] as HTMLElement;

  it("draws an enforced throttle as a solid Throttled chip with its own glyph and colour, the route and the 429", () => {
    renderFeed([throttled("enforce", 429)]);
    const cell = decisionCell(rows()[0]);
    const chip = within(cell).getByTestId("decision-chip");
    expect(cell.textContent).toBe("Throttled");
    expect(chip.getAttribute("data-decision")).toBe("throttle");
    expect(chip.getAttribute("data-mode")).toBe("enforce");
    expect(chip.className).toContain("border-solid");
    expect(chip.className).toContain("text-dec-throttle");
    expect(chip.querySelector("svg")?.getAttribute("data-shape")).toBe("hourglass-medium");
    expect(within(cell).queryByTestId("mode-tag")).toBeNull();
    const cells = within(rows()[0] as HTMLElement)
      .getAllByRole("cell")
      .map((one) => one.textContent);
    expect(cells.slice(4, 7)).toEqual(["POST", "/login", "429"]);
    // The row names no identifier of the Rule: like a Blocked row, it shows the Decision and the route.
    expect((rows()[0] as HTMLElement).textContent).not.toContain(RULE_ID);
  });

  it("draws a throttle in Monitor mode dashed and hollow with the Monitor mark: the response was unchanged", () => {
    renderFeed([throttled("monitor", 401)]);
    const cell = decisionCell(rows()[0]);
    const chip = within(cell).getByTestId("decision-chip");
    expect(chip.textContent).toBe("Throttled");
    expect(chip.getAttribute("data-mode")).toBe("monitor");
    expect(chip.className).toContain("border-dashed");
    expect(chip.className).toContain("bg-transparent");
    expect(within(cell).getByTestId("mode-tag").textContent).toBe("Monitor");
    expect(within(rows()[0] as HTMLElement).getAllByRole("cell")[6]?.textContent).toBe("401");
  });
});

describe("LiveFeed — the stream", () => {
  it("connects once, to the Console's own proxy for this App", () => {
    const { source } = renderFeed();
    expect(FakeEventSource.instances).toHaveLength(1);
    expect(source.url).toBe(`/api/apps/${APP_ID}/events/stream`);
    expect(source.listenerCount("security-event")).toBe(1);
  });

  it("adds a row for a security-event message within one render interval, not before", () => {
    const { source } = renderFeed();
    act(() =>
      source.emit(
        "security-event",
        eventAt(3_000, { request: { method: "GET", route: "/new", status: 200, latency_ms: 2 } }),
      ),
    );
    expect(rows()).toHaveLength(2);
    tick(RENDER_INTERVAL_MS - 1);
    expect(rows()).toHaveLength(2);
    tick(1);
    expect(rows()).toHaveLength(3);
    expect(within(rows()[0] as HTMLElement).getByText("/new")).toBeTruthy();
  });

  it("replaces the waiting state with the first Event", () => {
    const { source } = renderFeed([]);
    act(() => source.emit("security-event", eventAt(3_000)));
    tick(RENDER_INTERVAL_MS);
    expect(screen.queryByTestId("feed-waiting")).toBeNull();
    expect(rows()).toHaveLength(1);
  });

  it("merges a burst in one render, newest first", () => {
    const { source } = renderFeed([]);
    act(() => {
      source.emit("security-event", eventAt(3_000));
      source.emit("security-event", eventAt(5_000));
      source.emit("security-event", eventAt(4_000));
    });
    expect(rows()).toHaveLength(0);
    tick(RENDER_INTERVAL_MS);
    expect(rows().map((row) => row.getAttribute("data-event-id"))).toEqual([
      eventAt(5_000).event_id,
      eventAt(4_000).event_id,
      eventAt(3_000).event_id,
    ]);
  });

  it("keeps rendering at most once per interval while messages keep arriving", () => {
    const { source } = renderFeed([]);
    act(() => source.emit("security-event", eventAt(3_000)));
    tick(100);
    act(() => source.emit("security-event", eventAt(3_100)));
    tick(150);
    expect(rows()).toHaveLength(2);
    act(() => source.emit("security-event", eventAt(3_300)));
    tick(RENDER_INTERVAL_MS - 1);
    expect(rows()).toHaveLength(2);
    tick(1);
    expect(rows()).toHaveLength(3);
  });

  it("ignores a message that is not a valid stored Event", () => {
    const { source } = renderFeed();
    act(() => {
      source.emitRaw("security-event", "not json");
      source.emit("security-event", { hello: "world" });
      source.emit("security-event", { ...eventAt(3_000), event_id: "not-a-uuid" });
      source.emit("security-event", {
        ...eventAt(3_000),
        request: { method: "GET", route: "/x", status: 99, latency_ms: 1 },
      });
      source.emit("security-event", null);
    });
    tick(RENDER_INTERVAL_MS);
    expect(rows()).toHaveLength(2);
  });

  it("ignores an Event it already shows", () => {
    const { source } = renderFeed();
    act(() => source.emit("security-event", eventAt(2_000)));
    tick(RENDER_INTERVAL_MS);
    expect(rows()).toHaveLength(2);
  });

  it("shows only what the schema allows: unknown keys of a message never reach the page", () => {
    const { source, container } = renderFeed([]);
    act(() => source.emit("security-event", { ...eventAt(3_000), headers: { authorization: "Bearer leak-me" } }));
    tick(RENDER_INTERVAL_MS);
    expect(rows()).toHaveLength(1);
    expect(container.innerHTML).not.toContain("leak-me");
  });
});

describe("LiveFeed — the connection", () => {
  it("says Connecting, then Live when the stream opens", () => {
    const { source } = renderFeed();
    expect(indicator()).toBe("Connecting");
    act(() => source.open());
    expect(indicator()).toBe("Live");
  });

  it("says Reconnecting on an error and returns to Live when the browser reconnects by itself", () => {
    const { source } = renderFeed();
    act(() => source.open());
    act(() => source.drop());
    expect(indicator()).toBe("Reconnecting");
    expect(FakeEventSource.instances).toHaveLength(1);
    act(() => source.open());
    expect(indicator()).toBe("Live");
    expect(screen.queryByTestId("last-updated")).toBeNull();
  });

  it("shows when it was last in contact while it is reconnecting", () => {
    const { source } = renderFeed();
    act(() => source.open());
    vi.setSystemTime(BASE_MS + 65_000);
    act(() => source.emit("security-event", eventAt(65_000)));
    vi.setSystemTime(BASE_MS + 90_000);
    act(() => source.drop());
    expect(screen.getByTestId("last-updated").textContent).toBe("Last updated 08:01:05 UTC");
  });

  it("opens a new stream when the browser gives up, and recovers without a reload", () => {
    const { source } = renderFeed();
    act(() => source.open());
    // The API is down: the proxy answers with an error status and EventSource closes for good.
    act(() => source.fail());
    expect(indicator()).toBe("Reconnecting");
    expect(source.listenerCount("security-event")).toBe(0);
    tick(RECONNECT_DELAY_MS - 1);
    expect(FakeEventSource.instances).toHaveLength(1);
    tick(1);
    expect(FakeEventSource.instances).toHaveLength(2);

    // Still down: it keeps trying.
    act(() => FakeEventSource.latest().fail());
    tick(RECONNECT_DELAY_MS);
    expect(FakeEventSource.instances).toHaveLength(3);
    expect(indicator()).toBe("Reconnecting");

    // Back up.
    const recovered = FakeEventSource.latest();
    expect(recovered.url).toBe(source.url);
    act(() => recovered.open());
    expect(indicator()).toBe("Live");
    act(() => recovered.emit("security-event", eventAt(9_000)));
    tick(RENDER_INTERVAL_MS);
    expect(rows()).toHaveLength(3);
  });

  it("closes the stream and stops every timer when it leaves the page", () => {
    const { source, unmount } = renderFeed();
    act(() => source.emit("security-event", eventAt(3_000)));
    unmount();
    expect(source.readyState).toBe(FakeEventSource.CLOSED);
    expect(source.listenerCount("security-event")).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not reconnect after it left the page", () => {
    const { source, unmount } = renderFeed();
    act(() => source.fail());
    unmount();
    vi.advanceTimersByTime(RECONNECT_DELAY_MS * 2);
    expect(FakeEventSource.instances).toHaveLength(1);
  });
});

describe("LiveFeed — catching up (review finding F5)", () => {
  it("reads the list when the stream opens and shows an Event that arrived before the subscription", async () => {
    const first = eventAt(1_000);
    const missed = eventAt(2_000, { request: { method: "POST", route: "/api/login", status: 401, latency_ms: 1 } });
    fetchMock.mockImplementation(async () => listResponse([missed, first]));
    const { source } = renderFeed([first]);
    expect(rows()).toHaveLength(1);

    act(() => source.open());
    await settle(RENDER_INTERVAL_MS);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`/api/apps/${APP_ID}/events`);
    expect(rows()).toHaveLength(2);
    expect(rows()[0]?.textContent).toContain("/api/login");
  });

  it("reads the list again after a reconnect, so an Event ingested while disconnected appears", async () => {
    const { source } = renderFeed([eventAt(1_000)]);
    act(() => source.open());
    await settle(RENDER_INTERVAL_MS);
    expect(rows()).toHaveLength(1);

    act(() => source.fail());
    fetchMock.mockImplementation(async () => listResponse([eventAt(5_000), eventAt(1_000)]));
    await settle(RECONNECT_DELAY_MS);
    act(() => FakeEventSource.latest().open());
    await settle(RENDER_INTERVAL_MS);

    expect(indicator()).toBe("Live");
    expect(rows()).toHaveLength(2);
  });

  it("ignores a list that cannot be read and keeps the stream", async () => {
    fetchMock.mockImplementation(async () => {
      throw new TypeError("fetch failed");
    });
    const { source } = renderFeed([eventAt(1_000)]);
    act(() => source.open());
    await settle(RENDER_INTERVAL_MS);
    expect(indicator()).toBe("Live");
    expect(rows()).toHaveLength(1);
  });

  it("hands over to sign-in when the session is no longer accepted, and stops retrying", async () => {
    const onSessionExpired = vi.fn();
    fetchMock.mockImplementation(async () => listResponse([], 401));
    render(<LiveFeed appId={APP_ID} appName="shop-web" initialEvents={[]} onSessionExpired={onSessionExpired} />);
    act(() => FakeEventSource.latest().fail());
    await settle();

    expect(onSessionExpired).toHaveBeenCalledTimes(1);
    await settle(RECONNECT_DELAY_MS * 3);
    expect(FakeEventSource.instances).toHaveLength(1);
  });

  it("stops retrying when the App no longer exists", async () => {
    fetchMock.mockImplementation(async () => listResponse([], 404));
    const { source } = renderFeed();
    act(() => source.fail());
    await settle();
    await settle(RECONNECT_DELAY_MS * 3);
    expect(FakeEventSource.instances).toHaveLength(1);
    expect(indicator()).toBe("Reconnecting");
  });
});
