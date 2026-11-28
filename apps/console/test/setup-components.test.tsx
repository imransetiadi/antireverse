// Slice 16, SCR-01: the Set up page of an App — three steps, the framework picker, the snippets with the App's real
// values, the live waiting state and the "Set up: n of 3" progress shown elsewhere.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { type AppSetup, EXAMPLE_STORED_EVENT } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppNav } from "@/components/app-nav.tsx";
import { RENDER_INTERVAL_MS } from "@/features/live-feed/feed-state.ts";
import { SetupGuide } from "@/features/setup/setup-guide.tsx";
import { SetupProgressLink } from "@/features/setup/setup-progress.tsx";
import { SETUP_POLL_MS } from "@/features/setup/use-setup-progress.ts";
import { RELEASED_VERSION } from "@/lib/released-version.ts";
import { eventAt } from "./helpers/events.ts";
import { FakeEventSource } from "./helpers/fake-event-source.ts";

const APP_ID = EXAMPLE_STORED_EVENT.app_id;
const app = { id: APP_ID, name: "shop-web" };
const API = "https://api.example.test";
const PUBLIC_KEY = "Wq0yMSeS0lWJ1XjZ5Gv6l3o0t7m0aW7F9n2R1Kc8bYk";
const NONE: AppSetup = {
  environment: "development",
  shield: { done_at: null },
  guard: { done_at: null },
  harden: { done_at: null },
};
const AT = "2026-11-13T09:00:00.000Z";

const fetchMock = vi.fn<typeof fetch>();
let served: AppSetup = NONE;
const setupCalls = (): string[] =>
  fetchMock.mock.calls.map(([url]) => String(url)).filter((url) => url.includes("/setup"));

const settle = async (ms = 0): Promise<void> => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
};

function setVisibility(state: "visible" | "hidden"): void {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
  Object.defineProperty(document, "hidden", { configurable: true, get: () => state === "hidden" });
  act(() => {
    document.dispatchEvent(new Event("visibilitychange"));
  });
}

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  served = NONE;
  fetchMock.mockReset();
  fetchMock.mockImplementation(async (input) => {
    const url = String(input);
    const body = url.includes("/setup") ? { setup: served } : { events: [] };
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  vi.useFakeTimers();
  setVisibility("visible");
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function renderGuide(setup: AppSetup = NONE, shieldKey?: string, policyPublicKey: string | null = PUBLIC_KEY) {
  return render(
    <SetupGuide app={app} initialSetup={setup} apiUrl={API} policyPublicKey={policyPublicKey} shieldKey={shieldKey} />,
  );
}

const stepButton = (name: RegExp): HTMLElement => screen.getByRole("button", { name });
const status = (): string => screen.getByTestId("setup-status").textContent ?? "";
const codeIn = (element: HTMLElement): string[] =>
  Array.from(element.querySelectorAll("code")).map((code) => code.textContent ?? "");

describe("SetupGuide — steps", () => {
  it("lists the three steps in order and opens the first one not done", () => {
    renderGuide();
    const list = screen.getByRole("list", { name: "Set up steps" });
    const headers = within(list)
      .getAllByRole("button")
      .filter((button) => button.hasAttribute("data-step"));
    expect(headers.map((button) => button.getAttribute("data-step"))).toEqual(["shield", "guard", "harden"]);
    expect(headers.map((button) => button.getAttribute("aria-expanded"))).toEqual(["true", "false", "false"]);
    expect(screen.getByText("Step 1 of 3")).toBeTruthy();
    // The open step's panel is the element its button controls.
    const panel = document.getElementById(headers[0]?.getAttribute("aria-controls") ?? "");
    // The package is on npm: installed by name at the exact released version, with the honest status beside it.
    expect(panel?.textContent).toContain(`npm install --save-exact @antireverse/shield-node@${RELEASED_VERSION}`);
    expect(panel?.textContent).not.toMatch(/path\/to\/airverse|not published|experimental-strip-types/);
    expect(panel?.textContent).toContain(
      `Early release (${RELEASED_VERSION}). Shield, Guard and Harden are on npm. The Airverse API and this Console are not: you run them yourself from the repository, and there is no hosted service.`,
    );
  });

  it("shows when a done step was done, and opens the next one", () => {
    renderGuide({ ...NONE, shield: { done_at: AT }, harden: { done_at: "2026-11-12T08:00:00.000Z" } });
    const shield = stepButton(/Add Shield/);
    expect(shield.textContent).toContain("Done 2026-11-13 09:00:00 UTC");
    expect(shield.textContent).toMatch(/^1?Add Shield Done/);
    expect(shield.querySelector("time")?.getAttribute("dateTime")).toBe(AT);
    expect(shield.getAttribute("aria-expanded")).toBe("false");
    expect(stepButton(/Add Guard/).getAttribute("aria-expanded")).toBe("true");
    expect(stepButton(/Harden your build/).textContent).toContain("Done 2026-11-12 08:00:00 UTC");
    expect(stepButton(/Add Guard/).textContent).toContain("Not done yet");
    expect(screen.getByText("Step 2 of 3")).toBeTruthy();
  });

  it("opens and closes any step from its button", () => {
    renderGuide();
    fireEvent.click(stepButton(/Harden your build/));
    expect(stepButton(/Harden your build/).getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(stepButton(/Add Shield/));
    expect(stepButton(/Add Shield/).getAttribute("aria-expanded")).toBe("false");
  });
});

describe("SetupGuide — Add Shield", () => {
  it("offers Express and Node http, and names the frameworks not supported yet without a snippet", () => {
    renderGuide();
    const picker = screen.getByRole("radiogroup", { name: "Framework" });
    const options = within(picker).getAllByRole("radio");
    expect(options.map((option) => option.getAttribute("value"))).toEqual(["express", "node"]);
    expect((within(picker).getByLabelText("Express") as HTMLInputElement).checked).toBe(true);
    expect(screen.getByText("Next.js, Fastify, Koa and other frameworks are not supported yet.")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/from "next|fastify\.register|koa/);

    const express = screen.getByRole("region", { name: "Add Shield to your Express server" });
    expect(codeIn(express).join("\n")).toContain("app.use(shield.express());");
    expect(codeIn(express).join("\n")).toContain(`endpoint: "${API}"`);

    fireEvent.click(within(picker).getByLabelText("Node http"));
    const node = screen.getByRole("region", { name: "Add Shield to your Node http server" });
    expect(codeIn(node).join("\n")).toContain("protect(req, res, () => handle(req, res));");
    expect(within(node).getByText(/the live feed shows \(unmatched\) as the route of every request/)).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Add Shield to your Express server" })).toBeNull();
  });

  it("puts the Shield key into the snippet right after creation", () => {
    const shieldKey = generateKey("shield", "development").key;
    renderGuide(NONE, shieldKey);
    const express = screen.getByRole("region", { name: "Add Shield to your Express server" });
    expect(codeIn(express)).toContain(`export AR_SHIELD_KEY="${shieldKey}"`);
    expect(codeIn(express)).toContain(`export AR_POLICY_PUBLIC_KEY="${PUBLIC_KEY}"`);
    expect(screen.getByTestId("monitor-note").textContent).toBe(
      "Shield starts in monitor mode — it observes and cannot block anything yet.",
    );
  });

  it("says where the key was shown and how to get a new one when the key is no longer at hand", () => {
    renderGuide();
    const express = screen.getByRole("region", { name: "Add Shield to your Express server" });
    expect(codeIn(express).some((code) => code.includes("AR_SHIELD_KEY="))).toBe(false);
    expect(
      within(express).getByText(
        "The Shield key was shown once, when this App was created, and cannot be shown again. Give it to your server as AR_SHIELD_KEY. For a new key, create a new App.",
      ),
    ).toBeTruthy();
  });

  it("says so when the policy public key could not be loaded", () => {
    renderGuide(NONE, undefined, null);
    expect(screen.getByTestId("policy-key-unavailable")).toBeTruthy();
    expect(screen.queryByTestId("policy-public-key")).toBeNull();
  });
});

describe("SetupGuide — Add Guard and Harden", () => {
  it("shows Guard's script tag with the App's ID and the API, and its options", () => {
    renderGuide();
    fireEvent.click(stepButton(/Add Guard/));
    const guard = screen.getByRole("region", { name: "Add Guard to your web pages" });
    const code = codeIn(guard).join("\n");
    expect(code).toContain(`npm install --save-exact @antireverse/guard@${RELEASED_VERSION}`);
    // With a bundler: by name. Without one: a module script from where the site serves the installed files.
    expect(code).toContain('import { createGuard } from "@antireverse/guard";');
    expect(code).toContain('import { createGuard } from "/guard/index.js";');
    expect(code.match(new RegExp(`appId: "${APP_ID}"`, "g"))).toHaveLength(2);
    expect(guard.textContent).toContain("node_modules/@antireverse/guard/dist");
    expect(guard.textContent).not.toMatch(/packages\/guard\/src|not published|copy of the Airverse repository/);
    expect(code).toContain('<script type="module">');
    expect(code).toContain(`appId: "${APP_ID}"`);
    expect(code).toContain(`endpoint: "${API}"`);
    expect(code).toContain("guard.headers()");
    expect(within(guard).getByRole("heading", { name: "Options" })).toBeTruthy();
    expect(
      within(guard)
        .getAllByRole("term")
        .map((term) => term.textContent),
    ).toEqual(["appId", "endpoint", "storage"]);
  });

  it("shows the Harden command with --register and the App's values", () => {
    renderGuide({ ...NONE, environment: "staging" });
    fireEvent.click(stepButton(/Harden your build/));
    const harden = screen.getByRole("region", { name: "Harden your build and register it" });
    const command = codeIn(harden).join("\n");
    // Installed in the project from npm, then run there: only the installed copy, never a download.
    expect(command).toContain(`npm install --save-dev --save-exact @antireverse/harden@${RELEASED_VERSION}`);
    expect(command).toMatch(/^npx --no-install antireverse harden dist --out dist-protected/m);
    expect(command).not.toMatch(/npx (?!--no-install )|tsx|path\/to/);
    expect(harden.textContent).toContain("--no-install makes npx run only the copy installed in your project");
    expect(harden.textContent).not.toMatch(/not published|copy of the Airverse repository/);
    for (const part of [
      "--register",
      `--endpoint "${API}"`,
      "--key-env AR_ADMIN_KEY",
      `--app ${APP_ID}`,
      "--environment staging",
      // The command runs in the developer's own project, so the Build version is that repository's commit.
      '--build-version "$(git rev-parse --short HEAD)"',
    ]) {
      expect(command).toContain(part);
    }
  });

  it("has a Having trouble? disclosure in each step that lists the common causes", () => {
    renderGuide();
    for (const step of [/Add Shield/, /Add Guard/, /Harden your build/]) {
      if (stepButton(step).getAttribute("aria-expanded") !== "true") fireEvent.click(stepButton(step));
    }
    const toggles = screen.getAllByRole("button", { name: "Having trouble?" });
    expect(toggles).toHaveLength(3);
    for (const toggle of toggles) {
      expect(toggle.getAttribute("aria-expanded")).toBe("false");
      fireEvent.click(toggle);
      expect(toggle.getAttribute("aria-expanded")).toBe("true");
      const causes = document.getElementById(toggle.getAttribute("aria-controls") ?? "");
      const items = causes?.querySelectorAll("li") ?? [];
      expect(items.length).toBeGreaterThanOrEqual(3);
      expect(items.length).toBeLessThanOrEqual(5);
    }
  });
});

describe("SetupGuide — waiting for the first event", () => {
  it("turns the waiting state into First protected request received without a reload", async () => {
    renderGuide();
    const region = screen.getByTestId("setup-status");
    expect(region.getAttribute("role")).toBe("status");
    expect(region.getAttribute("aria-live")).toBe("polite");
    expect(status()).toBe("Waiting for the first event from shop-web…");

    const source = FakeEventSource.latest();
    expect(source.url).toBe(`/api/apps/${APP_ID}/events/stream`);
    act(() => source.open());
    // An Event of another Environment does not count for this one.
    act(() => source.emit("security-event", eventAt(1_000, { environment: "production" })));
    await settle(RENDER_INTERVAL_MS);
    expect(status()).toBe("Waiting for the first event from shop-web…");

    const event = eventAt(2_000, { environment: "development", received_at: AT });
    act(() => source.emit("security-event", event));
    await settle(RENDER_INTERVAL_MS);
    expect(status()).toContain("First protected request received");
    expect(status()).toContain("Waiting for the first request from shop-web with a Guard token…");
    expect(stepButton(/Add Shield/).textContent).toContain("Done 2026-11-13 09:00:00 UTC");
    expect(stepButton(/Add Guard/).getAttribute("aria-expanded")).toBe("true");
    // The stream is closed once Shield is done.
    expect(source.readyState).toBe(FakeEventSource.CLOSED);
  });

  it("polls the set-up every 5 s for Guard and Harden and stops once everything is done", async () => {
    renderGuide({ ...NONE, shield: { done_at: AT } });
    expect(SETUP_POLL_MS).toBe(5_000);
    expect(FakeEventSource.instances).toHaveLength(0);
    expect(status()).toBe("Waiting for the first request from shop-web with a Guard token…");

    await settle(SETUP_POLL_MS);
    expect(setupCalls()).toEqual([`/api/apps/${APP_ID}/setup?environment=development`]);

    served = { ...NONE, shield: { done_at: AT }, guard: { done_at: "2026-11-13T09:00:05.000Z" } };
    await settle(SETUP_POLL_MS);
    expect(status()).toContain("First request with a Guard token received");
    expect(stepButton(/Add Guard/).textContent).toContain("Done 2026-11-13 09:00:05 UTC");

    served = { ...served, harden: { done_at: "2026-11-13T09:00:09.000Z" } };
    await settle(SETUP_POLL_MS);
    expect(status()).toContain("First Build registered");
    expect(status()).toContain("All three steps are done.");
    const calls = setupCalls().length;
    await settle(SETUP_POLL_MS * 3);
    expect(setupCalls()).toHaveLength(calls);
  });

  it("announces every step that turned done at once", async () => {
    renderGuide();
    served = { ...NONE, shield: { done_at: AT }, guard: { done_at: AT }, harden: { done_at: AT } };
    await settle(SETUP_POLL_MS);
    expect(status()).toBe(
      "First protected request received. First request with a Guard token received. First Build registered. All three steps are done.",
    );
  });

  it("stops polling while the tab is hidden and asks again as soon as it is visible", async () => {
    renderGuide({ ...NONE, shield: { done_at: AT } });
    setVisibility("hidden");
    await settle(SETUP_POLL_MS * 3);
    expect(setupCalls()).toHaveLength(0);
    setVisibility("visible");
    await settle(0);
    expect(setupCalls()).toHaveLength(1);
    await settle(SETUP_POLL_MS);
    expect(setupCalls()).toHaveLength(2);
  });

  it("stops polling for good when the session expired (401) or the App is gone (404)", async () => {
    const expired = vi.fn();
    fetchMock.mockImplementation(async () => new Response("{}", { status: 401 }));
    const view = render(
      <SetupGuide
        app={app}
        initialSetup={{ ...NONE, shield: { done_at: AT } }}
        apiUrl={API}
        policyPublicKey={PUBLIC_KEY}
        onSessionExpired={expired}
      />,
    );
    await settle(SETUP_POLL_MS * 3);
    expect(setupCalls()).toHaveLength(1);
    expect(expired).toHaveBeenCalledTimes(1);
    view.unmount();

    fetchMock.mockClear();
    fetchMock.mockImplementation(async () => new Response("{}", { status: 404 }));
    renderGuide({ ...NONE, shield: { done_at: AT } });
    await settle(SETUP_POLL_MS * 3);
    expect(setupCalls()).toHaveLength(1);
  });

  it("ignores an answer for another Environment or outside the contract", async () => {
    renderGuide({ ...NONE, shield: { done_at: AT } });
    served = { ...NONE, environment: "production", guard: { done_at: AT } };
    await settle(SETUP_POLL_MS);
    expect(stepButton(/Add Guard/).textContent).toContain("Not done yet");
    fetchMock.mockImplementation(
      async () => new Response(JSON.stringify({ setup: { guard: "yes" } }), { status: 200 }),
    );
    await settle(SETUP_POLL_MS);
    expect(stepButton(/Add Guard/).textContent).toContain("Not done yet");
    expect(setupCalls()).toHaveLength(2);
  });

  it("keeps a step open when it turns done while focus is inside it, so focus is not lost (review F1)", async () => {
    renderGuide({ ...NONE, shield: { done_at: AT } });
    const guardButton = stepButton(/Add Guard/);
    const panel = document.getElementById(guardButton.getAttribute("aria-controls") ?? "");
    const copy = within(panel as HTMLElement).getAllByRole("button", { name: "Copy" })[0] as HTMLElement;
    copy.focus();
    expect(document.activeElement).toBe(copy);

    served = { ...NONE, shield: { done_at: AT }, guard: { done_at: "2026-11-13T09:00:05.000Z" } };
    await settle(SETUP_POLL_MS);
    expect(status()).toContain("First request with a Guard token received");
    // Shown as done, still open, focus where it was; the next step opens too.
    expect(guardButton.textContent).toContain("Done 2026-11-13 09:00:05 UTC");
    expect(guardButton.getAttribute("aria-expanded")).toBe("true");
    expect(document.activeElement).toBe(copy);
    expect(document.body.contains(copy)).toBe(true);
    expect(stepButton(/Harden your build/).getAttribute("aria-expanded")).toBe("true");
  });

  it("closes a step that turns done when focus is elsewhere", async () => {
    renderGuide({ ...NONE, shield: { done_at: AT } });
    served = { ...NONE, shield: { done_at: AT }, guard: { done_at: "2026-11-13T09:00:05.000Z" } };
    await settle(SETUP_POLL_MS);
    expect(stepButton(/Add Guard/).getAttribute("aria-expanded")).toBe("false");
  });

  it("never sends a poll while the previous one is still waiting for an answer", async () => {
    let answer: ((response: Response) => void) | undefined;
    fetchMock.mockImplementation(
      (input) =>
        new Promise<Response>((resolve) => {
          if (String(input).includes("/setup")) answer = resolve;
        }),
    );
    renderGuide({ ...NONE, shield: { done_at: AT } });
    await settle(SETUP_POLL_MS * 4);
    expect(setupCalls()).toHaveLength(1);
    answer?.(new Response(JSON.stringify({ setup: served }), { status: 200 }));
    await settle(SETUP_POLL_MS);
    expect(setupCalls()).toHaveLength(2);
  });

  it("neither streams nor polls when every step is done", async () => {
    const all = { ...NONE, shield: { done_at: AT }, guard: { done_at: AT }, harden: { done_at: AT } };
    renderGuide(all);
    await settle(SETUP_POLL_MS * 2);
    expect(FakeEventSource.instances).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(status()).toBe("All three steps are done.");
  });
});

describe("Set up progress", () => {
  it("shows Set up: n of 3 as a link to the Set up page until all three are done", () => {
    const { rerender } = render(<SetupProgressLink appId={APP_ID} appName="shop-web" done={1} />);
    const link = screen.getByRole("link", { name: "Set up of shop-web: 1 of 3" });
    expect(link.getAttribute("href")).toBe(`/apps/${APP_ID}/setup`);
    expect(link.textContent).toBe("Set up: 1 of 3");
    rerender(<SetupProgressLink appId={APP_ID} appName="shop-web" done={3} />);
    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.getByText("Done")).toBeTruthy();
    // Unknown (the API could not say): a plain way to the page, without a number.
    rerender(<SetupProgressLink appId={APP_ID} appName="shop-web" done={null} />);
    expect(screen.getByRole("link", { name: "Set up of shop-web" }).textContent).toBe("Set up");
  });

  it("adds Set up to the App's screens, with n of 3 until done", () => {
    const { rerender } = render(<AppNav appId={APP_ID} current="live" setupDone={2} />);
    const nav = screen.getByTestId("app-nav");
    const setup = within(nav).getByTestId("app-nav-setup");
    expect(setup.textContent).toBe("Set up: 2 of 3");
    expect(setup.getAttribute("href")).toBe(`/apps/${APP_ID}/setup`);
    expect(setup.getAttribute("aria-current")).toBeNull();
    rerender(<AppNav appId={APP_ID} current="setup" setupDone={3} />);
    expect(within(nav).getByTestId("app-nav-setup").textContent).toBe("Set up");
    expect(within(nav).getByTestId("app-nav-setup").getAttribute("aria-current")).toBe("page");
    // On the Set up page itself the page shows the progress live; the tab does not repeat a count that would go stale.
    rerender(<AppNav appId={APP_ID} current="setup" setupDone={1} />);
    expect(within(nav).getByTestId("app-nav-setup").textContent).toBe("Set up");
    rerender(<AppNav appId={APP_ID} current="live" />);
    expect(within(nav).getByTestId("app-nav-setup").textContent).toBe("Set up");
  });
});

// One source for the version in every snippet, and it is the last release recorded in the repository.
describe("the released version the Console shows", () => {
  it("is the newest folder under releases/", () => {
    const releases = join(import.meta.dirname, "../../../releases");
    const newest = readdirSync(releases)
      .filter((name) => /^\d+\.\d+\.\d+$/.test(name))
      .sort((a, b) => a.localeCompare(b, "en", { numeric: true }))
      .at(-1);
    expect(RELEASED_VERSION).toBe(newest);
  });

  it("is in each install line and nowhere written out by hand", () => {
    renderGuide();
    for (const step of [/Add Guard/, /Harden your build/]) fireEvent.click(stepButton(step));
    const code = codeIn(document.body).join("\n");
    const versions = [...code.matchAll(/@antireverse\/(shield-node|guard|harden)@(\S+)/g)].map((m) => [m[1], m[2]]);
    expect(versions).toEqual([
      ["shield-node", RELEASED_VERSION],
      ["guard", RELEASED_VERSION],
      ["harden", RELEASED_VERSION],
    ]);
    const sources = ["features/apps/shield-snippet.ts", "lib/messages/en.ts", "features/setup/setup-guide.tsx"];
    for (const file of sources) {
      const text = readFileSync(join(import.meta.dirname, "../src", file), "utf8");
      expect(text, file).not.toMatch(/@antireverse\/[a-z-]+@\d|Early release \(\d/);
    }
  });
});
