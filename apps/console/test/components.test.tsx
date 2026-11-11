import { generateKey } from "@antireverse/protocol/server";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DecisionChip } from "@/components/decision-chip.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { KeyReveal } from "@/components/key-reveal.tsx";
import { LiveIndicator } from "@/components/live-indicator.tsx";
import { ModeTag } from "@/components/mode-tag.tsx";
import { Snippet } from "@/components/snippet.tsx";

const writeText = vi.fn<(text: string) => Promise<void>>();

beforeEach(() => {
  writeText.mockReset();
  writeText.mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
});
afterEach(() => {
  vi.useRealTimers();
  localStorage.clear();
  sessionStorage.clear();
});

describe("KeyReveal", () => {
  const key = generateKey("admin").key;

  it("shows the title, the help text and the whole key", () => {
    render(<KeyReveal title="Admin key — shown once" help="Save this key now." value={key} testId="admin-key" />);
    expect(screen.getByRole("heading", { name: "Admin key — shown once" })).toBeTruthy();
    expect(screen.getByText("Save this key now.")).toBeTruthy();
    expect(screen.getByTestId("admin-key").textContent).toBe(key);
  });

  it("copies the key and answers Copy with Copied, then offers Copy again", async () => {
    vi.useFakeTimers();
    render(<KeyReveal title="Admin key — shown once" help="Save this key now." value={key} testId="admin-key" />);
    const button = screen.getByRole("button", { name: "Copy" });
    await act(async () => {
      fireEvent.click(button);
    });
    expect(writeText).toHaveBeenCalledWith(key);
    expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy();
    act(() => {
      vi.advanceTimersByTime(2_000);
    });
    expect(screen.getByRole("button", { name: "Copy" })).toBeTruthy();
  });

  it("says what to do when the clipboard refuses", async () => {
    writeText.mockRejectedValueOnce(new Error("denied"));
    render(<KeyReveal title="Shield key — shown once" help="Save this key now." value={key} testId="shield-key" />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    });
    expect(screen.getByRole("alert").textContent).toBe("Could not copy. Select the text and copy it yourself.");
    expect(screen.getByRole("button", { name: "Copy" })).toBeTruthy();
  });

  it("keeps the key out of browser storage and out of the address", async () => {
    render(<KeyReveal title="Admin key — shown once" help="Save this key now." value={key} testId="admin-key" />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    });
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(window.location.href).not.toContain(key);
  });
});

describe("DecisionChip", () => {
  it("reads Allowed and is hollow and dashed in monitor mode", () => {
    render(<DecisionChip action="allow" mode="monitor" />);
    const chip = screen.getByText("Allowed").closest("[data-decision]");
    expect(chip?.getAttribute("data-decision")).toBe("allow");
    expect(chip?.getAttribute("data-mode")).toBe("monitor");
    expect(chip?.className).toContain("border-dashed");
    expect(chip?.className).not.toContain("border-solid");
  });

  it("is solid in enforce mode", () => {
    render(<DecisionChip action="block" mode="enforce" />);
    const chip = screen.getByText("Blocked").closest("[data-decision]");
    expect(chip?.getAttribute("data-mode")).toBe("enforce");
    expect(chip?.className).toContain("border-solid");
    expect(chip?.className).not.toContain("border-dashed");
  });

  it("uses the fixed vocabulary and a decorative vector icon for every Decision", () => {
    const words = {
      allow: "Allowed",
      monitor: "Monitored",
      challenge: "Challenged",
      throttle: "Throttled",
      block: "Blocked",
      deceive: "Deceived",
    } as const;
    for (const [action, word] of Object.entries(words) as Array<[keyof typeof words, string]>) {
      const { container, unmount } = render(<DecisionChip action={action} mode="monitor" />);
      expect(container.textContent).toBe(word);
      expect(container.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
      unmount();
    }
  });
});

describe("ModeTag", () => {
  it("reads Monitor, dashed and hollow", () => {
    render(<ModeTag mode="monitor" />);
    const tag = screen.getByText("Monitor");
    expect(tag.getAttribute("data-mode")).toBe("monitor");
    expect(tag.className).toContain("border-dashed");
  });

  it("reads Enforce, solid", () => {
    render(<ModeTag mode="enforce" />);
    const tag = screen.getByText("Enforce");
    expect(tag.className).toContain("border-solid");
  });
});

describe("LiveIndicator", () => {
  it.each([
    ["connecting", "Connecting"],
    ["live", "Live"],
    ["reconnecting", "Reconnecting"],
  ] as const)("labels the %s state with the word %s", (state, word) => {
    render(<LiveIndicator state={state} />);
    const indicator = screen.getByTestId("live-indicator");
    expect(indicator.textContent).toBe(word);
    expect(indicator.getAttribute("data-state")).toBe(state);
    expect(indicator.getAttribute("role")).toBe("status");
  });

  it("pulses only while live, with a dot that is hidden from assistive technology", () => {
    const { container, rerender } = render(<LiveIndicator state="live" />);
    expect(container.querySelector("[aria-hidden='true']")?.className).toContain("live-dot-pulse");
    rerender(<LiveIndicator state="reconnecting" />);
    expect(container.querySelector("[aria-hidden='true']")?.className).not.toContain("live-dot-pulse");
  });
});

describe("EnvironmentTag", () => {
  it.each([
    ["production", "Production"],
    ["staging", "Staging"],
    ["development", "Development"],
  ] as const)("names the %s Environment", (environment, word) => {
    render(<EnvironmentTag environment={environment} />);
    expect(screen.getByTestId("environment-tag").textContent).toBe(word);
    expect(screen.getByTestId("environment-tag").getAttribute("data-environment")).toBe(environment);
  });
});

describe("Snippet", () => {
  it("shows the code under its label and copies exactly the code", async () => {
    const code = 'app.use(shield.express());\nconst a = "<b>";';
    render(<Snippet label="Add the middleware before your routes" code={code} />);
    expect(screen.getByText("Add the middleware before your routes")).toBeTruthy();
    expect(screen.getByRole("figure").querySelector("code")?.textContent).toBe(code);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    });
    expect(writeText).toHaveBeenCalledWith(code);
  });
});

describe("EmptyState", () => {
  it("says what will appear and offers the one action that makes it appear", () => {
    render(
      <EmptyState action={<a href="/apps/new">New App</a>}>No Apps yet. Create one to get a Shield key.</EmptyState>,
    );
    expect(screen.getByText("No Apps yet. Create one to get a Shield key.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "New App" }).getAttribute("href")).toBe("/apps/new");
  });
});
