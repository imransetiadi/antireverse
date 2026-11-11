import type { EventAttestation } from "@antireverse/protocol";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AttestationChip } from "@/components/attestation-chip.tsx";
import { en } from "@/lib/messages/en.ts";

// Contract P5 of slice 03: the attestation of one request as a word, a Phosphor icon and a token colour —
// never the colour alone (UIUX.md §8). Trusted is evidence, never proof of a genuine client.

const chip = (): HTMLElement => screen.getByTestId("attestation-chip");
const shape = (): string | null | undefined => chip().querySelector("svg")?.getAttribute("data-shape");
const risk = (): HTMLElement | null => screen.queryByTestId("attestation-risk");

const CASES: Array<{
  attestation: EventAttestation | null;
  word: string;
  state: string;
  status: string;
  verdict: string | null;
  icon: string;
  tone: string;
  risk: string | null;
}> = [
  {
    attestation: { status: "valid", verdict: "trusted", risk: 5 },
    word: "Trusted",
    state: "trusted",
    status: "valid",
    verdict: "trusted",
    icon: "shield-check",
    tone: "text-primary",
    risk: "risk 5",
  },
  {
    attestation: { status: "valid", verdict: "suspect", risk: 70 },
    word: "Suspect",
    state: "suspect",
    status: "valid",
    verdict: "suspect",
    icon: "shield-warning",
    tone: "text-sev-medium",
    risk: "risk 70",
  },
  {
    attestation: { status: "valid", verdict: "hostile", risk: 100 },
    word: "Hostile",
    state: "hostile",
    status: "valid",
    verdict: "hostile",
    icon: "shield-slash",
    tone: "text-sev-critical-text",
    risk: "risk 100",
  },
  {
    attestation: { status: "missing", verdict: null, risk: null },
    word: "No token",
    state: "missing",
    status: "missing",
    verdict: null,
    icon: "minus",
    tone: "text-fg-subtle",
    risk: null,
  },
  {
    attestation: { status: "invalid", verdict: null, risk: null },
    word: "Invalid",
    state: "invalid",
    status: "invalid",
    verdict: null,
    icon: "prohibit",
    tone: "text-sev-high",
    risk: null,
  },
  {
    attestation: { status: "expired", verdict: null, risk: null },
    word: "Expired",
    state: "expired",
    status: "expired",
    verdict: null,
    icon: "clock-countdown",
    tone: "text-fg-subtle",
    risk: null,
  },
  {
    attestation: null,
    word: "Not reported",
    state: "unreported",
    status: "unreported",
    verdict: null,
    icon: "circle-dashed",
    tone: "text-fg-subtle",
    risk: null,
  },
];

describe("AttestationChip", () => {
  it.each(CASES)("reads $word with its own icon and token colour", (c) => {
    render(<AttestationChip attestation={c.attestation} />);
    expect(chip().textContent).toBe(c.word);
    expect(chip().getAttribute("data-attestation")).toBe(c.state);
    expect(chip().getAttribute("data-status")).toBe(c.status);
    expect(chip().getAttribute("data-verdict")).toBe(c.verdict);
    expect(shape()).toBe(c.icon);
    expect(chip().className).toContain(c.tone);
    // The icon is decorative; the word carries the meaning.
    expect(chip().querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
    expect(risk()?.textContent ?? null).toBe(c.risk);
  });

  it("gives every state a distinct word and a distinct icon silhouette", () => {
    const seen = CASES.map((c) => {
      const view = render(<AttestationChip attestation={c.attestation} />);
      const result = [chip().textContent, shape()];
      view.unmount();
      return result;
    });
    expect(new Set(seen.map(([word]) => word)).size).toBe(CASES.length);
    expect(new Set(seen.map(([, icon]) => icon)).size).toBe(CASES.length);
  });

  it("shows the risk as a small code number next to the verdict, never inside the word", () => {
    render(<AttestationChip attestation={{ status: "valid", verdict: "suspect", risk: 70 }} />);
    expect(risk()?.className).toContain("code-3");
    expect(chip().contains(risk())).toBe(false);
  });

  it("shows a risk of 0", () => {
    render(<AttestationChip attestation={{ status: "valid", verdict: "trusted", risk: 0 }} />);
    expect(risk()?.textContent).toBe("risk 0");
  });

  it("explains every word on hover, and never says Trusted proves a genuine client", () => {
    for (const c of CASES) {
      const view = render(<AttestationChip attestation={c.attestation} />);
      const title = chip().getAttribute("title") ?? "";
      expect([c.word, title.length > 0]).toEqual([c.word, true]);
      view.unmount();
    }
    render(<AttestationChip attestation={{ status: "valid", verdict: "trusted", risk: 5 }} />);
    expect(chip().getAttribute("title")).toBe(
      "Shield verified a Guard token that reported no automation signal. This is evidence, not proof of a genuine client.",
    );
  });

  it("never claims proof or genuineness anywhere in the attestation copy", () => {
    const copy = Object.entries(en).filter(([key]) => key.startsWith("attestation.") || key === "live.client.note");
    expect(copy.length).toBeGreaterThan(0);
    for (const [key, text] of copy) {
      // "proof" only ever appears negated ("not proof"); nothing calls a client genuine, real or verified human.
      expect([key, /(?<!not )\bproo(f|ve)s?\b|\bproven\b/i.test(text)]).toEqual([key, false]);
      expect([key, /\b(is|are) (a )?(genuine|real|human|legitimate)\b|\bguarantee/i.test(text)]).toEqual([key, false]);
    }
  });
});
