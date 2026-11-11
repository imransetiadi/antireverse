import { BODY_STATES, type EventSignature, SIGNATURE_STATUSES } from "@antireverse/protocol";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SignatureChip } from "@/components/signature-chip.tsx";

// Contract P5 of slice 04: the request signature Shield verified for one request, as a word, a Phosphor icon and
// a token colour — never the colour alone (UIUX.md §8). A signature only counts with the body checked or absent.

const chip = (): HTMLElement => screen.getByTestId("signature-chip");
const shape = (): string | null | undefined => chip().querySelector("svg")?.getAttribute("data-shape");

interface Case {
  signature: EventSignature | null;
  word: string;
  state: string;
  icon: string;
  tone: string;
  tinted: boolean;
}

const SIGNED = { word: "Signed", state: "signed", icon: "signature", tone: "text-primary", tinted: true };
const UNCHECKED = {
  word: "Signed · body not checked",
  state: "unchecked",
  icon: "pen-nib",
  tone: "text-sev-medium",
  tinted: true,
};
const UNSIGNED = { word: "Unsigned", state: "missing", icon: "minus", tone: "text-fg-subtle", tinted: false };
const INVALID = { word: "Invalid", state: "invalid", icon: "prohibit", tone: "text-sev-high", tinted: true };
const CHANGED = {
  word: "Invalid · body changed",
  state: "mismatch",
  icon: "file-x",
  tone: "text-sev-critical-text",
  tinted: true,
};
const STALE = { word: "Stale", state: "stale", icon: "clock", tone: "text-sev-medium", tinted: true };
const REPLAYED = {
  word: "Replayed",
  state: "replayed",
  icon: "arrows-clockwise",
  tone: "text-sev-critical-text",
  tinted: true,
};
const UNREPORTED = {
  word: "Not reported",
  state: "unreported",
  icon: "circle-dashed",
  tone: "text-fg-subtle",
  tinted: false,
};

// Every (status, body) pair the protocol accepts: body null exactly when missing, mismatch only with invalid.
const CASES: Case[] = [
  { signature: { status: "valid", body: "checked" }, ...SIGNED },
  { signature: { status: "valid", body: "none" }, ...SIGNED },
  { signature: { status: "valid", body: "unchecked" }, ...UNCHECKED },
  { signature: { status: "missing", body: null }, ...UNSIGNED },
  { signature: { status: "invalid", body: "checked" }, ...INVALID },
  { signature: { status: "invalid", body: "unchecked" }, ...INVALID },
  { signature: { status: "invalid", body: "none" }, ...INVALID },
  { signature: { status: "invalid", body: "mismatch" }, ...CHANGED },
  { signature: { status: "stale", body: "checked" }, ...STALE },
  { signature: { status: "stale", body: "unchecked" }, ...STALE },
  { signature: { status: "stale", body: "none" }, ...STALE },
  { signature: { status: "replayed", body: "checked" }, ...REPLAYED },
  { signature: { status: "replayed", body: "unchecked" }, ...REPLAYED },
  { signature: { status: "replayed", body: "none" }, ...REPLAYED },
  { signature: null, ...UNREPORTED },
];

const label = (c: Case): string => (c.signature ? `${c.signature.status}/${c.signature.body}` : "null");

describe("SignatureChip", () => {
  it("covers every status and body state of the protocol", () => {
    const statuses = new Set(CASES.flatMap((c) => (c.signature ? [c.signature.status] : [])));
    const bodies = new Set(CASES.flatMap((c) => (c.signature?.body ? [c.signature.body] : [])));
    expect([...statuses].sort()).toEqual([...SIGNATURE_STATUSES].sort());
    expect([...bodies].sort()).toEqual([...BODY_STATES].sort());
  });

  it.each(CASES.map((c) => [label(c), c] as const))("reads %s with its own word, icon and token colour", (_, c) => {
    render(<SignatureChip signature={c.signature} />);
    expect(chip().textContent).toBe(c.word);
    expect(chip().getAttribute("data-signature")).toBe(c.state);
    expect(chip().getAttribute("data-status")).toBe(c.signature?.status ?? "unreported");
    expect(chip().getAttribute("data-body")).toBe(c.signature?.body ?? null);
    expect(shape()).toBe(c.icon);
    expect(chip().className).toContain(c.tone);
    expect(chip().className).toContain(c.tinted ? "bg-current/16" : "bg-transparent");
    // The icon is decorative; the word carries the meaning.
    expect(chip().querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
  });

  it("gives every state a distinct word and a distinct icon silhouette", () => {
    const states = new Map<string, [string | null, string | null | undefined]>();
    for (const c of CASES) {
      const view = render(<SignatureChip signature={c.signature} />);
      states.set(c.state, [chip().textContent, shape()]);
      view.unmount();
    }
    const seen = [...states.values()];
    expect(seen).toHaveLength(8);
    expect(new Set(seen.map(([word]) => word)).size).toBe(8);
    expect(new Set(seen.map(([, icon]) => icon)).size).toBe(8);
  });

  it("explains every word on hover", () => {
    const titles = new Map<string, string>();
    for (const c of CASES) {
      const view = render(<SignatureChip signature={c.signature} />);
      titles.set(c.state, chip().getAttribute("title") ?? "");
      view.unmount();
    }
    expect([...titles.values()].every((title) => title.length > 0)).toBe(true);
    expect(new Set(titles.values()).size).toBe(8);
    render(<SignatureChip signature={{ status: "valid", body: "unchecked" }} />);
    expect(chip().getAttribute("title")).toBe(
      "Shield verified the signature, but no body check ran. Add shield.verifyBody to your body parser.",
    );
  });
});
