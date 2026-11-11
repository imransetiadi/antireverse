// @vitest-environment node
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// The design skill the Console follows (UIUX.md §3, §4): the token sheet in globals.css and the class names in
// the source are checked here, so a value that leaves the system fails a test instead of a review.

const SRC = fileURLToPath(new URL("../src/", import.meta.url));
const CSS_SOURCE = readFileSync(join(SRC, "app/globals.css"), "utf8");
/** globals.css without its comments: the rules, not the prose about them. */
const CSS = CSS_SOURCE.replace(/\/\*[\s\S]*?\*\//g, "");

/** Every `.ts` and `.tsx` file under `src`. */
function sourceFiles(dir: string = SRC): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.tsx?$/.test(name) ? [path] : [];
  });
}
const SOURCES = sourceFiles().map((path) => ({ path: path.slice(SRC.length), text: readFileSync(path, "utf8") }));

/** The custom properties of the `:root` block, with `var()` references resolved. */
function rootTokens(): Record<string, string> {
  const block = CSS.match(/:root\s*\{([\s\S]*?)\n\}/)?.[1];
  if (!block) throw new Error("globals.css has no :root block");
  const raw: Record<string, string> = {};
  for (const [, name, value] of block.matchAll(/--([\w-]+):\s*([^;]+);/g))
    raw[name as string] = (value as string).trim();
  const resolve = (value: string, depth = 0): string => {
    const ref = value.match(/^var\(--([\w-]+)\)$/)?.[1];
    if (!ref) return value;
    const target = raw[ref];
    if (target === undefined || depth > 8) throw new Error(`unresolved token --${ref}`);
    return resolve(target, depth + 1);
  };
  return Object.fromEntries(Object.entries(raw).map(([name, value]) => [name, resolve(value)]));
}
const TOKENS = rootTokens();
const token = (name: string): string => {
  const value = TOKENS[name];
  if (value === undefined) throw new Error(`no token --${name}`);
  return value;
};

// WCAG 2.2 relative luminance and contrast ratio.
const rgb = (hex: string): [number, number, number] => {
  const match = hex.match(/^#([0-9a-f]{6})$/i);
  if (!match) throw new Error(`not a #rrggbb colour: ${hex}`);
  const n = Number.parseInt(match[1] as string, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};
const channel = (c: number): number => {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
const luminance = (hex: string): number => {
  const [r, g, b] = rgb(hex).map(channel) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a: string, b: string): number => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
};
/** `colour` at `share` over `base`: how a badge's 16 % tint renders. */
const over = (colour: string, base: string, share: number): string =>
  `#${rgb(colour)
    .map((c, i) => Math.round(c * share + (rgb(base)[i] as number) * (1 - share)))
    .map((c) => c.toString(16).padStart(2, "0"))
    .join("")}`;
const hsl = (hex: string): { h: number; s: number; l: number } => {
  const [r, g, b] = rgb(hex).map((c) => c / 255) as [number, number, number];
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  const d = max - min;
  if (d === 0) return { h: 0, s: 0, l };
  const s = d / (1 - Math.abs(2 * l - 1));
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return { h: (h * 60 + 360) % 360, s, l };
};

/** The surfaces text and controls sit on. */
const SURFACES = ["bg", "surface", "surface-raised", "muted"] as const;
/** The surfaces a tinted badge sits on (never on a muted hover fill). */
const BADGE_SURFACES = ["bg", "surface", "surface-raised"] as const;
/** Every token that is used as a text colour. */
const TEXT = [
  "fg",
  "fg-muted",
  "fg-subtle",
  "primary",
  "link",
  "sev-critical-text",
  "sev-high",
  "sev-medium",
  "sev-low",
  "sev-info",
  "dec-allow",
  "dec-monitor",
  "dec-challenge",
  "dec-throttle",
  "dec-block",
  "dec-deceive",
  "finding-withdrawn",
] as const;
/** The text colours of the tinted severity, decision and attestation badges. */
const BADGE_TEXT = [
  "primary",
  "sev-critical-text",
  "sev-high",
  "sev-medium",
  "sev-low",
  "sev-info",
  "dec-allow",
  "dec-monitor",
  "dec-challenge",
  "dec-throttle",
  "dec-block",
  "dec-deceive",
  "finding-withdrawn",
] as const;

describe("colour tokens", () => {
  it("takes every dark surface from the skill's set only", () => {
    const allowed = ["#000000", "#181818", "#1f1f1f", "#272727", "#313131", "#131209"];
    for (const name of [...SURFACES, "border"])
      expect([name, token(name).toLowerCase()]).toEqual([name, expect.toBeOneOf(allowed)]);
    expect(token("bg").toLowerCase()).toBe("#000000");
    expect(token("surface").toLowerCase()).toBe("#181818");
    expect(token("surface-raised").toLowerCase()).toBe("#1f1f1f");
    expect(token("muted").toLowerCase()).toBe("#272727");
    expect(token("border").toLowerCase()).toBe("#313131");
  });

  it("has one accent: a green near hue 140 below 80 % saturation, shared by the focus ring", () => {
    const { h, s } = hsl(token("primary"));
    expect(h).toBeGreaterThanOrEqual(130);
    expect(h).toBeLessThanOrEqual(150);
    expect(s).toBeLessThan(0.8);
    expect(token("ring")).toBe(token("primary"));
  });

  it("keeps every text colour at 4.5 : 1 or more on every surface", () => {
    for (const text of TEXT) {
      for (const surface of SURFACES) {
        expect([text, surface, contrast(token(text), token(surface))]).toEqual([
          text,
          surface,
          expect.toSatisfy((ratio: number) => ratio >= 4.5),
        ]);
      }
    }
  });

  it("keeps badge text at 4.5 : 1 or more on its own 16 % tint", () => {
    for (const text of BADGE_TEXT) {
      for (const surface of BADGE_SURFACES) {
        const tint = over(token(text), token(surface), 0.16);
        expect([text, surface, contrast(token(text), tint)]).toEqual([
          text,
          surface,
          expect.toSatisfy((ratio: number) => ratio >= 4.5),
        ]);
      }
    }
  });

  it("keeps the focus ring and control boundaries at 3 : 1 or more on every surface", () => {
    for (const name of ["ring", "border-strong"]) {
      for (const surface of SURFACES) {
        expect([name, surface, contrast(token(name), token(surface))]).toEqual([
          name,
          surface,
          expect.toSatisfy((ratio: number) => ratio >= 3),
        ]);
      }
    }
  });

  it("keeps text on fills at 4.5 : 1 or more", () => {
    expect(contrast(token("on-primary"), token("primary"))).toBeGreaterThanOrEqual(4.5);
    expect(contrast(token("on-destructive"), token("destructive"))).toBeGreaterThanOrEqual(4.5);
    // The enforce mode tag: --bg text on an --fg fill.
    expect(contrast(token("bg"), token("fg"))).toBeGreaterThanOrEqual(4.5);
  });

  it("has flat surfaces: no gradient anywhere", () => {
    expect(CSS).not.toMatch(/gradient/);
    for (const { path, text } of SOURCES) expect([path, /gradient/.test(text)]).toEqual([path, false]);
  });
});

describe("motion tokens", () => {
  /** Every duration written in globals.css, in milliseconds. */
  const durations = [...CSS.matchAll(/(?<![\w.-])(\d+(?:\.\d+)?)(ms|s)\b/g)].map(([, value, unit]) =>
    unit === "s" ? Number(value) * 1000 : Number(value),
  );

  it("never moves faster than 200 ms, also under reduced motion", () => {
    expect(durations.length).toBeGreaterThan(0);
    for (const ms of durations) expect(ms).toBeGreaterThanOrEqual(200);
    for (const { path, text } of SOURCES) {
      for (const [, ms] of text.matchAll(/\bduration-(\d+)\b/g))
        expect([path, Number(ms) >= 200]).toEqual([path, true]);
    }
  });

  it("has the base curve, 300 ms for colour and opacity and 500 ms for layout", () => {
    expect(token("ease-base").replace(/\s/g, "")).toBe("cubic-bezier(0.22,1,0.36,1)");
    expect(token("motion-hover")).toBe("300ms");
    expect(token("motion-layout")).toBe("500ms");
  });
});

describe("type and space in the source", () => {
  // Spacing scale in px: 0 2 4 8 12 16 24 32 40 48 64 80 96 — in Tailwind steps of 4 px:
  const SPACING_STEPS = new Set(["0", "0.5", "1", "2", "3", "4", "6", "8", "10", "12", "16", "20", "24", "px"]);
  const SPACING =
    /(?<![\w-])-?(?:[a-z-]+:)*-?(p[xytbse]?|m[xytbse]?|gap(?:-[xy])?|space-[xy]|inset(?:-[xy])?|top|bottom|start|end|left|right|size|h|w|min-h|min-w|max-h)-(\d+(?:\.\d+)?|\[[^\]]+\])(?![\w.-])/g;

  it("uses only spacing steps of the scale; widths over 96 px are layout, not spacing", () => {
    const offScale: string[] = [];
    for (const { path, text } of SOURCES) {
      for (const [match, property, step] of text.matchAll(SPACING)) {
        const value = step as string;
        if (value.startsWith("[")) {
          offScale.push(`${path}: ${match}`);
          continue;
        }
        // Widths and minimum widths beyond the scale are layout measures (columns, panels).
        if (/^(w|min-w)$/.test(property as string) && Number(value) > 24) continue;
        if (!SPACING_STEPS.has(value)) offScale.push(`${path}: ${match}`);
      }
    }
    expect(offScale).toEqual([]);
  });

  it("sets text only with the named text styles: no size, weight, italic or legacy role utilities", () => {
    const LEGACY =
      /(?<![\w-])(?:[a-z-]+:)*(text-(?:page|section|body|touch|dense|label|data|xs|sm|base|lg|xl|[2-9]xl)|font-(?:thin|extralight|light|normal|medium|semibold|bold|extrabold|black|mono)|italic|uppercase|tracking-[\w-]+)(?![\w-])/g;
    const found: string[] = [];
    for (const { path, text } of SOURCES) for (const [match] of text.matchAll(LEGACY)) found.push(`${path}: ${match}`);
    expect(found).toEqual([]);
  });

  it("defines every named text style once, from the Tailwind type scale, never bolder than 700 and never italic", () => {
    const styles = [...CSS.matchAll(/@utility ((?:heading|title|body|button|caption|code)-[\w-]+) \{([\s\S]*?)\n\}/g)];
    const names = styles.map(([, name]) => name);
    expect(new Set(names).size).toBe(names.length);
    for (const name of ["heading-2", "heading-4", "heading-6", "title-4", "body-3", "body-4", "body-5", "button-md"])
      expect(names).toContain(name);
    for (const name of ["button-sm", "caption-1", "code-1", "code-2", "code-3"]) expect(names).toContain(name);
    const SCALE = new Set([
      "0.75rem/1rem",
      "0.875rem/1.25rem",
      "1rem/1.5rem",
      "1.125rem/1.75rem",
      "1.25rem/1.75rem",
      "1.5rem/2rem",
      "1.875rem/2.25rem",
    ]);
    for (const [, name, body] of styles) {
      const size = (body as string).match(/font-size:\s*([\d.]+rem)/)?.[1];
      const leading = (body as string).match(/line-height:\s*([\d.]+rem)/)?.[1];
      expect([name, `${size}/${leading}`]).toEqual([name, expect.toBeOneOf([...SCALE])]);
      const weight = Number((body as string).match(/font-weight:\s*(\d+)/)?.[1]);
      expect([name, weight <= 700]).toEqual([name, true]);
    }
    expect(CSS).not.toMatch(/italic|font-weight:\s*[89]00/);
  });
});
