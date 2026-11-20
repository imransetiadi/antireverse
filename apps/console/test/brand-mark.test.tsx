import { readFileSync } from "node:fs";
import { join } from "node:path";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AppShell } from "@/components/app-shell.tsx";
import { BrandMark } from "@/components/brand-mark.tsx";

describe("BrandMark", () => {
  it("is decorative: hidden from assistive technology, because the brand name follows it as text", () => {
    const { container } = render(<BrandMark />);
    const svg = container.querySelector("svg");
    expect(svg?.getAttribute("aria-hidden")).toBe("true");
    expect(svg?.getAttribute("focusable")).toBe("false");
  });

  it("takes the shield and the letter from the text colour and the trace from the brand token, with no raw colour", () => {
    const { container } = render(<BrandMark />);
    const [shield, letter, trace] = [...container.querySelectorAll("path")];
    expect(shield?.getAttribute("stroke")).toBe("currentColor");
    expect(letter?.getAttribute("stroke")).toBe("currentColor");
    expect(trace?.getAttribute("class")).toContain("stroke-brand");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
  });

  it("draws the same shapes as the brand source in brand/mark-on-dark.svg", () => {
    const source = readFileSync(join(import.meta.dirname, "../../../brand/mark-on-dark.svg"), "utf8");
    const { container } = render(<BrandMark />);
    const svg = container.querySelector("svg");
    const paths = [...container.querySelectorAll("path")];
    expect(paths).toHaveLength(3);
    expect(source.match(/<path /g)).toHaveLength(3);
    expect(source).toContain(`viewBox="${svg?.getAttribute("viewBox")}"`);
    expect(source).toContain(`stroke-width="${svg?.getAttribute("stroke-width")}"`);
    for (const path of paths) {
      expect(source).toContain(`d="${path.getAttribute("d")}"`);
    }
  });

  it("gives the trace the brand token's colour, the one the brand source and the icon use", () => {
    const css = readFileSync(join(import.meta.dirname, "../src/app/globals.css"), "utf8");
    const brand = css.match(/--brand:\s*(#[0-9a-f]{6})/i)?.[1];
    expect(brand).toBeDefined();
    expect(css).toContain("--color-brand: var(--brand);");
    const source = readFileSync(join(import.meta.dirname, "../../../brand/mark-on-dark.svg"), "utf8");
    const icon = readFileSync(join(import.meta.dirname, "../src/app/icon.svg"), "utf8");
    expect(source.toLowerCase()).toContain(`d="m27.5 35 h60" stroke="${brand?.toLowerCase()}"`);
    expect(icon.toLowerCase()).toContain(`d="m27.5 35 h60" stroke="${brand?.toLowerCase()}"`);
  });
});

describe("AppShell brand", () => {
  it("shows the mark before the brand name in the top bar", () => {
    render(<AppShell>content</AppShell>);
    const brand = screen.getByTestId("brand");
    expect(brand.textContent).toBe("Airverse");
    expect(brand.firstElementChild?.tagName.toLowerCase()).toBe("svg");
  });
});
