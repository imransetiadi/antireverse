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

  it("takes the letter from the text colour and the barrier from the accent, with no raw colour", () => {
    const { container } = render(<BrandMark />);
    expect(container.querySelector("path")?.getAttribute("fill")).toBe("currentColor");
    expect(container.querySelector("rect")?.getAttribute("class")).toContain("fill-primary");
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{3,8}\b/i);
  });

  it("draws the same shapes as the brand source in brand/mark-on-dark.svg", () => {
    const source = readFileSync(join(import.meta.dirname, "../../../brand/mark-on-dark.svg"), "utf8");
    const { container } = render(<BrandMark />);
    expect(source).toContain(`d="${container.querySelector("path")?.getAttribute("d")}"`);
    for (const name of ["x", "y", "width", "height"]) {
      expect(source).toContain(`${name}="${container.querySelector("rect")?.getAttribute(name)}"`);
    }
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
