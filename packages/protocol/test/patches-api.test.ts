import { describe, expect, it } from "vitest";
import {
  EXAMPLE_PATCH_SUMMARY,
  ListPatchesResponseSchema,
  PatchModeResponseSchema,
  type PatchSummary,
  PatchSummarySchema,
  SetPatchModeRequestSchema,
} from "../src/index.ts";

describe("patch API schemas", () => {
  it("accepts the documented example, and the list and mode responses that carry it", () => {
    expect(PatchSummarySchema.parse(EXAMPLE_PATCH_SUMMARY)).toEqual(EXAMPLE_PATCH_SUMMARY);
    expect(ListPatchesResponseSchema.parse({ patches: [EXAMPLE_PATCH_SUMMARY] })).toEqual({
      patches: [EXAMPLE_PATCH_SUMMARY],
    });
    expect(PatchModeResponseSchema.parse({ patch: EXAMPLE_PATCH_SUMMARY })).toEqual({ patch: EXAMPLE_PATCH_SUMMARY });
  });

  it("accepts an inactive patch without Findings or hits", () => {
    const inactive: PatchSummary = {
      ...EXAMPLE_PATCH_SUMMARY,
      active: false,
      shipped: false,
      findings: [],
      hits_24h: 0,
      last_hit: null,
    };
    expect(PatchSummarySchema.parse(inactive)).toEqual(inactive);
  });

  it("refuses bad members", () => {
    const bad: Record<string, unknown>[] = [
      { id: "patch" },
      { title: "" },
      { advisories: [] },
      { advisories: ["not an advisory"] },
      { package: "" },
      { mode: "block" },
      { active: "yes" },
      { findings: ["fnd_x"] },
      { hits_24h: -1 },
      { hits_24h: 1.5 },
      { last_hit: "yesterday" },
    ];
    for (const change of bad)
      expect(PatchSummarySchema.safeParse({ ...EXAMPLE_PATCH_SUMMARY, ...change }).success).toBe(false);
  });

  it("strips unknown members", () => {
    expect(PatchSummarySchema.parse({ ...EXAMPLE_PATCH_SUMMARY, secret: 1 })).toEqual(EXAMPLE_PATCH_SUMMARY);
  });

  it("takes a mode change: environment and mode, confirm optional (the API checks it against the patch id)", () => {
    expect(SetPatchModeRequestSchema.parse({ environment: "production", mode: "monitor" })).toEqual({
      environment: "production",
      mode: "monitor",
    });
    expect(
      SetPatchModeRequestSchema.parse({ environment: "staging", mode: "enforce", confirm: "vp_example_parser_proto" }),
    ).toEqual({ environment: "staging", mode: "enforce", confirm: "vp_example_parser_proto" });
    for (const body of [
      { environment: "prod", mode: "monitor" },
      { environment: "production", mode: "block" },
      { environment: "production", mode: "enforce", confirm: "x".repeat(65) },
      { mode: "monitor" },
    ]) {
      expect(SetPatchModeRequestSchema.safeParse(body).success).toBe(false);
    }
  });
});
