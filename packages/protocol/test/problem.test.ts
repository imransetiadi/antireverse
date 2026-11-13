import { describe, expect, it } from "vitest";
import {
  CONFLICT_REASONS,
  type ConflictReason,
  CreateAppRequestSchema,
  CreateOrganizationRequestSchema,
  EventBatchSchema,
  EXAMPLE_EVENT_BATCH,
  EXAMPLE_SHIELD_EVENT,
  type Problem,
  type ProblemError,
  ProblemSchema,
  toProblemErrors,
} from "../src/index.ts";

const errorsOf = (schema: { safeParse(value: unknown): unknown }, value: unknown): ProblemError[] => {
  const result = schema.safeParse(value) as ReturnType<typeof EventBatchSchema.safeParse>;
  if (result.success) throw new Error("expected the value to be rejected");
  return toProblemErrors(result.error);
};

describe("ProblemSchema", () => {
  it("parses a problem document with and without the optional members", () => {
    const minimal: Problem = { type: "about:blank", title: "Not found", status: 404 };
    const full: Problem = {
      type: "https://antireverse.dev/problems/validation",
      title: "Invalid request",
      status: 400,
      detail: "The request body is not valid.",
      errors: [{ path: "name", message: "Too small: expected string to have >=1 characters" }],
    };
    expect(ProblemSchema.parse(minimal)).toEqual(minimal);
    expect(ProblemSchema.parse({ ...full, stack: "synthetic" })).toEqual(full);
  });

  it("rejects a document without title or with a status outside 100..599", () => {
    expect(ProblemSchema.safeParse({ type: "about:blank", status: 404 }).success).toBe(false);
    expect(ProblemSchema.safeParse({ type: "about:blank", title: "x", status: 99 }).success).toBe(false);
    expect(ProblemSchema.safeParse({ type: "about:blank", title: "x", status: 600 }).success).toBe(false);
    expect(
      ProblemSchema.safeParse({ type: "about:blank", title: "x", status: 400, errors: [{ path: 1 }] }).success,
    ).toBe(false);
  });
});

describe("toProblemErrors", () => {
  it("joins the path of a nested issue with dots", () => {
    const invalid = { ...EXAMPLE_SHIELD_EVENT, request: { ...EXAMPLE_SHIELD_EVENT.request, status: 600 } };
    const errors = errorsOf(EventBatchSchema, { ...EXAMPLE_EVENT_BATCH, events: [EXAMPLE_SHIELD_EVENT, invalid] });
    expect(errors).toHaveLength(1);
    expect(errors[0]?.path).toBe("events.1.request.status");
    expect(errors[0]?.message).toEqual(expect.any(String));
    expect(errors[0]?.message).not.toBe("");
  });

  it("uses the member name for a top-level issue and an empty path for the document itself", () => {
    expect(errorsOf(CreateOrganizationRequestSchema, { name: "" }).map((error) => error.path)).toEqual(["name"]);
    expect(errorsOf(CreateOrganizationRequestSchema, undefined).map((error) => error.path)).toEqual([""]);
  });

  it("returns one entry per issue, in order, with only path and message", () => {
    const errors = errorsOf(CreateAppRequestSchema, { name: "", environment: "qa" });
    expect(errors.map((error) => error.path)).toEqual(["name", "environment"]);
    for (const error of errors) expect(Object.keys(error).sort()).toEqual(["message", "path"]);
    expect(
      ProblemSchema.safeParse({ type: "about:blank", title: "Invalid request", status: 400, errors }).success,
    ).toBe(true);
  });

  it("never repeats the rejected value in a message", () => {
    const secret = "synthetic-secret-value";
    const messages = [
      ...errorsOf(CreateOrganizationRequestSchema, { name: secret.repeat(5) }),
      ...errorsOf(CreateAppRequestSchema, { name: "Storefront", environment: secret }),
      ...errorsOf(EventBatchSchema, {
        ...EXAMPLE_EVENT_BATCH,
        events: [{ ...EXAMPLE_SHIELD_EVENT, event_id: secret }],
      }),
      ...errorsOf(EventBatchSchema, { ...EXAMPLE_EVENT_BATCH, events: [{ ...EXAMPLE_SHIELD_EVENT, type: secret }] }),
    ].map((error) => error.message);
    expect(messages).toHaveLength(4);
    for (const message of messages) expect(message).not.toContain("synthetic-secret");
  });
});

describe("conflict reasons", () => {
  const conflict = {
    type: "https://antireverse.dev/problems/conflict",
    title: "Conflict",
    status: 409,
    detail: "The block has already expired or been lifted.",
  };

  it("names every reason a 409 can carry, once", () => {
    expect(CONFLICT_REASONS).toEqual([
      "incident-resolved",
      "actor-unknown",
      "prefix-allowlisted",
      "containment-limit",
      "containment-ended",
      "allowlist-duplicate",
      "allowlist-limit",
      "beacon-token-taken",
      "containment-not-applicable",
      "target-in-scope",
      "target-limit",
      "target-duplicate",
      "smtp-not-configured",
      "recipient-confirmed",
      "no-confirmed-recipients",
    ]);
    expect(Object.isFrozen(CONFLICT_REASONS)).toBe(true);
  });

  it("accepts a problem with a known reason, keeps problems without one valid, and refuses an unknown reason", () => {
    for (const reason of CONFLICT_REASONS) {
      const problem: Problem = { ...conflict, reason };
      expect(ProblemSchema.parse(problem)).toEqual(problem);
      const typed: ConflictReason | undefined = ProblemSchema.parse(problem).reason;
      expect(typed).toBe(reason);
    }
    expect(ProblemSchema.parse(conflict)).toEqual(conflict);
    expect(ProblemSchema.parse(conflict)).not.toHaveProperty("reason");
    expect(ProblemSchema.safeParse({ ...conflict, reason: "something-else" }).success).toBe(false);
    expect(ProblemSchema.safeParse({ ...conflict, reason: null }).success).toBe(false);
  });
});
