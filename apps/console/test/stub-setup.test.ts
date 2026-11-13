// @vitest-environment node
import { AppSetupResponseSchema } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createSetupStore } from "../scripts/stub-setup.mjs";

// The stand-in API answers `GET /v1/apps/:appId/setup` (slice 16) with a body the protocol accepts, dated as the API
// dates it: Shield at the first Event, Guard at the first Event with a valid attestation (whatever the verdict),
// Harden at the first registered Build — each per Environment, and never moved later by what comes after.

const APP = "app_0123456789abcdef01234567";
const event = (at: string, environment: string, attestation: unknown = null) => ({
  app_id: APP,
  environment,
  received_at: at,
  attestation,
});
const build = (at: string, environment: string) => ({ environment, registered_at: at });

describe("createSetupStore", () => {
  it("answers with nothing done for an App that has seen nothing, in a shape the protocol accepts", () => {
    const store = createSetupStore();
    const body = { setup: store.setup(APP, "development", []) };
    const parsed = AppSetupResponseSchema.safeParse(body);
    expect(parsed.success ? [] : parsed.error.issues).toEqual([]);
    expect(parsed.data).toEqual({
      setup: {
        environment: "development",
        shield: { done_at: null },
        guard: { done_at: null },
        harden: { done_at: null },
      },
    });
  });

  it("dates Shield at the first Event and Guard at the first valid attestation of the Environment", () => {
    const store = createSetupStore();
    store.recordEvent(
      event("2026-11-13T09:00:00.000Z", "production", { status: "valid", verdict: "trusted", risk: 5 }),
    );
    store.recordEvent(event("2026-11-13T09:00:01.000Z", "development", null));
    store.recordEvent(
      event("2026-11-13T09:00:02.000Z", "development", { status: "invalid", verdict: null, risk: null }),
    );
    store.recordEvent(
      event("2026-11-13T09:00:03.000Z", "development", { status: "valid", verdict: "hostile", risk: 100 }),
    );
    store.recordEvent(
      event("2026-11-13T09:00:04.000Z", "development", { status: "valid", verdict: "trusted", risk: 5 }),
    );

    const setup = store.setup(APP, "development", []);
    expect(setup.shield.done_at).toBe("2026-11-13T09:00:01.000Z");
    // Any valid attestation counts, whatever its verdict.
    expect(setup.guard.done_at).toBe("2026-11-13T09:00:03.000Z");
    expect(store.setup(APP, "production", []).guard.done_at).toBe("2026-11-13T09:00:00.000Z");
    expect(store.setup(APP, "staging", []).shield.done_at).toBeNull();
  });

  it("dates Harden at the earliest registered Build of the Environment", () => {
    const store = createSetupStore();
    const builds = [
      build("2026-11-13T08:00:00.000Z", "development"),
      build("2026-11-12T08:00:00.000Z", "development"),
      build("2026-11-11T08:00:00.000Z", "production"),
    ];
    expect(store.setup(APP, "development", builds).harden.done_at).toBe("2026-11-12T08:00:00.000Z");
    expect(store.setup(APP, "staging", builds).harden.done_at).toBeNull();
    const parsed = AppSetupResponseSchema.safeParse({ setup: store.setup(APP, "development", builds) });
    expect(parsed.success).toBe(true);
  });
});
