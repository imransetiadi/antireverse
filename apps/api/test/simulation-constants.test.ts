import { describe, expect, it } from "vitest";
// Shield's own constants, read from its source: the replay and the route copy them, since the API imports no
// Shield code at run time.
import { LATENCY_MAX_MS as SHIELD_LATENCY_MAX_MS } from "../../../packages/shield-node/src/express.ts";
import { LIMIT_SLOT_HOLD_MS } from "../../../packages/shield-node/src/limits.ts";
import { LATENCY_MAX_MS as ROUTE_LATENCY_MAX_MS } from "../src/routes/simulate.ts";
import { LATENCY_MAX_MS, SLOT_HOLD_MS } from "../src/simulate/replay.ts";

describe("the simulation's copies of Shield's constants", () => {
  it("equal Shield's latency cap and failure slot hold (D-071)", () => {
    expect(LATENCY_MAX_MS).toBe(SHIELD_LATENCY_MAX_MS);
    expect(ROUTE_LATENCY_MAX_MS).toBe(SHIELD_LATENCY_MAX_MS);
    expect(SLOT_HOLD_MS).toBe(LIMIT_SLOT_HOLD_MS);
  });
});
