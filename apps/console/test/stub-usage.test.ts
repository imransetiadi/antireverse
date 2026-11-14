// @vitest-environment node
import { ProblemSchema, UsageQuerySchema, UsageResponseSchema } from "@antireverse/protocol";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { validateQuery } from "../../api/src/validate.ts";
import { createUsageStore } from "../scripts/stub-usage.mjs";

// Slice 17a: the stand-in API answers `GET /v1/usage` in the shape of the protocol and in the API's order — the month's
// form first, then its range, then the shared read budget — so that the Console can be looked at against it.

const ORG = "org_0123456789abcdef01234567";
const T0 = Date.parse("2026-11-14T09:00:00.000Z");
const APPS = [
  // Newest first, as the stub keeps them; the API lists the oldest first.
  { id: "app_89abcdef0123456789abcdef", name: "Back office", created_at: "2026-11-02T00:00:00.000Z" },
  { id: "app_0123456789abcdef01234567", name: "Storefront", created_at: "2026-11-01T00:00:00.000Z" },
];

interface Answer {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

function store(options: { allowed?: boolean; apps?: typeof APPS } = {}) {
  let reads = 0;
  const usage = createUsageStore({
    now: () => T0,
    apps: () => options.apps ?? APPS,
    eventRetentionDays: () => 90,
    takeRead: () => {
      reads += 1;
      return options.allowed === false ? { allowed: false, retryAfterS: 17 } : { allowed: true, retryAfterS: 0 };
    },
  });
  const get = (query = ""): Answer => {
    const answer = usage.handle(ORG, "GET", "/v1/usage", new URLSearchParams(query));
    if (answer === null) throw new Error("no answer");
    return answer as Answer;
  };
  return { usage, get, reads: () => reads };
}
const problemOf = (answer: Answer) => ProblemSchema.parse(answer.body);

describe("stub usage", () => {
  it("answers the current month by default: every App (oldest first), every day, the totals adding up", () => {
    const { get } = store();
    const answer = get();
    expect(answer.status).toBe(200);
    const body = UsageResponseSchema.parse(answer.body);
    expect(body.month).toBe("2026-11");
    expect(body.closed).toBe(false);
    expect(body.apps.map((app) => app.name)).toEqual(["Storefront", "Back office"]);
    expect(body.daily).toHaveLength(30);
    expect(body.daily[0]?.day).toBe("2026-11-01");
    // Nothing after today.
    expect(body.daily.slice(14).every((day) => day.requests === 0)).toBe(true);
    expect(body.daily.slice(0, 14).some((day) => day.requests > 0)).toBe(true);
    const sum = (key: "requests" | "guard_devices" | "sandbox_seconds") =>
      body.apps.reduce((total, app) => total + app[key], 0);
    expect(body.totals.requests).toBe(sum("requests"));
    expect(body.totals.requests).toBe(body.daily.reduce((total, day) => total + day.requests, 0));
    expect(body.totals.guard_devices).toBe(sum("guard_devices"));
    expect(body.totals.sandbox_seconds).toBe(sum("sandbox_seconds"));
    // The totals' minutes are the sum of the Apps' minutes, so the parts add up; nothing is capped here.
    expect(body.totals.sandbox_minutes).toBe(
      Math.round(body.apps.reduce((total, app) => total + app.sandbox_minutes, 0) * 100) / 100,
    );
    expect(body.totals.guard_devices_capped).toBe(false);
    expect(body.apps.every((app) => app.guard_devices_capped === false)).toBe(true);
    expect(body).toMatchObject({ apps_count: 2, event_retention_days: 90, seats: null, seats_note: "not applicable" });
  });

  it("answers a closed month the same each time, and an empty one without Apps", () => {
    const { get } = store();
    const october = UsageResponseSchema.parse(get("month=2026-10").body);
    expect(october.closed).toBe(true);
    expect(october.daily).toHaveLength(31);
    expect(UsageResponseSchema.parse(get("month=2026-10").body)).toEqual(october);
    const none = UsageResponseSchema.parse(store({ apps: [] }).get("month=2026-10").body);
    expect(none.apps).toEqual([]);
    expect(none.totals.requests).toBe(0);
  });

  it("refuses a malformed month, then one out of range, before it takes a read", () => {
    const { get, reads } = store();
    const malformed = get("month=2026-13");
    expect(malformed.status).toBe(400);
    expect(problemOf(malformed).errors).toEqual([{ path: "month", message: "Expected a month as YYYY-MM." }]);
    const future = get("month=2026-12");
    expect(problemOf(future).errors).toEqual([{ path: "month", message: "The month is in the future." }]);
    const old = get("month=2025-09");
    expect(problemOf(old).errors).toEqual([{ path: "month", message: "The month is older than 13 months." }]);
    expect(get("month=2025-10").status).toBe(200);
    expect(reads()).toBe(1);
  });

  it("refuses a repeated month as the API's own query validation does (review 17a, L2)", async () => {
    const api = new Hono().get("/v1/usage", validateQuery(UsageQuerySchema), (c) => c.json({}));
    for (const query of ["month=2026-10&month=2026-11", "month=2026-11&month=2026-11"]) {
      const real = await api.request(`/v1/usage?${query}`);
      expect(real.status).toBe(400);
      const { get, reads } = store();
      const stub = get(query);
      expect(stub.status).toBe(400);
      expect(problemOf(stub).errors).toEqual(ProblemSchema.parse(await real.json()).errors);
      expect(reads()).toBe(0);
    }
  });

  it("answers 429 with Retry-After when the Organization's reads are spent", () => {
    const answer = store({ allowed: false }).get();
    expect(answer.status).toBe(429);
    expect(problemOf(answer).type).toBe("https://antireverse.dev/problems/too-many-requests");
    expect(problemOf(answer).detail).toBe(
      "Too many reads for this Organization. Try again after the time in Retry-After.",
    );
    expect(answer.headers).toEqual({ "retry-after": "17" });
  });

  it("answers nothing for another route or method (the stub then answers 404)", () => {
    const { usage } = store();
    expect(usage.handle(ORG, "GET", "/v1/usagex", new URLSearchParams())).toBeNull();
    expect(usage.handle(ORG, "POST", "/v1/usage", new URLSearchParams())).toBeNull();
  });
});
