// Usage of the stand-in API (slice 17a), in the shape of the protocol (checked by test/stub-usage.test.ts):
// `GET /v1/usage?month=YYYY-MM`, the current UTC month by default. As in the API: the month's form is validated first
// (400 on `month`), then its range (the current month and the 13 before it), then one read is taken from the
// Organization's budget that audit verification and the exports share (429 too-many-requests with Retry-After). No
// metering runs here: each App's figures are made up from its id and the day, the same on every read, none after
// today. Apps are listed oldest first, as the API lists them.
import {
  sandboxMinutes,
  USAGE_SEATS_NOTE,
  UsageQuerySchema,
  usageMonthOf,
  usageMonthRefusal,
} from "@antireverse/protocol";

const PROBLEMS = "https://antireverse.dev/problems/";

const problem = (status, kind, title, extra = {}) => ({
  status,
  body: { type: `${PROBLEMS}${kind}`, title, status, ...extra },
});
const invalid = (errors) => problem(400, "validation", "Invalid request", { errors });

/** A stable number in [0, 1) from a text: the same App and day always give the same figure. */
function unit(text) {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) / 2 ** 32;
}

/**
 * @param {{
 *   now?: () => number,
 *   apps: (organizationId: string) => { id: string, name: string, created_at: string }[],
 *   eventRetentionDays: (organizationId: string) => number,
 *   takeRead: (organizationId: string) => { allowed: boolean, retryAfterS: number },
 * }} deps
 */
export function createUsageStore({ now = () => Date.now(), apps, eventRetentionDays, takeRead }) {
  /** The body of `GET /v1/usage` for a month that can be read. */
  function usageOf(organizationId, month, at) {
    const today = at.toISOString().slice(0, 10);
    const year = Number(month.slice(0, 4));
    const length = new Date(Date.UTC(year, Number(month.slice(5, 7)), 0)).getUTCDate();
    const days = Array.from({ length }, (_, i) => `${month}-${String(i + 1).padStart(2, "0")}`);
    const listed = [...apps(organizationId)].sort(
      (a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id),
    );
    const perDay = new Map(days.map((day) => [day, 0]));
    const perApp = listed.map((app, index) => {
      let requests = 0;
      for (const day of days) {
        if (day > today) continue;
        const count = Math.floor(unit(`${app.id}:${day}`) * 2000);
        requests += count;
        perDay.set(day, (perDay.get(day) ?? 0) + count);
      }
      const guard_devices = Math.floor(unit(`${app.id}:${month}:devices`) * 600);
      // Every second App ran no Assessment, so a zero shows too.
      const sandbox_seconds = index % 2 === 0 ? Math.floor(unit(`${app.id}:${month}:sandbox`) * 6000) : 0;
      return {
        app_id: app.id,
        name: app.name,
        requests,
        guard_devices,
        // The stub records far fewer than USAGE_DEVICE_DAILY_CAP new devices a day: never capped.
        guard_devices_capped: false,
        sandbox_seconds,
        sandbox_minutes: sandboxMinutes(sandbox_seconds),
      };
    });
    const sum = (key) => perApp.reduce((total, app) => total + app[key], 0);
    return {
      month,
      closed: month < usageMonthOf(at),
      totals: {
        requests: sum("requests"),
        guard_devices: sum("guard_devices"),
        guard_devices_capped: perApp.some((app) => app.guard_devices_capped),
        sandbox_seconds: sum("sandbox_seconds"),
        // The sum of the Apps' minutes, so the parts add up (to the hundredth).
        sandbox_minutes: Math.round(sum("sandbox_minutes") * 100) / 100,
      },
      apps: perApp,
      daily: days.map((day) => ({ day, requests: perDay.get(day) ?? 0 })),
      apps_count: listed.length,
      event_retention_days: eventRetentionDays(organizationId),
      seats: null,
      seats_note: USAGE_SEATS_NOTE,
    };
  }

  return {
    /** `GET /v1/usage`; null for any other request. */
    handle(organizationId, method, path, searchParams) {
      if (path !== "/v1/usage" || method !== "GET") return null;
      // As Hono reads a query: a repeated key is an array, which the schema refuses (400 on `month`).
      const query = {};
      for (const key of new Set(searchParams.keys())) {
        const values = searchParams.getAll(key);
        query[key] = values.length > 1 ? values : values[0];
      }
      const read = UsageQuerySchema.safeParse(query);
      if (!read.success) {
        return invalid(read.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })));
      }
      const at = new Date(now());
      const month = read.data.month ?? usageMonthOf(at);
      const refusal = usageMonthRefusal(month, at);
      if (refusal !== null) return invalid([{ path: "month", message: refusal }]);
      const taken = takeRead(organizationId);
      if (!taken.allowed) {
        return {
          ...problem(429, "too-many-requests", "Too many requests", {
            detail: "Too many reads for this Organization. Try again after the time in Retry-After.",
          }),
          headers: { "retry-after": String(taken.retryAfterS) },
        };
      }
      return { status: 200, body: usageOf(organizationId, month, at) };
    },
  };
}
