// Operator SLOs of the stand-in API (slice 18d), in the shape of the protocol (checked by test/stub-ops.test.ts):
// `GET /v1/ops/slo` with `Authorization: Bearer <token>`. As in the API: without an operator token configured
// (`AR_STUB_OPS_TOKEN` unset) it answers 404; any other bearer, an admin key included, gets 401; the token is compared
// over SHA-256 digests in constant time and never logged. The figures are made up to show every state of the
// dashboard: SLO-01 healthy, SLO-04 below its objective with nothing firing, SLO-02 overspent with the slow page and the ticket firing, SLO-05 firing the fast page with
// a missed latency target, SLO-10 without traffic yet, SLO-06 and SLO-08 not measured.
import { createHash, timingSafeEqual } from "node:crypto";
import { SLO_BURN_RULES, SLO_CATALOG } from "@antireverse/protocol";

const PROBLEMS = "https://antireverse.dev/problems/";
/** The API's own problem documents of these two refusals (apps/api/src/problem.ts), word for word. */
const NOT_FOUND = {
  status: 404,
  body: { type: `${PROBLEMS}not-found`, title: "Not found", status: 404, detail: "The resource does not exist." },
};
const UNAUTHORIZED = {
  status: 401,
  body: {
    type: `${PROBLEMS}unauthorized`,
    title: "Unauthorized",
    status: 401,
    detail: "A valid key is required. Send it as: Authorization: Bearer <key>.",
  },
  headers: { "www-authenticate": "Bearer" },
};
const digest = (text) => createHash("sha256").update(text, "utf8").digest();

/** The figures of one measured SLO: `good` of `total`, burn per window, latency per target, firing rules since when. */
function measured(def, { good, total, burn, observed = (ms) => Math.round(ms / 2), firing = {} }) {
  const attainment = total === 0 ? null : good / total;
  const budget = 1 - def.objective;
  return {
    good,
    total,
    attainment,
    budget_remaining: attainment === null ? null : 1 - (1 - attainment) / budget,
    burn,
    latency: def.latency_targets.map((target) => {
      const ms = total === 0 ? null : observed(target.ms);
      return {
        variant: target.variant,
        percentile: target.percentile,
        target_ms: target.ms,
        observed_ms: ms,
        met: ms === null ? null : ms <= target.ms,
      };
    }),
    alerts: SLO_BURN_RULES.map((rule) => ({
      rule: rule.id,
      severity: rule.severity,
      state: firing[rule.id] === undefined ? "ok" : "firing",
      since: firing[rule.id] ?? null,
    })),
  };
}

const QUIET = { "5m": 0, "30m": 0.2, "1h": 0.1, "6h": 0.3, "3d": 0.4 };
const NONE = { "5m": null, "30m": null, "1h": null, "6h": null, "3d": null };

/** @param {{ token: string | undefined, now?: () => number }} options */
export function createOpsStore({ token, now = () => Date.now() }) {
  const expected = token ? digest(token) : undefined;

  function report() {
    const at = now();
    const ago = (minutes) => new Date(at - minutes * 60_000).toISOString();
    const figures = {
      "SLO-01": { good: 1_999_900, total: 2_000_000, burn: QUIET },
      "SLO-02": {
        good: 4_990_000,
        total: 5_000_000,
        burn: { "5m": 3.2, "30m": 7.5, "1h": 6.8, "6h": 6.4, "3d": 2.1 },
        firing: { slow: ago(95), ticket: ago(60 * 20) },
      },
      "SLO-03": { good: 120_000, total: 120_000, burn: { "5m": 0, "30m": 0, "1h": 0, "6h": 0, "3d": 0 } },
      "SLO-04": { good: 4_900_000, total: 5_000_000, burn: QUIET },
      "SLO-05": {
        good: 9_200,
        total: 10_000,
        burn: { "5m": 18, "30m": 16, "1h": 15.2, "6h": 4.1, "3d": 0.9 },
        observed: (ms) => ms * 3,
        firing: { fast: ago(12) },
      },
      "SLO-07": { good: 49_990, total: 50_000, burn: QUIET, observed: (ms) => (ms === 500 ? 750 : 150) },
      "SLO-09": { good: 40, total: 40, burn: { "5m": null, "30m": null, "1h": 0, "6h": 0, "3d": 0 } },
      "SLO-10": { good: 0, total: 0, burn: NONE },
    };
    return {
      generated_at: new Date(at).toISOString(),
      window_days: 30,
      scope: "instance",
      // Slice 18g: the stand-in runs no synthetic probes, so SLO-06 is not measured, as on an API without AR_PROBES=1.
      probes: null,
      slos: SLO_CATALOG.map((def) => ({
        id: def.id,
        name: def.name,
        indicator: def.indicator,
        objective: def.objective,
        measured: def.measured,
        not_measured_reason: def.not_measured_reason,
        runbook: def.runbook,
        ...(def.measured
          ? measured(def, figures[def.id] ?? { good: 0, total: 0, burn: NONE })
          : { good: 0, total: 0, attainment: null, budget_remaining: null, burn: NONE, latency: [], alerts: [] }),
      })),
    };
  }

  return {
    /** The answer to `method path`, or null when it is not an operator route. */
    handle(method, path, authorization) {
      if (method !== "GET" || path !== "/v1/ops/slo") return null;
      if (expected === undefined) return NOT_FOUND;
      const presented = /^Bearer (\S+)$/i.exec(authorization ?? "")?.[1];
      if (presented === undefined || !timingSafeEqual(digest(presented), expected)) {
        return UNAUTHORIZED;
      }
      return { status: 200, body: report() };
    },
  };
}
