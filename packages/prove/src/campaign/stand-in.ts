// The scripted stand-in engine of Pentest Campaigns (slice 15a, D-105). It runs a fixed, reviewed catalog of
// harmless GET probes against the seeded weaknesses of the reference target (ar-range) and reports what it sees. It
// measures the pipeline and its safety controls. It is not a penetration test: it has no AI model, it follows no link,
// it reads no instruction from a response, and what it asks for never depends on what a target answered — only
// whether it repeats a probe once does.
//
// Its only capability is `request({ method, path, query })`: there is no way to name a host, a scheme, a port, a body,
// a header or a cookie. The API's request gate decides whether a probe is sent at all.
import {
  type CampaignEngine,
  type CampaignExchange,
  type CampaignIntensity,
  type CampaignProbe,
  type CampaignSeverity,
  INTENSITIES,
  STAND_IN_ENGINE,
} from "@antireverse/protocol";

/** Inert text: it is neither markup that runs nor an instruction. Reflected unencoded, it shows missing encoding. */
export const STAND_IN_MARKER = '"><airverse-probe-marker>';
/** A URL on a host that can never resolve (`.invalid`, RFC 2606). The redirect to it is reported, never followed. */
export const STAND_IN_REDIRECT = "https://redirect-check.airverse.invalid/landing";

type Answered = Extract<CampaignExchange, { ok: true }>;

export interface StandInCheck {
  readonly id: string;
  readonly title: string;
  readonly severity: CampaignSeverity;
  /** The least intensity at which the check runs. */
  readonly intensity: CampaignIntensity;
  readonly probe: CampaignProbe;
  /**
   * Whether the check reads the response's body. If it does and the body was withheld (not text) or cut at the read
   * cap without showing the weakness, the check cannot tell: it is inconclusive, never clean.
   */
  readonly readsBody: boolean;
  /** Where in the (redacted) body the evidence starts, or null when the response does not show the weakness. */
  detect(exchange: Answered): number | null;
}

// A stack frame as Node prints it: a line of spaces, `at`, a name and `(file:line:column)`. Every part is bounded and
// no part can match a line break, so a hostile body costs linear time.
const STACK_FRAME = /\n[ \t]{1,16}at [^\s()]{1,200} \([^\s()]{1,400}:\d{1,7}:\d{1,7}\)/;

const SECURITY_HEADERS = ["content-security-policy", "x-content-type-options", "x-frame-options"] as const;

function freeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const member of Object.values(value)) freeze(member);
  }
  return value;
}

const at = (body: string, needle: string | RegExp): number | null => {
  const index = typeof needle === "string" ? body.indexOf(needle) : body.search(needle);
  return index === -1 ? null : index;
};

/** The whole catalog. Changing it is a reviewed change: a test pins every probe. */
export const STAND_IN_CATALOG: readonly StandInCheck[] = freeze([
  {
    id: "RW-01",
    title: "Missing security headers",
    severity: "low",
    intensity: "passive",
    probe: { method: "GET", path: "/" },
    readsBody: false,
    detect: (exchange) =>
      exchange.status === 200 && SECURITY_HEADERS.some((name) => exchange.headers[name] === undefined) ? 0 : null,
  },
  {
    id: "RW-02",
    title: "Error with a stack trace",
    severity: "medium",
    intensity: "safe-active",
    probe: { method: "GET", path: "/api/orders/x" },
    readsBody: true,
    detect: (exchange) => (exchange.status >= 500 ? at(exchange.body, STACK_FRAME) : null),
  },
  {
    id: "RW-03",
    title: "Admin data without authentication",
    severity: "high",
    intensity: "safe-active",
    probe: { method: "GET", path: "/api/admin/reports" },
    readsBody: true,
    detect: (exchange) => (exchange.status === 200 ? at(exchange.body, '"reports"') : null),
  },
  {
    id: "RW-04",
    title: "Synthetic order readable by a guessable id",
    severity: "high",
    intensity: "safe-active",
    probe: { method: "GET", path: "/api/orders/1001" },
    readsBody: true,
    detect: (exchange) => (exchange.status === 200 ? at(exchange.body, '"order_id"') : null),
  },
  {
    id: "RW-05",
    title: "Marker reflected unencoded",
    severity: "medium",
    intensity: "safe-active",
    probe: { method: "GET", path: "/search", query: { q: STAND_IN_MARKER } },
    readsBody: true,
    detect: (exchange) => (exchange.status === 200 ? at(exchange.body, STAND_IN_MARKER) : null),
  },
  {
    id: "RW-06",
    title: "Redirect to another host",
    severity: "low",
    intensity: "safe-active",
    probe: { method: "GET", path: "/go", query: { to: STAND_IN_REDIRECT } },
    readsBody: false,
    detect: (exchange) =>
      exchange.status >= 300 && exchange.status < 400 && exchange.location === "other-host" ? 0 : null,
  },
] satisfies StandInCheck[]);

/**
 * What a check came to: it reported a Finding, it ran and found nothing, it got an answer it could not read
 * (inconclusive), or it did not run (or got no answer).
 */
export interface EngineCheck {
  id: string;
  result: "reported" | "clean" | "inconclusive" | "skipped";
}

/** A Finding as the engine reports it: which sent request shows it (`seq`) and where in its body (`at`). */
export interface EngineFinding {
  check_id: string;
  path: string;
  title: string;
  severity: CampaignSeverity;
  seq: number;
  at: number;
}

/** Everything an engine can do. */
export interface EngineContext {
  readonly intensity: CampaignIntensity;
  request(probe: CampaignProbe): Promise<CampaignExchange>;
  check(check: EngineCheck): void;
  finding(finding: EngineFinding): void;
}

/** An engine: its tag and its run. */
export interface CampaignEngineModule {
  readonly tag: CampaignEngine;
  /** The ids of every check it may run, for a report's count of skipped checks. */
  readonly checks: readonly string[];
  run(context: EngineContext): Promise<void>;
}

/**
 * Runs the catalog in order. A check above the Campaign's intensity is skipped without a request. A probe that is
 * refused or gets no answer skips its check; a fatal refusal ends the run at once. A response that shows the weakness
 * is reported as a Finding and the same probe is sent once more: if it shows again, it is reported again (which is
 * what confirms it).
 */
export async function runStandIn(context: EngineContext): Promise<void> {
  const allowed = INTENSITIES.indexOf(context.intensity);
  for (const check of STAND_IN_CATALOG) {
    if (INTENSITIES.indexOf(check.intensity) > allowed) {
      context.check({ id: check.id, result: "skipped" });
      continue;
    }
    const report = (exchange: Answered, position: number): void =>
      context.finding({
        check_id: check.id,
        path: check.probe.path,
        title: check.title,
        severity: check.severity,
        seq: exchange.seq,
        at: position,
      });
    const first = await context.request(check.probe);
    if (!first.ok) {
      if ("refused" in first && first.fatal) return;
      context.check({ id: check.id, result: "skipped" });
      continue;
    }
    const seen = check.detect(first);
    if (seen === null) {
      const unread = check.readsBody && (first.withheld || first.truncated);
      context.check({ id: check.id, result: unread ? "inconclusive" : "clean" });
      continue;
    }
    report(first, seen);
    const repeat = await context.request(check.probe);
    if (!repeat.ok && "refused" in repeat && repeat.fatal) {
      context.check({ id: check.id, result: "reported" });
      return;
    }
    if (repeat.ok) {
      const again = check.detect(repeat);
      if (again !== null) report(repeat, again);
    }
    context.check({ id: check.id, result: "reported" });
  }
}

export const standInEngine: CampaignEngineModule = Object.freeze({
  tag: STAND_IN_ENGINE,
  checks: Object.freeze(STAND_IN_CATALOG.map((check) => check.id)),
  run: runStandIn,
});
