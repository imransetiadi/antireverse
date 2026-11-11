// Canaries in use (slice 07, observe only). A request that carries a decoy key or asks for a decoy route adds the
// signal `canary.touched:<cny id>` to its Event. The decoy value is compared inside the process and never leaves
// it: only the Canary id goes into the signal. Nothing here changes the request or the response, and nothing logs.
//
// Every comparison is an exact lookup in a Map built once per applied bundle: the cost does not grow with the
// number of Canaries.
import { canonicalPaths, normalisePath } from "./policy/match.ts";
import type { AppliedPolicy } from "./policy/store.ts";

/** Equal to `CANARY_SIGNAL_PREFIX` of the protocol (pinned by a test). */
export const CANARY_SIGNAL_PREFIX = "canary.touched:";
/** Signals of an Event at most. Equal to the bound of `ShieldEventSchema.signals` of the protocol. */
export const SIGNALS_MAX = 32;

export interface Signal {
  id: string;
  confidence: number;
}

/** The parts of a request Canaries are read from: headers (names in lower case, as node:http gives them) and URL. */
export interface CanaryRequest {
  headers?: Record<string, string | string[] | undefined>;
  url?: unknown;
  originalUrl?: unknown;
}

/**
 * The token of `Bearer <token>`: the scheme in any case (RFC 9110: the scheme is case-insensitive), then one or
 * more spaces or tabs, then the token up to trailing spaces and tabs. The token itself is compared exactly.
 */
function bearerToken(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length < 8) return undefined;
  let at = 6;
  let code = value.charCodeAt(at);
  if (code !== 32 && code !== 9) return undefined;
  if (value.slice(0, 6).toLowerCase() !== "bearer") return undefined;
  while (code === 32 || code === 9) code = value.charCodeAt(++at);
  let end = value.length;
  const isSpace = (c: number): boolean => c === 32 || c === 9;
  while (end > at && isSpace(value.charCodeAt(end - 1))) end -= 1;
  return end > at ? value.slice(at, end) : undefined;
}

/**
 * `text` with A-Z in lower case and every other character as it is; `text` itself when it has no upper-case
 * letter. ASCII only, as Rules compare: `toLowerCase` would also fold characters such as the Kelvin sign into `k`.
 */
function asciiLower(text: string): string {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 65 && code <= 90) return text.replace(/[A-Z]+/g, (run) => run.toLowerCase());
  }
  return text;
}

/** The query string of the request target, without `?`, or undefined. */
function queryOf(request: CanaryRequest): string | undefined {
  const url = typeof request.originalUrl === "string" ? request.originalUrl : request.url;
  if (typeof url !== "string") return undefined;
  const at = url.indexOf("?");
  if (at === -1) return undefined;
  const hash = url.indexOf("#", at);
  return hash === -1 ? url.slice(at + 1) : url.slice(at + 1, hash);
}

/**
 * The Canary signals of one request under `policy`, deduplicated, at most `SIGNALS_MAX`, in the order keys
 * (bearer token, `x-api-key`, `api_key`) then route. `path` is the path Rules are matched against (without the
 * query string under Express; the request URL without Express). Empty, without allocating a lookup, when the
 * Policy has no Canaries. Never throws on input it cannot read: that part matches nothing.
 */
export function canarySignals(
  policy: Pick<AppliedPolicy, "canaryKeys" | "canaryRoutes">,
  request: CanaryRequest,
  path: string,
): Signal[] {
  const signals: Signal[] = [];
  const keys = policy.canaryKeys;
  const routes = policy.canaryRoutes;
  if (keys.size === 0 && routes.size === 0) return signals;

  const add = (id: string | undefined): void => {
    if (id === undefined || signals.length >= SIGNALS_MAX) return;
    const signal = CANARY_SIGNAL_PREFIX + id;
    for (let i = 0; i < signals.length; i++) if ((signals[i] as Signal).id === signal) return;
    signals.push({ id: signal, confidence: 1 });
  };

  if (keys.size > 0) {
    const headers = request.headers;
    if (headers !== undefined && headers !== null) {
      const token = bearerToken(headers.authorization);
      if (token !== undefined) add(keys.get(token));
      const apiKey = headers["x-api-key"];
      if (typeof apiKey === "string") add(keys.get(apiKey));
    }
    const query = queryOf(request);
    if (query !== undefined && query.length > 0) {
      for (const value of new URLSearchParams(query).getAll("api_key")) add(keys.get(value));
    }
  }

  // Routes match without regard to ASCII case, as Rules do and as Express routes by default (Jev: case_insensitive,
  // 1.0): decoy routes are lower case, so each form is lower-cased before the lookup. Keys stay exact.
  if (routes.size > 0 && typeof path === "string") {
    const normalised = normalisePath(path);
    const id = routes.get(asciiLower(normalised));
    if (id !== undefined) {
      add(id);
    } else {
      // Decoded and dot-resolved forms: the slice-02 path forms Rules are matched against. Only a path that is not
      // canonical has any.
      const forms = canonicalPaths(normalised);
      for (let i = 0; i < forms.length; i++) {
        const found = routes.get(asciiLower(forms[i] as string));
        if (found !== undefined) add(found);
      }
    }
  }
  return signals;
}
