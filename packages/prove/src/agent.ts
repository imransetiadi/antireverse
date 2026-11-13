// The deterministic stand-in adversary agent (slice 12a, D-067): what runs until a real model is configured. It
// uses only the Toolbelt: it lists the artifact, reads every file in order (in chunks) while keeping three calls
// for its submissions, and then submits what simple patterns find: Canary-shaped and secret-shaped strings (W2),
// URL path literals and fetch/XHR/client call sites (W1), and one unsigned request built from the observed call
// sites (W5). Same artifact, same calls, same submissions. Its scores measure the pipeline, not real resistance.
import { STAND_IN_MODEL } from "@antireverse/protocol";
import { BudgetExhaustedError } from "./budget.ts";
import { TOOLBELT_LIMITS } from "./toolbelt.ts";
import type { AdversaryAgent, AgentContext, BudgetView, ReplayRequest, Toolbelt } from "./types.ts";

export const STAND_IN_VERSION = "0.1.0";

/** The stand-in agent's scope: name, version, model. */
export const STAND_IN_AGENT = Object.freeze({ name: "stand-in", version: STAND_IN_VERSION, model: STAND_IN_MODEL });

/** Characters of the previous chunk scanned again with the next (longer than any pattern's longest match). */
const SCAN_OVERLAP = 20_000;

/** Calls kept back for the three submissions (W2, W1, W5). */
const RESERVED_CALLS = 3;

// --- W2: Canary-shaped and secret-shaped strings ------------------------------------------------------------
// Every repetition in these patterns is bounded: the artifact is adversarial and the agent runs in the host
// process, so a pattern that can backtrack over a long run would block the run's own timer.

const SECRET_PATTERNS: readonly RegExp[] = [
  /ak_live_[0-9A-Za-z]{32}/g, // decoy key shape
  /\/api\/internal\/[0-9a-z]{8}\/(?:export|debug|config|backup|sync)\b/g, // decoy route shape
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[0-9A-Za-z]{36}/g,
  /\b[sr]k_live_[0-9A-Za-z]{24,256}/g,
  /\bxox[abprs]-[0-9A-Za-z-]{10,256}/g,
  /\bAIza[0-9A-Za-z_-]{35}/g,
  /-----BEGIN (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY-----[\s\S]{0,16384}?-----END (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY-----/g,
  /\bhttps?:\/\/(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|[A-Za-z0-9.-]{1,253}\.(?:internal|local|corp|lan))(?::\d{1,5})?[^\s"'`<>()\\]{0,2048}/gi,
];
const SECRET_NAME = /secret|token|password|passwd|api[_-]?key|private[_-]?key|client[_-]?secret/i;
const ASSIGNMENT = /([A-Za-z_$][\w$-]{0,63})["']?[ \t]{0,8}[:=][ \t]{0,8}(["'`])((?:\\.|(?!\2)[^\\\n]){0,1024})\2/g;

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function findSecrets(text: string, into: Set<string>): void {
  for (const pattern of SECRET_PATTERNS) {
    for (const match of text.matchAll(pattern)) into.add(match[0]);
  }
  for (const match of text.matchAll(ASSIGNMENT)) {
    const [, name = "", , value = ""] = match;
    if (SECRET_NAME.test(name) && value.length >= 16 && entropy(value) >= 3.5) into.add(value);
  }
}

// --- W1 and W5: routes and call sites ------------------------------------------------------------------------

interface CallSite {
  method: string;
  path: string;
}

const FETCH = /\bfetch\([ \t]{0,8}(["'`])([^"'`\n]{0,2048}?)\1[ \t]{0,8}(?:,[ \t\n]{0,16}\{([^}]{0,512})\})?/g;
const XHR_OPEN = /\.open\([ \t]{0,8}["'`]([A-Za-z]{1,16})["'`][ \t]{0,8},[ \t]{0,8}(["'`])([^"'`\n]{0,2048}?)\2/g;
const CLIENT_CALL = /\.(get|post|put|patch|delete)\([ \t]{0,8}(["'`])([^"'`\n]{0,2048}?)\2/g;
const PATH_LITERAL = /(["'`])(\/(?:api|v\d{1,3})\/[^"'`\s]{0,2048})\1/g;
const METHOD_OPTION = /method[ \t]{0,8}:[ \t]{0,8}["'`]([A-Za-z]{1,16})["'`]/;
const SEGMENT = /^(?:[A-Za-z0-9._~-]+|:param)$/;

/** A route path from a literal: origin and query dropped, `${…}` as `:param`; null when it is not a plain path. */
function routePath(raw: string): string | null {
  let path = raw.replace(/\$\{[^}]*\}/g, ":param").replace(/^https?:\/\/[^/]+/i, "");
  path = path.replace(/[?#].*$/, "");
  if (!path.startsWith("/")) return null;
  if (path.length > 1) path = path.replace(/\/+$/, "");
  if (path === "/") return path;
  const segments = path.slice(1).split("/");
  return segments.every((segment) => SEGMENT.test(segment)) ? path : null;
}

function findRoutes(text: string, endpoints: Set<string>, sites: CallSite[]): void {
  const site = (method: string, raw: string) => {
    const path = routePath(raw);
    if (path === null) return;
    const upper = method.toUpperCase();
    endpoints.add(`${upper} ${path}`);
    if (!sites.some((s) => s.method === upper && s.path === path)) sites.push({ method: upper, path });
  };
  for (const match of text.matchAll(FETCH)) {
    site(METHOD_OPTION.exec(match[3] ?? "")?.[1] ?? "GET", match[2] ?? "");
  }
  for (const match of text.matchAll(XHR_OPEN)) site(match[1] ?? "GET", match[3] ?? "");
  for (const match of text.matchAll(CLIENT_CALL)) site(match[1] ?? "get", match[3] ?? "");
  for (const match of text.matchAll(PATH_LITERAL)) {
    const path = routePath(match[2] ?? "");
    if (path !== null) endpoints.add(`GET ${path}`);
  }
}

/** One request from the observed call sites: the first that changes state, else the first, else `GET /`. */
function replayRequest(sites: readonly CallSite[], endpoints: readonly string[]): ReplayRequest {
  const chosen =
    sites.find((s) => s.method !== "GET" && s.method !== "HEAD") ??
    sites[0] ??
    (endpoints[0] === undefined
      ? undefined
      : { method: endpoints[0].split(" ")[0] as string, path: endpoints[0].split(" ")[1] as string });
  if (chosen === undefined) return { method: "GET", path: "/", headers: {} };
  const path = chosen.path.replace(/:param/g, "1");
  if (chosen.method === "GET" || chosen.method === "HEAD") return { method: chosen.method, path, headers: {} };
  return { method: chosen.method, path, headers: { "content-type": "application/json" }, body: "{}" };
}

// --- The agent -------------------------------------------------------------------------------------------

export class StandInAgent implements AdversaryAgent {
  readonly name = STAND_IN_AGENT.name;
  readonly version = STAND_IN_AGENT.version;
  readonly model = STAND_IN_AGENT.model;

  async run(_context: AgentContext, toolbelt: Toolbelt, budget: BudgetView): Promise<void> {
    try {
      await this.#work(toolbelt, budget);
    } catch (error) {
      if (!(error instanceof BudgetExhaustedError)) throw error;
      // The budget is spent: the run ends here, with whatever was submitted.
    }
  }

  async #work(toolbelt: Toolbelt, budget: BudgetView): Promise<void> {
    if (budget.callsLeft() < 1) return;
    const listed = await toolbelt.list();
    if (!listed.ok) return;

    const secrets = new Set<string>();
    const endpoints = new Set<string>();
    const sites: CallSite[] = [];
    const canRead = () => budget.callsLeft() > RESERVED_CALLS && budget.secondsLeft() > 0;
    for (const file of listed.files) {
      // Each chunk is scanned as it arrives, with the tail of the previous one in front, so no scan is longer
      // than one chunk plus the overlap and a match across a chunk boundary is still found.
      let tail = "";
      let offset = 0;
      let complete = false;
      while (canRead()) {
        const read = await toolbelt.read(file.path, { offset, length: TOOLBELT_LIMITS.readBytesMax });
        if (!read.ok) break;
        const window = tail + read.text;
        findSecrets(window, secrets);
        findRoutes(window, endpoints, sites);
        tail = window.slice(-SCAN_OVERLAP);
        offset += TOOLBELT_LIMITS.readBytesMax;
        if (!read.more) {
          complete = true;
          break;
        }
      }
      if (!complete) break;
    }

    const values = [...secrets].filter((value) => value.length <= TOOLBELT_LIMITS.valueCharsMax);
    if (values.length > 0) {
      await toolbelt.submit("W2", { values: values.slice(0, TOOLBELT_LIMITS.valuesMax) });
    }
    const routes = [...endpoints].slice(0, TOOLBELT_LIMITS.endpointsMax);
    if (routes.length > 0) await toolbelt.submit("W1", { endpoints: routes });
    await toolbelt.submit("W5", { request: replayRequest(sites, routes) });
  }
}
