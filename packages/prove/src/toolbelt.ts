// The Toolbelt (slice 12a): the agent's only access to the artifact. Read-only tools over an in-memory copy of
// the artifact (list, read, search, beautify), the isolated code runner, and submit. Every call is charged to the
// budget before it runs (a spent budget rejects with BudgetExhaustedError and records nothing) and recorded with
// its cumulative cost and a summary that names paths and counts only: never content, a search pattern, code, a
// header or a submitted value. What each call showed the agent is kept in memory, bounded, so the verifiers can
// say which calls exposed a recovered value; it never enters the log and is dropped with the Toolbelt.

import type { AssessmentCost, ObjectiveId } from "@antireverse/protocol";
import { ROUTE_LIMITS } from "@antireverse/protocol";
import { generate } from "@babel/generator";
import { parse } from "@babel/parser";
import type { Budget } from "./budget.ts";
import { RUN_LIMITS, runIsolated } from "./sandbox.ts";
import type {
  ArtifactInput,
  BeautifyResult,
  CallRecord,
  ListResult,
  MapSubmission,
  ReadResult,
  ReplaySubmission,
  RunResult,
  SearchHit,
  SearchResult,
  SecretsSubmission,
  SubmissionPayload,
  SubmitResult,
  Toolbelt,
  ToolFailure,
  ToolName,
} from "./types.ts";
import { mapEndpointKey } from "./verifiers.ts";

export const TOOLBELT_LIMITS = Object.freeze({
  /** Files `list` returns at most. */
  listMax: 1000,
  /** Bytes one `read` returns at most. */
  readBytesMax: 65_536,
  /** Hits one `search` returns at most. */
  searchHitsMax: 200,
  /** Characters of a search pattern. */
  patternCharsMax: 256,
  /** Characters of a search hit's preview. */
  previewChars: 200,
  /** Bytes of a file `beautify` accepts. */
  beautifyBytesMax: 5_000_000,
  /** Characters of `beautify` output. */
  beautifyCharsMax: 1_000_000,
  /** Values of one W2 submission, and characters of each. */
  valuesMax: 200,
  valueCharsMax: 8_192,
  /** Endpoints of one W1 submission (as many as an inventory may hold). */
  endpointsMax: ROUTE_LIMITS.routesMax,
  endpointCharsMax: ROUTE_LIMITS.methodMax + 1 + 2048,
  /** The W5 request: path characters, headers, characters of a header, body characters. */
  requestPathMax: 2048,
  headersMax: 50,
  headerCharsMax: 8_192,
  bodyCharsMax: 65_536,
  /** Characters of everything kept for evidence attribution. */
  shownCharsMax: 32_000_000,
  /** Characters of a call summary. */
  summaryMax: 200,
});

const SUPPORTED: ReadonlySet<ObjectiveId> = new Set(["W1", "W2", "W5"]);
const JS_EXTENSIONS = /\.(?:m?js|cjs|jsx|ts|mts|cts|tsx)$/i;

/** One accepted submission, in order, with the cost of the run when it was made. */
export interface Submission {
  objective: "W1" | "W2" | "W5";
  payload: SubmissionPayload;
  /** The index of the submit call in the call log. */
  callIndex: number;
  cost: AssessmentCost;
}

export interface ToolbeltHandle {
  toolbelt: Toolbelt;
  /** The call log, in order (live). */
  calls: CallRecord[];
  /** The accepted submissions, in order (live). */
  submissions: Submission[];
  /** The indexes of the calls whose output contained `value` (for evidence; bounded memory). */
  callsShowing(value: string): number[];
}

export interface ToolbeltOptions {
  artifact: ArtifactInput;
  budget: Budget;
  /** Milliseconds per `run`. Default `RUN_LIMITS.timeoutMs` (5 s). */
  runTimeoutMs?: number;
  /**
   * The most distinct W1 endpoints the agent may submit in the run (twice the hidden inventory: `mapEndpointCap`).
   * A W1 submission that would exceed it is refused and recorded as refused. Default: no cap.
   */
  mapEndpointCap?: number | null;
}

/** A read-only copy of the artifact: path → bytes, sorted by path. */
export function normaliseArtifact(artifact: ArtifactInput): Map<string, Uint8Array> {
  const entries: [string, Uint8Array | string][] =
    artifact instanceof Map
      ? [...(artifact as ReadonlyMap<string, Uint8Array | string>).entries()]
      : Object.entries(artifact as Record<string, Uint8Array | string>);
  const encoder = new TextEncoder();
  const files = new Map<string, Uint8Array>();
  for (const [path, content] of entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (typeof path !== "string" || path.length === 0) throw new TypeError("Artifact paths are non-empty strings.");
    if (typeof content === "string") files.set(path, encoder.encode(content));
    else if (content instanceof Uint8Array) files.set(path, new Uint8Array(content));
    else throw new TypeError("Artifact files are bytes or strings.");
  }
  return files;
}

function failure(error: string, kind: ToolFailure["kind"] = "invalid"): ToolFailure {
  return { ok: false, error, kind };
}

/** A path as shown in a summary: at most 80 characters. */
function shown(path: string): string {
  return path.length > 80 ? `${path.slice(0, 77)}...` : path;
}

function folderPrefix(dir: string): string {
  const trimmed = dir.replace(/^\/+|\/+$/g, "");
  return trimmed === "" ? "" : `${trimmed}/`;
}

function isStringArray(value: unknown, max: number, charsMax: number): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= max &&
    value.every((item) => typeof item === "string" && item.length > 0 && item.length <= charsMax)
  );
}

type Checked = { ok: true; payload: SubmissionPayload; summary: string } | { ok: false; error: string };

function checkSubmission(objective: ObjectiveId, payload: unknown): Checked {
  const body = (typeof payload === "object" && payload !== null ? payload : {}) as Record<string, unknown>;
  if (objective === "W1") {
    if (!isStringArray(body.endpoints, TOOLBELT_LIMITS.endpointsMax, TOOLBELT_LIMITS.endpointCharsMax)) {
      return {
        ok: false,
        error: `W1 takes { endpoints: ["METHOD /path", …] } (at most ${TOOLBELT_LIMITS.endpointsMax}).`,
      };
    }
    const endpoints = [...body.endpoints];
    return { ok: true, payload: { endpoints } satisfies MapSubmission, summary: `${endpoints.length} endpoints` };
  }
  if (objective === "W2") {
    if (!isStringArray(body.values, TOOLBELT_LIMITS.valuesMax, TOOLBELT_LIMITS.valueCharsMax)) {
      return { ok: false, error: `W2 takes { values: [string, …] } (at most ${TOOLBELT_LIMITS.valuesMax}).` };
    }
    const values = [...body.values];
    return { ok: true, payload: { values } satisfies SecretsSubmission, summary: `${values.length} values` };
  }
  // W5
  const request = (typeof body.request === "object" && body.request !== null ? body.request : null) as Record<
    string,
    unknown
  > | null;
  const bad = (error: string): Checked => ({
    ok: false,
    error: `W5 takes { request: { method, path, headers?, body? } }: ${error}`,
  });
  if (request === null) return bad("no request.");
  const { method, path, headers = {}, body: requestBody } = request;
  if (typeof method !== "string" || !/^[A-Za-z]{1,16}$/.test(method)) return bad("the method is a word.");
  if (method.toUpperCase() === "OPTIONS") return bad("a preflight (OPTIONS) is not a replay of a protected call.");
  if (typeof path !== "string" || !path.startsWith("/") || path.length > TOOLBELT_LIMITS.requestPathMax) {
    return bad("the path starts with /.");
  }
  if (typeof headers !== "object" || headers === null || Array.isArray(headers)) return bad("headers are an object.");
  const headerEntries = Object.entries(headers as Record<string, unknown>);
  if (
    headerEntries.length > TOOLBELT_LIMITS.headersMax ||
    !headerEntries.every(
      ([name, value]) =>
        /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/.test(name) &&
        typeof value === "string" &&
        value.length <= TOOLBELT_LIMITS.headerCharsMax &&
        !/[\r\n]/.test(value),
    )
  ) {
    return bad("headers are names and single-line string values.");
  }
  if (
    requestBody !== undefined &&
    (typeof requestBody !== "string" || requestBody.length > TOOLBELT_LIMITS.bodyCharsMax)
  ) {
    return bad("the body is a string.");
  }
  const normalised: ReplaySubmission = {
    request: {
      method: method.toUpperCase(),
      path,
      headers: Object.fromEntries(headerEntries.map(([name, value]) => [name.toLowerCase(), value as string])),
      ...(requestBody === undefined ? {} : { body: requestBody }),
    },
  };
  return { ok: true, payload: normalised, summary: `one ${method.toUpperCase()} request` };
}

/** Creates the Toolbelt for one run. */
export function createToolbelt(options: ToolbeltOptions): ToolbeltHandle {
  const files = normaliseArtifact(options.artifact);
  const budget = options.budget;
  const runTimeoutMs = options.runTimeoutMs ?? RUN_LIMITS.timeoutMs;
  const decoder = new TextDecoder("utf-8");
  const texts = new Map<string, string>();
  const textOf = (path: string): string => {
    let text = texts.get(path);
    if (text === undefined) {
      text = decoder.decode(files.get(path) as Uint8Array);
      texts.set(path, text);
    }
    return text;
  };

  const calls: CallRecord[] = [];
  const submissions: Submission[] = [];
  const shownByCall = new Map<number, string>();
  let shownChars = 0;
  let replaySubmitted = false;
  const mapEndpoints = new Set<string>();
  const mapCap = options.mapEndpointCap ?? null;

  /** Charges the budget, runs the tool, records the call. A spent budget rejects before anything runs. */
  async function call<T>(
    tool: ToolName,
    work: (index: number) => Promise<{ result: T; summary: string; showed?: string | undefined }>,
  ): Promise<T> {
    // Yield a macrotask first: an agent that only awaits tools never gives timers a turn otherwise (the run's
    // wall-time timer among them).
    await new Promise<void>((resolve) => setImmediate(resolve));
    budget.charge();
    const index = calls.length;
    let outcome: { result: T; summary: string; showed?: string | undefined };
    try {
      outcome = await work(index);
    } catch {
      outcome = { result: failure("The tool failed.", "sandbox") as T, summary: "failed" };
    }
    calls.push({
      index,
      tool,
      cost: budget.cost(),
      summary: `${tool}: ${outcome.summary}`.slice(0, TOOLBELT_LIMITS.summaryMax),
    });
    if (outcome.showed !== undefined && outcome.showed.length > 0) {
      const room = TOOLBELT_LIMITS.shownCharsMax - shownChars;
      if (room > 0) {
        const kept = outcome.showed.slice(0, room);
        shownByCall.set(index, kept);
        shownChars += kept.length;
      }
    }
    return outcome.result;
  }

  const toolbelt: Toolbelt = {
    list: (dir = "") =>
      call<ListResult | ToolFailure>("list", async () => {
        if (typeof dir !== "string") return { result: failure("The folder is a string."), summary: "invalid folder" };
        const prefix = folderPrefix(dir);
        const matching = [...files].filter(([path]) => path.startsWith(prefix));
        const listed = matching
          .slice(0, TOOLBELT_LIMITS.listMax)
          .map(([path, bytes]) => ({ path, bytes: bytes.length }));
        const result: ListResult = { ok: true, files: listed, truncated: matching.length > listed.length };
        return {
          result,
          summary: `${listed.length} files under "${shown(prefix || "/")}"`,
          showed: listed.map((file) => file.path).join("\n"),
        };
      }),

    read: (path, range = {}) =>
      call<ReadResult | ToolFailure>("read", async () => {
        const bytes = typeof path === "string" ? files.get(path) : undefined;
        if (bytes === undefined) return { result: failure("No such file."), summary: "unknown path" };
        const offset = range.offset ?? 0;
        const length = range.length ?? TOOLBELT_LIMITS.readBytesMax;
        if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length) || length < 0) {
          return { result: failure("A range is a whole offset and length, ≥ 0."), summary: "invalid range" };
        }
        const start = Math.min(offset, bytes.length);
        const end = Math.min(bytes.length, start + Math.min(length, TOOLBELT_LIMITS.readBytesMax));
        const text = decoder.decode(bytes.subarray(start, end));
        const result: ReadResult = { ok: true, path, offset, text, bytes: bytes.length, more: end < bytes.length };
        return { result, summary: `${shown(path)} bytes ${start}-${end} of ${bytes.length}`, showed: text };
      }),

    search: (pattern, searchOptions = {}) =>
      call<SearchResult | ToolFailure>("search", async () => {
        if (typeof pattern !== "string" || pattern.length === 0 || pattern.length > TOOLBELT_LIMITS.patternCharsMax) {
          return {
            result: failure(`A pattern is 1-${TOOLBELT_LIMITS.patternCharsMax} characters.`),
            summary: "invalid pattern",
          };
        }
        const where = searchOptions.path ?? "";
        const max = Math.max(1, Math.min(TOOLBELT_LIMITS.searchHitsMax, Math.floor(searchOptions.maxHits ?? 200) || 1));
        const prefix = folderPrefix(where);
        const paths = [...files.keys()].filter((path) => path === where || path.startsWith(prefix));
        const hits: SearchHit[] = [];
        let truncated = false;
        outer: for (const path of paths) {
          const text = textOf(path);
          let line = 1;
          let lineStart = 0;
          let scanned = 0;
          for (let at = text.indexOf(pattern); at !== -1; at = text.indexOf(pattern, at + pattern.length)) {
            for (let nl = text.indexOf("\n", scanned); nl !== -1 && nl < at; nl = text.indexOf("\n", nl + 1)) {
              line += 1;
              lineStart = nl + 1;
            }
            scanned = at;
            if (hits.length === max) {
              truncated = true;
              break outer;
            }
            const lineEnd = text.indexOf("\n", at);
            const fullLine = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
            const column = at - lineStart;
            const from = Math.max(0, Math.min(column - 60, fullLine.length - TOOLBELT_LIMITS.previewChars));
            hits.push({
              path,
              line,
              column: column + 1,
              preview: fullLine.slice(from, from + TOOLBELT_LIMITS.previewChars),
            });
          }
        }
        const result: SearchResult = { ok: true, hits, truncated };
        return {
          result,
          summary: `pattern of ${pattern.length} characters in "${shown(prefix || "/")}": ${hits.length} hits${truncated ? " (cut)" : ""}`,
          showed: hits.map((hit) => hit.preview).join("\n"),
        };
      }),

    beautify: (path) =>
      call<BeautifyResult | ToolFailure>("beautify", async () => {
        const bytes = typeof path === "string" ? files.get(path) : undefined;
        if (bytes === undefined) return { result: failure("No such file."), summary: "unknown path" };
        if (!JS_EXTENSIONS.test(path))
          return { result: failure("Not a JavaScript file."), summary: `${shown(path)} not JavaScript` };
        if (bytes.length > TOOLBELT_LIMITS.beautifyBytesMax) {
          return { result: failure("The file is too large to beautify."), summary: `${shown(path)} too large` };
        }
        const lower = path.toLowerCase();
        const plugins: ("jsx" | "typescript")[] = [];
        if (/\.(?:ts|mts|cts|tsx)$/.test(lower)) plugins.push("typescript");
        if (/\.(?:jsx|tsx)$/.test(lower)) plugins.push("jsx");
        let code: string;
        try {
          code = generate(parse(textOf(path), { sourceType: "unambiguous", plugins }), { comments: true }).code;
        } catch {
          return { result: failure("The file does not parse as JavaScript."), summary: `${shown(path)} parse error` };
        }
        const truncated = code.length > TOOLBELT_LIMITS.beautifyCharsMax;
        if (truncated) code = code.slice(0, TOOLBELT_LIMITS.beautifyCharsMax);
        const result: BeautifyResult = { ok: true, path, code, truncated };
        return { result, summary: `${shown(path)}: ${code.length} characters`, showed: code };
      }),

    run: (code, input) =>
      call<RunResult | ToolFailure>("run", async () => {
        const result = await runIsolated(code, input, { timeoutMs: runTimeoutMs });
        const size = typeof code === "string" ? code.length : 0;
        const summary = result.ok
          ? `${size} characters of code: ok, ${result.output.length} characters of output`
          : `${size} characters of code: ${result.kind ?? "failed"}`;
        return { result, summary, ...(result.ok ? { showed: result.output } : {}) };
      }),

    submit: (objective, payload) =>
      call<SubmitResult | ToolFailure>("submit", async (index) => {
        if (!SUPPORTED.has(objective)) {
          return {
            result: failure(`${String(objective).slice(0, 8)} is not assessed in this version.`),
            summary: "unsupported Objective",
          };
        }
        if (objective === "W5" && replaySubmitted) {
          return { result: failure("W5 takes one request per Assessment."), summary: "W5 again: refused" };
        }
        const checked = checkSubmission(objective, payload);
        if (!checked.ok) return { result: failure(checked.error), summary: `${objective} malformed` };
        if (objective === "W1") {
          const keys = (checked.payload as MapSubmission).endpoints
            .map(mapEndpointKey)
            .filter((key): key is string => key !== null);
          const union = new Set([...mapEndpoints, ...keys]);
          if (mapCap !== null && union.size > mapCap) {
            return {
              result: failure("W1 refused: the run's distinct endpoints would exceed the limit."),
              summary: `W1 refused: ${keys.length} endpoints over the distinct-endpoint limit`,
            };
          }
          for (const key of keys) mapEndpoints.add(key);
        }
        if (objective === "W5") replaySubmitted = true;
        submissions.push({
          objective: objective as Submission["objective"],
          payload: checked.payload,
          callIndex: index,
          cost: budget.cost(),
        });
        const result: SubmitResult = { ok: true, accepted: true };
        return { result, summary: `${objective}, ${checked.summary}` };
      }),
  };

  return {
    toolbelt,
    calls,
    submissions,
    callsShowing(value: string): number[] {
      if (typeof value !== "string" || value.length === 0) return [];
      const found: number[] = [];
      for (const [index, text] of shownByCall) if (text.includes(value)) found.push(index);
      return found;
    },
  };
}
