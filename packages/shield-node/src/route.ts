// The route template of an Express 5 request: `/orgs/:orgId/apps/:appId`, never `/orgs/9/apps/7`.
//
// Express exposes the template of the matched route (`req.route.path`) but only the concrete URL of the routers it
// is mounted under (`req.baseUrl`), and it resets `req.baseUrl` and `req.params` when routing leaves a router. So
// the template has to be captured while the router is still inside the match. router 2.2.0 does three plain
// assignments this module relies on (Express is pinned exactly; test/routes.test.ts guards every case):
//
//   req.params = layer.params   for every layer that matches, while req.baseUrl is still the base of the router
//                               that owns the layer. For a mount layer (`app.use("/orgs/:orgId", router)`) these are
//                               the parameters of the mount path, and req.baseUrl.length is where that path starts.
//   req.route = route           when a route matches, before its own parameters are assigned and while req.baseUrl
//                               is the concrete mount path of all routers above it.
//   req.params = <parent's>     when routing leaves a router.
//
// Accessors on `req.params` and `req.route` observe these assignments. The mount layers above the current router
// are kept as a chain ordered by their offset in `req.baseUrl`; when a route is assigned, each concrete segment of
// the base that is the value of a mount parameter is replaced by `:name`.
//
// Fail closed: if a parameter value cannot be found in the base, the template is unknown and the caller records
// `(unmatched)` instead of a path that may still contain an identifier. The same holds for what this module
// cannot attribute at all:
//   - the path above the point where Shield was installed (`router.use(shield.express())` on a mounted router):
//     its parameters were assigned before Shield could see them, so it is recorded as the placeholder `(mount)`;
//   - a mount that is a regular expression: its captures have numeric names and no template, so the route is
//     unknown;
//   - a literal segment of a mount path that looks like an identifier (digits only, a UUID, long hexadecimal or
//     very long text): it may come from a regular expression without captures, so the route is unknown.
import type { IncomingMessage } from "node:http";

type Params = Record<string, unknown>;

interface Routed {
  baseUrl?: unknown;
  route?: { path?: unknown } | undefined;
  params?: Params | undefined;
  app?: { enabled?: (setting: string) => unknown };
}

/** The parameters of one matched layer and the length of `req.baseUrl` when it matched. */
interface Mount {
  offset: number;
  params: Params;
}

/** One segment of the base: literal text interleaved with the parameters found in it. */
interface Segment {
  /** Index of the segment's leading slash in the base. */
  start: number;
  /** Literal pieces are strings; a parameter that replaced text is `{ name }`. */
  pieces: (string | { name: string })[];
  /** The whole segment is one parameter, or it was absorbed by a wildcard. */
  replaced: string | null;
  removed: boolean;
}

/** Characters of `request.route` the protocol accepts. */
const ROUTE_MAX = 256;

/** Stands for the concrete path above the point where Shield was installed. */
const MOUNT_PLACEHOLDER = "(mount)";

/** A literal segment that may be an identifier rather than part of a mount path someone wrote. */
const IDENTIFIER_LIKE =
  /^(?:[0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|.{41,})$/i;

function decode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

function isUntouched(segment: Segment): boolean {
  return segment.replaced === null && !segment.removed && segment.pieces.length === 1;
}

/** Replaces a whole segment that equals `value`. Searches the span from its end. */
function replaceWhole(segments: Segment[], from: number, to: number, name: string, value: string): boolean {
  for (let i = to - 1; i >= from; i--) {
    const segment = segments[i] as Segment;
    if (isUntouched(segment) && segment.pieces[0] === value) {
      segment.replaced = `:${name}`;
      return true;
    }
  }
  return false;
}

/** Replaces `value` inside a segment (`report.pdf` under `/:name.:ext`). Only literal text is searched. */
function replaceInside(segments: Segment[], from: number, to: number, name: string, value: string): boolean {
  for (let i = to - 1; i >= from; i--) {
    const segment = segments[i] as Segment;
    if (segment.replaced !== null || segment.removed) continue;
    for (let p = segment.pieces.length - 1; p >= 0; p--) {
      const piece = segment.pieces[p];
      if (typeof piece !== "string") continue;
      const at = piece.lastIndexOf(value);
      if (at === -1) continue;
      const before = piece.slice(0, at);
      const after = piece.slice(at + value.length);
      const replacement: (string | { name: string })[] = [];
      if (before !== "") replacement.push(before);
      replacement.push({ name });
      if (after !== "") replacement.push(after);
      segment.pieces.splice(p, 1, ...replacement);
      return true;
    }
  }
  return false;
}

/** Replaces the run of segments a wildcard parameter matched (`/files/*path`) by `*name`. */
function replaceRun(segments: Segment[], from: number, to: number, name: string, values: string[]): boolean {
  for (let i = to - values.length; i >= from; i--) {
    let matches = true;
    for (let k = 0; k < values.length && matches; k++) {
      const segment = segments[i + k] as Segment;
      matches = isUntouched(segment) && segment.pieces[0] === values[k];
    }
    if (!matches) continue;
    (segments[i] as Segment).replaced = `*${name}`;
    for (let k = 1; k < values.length; k++) (segments[i + k] as Segment).removed = true;
    return true;
  }
  return false;
}

/** With mergeParams a router's parameters include those of the routers above it: they are already placed. */
function inherited(chain: Mount[], index: number, name: string, value: unknown): boolean {
  for (let i = 0; i < index; i++) {
    const above = (chain[i] as Mount).params[name];
    if (above === value) return true;
    if (Array.isArray(above) && Array.isArray(value) && above.join("/") === value.join("/")) return true;
  }
  return false;
}

/**
 * The template of the concrete mount path `base`, or null when it cannot be established.
 * `chain` holds the mount layers above the current router, ordered by offset.
 */
function templateOfBase(base: string, chain: Mount[], caseSensitive: boolean): string | null {
  if (base === "") return "";
  if (base.charCodeAt(0) !== 47) return null;
  const segments: Segment[] = [];
  let start = 0;
  for (const raw of base.slice(1).split("/")) {
    segments.push({ start, pieces: [decode(raw)], replaced: null, removed: false });
    start += raw.length + 1;
  }

  for (let c = 0; c < chain.length; c++) {
    const mount = chain[c] as Mount;
    if (mount.offset >= base.length) break; // a layer inside the current router, not above it
    const next = chain[c + 1];
    const end = next !== undefined && next.offset < base.length ? next.offset : base.length;
    let from = 0;
    while (from < segments.length && (segments[from] as Segment).start < mount.offset) from++;
    let to = from;
    while (to < segments.length && (segments[to] as Segment).start < end) to++;

    // Last parameter first: with mergeParams the router's own parameters come after the inherited ones.
    const names = Object.keys(mount.params);
    for (let n = names.length - 1; n >= 0; n--) {
      const name = names[n] as string;
      // A numeric name is a capture of a regular-expression mount: there is no template for it.
      if (/^[0-9]+$/.test(name)) return null;
      const value = mount.params[name];
      if (typeof value === "string") {
        if (value === "") continue;
        if (replaceWhole(segments, from, to, name, value)) continue;
        if (inherited(chain, c, name, value)) continue;
        if (replaceInside(segments, from, to, name, value)) continue;
        return null;
      }
      if (Array.isArray(value)) {
        if (value.length === 0) continue;
        if (!value.every((item) => typeof item === "string")) return null;
        if (replaceRun(segments, from, to, name, value as string[])) continue;
        if (inherited(chain, c, name, value)) continue;
        return null;
      }
      if (value !== undefined && value !== null) return null;
    }
  }

  let template = "";
  for (const segment of segments) {
    if (segment.removed) continue;
    template += "/";
    if (segment.replaced !== null) {
      template += segment.replaced;
      continue;
    }
    if (
      segment.pieces.length === 1 &&
      typeof segment.pieces[0] === "string" &&
      IDENTIFIER_LIKE.test(segment.pieces[0])
    ) {
      return null;
    }
    for (const piece of segment.pieces) {
      // Literal text of a mount path. Express matches it without regard to case unless told otherwise, so the
      // client's spelling (/API/V1) must not become part of the template.
      if (typeof piece === "string") template += caseSensitive ? piece : piece.toLowerCase();
      else template += `:${piece.name}`;
    }
  }
  return template;
}

function formatRoute(base: string, path: unknown): string {
  let template: string;
  if (typeof path === "string") template = base + path || "/";
  else if (Array.isArray(path)) template = `${base}[${path.map(String).join("|")}]`;
  else template = base + String(path); // a RegExp
  return template.length > ROUTE_MAX ? template.slice(0, ROUTE_MAX) : template;
}

/**
 * Starts observing the routing of one request. The returned function gives the route template once the response
 * is done, or null when no route matched (a 404, or a response ended by middleware) or the template is unknown.
 */
export function trackRoute(request: IncomingMessage): () => string | null {
  const req = request as IncomingMessage & Routed;
  let route = req.route;
  let params = req.params;
  /** The template of the mount path of the current route; null when it could not be established. */
  let base: string | null = "";
  const chain: Mount[] = [];
  // The concrete path Shield was installed under. Its parameters were assigned before these accessors existed.
  const installed = typeof req.baseUrl === "string" ? req.baseUrl : "";

  Object.defineProperty(req, "params", {
    configurable: true,
    enumerable: true,
    get: () => params,
    set: (value: Params | undefined) => {
      params = value;
      const offset = Math.max(0, (typeof req.baseUrl === "string" ? req.baseUrl.length : 0) - installed.length);
      while (chain.length > 0 && (chain[chain.length - 1] as Mount).offset >= offset) chain.pop();
      if (typeof value === "object" && value !== null) chain.push({ offset, params: value });
    },
  });

  Object.defineProperty(req, "route", {
    configurable: true,
    enumerable: true,
    get: () => route,
    set: (value: { path?: unknown } | undefined) => {
      // The router assigns the same route twice per match (Router.handle, then Route.dispatch).
      if (value !== route) {
        try {
          const concrete = typeof req.baseUrl === "string" ? req.baseUrl : "";
          if (!concrete.startsWith(installed)) {
            base = null;
          } else {
            const below = concrete.slice(installed.length);
            const template = below === "" ? "" : templateOfBase(below, chain, isCaseSensitive(req));
            base = template === null ? null : (installed === "" ? "" : MOUNT_PLACEHOLDER) + template;
          }
        } catch {
          base = null;
        }
      }
      route = value;
    },
  });

  return () => {
    const path = route?.path;
    if (path === undefined || path === null || base === null) return null;
    return formatRoute(base, path);
  };
}

function isCaseSensitive(req: Routed): boolean {
  const app = req.app;
  return typeof app?.enabled === "function" && app.enabled("case sensitive routing") === true;
}
