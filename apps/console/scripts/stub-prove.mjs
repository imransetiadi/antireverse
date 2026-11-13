// Prove of the stand-in API (slice 14): Verified Targets, signed Rules of Engagement and the dry authorization
// check, in memory, per Organization. The answers have the shape of the protocol's schemas (prove.ts); a test
// checks them. Only node:crypto is imported, so that the test can load this module as it is.
//
// Seed of every Organization: shop.acme-shop.io verified through DNS, api.acme-shop.io verified through the file,
// legacy.acme-shop.io lapsed, staging.acme-shop.io pending, and two signed versions (the current one covers shop
// and api, safe-active, weekdays 09:00–17:00 UTC; the older one covered shop only, passive).
//
// Verify is decided by the first label of the host, so every outcome can be looked at:
//   dns.<…>            passes through DNS            file.<…>          passes through the file
//   <dns failure>.<…>  fails, DNS with that reason, the file with "status" (no-record, mismatch, lookup-failed)
//   <file failure>.<…> fails, DNS "no_record", the file with that reason (resolve-failed, address-not-public,
//                      connect-failed, tls-failed, redirect, status, timeout, too-large, mismatch)
//   anything else      fails the first time (no_record, status), passes through DNS from the second time.
// Ten checks per target per hour; the eleventh answers 429 with Retry-After. Each 409 carries its reason:
// target-duplicate (host already added), target-limit (50 targets), target-in-scope (delete of a scoped target).
import { createHash, randomBytes } from "node:crypto";

const HOUR_MS = 3_600_000;
const VERIFY_PER_HOUR = 10;
const TARGETS_MAX = 50;
const FRESHNESS_MS = 93_600_000;
const SKEW_MS = 300_000;
const INTENSITIES = ["passive", "safe-active", "full"];
const WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const DNS_FAILURES = ["no_record", "mismatch", "lookup_failed"];
const FILE_FAILURES = [
  "not_reachable",
  "connect_failed",
  "tls_failed",
  "redirect",
  "status",
  "timeout",
  "too_large",
  "mismatch",
];
const PRIVATE_SUFFIXES = [
  "localhost",
  "local",
  "internal",
  "intranet",
  "lan",
  "home.arpa",
  "example",
  "invalid",
  "test",
  "onion",
  "example.com",
  "example.net",
  "example.org",
  "corp",
  "home",
  "svc",
  "cluster.local",
  "default",
  "localdomain",
  "arpa",
];
const HOST_MESSAGE =
  "Must be a public DNS name such as shop.acme-shop.io: no IP address and no name under localhost, local, internal, intranet, lan, home.arpa, example, invalid, test, onion, example.com, example.net, example.org, corp, home, svc, cluster.local, default, localdomain or arpa.";
const LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const NUMERIC_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/;
const TIME = /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TGT = /^tgt_[0-9a-f]{24}$/;

const newId = (prefix) => `${prefix}_${randomBytes(12).toString("hex")}`;
const iso = (ms) => new Date(ms).toISOString();

/** The host as stored, or null: the rules of the protocol's `normaliseHost`. */
export function stubNormaliseHost(value) {
  if (typeof value !== "string" || value.length > 512) return null;
  let host = value.trim();
  if (!/^[A-Za-z0-9.-]+$/.test(host)) return null;
  host = host.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.length === 0 || host.length > 253) return null;
  const labels = host.split(".");
  if (labels.length < 2) return null;
  if (labels.some((label) => label.length > 63 || !LABEL.test(label))) return null;
  if (NUMERIC_LABEL.test(labels.at(-1))) return null;
  if (PRIVATE_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`))) return null;
  return host;
}

/** Canonical JSON as the protocol writes it: keys sorted at every depth, no whitespace. */
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** SHA-256 hex of the canonical JSON of the five content fields. */
export function stubContentSha256({ scope, exclusions, intensity, window, contacts }) {
  return createHash("sha256").update(canonicalJson({ scope, exclusions, intensity, window, contacts })).digest("hex");
}

const token = () => randomBytes(32).toString("base64url");
const instructions = (host, value) => ({
  dns_name: `_airverse-challenge.${host}`,
  dns_value: `airverse-verification=${value}`,
  file_url: `https://${host}/.well-known/airverse-verification.txt`,
  file_content: value,
});

const ok = (body, status = 200) => ({ status, body });
const problem = (status, title, extra = {}, headers = {}) => ({
  status,
  body: { type: "about:blank", title, status, ...extra },
  headers,
});
const invalid = (errors) => problem(400, "Invalid request", { errors });

/** A path in the form exclusions are matched in, simplified: `\` as `/`, slashes collapsed, lower case. */
function matchPath(path) {
  let rest = String(path).split(/[?#]/)[0] ?? "/";
  try {
    rest = decodeURIComponent(rest);
  } catch {
    // Kept as it is.
  }
  return rest
    .replace(/\\/g, "/")
    .replace(/\/{2,}/g, "/")
    .toLowerCase();
}

function excluded(path, exclusions) {
  const subject = matchPath(path);
  return exclusions.some((exclusion) => {
    const prefix = matchPath(exclusion).replace(/\/$/, "");
    return prefix === "" || subject === prefix || subject.startsWith(`${prefix}/`);
  });
}

function insideWindow(window, ms) {
  const date = new Date(ms);
  const day = (date.getUTCDay() + 6) % 7;
  const minute = date.getUTCHours() * 60 + date.getUTCMinutes();
  const minutes = (time) => Number(time.slice(0, 2)) * 60 + Number(time.slice(3, 5));
  const from = minutes(window.from);
  const to = minutes(window.to);
  const listed = (index) => window.days.includes(WEEKDAYS[(index + 7) % 7]);
  if (from < to) return listed(day) && minute >= from && minute < to;
  return (listed(day) && minute >= from) || (listed(day - 1) && minute < to);
}

/** Field errors of a Rules of Engagement version to sign, with protocol paths; empty when it is well formed. */
function contentErrors(body) {
  const errors = [];
  const add = (path, message) => errors.push({ path, message });
  const scope = body?.scope;
  if (!Array.isArray(scope) || scope.length < 1 || scope.length > 50 || !scope.every((id) => TGT.test(id)))
    add("scope", "Choose 1 to 50 targets.");
  else if (new Set(scope).size !== scope.length) add("scope", "Each target may be listed once.");
  const exclusions = body?.exclusions;
  if (!Array.isArray(exclusions) || exclusions.length > 50) add("exclusions", "At most 50 prefixes.");
  else {
    exclusions.forEach((prefix, index) => {
      const good =
        typeof prefix === "string" &&
        prefix.length <= 256 &&
        /^\/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$/.test(prefix) &&
        !/(^|\/)\.\.?(\/|$)/.test(prefix) &&
        (prefix === "/" || !prefix.endsWith("/"));
      if (!good) add(`exclusions.${index}`, "Must be a normalised path prefix without a trailing /, such as /admin.");
    });
    if (new Set(exclusions).size !== exclusions.length) add("exclusions", "Each prefix may be listed once.");
  }
  if (!INTENSITIES.includes(body?.intensity)) add("intensity", "Invalid option");
  const window = body?.window;
  if (
    !Array.isArray(window?.days) ||
    window.days.length < 1 ||
    !window.days.every((day) => WEEKDAYS.includes(day)) ||
    new Set(window.days).size !== window.days.length
  )
    add("window.days", "Choose at least one day.");
  if (typeof window?.from !== "string" || !TIME.test(window.from)) add("window.from", "Must be HH:MM, 00:00 to 23:59.");
  if (typeof window?.to !== "string" || !(window.to === "24:00" || TIME.test(window.to)))
    add("window.to", "Must be HH:MM, 00:00 to 24:00.");
  else if (window.to === window?.from) add("window.to", "The window must not be empty: `to` differs from `from`.");
  const contacts = body?.contacts;
  if (!Array.isArray(contacts) || contacts.length < 1 || contacts.length > 5) add("contacts", "Give 1 to 5 contacts.");
  else {
    contacts.forEach((email, index) => {
      if (typeof email !== "string" || email.length > 254 || !EMAIL.test(email))
        add(`contacts.${index}`, "Invalid email address");
    });
    if (new Set(contacts).size !== contacts.length) add("contacts", "Each contact may be listed once.");
  }
  if (errors.length === 0 && body.confirm !== `I authorise ${body.intensity} testing`)
    add("confirm", "Type the exact phrase: I authorise <intensity> testing.");
  return errors;
}

/**
 * The Prove state of one Organization. `keyId` signs the seeded versions and every new one; `now` is the clock
 * (milliseconds). `handle(method, path, body)` answers a request under `/v1/targets`, `/v1/rules-of-engagement` or
 * `/v1/prove/authorize` with `{ status, body, headers? }`, or returns null for any other path.
 */
export function createProveStore({ keyId, now = () => Date.now() }) {
  /** @type {Array<{ target: object, token: string, attempts: number[], tries: number }>} oldest first */
  const targets = [];
  /** @type {object[]} newest first */
  const versions = [];
  const start = now();

  const seedTarget = (host, status, extra = {}) => {
    const entry = {
      target: {
        id: newId("tgt"),
        host,
        status,
        method: null,
        verified_at: null,
        last_checked_at: null,
        lapsed_reason: null,
        created_at: iso(start - 6 * 24 * HOUR_MS),
        ...extra,
      },
      token: token(),
      attempts: [],
      tries: 0,
    };
    targets.push(entry);
    return entry.target;
  };
  const shop = seedTarget("shop.acme-shop.io", "verified", {
    method: "dns",
    verified_at: iso(start - 2 * HOUR_MS),
    last_checked_at: iso(start - 2 * HOUR_MS),
  });
  const api = seedTarget("api.acme-shop.io", "verified", {
    method: "file",
    verified_at: iso(start - 5 * HOUR_MS),
    last_checked_at: iso(start - 5 * HOUR_MS),
  });
  seedTarget("legacy.acme-shop.io", "lapsed", {
    method: "dns",
    verified_at: iso(start - 50 * HOUR_MS),
    last_checked_at: iso(start - 26 * HOUR_MS),
    lapsed_reason: "The daily check found no TXT record and the file answered with status 404.",
  });
  seedTarget("staging.acme-shop.io", "pending", { created_at: iso(start - HOUR_MS) });

  const sign = (content, signedAt) => {
    const version = {
      id: newId("roe"),
      ...content,
      signed_by: keyId,
      signed_at: iso(signedAt),
      content_sha256: stubContentSha256(content),
    };
    versions.unshift(version);
    return version;
  };
  sign(
    {
      scope: [shop.id],
      exclusions: ["/admin"],
      intensity: "passive",
      window: { days: ["sat", "sun"], from: "22:00", to: "06:00" },
      contacts: ["security@acme-shop.io"],
    },
    start - 4 * 24 * HOUR_MS,
  );
  sign(
    {
      scope: [shop.id, api.id],
      exclusions: ["/admin", "/checkout"],
      intensity: "safe-active",
      window: { days: ["mon", "tue", "wed", "thu", "fri"], from: "09:00", to: "17:00" },
      contacts: ["security@acme-shop.io", "oncall@acme-shop.io"],
    },
    start - 24 * HOUR_MS,
  );

  const find = (id) => targets.find((entry) => entry.target.id === id);
  const response = (entry) => ({
    target: { ...entry.target },
    verification: instructions(entry.target.host, entry.token),
  });

  function verify(entry) {
    const at = now();
    entry.attempts = entry.attempts.filter((ms) => at - ms < HOUR_MS);
    if (entry.attempts.length >= VERIFY_PER_HOUR) {
      const wait = Math.max(1, Math.ceil((HOUR_MS - (at - (entry.attempts[0] ?? at))) / 1000));
      return problem(429, "Too Many Requests", {}, { "retry-after": String(wait) });
    }
    entry.attempts.push(at);
    entry.tries += 1;
    const first = entry.target.host.split(".")[0].replace(/-/g, "_");
    let result;
    if (first === "dns" || first === "file") result = { verified: true, method: first };
    else if (FILE_FAILURES.includes(first)) result = { verified: false, dns: "no_record", file: first };
    else if (DNS_FAILURES.includes(first)) result = { verified: false, dns: first, file: "status" };
    else if (entry.tries === 1) result = { verified: false, dns: "no_record", file: "status" };
    else result = { verified: true, method: "dns" };
    const checkedAt = iso(at);
    result = { ...result, checked_at: checkedAt };
    entry.target.last_checked_at = checkedAt;
    if (result.verified) {
      Object.assign(entry.target, {
        status: "verified",
        method: result.method,
        verified_at: checkedAt,
        lapsed_reason: null,
      });
    }
    // A failed check leaves a pending target pending and a verified or lapsed one as it was: only the daily
    // re-check of the real API lapses a target.
    return ok({ target: { ...entry.target }, result });
  }

  function authorize(body) {
    const errors = [];
    const host = stubNormaliseHost(body?.host);
    if (host === null) errors.push({ path: "host", message: HOST_MESSAGE });
    if (typeof body?.path !== "string" || !body.path.startsWith("/") || body.path.length > 2048)
      errors.push({ path: "path", message: "Must start with /." });
    if (!INTENSITIES.includes(body?.intensity)) errors.push({ path: "intensity", message: "Invalid option" });
    const at = typeof body?.at === "string" ? Date.parse(body.at) : Number.NaN;
    if (!Number.isFinite(at) || !/Z$|[+-]\d{2}:\d{2}$/.test(body.at))
      errors.push({ path: "at", message: "Invalid ISO datetime" });
    if (errors.length > 0) return invalid(errors);
    const refuse = (reason) => ok({ allowed: false, reason });
    const target = targets.find((entry) => entry.target.host === host)?.target;
    if (!target) return refuse("target_unknown");
    const verifiedAt = target.verified_at === null ? Number.NaN : Date.parse(target.verified_at);
    if (target.status !== "verified" || !(verifiedAt <= at + SKEW_MS && at - verifiedAt <= FRESHNESS_MS))
      return refuse("target_not_verified");
    const current = versions[0];
    if (!current) return refuse("no_rules_of_engagement");
    if (!current.scope.includes(target.id)) return refuse("out_of_scope");
    if (excluded(body.path, current.exclusions)) return refuse("path_excluded");
    if (INTENSITIES.indexOf(body.intensity) > INTENSITIES.indexOf(current.intensity))
      return refuse("intensity_exceeds");
    if (!insideWindow(current.window, at)) return refuse("outside_window");
    return ok({ allowed: true, roe_id: current.id });
  }

  function handle(method, path, body) {
    if (path === "/v1/targets") {
      if (method === "GET") return ok({ targets: targets.map((entry) => ({ ...entry.target })) });
      if (method !== "POST") return problem(405, "Method Not Allowed");
      const host = stubNormaliseHost(body?.host);
      if (host === null) return invalid([{ path: "host", message: HOST_MESSAGE }]);
      if (targets.some((entry) => entry.target.host === host))
        return problem(409, "Conflict", { reason: "target-duplicate" });
      if (targets.length >= TARGETS_MAX) return problem(409, "Conflict", { reason: "target-limit" });
      const entry = { target: null, token: token(), attempts: [], tries: 0 };
      entry.target = {
        id: newId("tgt"),
        host,
        status: "pending",
        method: null,
        verified_at: null,
        last_checked_at: null,
        lapsed_reason: null,
        created_at: iso(now()),
      };
      targets.push(entry);
      return ok(response(entry), 201);
    }
    const one = /^\/v1\/targets\/([^/]+)(\/verify)?$/.exec(path);
    if (one) {
      const index = targets.findIndex((entry) => entry.target.id === one[1]);
      const entry = targets[index];
      if (!entry) return problem(404, "Not Found");
      if (one[2]) return method === "POST" ? verify(entry) : problem(405, "Method Not Allowed");
      if (method === "GET") return ok(response(entry));
      if (method === "DELETE") {
        if (versions[0]?.scope.includes(entry.target.id))
          return problem(409, "Conflict", { reason: "target-in-scope" });
        targets.splice(index, 1);
        return { status: 204, body: undefined };
      }
      return problem(405, "Method Not Allowed");
    }
    if (path === "/v1/rules-of-engagement") {
      if (method === "GET") return ok({ versions: versions.map((version) => ({ ...version })) });
      if (method !== "POST") return problem(405, "Method Not Allowed");
      const errors = contentErrors(body);
      if (errors.length > 0) return invalid(errors);
      const unverified = body.scope.findIndex((id) => find(id)?.target.status !== "verified");
      if (unverified !== -1)
        return invalid([{ path: `scope.${unverified}`, message: "Every target in scope must be verified." }]);
      const { scope, exclusions, intensity, window, contacts } = body;
      const version = sign(
        { scope, exclusions, intensity, window: { days: window.days, from: window.from, to: window.to }, contacts },
        now(),
      );
      return ok({ version: { ...version } }, 201);
    }
    if (path === "/v1/rules-of-engagement/current") {
      if (method !== "GET") return problem(405, "Method Not Allowed");
      return ok({ version: versions[0] ? { ...versions[0] } : null });
    }
    if (path === "/v1/prove/authorize") {
      if (method !== "POST") return problem(405, "Method Not Allowed");
      return authorize(body);
    }
    return null;
  }

  return { handle };
}
