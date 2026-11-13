// Slice 14 over HTTP: Verified Targets and Rules of Engagement against a real API (startApi). Ownership is proven
// through a stand-in DNS resolver (TXT) and through the file method — a real local HTTPS server with a test CA and a
// certificate for shop.acme-shop.io, reached through the real guarded fetcher with its test-only option (the stand-in
// resolver maps the host to 127.0.0.1). Without that option the same server is refused before any connection.
// Then Rules of Engagement are signed, `authorize` (HTTP and RunningApi.authorize) is exercised rule by rule, the
// daily re-check is driven through its timer and the API's clock seams, and tenancy is checked. No real network.
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { createGuardedFetcher, type Resolver, type RunningApi, startApi } from "@antireverse/api";
import {
  type AuthorizeResult,
  AuthorizeResultSchema,
  CreateOrganizationResponseSchema,
  CurrentRulesOfEngagementResponseSchema,
  ListRulesOfEngagementResponseSchema,
  ListTargetsResponseSchema,
  ProblemSchema,
  type RulesOfEngagementContent,
  RulesOfEngagementResponseSchema,
  TARGET_LIMITS,
  type Target,
  TargetResponseSchema,
  VERIFICATION_FILE_PATH,
  VerifyTargetResponseSchema,
} from "@antireverse/protocol";
import { hashKey, rulesOfEngagementSha256 } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const tls = (name: string) =>
  readFileSync(new URL(`../../apps/api/test/fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const CA = tls("ca.pem");
/** The name the fixture certificate is issued for. */
const FILE_HOST = "shop.acme-shop.io";

const HOUR_MS = 3_600_000;
/** Monday 2026-11-16 10:00 UTC. */
const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();
const silent = { info() {}, warn() {} };

// --- Stand-in DNS ---------------------------------------------------------------------------------------------

const dnsError = (code: string) => Object.assign(new Error(code), { code });

/** TXT records and addresses by name; a name in `failing` answers SERVFAIL (a failure on our side). */
function fakeDns() {
  const txt = new Map<string, string[][]>();
  const addresses = new Map<string, string[]>();
  const failing = new Set<string>();
  const resolver: Resolver = {
    async txt(name) {
      if (failing.has(name)) throw dnsError("ESERVFAIL");
      const records = txt.get(name);
      if (records === undefined) throw dnsError("ENOTFOUND");
      return records;
    },
    async addresses(host) {
      if (failing.has(host)) throw dnsError("ESERVFAIL");
      const answer = addresses.get(host);
      if (answer === undefined) throw dnsError("ENOTFOUND");
      return answer;
    },
  };
  return { txt, addresses, failing, resolver };
}

// --- The local HTTPS server of the file method ---------------------------------------------------------------

let fileServer: Server;
let filePort: number;
const fileRequests: { url: string | undefined; host: string | undefined }[] = [];
let fileHandler: (req: IncomingMessage, res: ServerResponse) => void = (_req, res) => res.end("");

// --- HTTP helpers ---------------------------------------------------------------------------------------------

function call(
  api: RunningApi,
  path: string,
  init: { method?: string; key?: string; body?: unknown } = {},
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
  // Slice 18a: every change carries a reason, as an operator gives one; sensitive changes refuse to go without.
  if (init.key && (init.method ?? "GET") !== "GET") headers["x-airverse-reason"] = "End-to-end test";
  if (init.body !== undefined) headers["content-type"] = "application/json";
  return fetch(`${api.url}${path}`, {
    method: init.method ?? "GET",
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
}

interface Org {
  id: string;
  key: string;
  keyId: string;
}

async function createOrg(api: RunningApi, name: string): Promise<Org> {
  const response = await call(api, "/v1/organizations", { method: "POST", body: { name } });
  expect(response.status).toBe(201);
  const created = CreateOrganizationResponseSchema.parse(await response.json());
  const key = created.admin_key.key;
  // The admin key's id, as the API records it (the response shows only its prefix and last four characters).
  const { rows } = await api.db.tx("none", (q) =>
    q.query<{ key_id: string }>("SELECT key_id FROM auth_lookup_key($1)", [hashKey(key)]),
  );
  const keyId = rows[0]?.key_id;
  expect(keyId).toMatch(/^key_[0-9a-f]{24}$/);
  return { id: created.organization.id, key, keyId: keyId as string };
}

async function addTarget(api: RunningApi, org: Org, host: string) {
  const response = await call(api, "/v1/targets", { method: "POST", key: org.key, body: { host } });
  expect(response.status).toBe(201);
  return TargetResponseSchema.parse(await response.json());
}

async function verify(api: RunningApi, org: Org, targetId: string) {
  const response = await call(api, `/v1/targets/${targetId}/verify`, { method: "POST", key: org.key });
  expect(response.status).toBe(200);
  return VerifyTargetResponseSchema.parse(await response.json());
}

async function readTarget(api: RunningApi, org: Org, targetId: string): Promise<Target> {
  const response = await call(api, `/v1/targets/${targetId}`, { key: org.key });
  expect(response.status).toBe(200);
  return TargetResponseSchema.parse(await response.json()).target;
}

/** Adds `host`, publishes its TXT record in the stand-in DNS and verifies it. */
async function dnsVerified(api: RunningApi, dns: ReturnType<typeof fakeDns>, org: Org, host: string) {
  const { target, verification } = await addTarget(api, org, host);
  dns.txt.set(verification.dns_name, [[verification.dns_value]]);
  const { result } = await verify(api, org, target.id);
  expect(result).toMatchObject({ verified: true, method: "dns" });
  return target;
}

function sign(api: RunningApi, org: Org, content: RulesOfEngagementContent, confirm: string) {
  return call(api, "/v1/rules-of-engagement", { method: "POST", key: org.key, body: { ...content, confirm } });
}

async function authorizeDry(api: RunningApi, org: Org, request: Record<string, unknown>): Promise<AuthorizeResult> {
  const response = await call(api, "/v1/prove/authorize", { method: "POST", key: org.key, body: request });
  expect(response.status).toBe(200);
  return AuthorizeResultSchema.parse(await response.json());
}

/** The API's test clock, as each describe below keeps it. */
interface ClockSeam {
  get(): number;
  set(ms: number): void;
}

/**
 * The dry check over HTTP and RunningApi.authorize (what slice 15 calls) at the same moment: the API's clock is set to
 * the request's `at` around both calls and restored after. Freshness is always judged by the API's clock; the dry
 * check takes `at` for the window only, and RunningApi.authorize ignores it (review F6). Both must give the same answer.
 */
async function authorizeBoth(
  api: RunningApi,
  clock: ClockSeam,
  org: Org,
  request: { host: string; path: string; intensity: string; at: string },
): Promise<AuthorizeResult> {
  const saved = clock.get();
  clock.set(Date.parse(request.at));
  try {
    const overHttp = await authorizeDry(api, org, request);
    const inProcess = await api.authorize(org.id, request as Parameters<RunningApi["authorize"]>[1]);
    expect(inProcess).toEqual(overHttp);
    return overHttp;
  } finally {
    clock.set(saved);
  }
}

beforeAll(async () => {
  fileServer = createServer({ key: tls("key.pem"), cert: tls("cert.pem") }, (req, res) => {
    fileRequests.push({ url: req.url, host: req.headers.host });
    fileHandler(req, res);
  });
  await new Promise<void>((resolve) => fileServer.listen(0, "127.0.0.1", resolve));
  filePort = (fileServer.address() as AddressInfo).port;
});

afterAll(async () => {
  fileServer.closeAllConnections();
  await new Promise<void>((resolve) => fileServer.close(() => resolve()));
});

// =============================================================================================================
// One API with the test-only file transport: verification, Rules of Engagement, authorize, tenancy.
// =============================================================================================================

describe("Verified Targets, Rules of Engagement and authorize over HTTP", () => {
  let api: RunningApi;
  let clock = T0;
  const seam: ClockSeam = {
    get: () => clock,
    set: (ms) => {
      clock = ms;
    },
  };
  const dns = fakeDns();
  let orgA: Org;
  let orgB: Org;
  let dnsTarget: Target;
  let fileTarget: Target;
  let pendingTarget: Target;
  let extraTarget: Target;
  let first: ReturnType<typeof RulesOfEngagementResponseSchema.parse>["version"];
  let second: typeof first;

  const CONTENT = (scope: string[], exclusions: string[]): RulesOfEngagementContent => ({
    scope,
    exclusions,
    intensity: "safe-active",
    window: { days: ["mon"], from: "09:00", to: "17:00" },
    contacts: ["security@acme-shop.io"],
  });

  beforeAll(async () => {
    dns.addresses.set(FILE_HOST, ["127.0.0.1"]);
    api = await startApi({
      logger: silent,
      now: () => new Date(clock),
      prove: {
        resolver: dns.resolver,
        fetcher: createGuardedFetcher({
          resolver: dns.resolver,
          testing: { ca: CA, port: filePort, allowLoopback: true },
        }),
      },
      // The re-check never fires here: its timer is captured and never called.
      recheck: { setTimer: () => ({}), clearTimer: () => {} },
    });
    orgA = await createOrg(api, "Acme");
    orgB = await createOrg(api, "Globex");
  });

  afterAll(async () => {
    await api?.close();
  });

  it("DNS: adds a host, answers both instructions with the token, and verifies it by the TXT record", async () => {
    const { target, verification } = await addTarget(api, orgA, "DNS.Acme-Shop.io.");
    expect(target).toMatchObject({
      host: "dns.acme-shop.io",
      status: "pending",
      method: null,
      verified_at: null,
      lapsed_reason: null,
    });
    const token = verification.file_content;
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(verification).toEqual({
      dns_name: "_airverse-challenge.dns.acme-shop.io",
      dns_value: `airverse-verification=${token}`,
      file_url: "https://dns.acme-shop.io/.well-known/airverse-verification.txt",
      file_content: token,
    });
    // The list never carries the token; the single target does, again.
    const list = ListTargetsResponseSchema.parse(await (await call(api, "/v1/targets", { key: orgA.key })).json());
    expect(JSON.stringify(list)).not.toContain(token);
    const again = TargetResponseSchema.parse(
      await (await call(api, `/v1/targets/${target.id}`, { key: orgA.key })).json(),
    );
    expect(again.verification.file_content).toBe(token);

    // Before the record is published: not verified, and why.
    const before = await verify(api, orgA, target.id);
    expect(before.result).toEqual({
      verified: false,
      dns: "no_record",
      file: "not_reachable",
      checked_at: iso(clock),
    });
    expect(before.target.status).toBe("pending");

    // The record is published (split into two chunks, as long TXT values are).
    const value = verification.dns_value;
    dns.txt.set(verification.dns_name, [["v=spf1 -all"], [value.slice(0, 20), value.slice(20)]]);
    const after = await verify(api, orgA, target.id);
    expect(after.result).toEqual({ verified: true, method: "dns", checked_at: iso(clock) });
    expect(after.target).toMatchObject({
      status: "verified",
      method: "dns",
      verified_at: iso(clock),
      last_checked_at: iso(clock),
      lapsed_reason: null,
    });
    dnsTarget = after.target;
  });

  it("file: a wrong body is a mismatch, a redirect fails, the exact token verifies by file", async () => {
    const { target, verification } = await addTarget(api, orgA, FILE_HOST);
    const token = verification.file_content;
    const before = fileRequests.length;

    fileHandler = (_req, res) => res.end("not-the-token\n");
    const wrong = await verify(api, orgA, target.id);
    expect(wrong.result).toMatchObject({ verified: false, dns: "no_record", file: "mismatch" });
    expect(wrong.target.status).toBe("pending");

    fileHandler = (_req, res) => {
      res.writeHead(302, { location: `https://${FILE_HOST}/elsewhere.txt` });
      res.end();
    };
    const redirected = await verify(api, orgA, target.id);
    expect(redirected.result).toMatchObject({ verified: false, dns: "no_record", file: "redirect" });
    expect(redirected.target.status).toBe("pending");

    fileHandler = (req, res) => {
      if (req.url !== VERIFICATION_FILE_PATH) {
        res.writeHead(404);
        res.end();
        return;
      }
      res.end(`  ${token}\n`);
    };
    const passed = await verify(api, orgA, target.id);
    expect(passed.result).toEqual({ verified: true, method: "file", checked_at: iso(clock) });
    expect(passed.target).toMatchObject({ status: "verified", method: "file", verified_at: iso(clock) });
    fileTarget = passed.target;

    // Three GETs of the well-known path, with the name as Host (the redirect was not followed).
    const seen = fileRequests.slice(before);
    expect(seen).toHaveLength(3);
    for (const request of seen) {
      expect(request.url).toBe(VERIFICATION_FILE_PATH);
      expect(request.host).toBe(FILE_HOST);
    }
  });

  it("Rules of Engagement: a wrong phrase and an unverified target are refused; signing records who and what", async () => {
    pendingTarget = (await addTarget(api, orgA, "pending.acme-shop.io")).target;
    const content = CONTENT([dnsTarget.id, fileTarget.id], ["/admin"]);

    for (const confirm of ["I authorise full testing", "i authorise safe-active testing", ""]) {
      const response = await sign(api, orgA, content, confirm);
      expect(response.status).toBe(400);
      const problem = ProblemSchema.parse(await response.json());
      expect(problem.errors?.map((error) => error.path)).toContain("confirm");
    }

    const unverified = await sign(
      api,
      orgA,
      CONTENT([dnsTarget.id, pendingTarget.id], ["/admin"]),
      "I authorise safe-active testing",
    );
    expect(unverified.status).toBe(400);
    expect(ProblemSchema.parse(await unverified.json()).errors).toEqual([
      { path: "scope.1", message: expect.any(String) },
    ]);
    // Nothing was signed by the refusals.
    const none = CurrentRulesOfEngagementResponseSchema.parse(
      await (await call(api, "/v1/rules-of-engagement/current", { key: orgA.key })).json(),
    );
    expect(none.version).toBeNull();

    clock = T0 + 60_000;
    const signed = await sign(api, orgA, content, "I authorise safe-active testing");
    expect(signed.status).toBe(201);
    first = RulesOfEngagementResponseSchema.parse(await signed.json()).version;
    expect(first).toEqual({
      id: expect.stringMatching(/^roe_[0-9a-f]{24}$/),
      ...content,
      signed_by: orgA.keyId,
      signed_at: iso(clock),
      content_sha256: rulesOfEngagementSha256(content),
    });
  });

  it("a second version becomes current; the first stays in the history unchanged and has no change endpoint", async () => {
    clock = T0 + 120_000;
    const content = CONTENT([dnsTarget.id, fileTarget.id], ["/admin", "/checkout"]);
    const signed = await sign(api, orgA, content, "I authorise safe-active testing");
    expect(signed.status).toBe(201);
    second = RulesOfEngagementResponseSchema.parse(await signed.json()).version;
    expect(second.id).not.toBe(first.id);
    expect(second.content_sha256).toBe(rulesOfEngagementSha256(content));
    expect(second.content_sha256).not.toBe(first.content_sha256);

    const current = CurrentRulesOfEngagementResponseSchema.parse(
      await (await call(api, "/v1/rules-of-engagement/current", { key: orgA.key })).json(),
    );
    expect(current.version).toEqual(second);

    // No route changes or removes a signed version.
    for (const method of ["PUT", "PATCH", "DELETE"]) {
      const response = await call(api, `/v1/rules-of-engagement/${first.id}`, {
        method,
        key: orgA.key,
        body: method === "DELETE" ? undefined : { ...first, intensity: "full" },
      });
      expect([404, 405]).toContain(response.status);
    }
    const history = ListRulesOfEngagementResponseSchema.parse(
      await (await call(api, "/v1/rules-of-engagement", { key: orgA.key })).json(),
    );
    expect(history.versions).toEqual([second, first]);
  });

  it("authorize allows a test inside the scope and window, over HTTP and RunningApi.authorize", async () => {
    const base = { host: "dns.acme-shop.io", path: "/products/1", intensity: "safe-active", at: iso(T0 + 30 * 60_000) };
    expect(await authorizeBoth(api, seam, orgA, base)).toEqual({ allowed: true, roe_id: second.id });
    expect(await authorizeBoth(api, seam, orgA, { ...base, intensity: "passive" })).toEqual({
      allowed: true,
      roe_id: second.id,
    });
    // The host is normalised; the file-verified target is in scope too; a path that only starts with the letters of
    // an exclusion is not excluded.
    expect(await authorizeBoth(api, seam, orgA, { ...base, host: "DNS.ACME-SHOP.IO" })).toMatchObject({
      allowed: true,
    });
    expect(await authorizeBoth(api, seam, orgA, { ...base, host: FILE_HOST })).toMatchObject({ allowed: true });
    expect(await authorizeBoth(api, seam, orgA, { ...base, path: "/administrator" })).toMatchObject({ allowed: true });
    // The end of the window: 16:59 inside, 17:00 (exclusive) outside. (09:00 lies before the first check, which
    // authorize does not accept beyond 5 minutes of clock skew.)
    expect(await authorizeBoth(api, seam, orgA, { ...base, at: "2026-11-16T16:59:00.000Z" })).toMatchObject({
      allowed: true,
    });
    expect(await authorizeBoth(api, seam, orgA, { ...base, at: "2026-11-16T17:00:00.000Z" })).toEqual({
      allowed: false,
      reason: "outside_window",
    });
  });

  it("authorize refuses an unknown, unverified or out-of-scope host, an excluded path, more intensity, another time", async () => {
    // A verified target of the Organization that no version names.
    extraTarget = await dnsVerified(api, dns, orgA, "extra.acme-shop.io");
    const base = { host: "dns.acme-shop.io", path: "/products/1", intensity: "safe-active", at: iso(T0 + 30 * 60_000) };
    const refused = (reason: string) => ({ allowed: false, reason });

    expect(await authorizeBoth(api, seam, orgA, { ...base, host: "unknown.acme-shop.io" })).toEqual(
      refused("target_unknown"),
    );
    expect(await authorizeBoth(api, seam, orgA, { ...base, host: pendingTarget.host })).toEqual(
      refused("target_not_verified"),
    );
    expect(await authorizeBoth(api, seam, orgA, { ...base, host: extraTarget.host })).toEqual(refused("out_of_scope"));
    for (const path of [
      "/admin",
      "/admin/users",
      "/Admin",
      "/ADMIN/users",
      "/%2fadmin",
      "/%2Fadmin/users",
      "/%61dmin",
      "//admin",
      "/products/../admin",
      "/admin;x=1/users",
      "/admin?debug=1",
      "/checkout",
      // Spellings a server may read as /admin (review F1): trailing space and dot, a NUL cut, fullwidth letters
      // (NFKC), an NTFS alternate data stream.
      "/admin%20",
      "/admin.",
      "/admin%00",
      "/\uFF41\uFF44\uFF4D\uFF49\uFF4E",
      "/admin::$DATA",
    ]) {
      expect({ path, result: await authorizeBoth(api, seam, orgA, { ...base, path }) }).toEqual({
        path,
        result: refused("path_excluded"),
      });
    }
    expect(await authorizeBoth(api, seam, orgA, { ...base, intensity: "full" })).toEqual(refused("intensity_exceeds"));
    // 18:00 on the Monday, and 10:00 on the Tuesday (both within 26 hours of the last check).
    expect(await authorizeBoth(api, seam, orgA, { ...base, at: iso(T0 + 8 * HOUR_MS) })).toEqual(
      refused("outside_window"),
    );
    expect(await authorizeBoth(api, seam, orgA, { ...base, at: iso(T0 + 24 * HOUR_MS) })).toEqual(
      refused("outside_window"),
    );
  });

  it("authorize refuses target_not_verified once the last successful check is older than 26 hours", async () => {
    // Freshness is judged by the API's clock (driven here through startApi's `now` seam), never by a supplied time.
    const verifiedAt = Date.parse(dnsTarget.verified_at as string);
    // A Monday a week later, 10:00, inside the window: only the age of the check refuses.
    const nextMonday = verifiedAt + 7 * 24 * HOUR_MS;
    const base = { host: "dns.acme-shop.io", path: "/products/1", intensity: "safe-active" };
    expect(await authorizeBoth(api, seam, orgA, { ...base, at: iso(nextMonday) })).toEqual({
      allowed: false,
      reason: "target_not_verified",
    });
    // Just past the freshness bound, and at it (Tuesday: the window refuses instead, after the target passed).
    const bound = verifiedAt + TARGET_LIMITS.authorizeFreshnessS * 1000;
    expect(await authorizeBoth(api, seam, orgA, { ...base, at: iso(bound + 1000) })).toEqual({
      allowed: false,
      reason: "target_not_verified",
    });
    expect(await authorizeBoth(api, seam, orgA, { ...base, at: iso(bound) })).toEqual({
      allowed: false,
      reason: "outside_window",
    });

    const saved = clock;
    try {
      // The dry check's `at` places the test in the window only: with the API clock still fresh, a test next Monday
      // is allowed, although that day lies beyond 26 hours of the last check...
      clock = verifiedAt + 30 * 60_000;
      expect(await authorizeDry(api, orgA, { ...base, at: iso(nextMonday) })).toEqual({
        allowed: true,
        roe_id: second.id,
      });
      // ...and RunningApi.authorize ignores a supplied time altogether: judged now (inside the window), allowed.
      expect(await api.authorize(orgA.id, { ...base, intensity: "safe-active", at: iso(bound + HOUR_MS) })).toEqual({
        allowed: true,
        roe_id: second.id,
      });
      // With the API clock past the bound, a supplied time inside the window does not make the check fresh again.
      clock = bound + 1000;
      const inWindow = iso(verifiedAt + 30 * 60_000);
      expect(await authorizeDry(api, orgA, { ...base, at: inWindow })).toEqual({
        allowed: false,
        reason: "target_not_verified",
      });
      expect(await api.authorize(orgA.id, { ...base, intensity: "safe-active", at: inWindow })).toEqual({
        allowed: false,
        reason: "target_not_verified",
      });
    } finally {
      clock = saved;
    }
  });

  it("refuses to add internal names such as kubernetes.default and x.corp", async () => {
    for (const host of [
      "kubernetes.default",
      "x.corp",
      "api.svc",
      "db.cluster.local",
      "printer.home",
      "nas.localdomain",
      "1.0.168.192.in-addr.arpa",
      "intranet.local",
      "127.0.0.1",
    ]) {
      const response = await call(api, "/v1/targets", { method: "POST", key: orgA.key, body: { host } });
      expect({ host, status: response.status }).toEqual({ host, status: 400 });
      const problem = ProblemSchema.parse(await response.json());
      expect(problem.errors?.map((error) => error.path)).toContain("host");
    }
  });

  it("keeps the 10-per-hour verify limit of a host across delete and re-add (the 11th attempt is 429)", async () => {
    const org = await createOrg(api, "Umbrella");
    const host = "limit.acme-shop.io";
    const verifyStatus = async (targetId: string) =>
      call(api, `/v1/targets/${targetId}/verify`, { method: "POST", key: org.key });

    const firstAdd = await addTarget(api, org, host);
    for (let attempt = 0; attempt < 6; attempt++) expect((await verifyStatus(firstAdd.target.id)).status).toBe(200);
    expect((await call(api, `/v1/targets/${firstAdd.target.id}`, { method: "DELETE", key: org.key })).status).toBe(204);
    const again = await addTarget(api, org, host);
    expect(again.target.id).not.toBe(firstAdd.target.id);
    for (let attempt = 0; attempt < 4; attempt++) expect((await verifyStatus(again.target.id)).status).toBe(200);
    const eleventh = await verifyStatus(again.target.id);
    expect(eleventh.status).toBe(429);
    expect(Number(eleventh.headers.get("retry-after"))).toBeGreaterThan(0);
    // Another host of the same Organization still has its own attempts.
    const other = await addTarget(api, org, "other.acme-shop.io");
    expect((await verifyStatus(other.target.id)).status).toBe(200);
  });

  it("tenancy: another Organization gets 404 on the targets, sees no versions, and its authorize knows no host", async () => {
    for (const target of [dnsTarget, fileTarget]) {
      expect((await call(api, `/v1/targets/${target.id}`, { key: orgB.key })).status).toBe(404);
      expect((await call(api, `/v1/targets/${target.id}/verify`, { method: "POST", key: orgB.key })).status).toBe(404);
      expect((await call(api, `/v1/targets/${target.id}`, { method: "DELETE", key: orgB.key })).status).toBe(404);
    }
    for (const version of [first, second]) {
      const response = await call(api, `/v1/rules-of-engagement/${version.id}`, { key: orgB.key });
      expect(response.status).toBe(404);
    }
    const targets = ListTargetsResponseSchema.parse(await (await call(api, "/v1/targets", { key: orgB.key })).json());
    expect(targets.targets).toEqual([]);
    const versions = ListRulesOfEngagementResponseSchema.parse(
      await (await call(api, "/v1/rules-of-engagement", { key: orgB.key })).json(),
    );
    expect(versions.versions).toEqual([]);
    const current = CurrentRulesOfEngagementResponseSchema.parse(
      await (await call(api, "/v1/rules-of-engagement/current", { key: orgB.key })).json(),
    );
    expect(current.version).toBeNull();

    const request = { host: "dns.acme-shop.io", path: "/products/1", intensity: "passive", at: iso(T0 + 30 * 60_000) };
    expect(await authorizeBoth(api, seam, orgB, request)).toEqual({ allowed: false, reason: "target_unknown" });
    // B adds the same host independently: its own pending target and token, which does not make A's record count.
    const added = await addTarget(api, orgB, "dns.acme-shop.io");
    expect(added.target.id).not.toBe(dnsTarget.id);
    const checked = await verify(api, orgB, added.target.id);
    expect(checked.result).toMatchObject({ verified: false, dns: "mismatch" });
    expect(await authorizeBoth(api, seam, orgB, request)).toEqual({ allowed: false, reason: "target_not_verified" });
    // A is unaffected.
    expect(await authorizeBoth(api, seam, orgA, request)).toEqual({ allowed: true, roe_id: second.id });
    // A's targets did not leak into B's list, nor B's into A's verification.
    expect((await readTarget(api, orgA, dnsTarget.id)).status).toBe("verified");
  });
});

// =============================================================================================================
// The production transport (no test-only option): a private address is refused before any connection.
// =============================================================================================================

describe("the guarded fetcher without its test-only option", () => {
  let api: RunningApi;
  const dns = fakeDns();

  beforeAll(async () => {
    dns.addresses.set(FILE_HOST, ["127.0.0.1"]);
    // Only the resolver is replaced: the fetcher is the API's default, createGuardedFetcher({ resolver }).
    api = await startApi({
      logger: silent,
      prove: { resolver: dns.resolver },
      recheck: { setTimer: () => ({}), clearTimer: () => {} },
    });
  });

  afterAll(async () => {
    await api?.close();
  });

  it("answers not_reachable for a name that resolves to a non-public address, and the local server sees no request", async () => {
    const org = await createOrg(api, "Initech");
    const { target, verification } = await addTarget(api, org, FILE_HOST);
    const before = fileRequests.length;
    fileHandler = (_req, res) => res.end(verification.file_content);
    for (const answer of [["127.0.0.1"], ["10.0.0.7"], ["169.254.169.254"], ["::ffff:127.0.0.1"]]) {
      dns.addresses.set(FILE_HOST, answer);
      const { result, target: after } = await verify(api, org, target.id);
      expect(result).toMatchObject({ verified: false, dns: "no_record", file: "not_reachable" });
      expect(after.status).toBe("pending");
    }
    expect(fileRequests.length).toBe(before);
  });
});

// =============================================================================================================
// The daily re-check, driven through its timer seam and the API's clock.
// =============================================================================================================

describe("the daily re-check", () => {
  let api: RunningApi;
  let clock = T0;
  const seam: ClockSeam = {
    get: () => clock,
    set: (ms) => {
      clock = ms;
    },
  };
  const dns = fakeDns();
  const timers: (() => void)[] = [];
  let org: Org;
  let gone: Target;
  let flaky: Target;
  let roeId: string;

  /** Fires the pending re-check timer and waits until the run has finished and the next one is scheduled. */
  async function runRecheck(): Promise<void> {
    const scheduled = timers.length;
    const fire = timers[scheduled - 1];
    expect(fire).toBeDefined();
    (fire as () => void)();
    const started = Date.now();
    while (timers.length === scheduled) {
      if (Date.now() - started > 10_000) throw new Error("the re-check run did not finish");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  beforeAll(async () => {
    api = await startApi({
      logger: silent,
      now: () => new Date(clock),
      prove: {
        resolver: dns.resolver,
        // A stand-in file method that asks the same resolver first: a name it cannot resolve is resolve_failed (the
        // guarded fetcher's internal reason, which the API answers as not_reachable and the re-check reads as a
        // failure on our side), any other is a non-200 answer.
        fetcher: async (host) => {
          try {
            await dns.resolver.addresses(host);
          } catch {
            return { ok: false, reason: "resolve_failed" };
          }
          return { ok: false, reason: "status" };
        },
      },
      recheck: {
        random: () => 0,
        setTimer: (fn) => {
          timers.push(fn);
          return {};
        },
        clearTimer: () => {},
      },
    });
    org = await createOrg(api, "Hooli");
    gone = await dnsVerified(api, dns, org, "gone.acme-shop.io");
    flaky = await dnsVerified(api, dns, org, "flaky.acme-shop.io");
    const signed = await sign(
      api,
      org,
      {
        scope: [gone.id, flaky.id],
        exclusions: [],
        intensity: "passive",
        window: { days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], from: "00:00", to: "24:00" },
        contacts: ["ops@acme-shop.io"],
      },
      "I authorise passive testing",
    );
    expect(signed.status).toBe(201);
    roeId = RulesOfEngagementResponseSchema.parse(await signed.json()).version.id;
  });

  afterAll(async () => {
    await api?.close();
  });

  const authorizeAt = (host: string, at: number) =>
    authorizeBoth(api, seam, org, { host, path: "/", intensity: "passive", at: iso(at) });

  it("does nothing while the last success is younger than 24 hours", async () => {
    clock = T0 + 23 * HOUR_MS;
    dns.txt.delete("_airverse-challenge.gone.acme-shop.io");
    await runRecheck();
    expect((await readTarget(api, org, gone.id)).status).toBe("verified");
  });

  it("lapses a target whose record disappeared; one failing only on our resolver stays verified for now", async () => {
    dns.failing.add("_airverse-challenge.flaky.acme-shop.io");
    dns.failing.add("flaky.acme-shop.io");
    clock = T0 + 24 * HOUR_MS + 60_000;
    await runRecheck();
    expect(await readTarget(api, org, gone.id)).toMatchObject({
      status: "lapsed",
      method: "dns",
      verified_at: iso(T0),
      last_checked_at: iso(clock),
      lapsed_reason: "DNS: no_record; file: not_reachable",
    });
    expect(await authorizeAt(gone.host, clock)).toEqual({ allowed: false, reason: "target_not_verified" });
    expect(await readTarget(api, org, flaky.id)).toMatchObject({ status: "verified", verified_at: iso(T0) });
    expect(await authorizeAt(flaky.host, clock)).toEqual({ allowed: true, roe_id: roeId });
  });

  it("lapses the target that fails only on our resolver on the third run in a row", async () => {
    clock = T0 + 25 * HOUR_MS + 60_000;
    await runRecheck();
    expect((await readTarget(api, org, flaky.id)).status).toBe("verified");
    // Still verified, but its last success is now older than 26 hours: authorize refuses all the same.
    expect(await authorizeAt(flaky.host, T0 + 26 * HOUR_MS + 60_000)).toEqual({
      allowed: false,
      reason: "target_not_verified",
    });

    clock = T0 + 26 * HOUR_MS + 2 * 60_000;
    await runRecheck();
    expect(await readTarget(api, org, flaky.id)).toMatchObject({
      status: "lapsed",
      lapsed_reason: "DNS: lookup_failed; file: not_reachable",
    });
  });

  it("a lapsed target recovers when its record returns", async () => {
    const { verification } = TargetResponseSchema.parse(
      await (await call(api, `/v1/targets/${gone.id}`, { key: org.key })).json(),
    );
    dns.txt.set(verification.dns_name, [[verification.dns_value]]);
    // Lapsed targets are re-checked once their last check is 24 hours old.
    clock = T0 + 48 * HOUR_MS + 2 * 60_000;
    await runRecheck();
    expect(await readTarget(api, org, gone.id)).toMatchObject({
      status: "verified",
      method: "dns",
      verified_at: iso(clock),
      last_checked_at: iso(clock),
      lapsed_reason: null,
    });
    expect(await authorizeAt(gone.host, clock)).toEqual({ allowed: true, roe_id: roeId });
  });
});
