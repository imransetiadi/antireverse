import {
  type AuthorizeResult,
  AuthorizeResultSchema,
  CurrentRulesOfEngagementResponseSchema,
  confirmationPhrase,
  type Intensity,
  ListRulesOfEngagementResponseSchema,
  ListTargetsResponseSchema,
  type RulesOfEngagementContent,
  RulesOfEngagementResponseSchema,
  TARGET_LIMITS,
  type Target,
  TargetResponseSchema,
  VerifyTargetResponseSchema,
} from "@antireverse/protocol";
import { hashKey, rulesOfEngagementSha256 } from "@antireverse/protocol/server";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createAuthorize } from "../src/index.ts";
import { CONFLICT_DETAILS } from "../src/problem.ts";
import type { Fetcher, FetchOutcome, Resolver } from "../src/prove/verify.ts";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
  withReason,
} from "./helpers.ts";

// Slice 14 routes: Verified Targets, Rules of Engagement and the dry authorization check, with a stand-in resolver
// and fetcher (no network) and a test clock.

const T0 = Date.parse("2026-11-16T10:00:00.000Z"); // a Monday, 10:00 UTC
const HOUR = 3_600_000;
let clock = T0;
const now = () => new Date(clock);

const txt = new Map<string, string[][]>();
/** When set, a TXT lookup waits for it before reading the records (a slow DNS answer). */
let txtGate: (() => Promise<void>) | null = null;
const files = new Map<string, FetchOutcome>();
const fetched: string[] = [];

const resolver: Resolver = {
  async txt(name) {
    if (txtGate !== null) await txtGate();
    const records = txt.get(name);
    if (records === undefined) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    return records;
  },
  async addresses() {
    throw new Error("The routes never resolve addresses themselves.");
  },
};
const fetcher: Fetcher = async (host) => {
  fetched.push(host);
  return files.get(host) ?? { ok: false, reason: "status" };
};

let api: TestApi;
let adminA: string;
let adminB: string;
let keyIdA: string;
let shieldA: string;

const tokens: string[] = [];

async function addTarget(admin: string, host: string): Promise<{ target: Target; token: string }> {
  const res = await api.app.request("/v1/targets", json({ host }, bearer(admin)));
  expect(res.status).toBe(201);
  const body = TargetResponseSchema.parse(await res.json());
  tokens.push(body.verification.file_content);
  return { target: body.target, token: body.verification.file_content };
}

async function verify(admin: string, id: string) {
  const res = await api.app.request(`/v1/targets/${id}/verify`, { method: "POST", headers: bearer(admin) });
  expect(res.status).toBe(200);
  return VerifyTargetResponseSchema.parse(await res.json());
}

function publishDns(host: string, token: string): void {
  txt.set(`_airverse-challenge.${host}`, [[`airverse-verification=${token}`]]);
}

async function verifiedTarget(admin: string, host: string): Promise<Target> {
  const { target, token } = await addTarget(admin, host);
  publishDns(host, token);
  const { target: verified } = await verify(admin, target.id);
  expect(verified.status).toBe("verified");
  return verified;
}

const CONTENT = (scope: string[], intensity: Intensity = "safe-active"): RulesOfEngagementContent => ({
  scope,
  exclusions: ["/admin"],
  intensity,
  window: { days: ["mon", "tue", "wed", "thu", "fri"], from: "09:00", to: "17:00" },
  contacts: ["security@acme-shop.io"],
});

function sign(admin: string, content: RulesOfEngagementContent, confirm = confirmationPhrase(content.intensity)) {
  return api.app.request("/v1/rules-of-engagement", json({ ...content, confirm }, withReason(bearer(admin))));
}

async function authorizeDry(admin: string, request: Record<string, unknown>): Promise<AuthorizeResult> {
  const res = await api.app.request("/v1/prove/authorize", json(request, bearer(admin)));
  expect(res.status).toBe(200);
  return AuthorizeResultSchema.parse(await res.json());
}

beforeAll(async () => {
  api = await makeTestApi({ now, prove: { resolver, fetcher } });
  const a = await createOrganization(api, "Acme");
  const b = await createOrganization(api, "Bravo");
  adminA = a.admin_key.key;
  adminB = b.admin_key.key;
  shieldA = (await createAppFor(api, adminA)).shield_key.key;
  const { rows } = await api.db.tx("none", (q) =>
    q.query<{ key_id: string }>("SELECT key_id FROM auth_lookup_key($1)", [hashKey(adminA)]),
  );
  keyIdA = rows[0]?.key_id ?? "";
});

afterAll(async () => {
  await api.close();
});

beforeEach(() => {
  clock = T0;
});

describe("Verified Targets", () => {
  it("adds a host (normalised) and answers the token with both ways to prove ownership", async () => {
    const res = await api.app.request("/v1/targets", json({ host: " Add.Acme-Shop.io. " }, bearer(adminA)));
    expect(res.status).toBe(201);
    const body = TargetResponseSchema.parse(await res.json());
    tokens.push(body.verification.file_content);
    expect(body.target).toMatchObject({
      host: "add.acme-shop.io",
      status: "pending",
      method: null,
      verified_at: null,
      last_checked_at: null,
      lapsed_reason: null,
      created_at: new Date(T0).toISOString(),
    });
    expect(body.verification).toEqual({
      dns_name: "_airverse-challenge.add.acme-shop.io",
      dns_value: `airverse-verification=${body.verification.file_content}`,
      file_url: "https://add.acme-shop.io/.well-known/airverse-verification.txt",
      file_content: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
    });
  });

  it.each([
    "127.0.0.1",
    "[::1]",
    "localhost",
    "db.internal",
    "printer.local",
    "example.com",
    "shop.example.org",
    "a.test",
    "single",
    "-bad-.acme-shop.io",
    "bücher.de",
    "",
  ])("refuses the host %j", async (host) => {
    await expectProblem(await api.app.request("/v1/targets", json({ host }, bearer(adminA))), 400);
  });

  it("refuses the same host twice in one Organization (409), but another Organization adds it independently", async () => {
    const first = await addTarget(adminA, "dup.acme-shop.io");
    const again = await expectProblem(
      await api.app.request("/v1/targets", json({ host: "DUP.acme-shop.io" }, bearer(adminA))),
      409,
    );
    expect(again.type).toMatch(/conflict$/);
    expect(again.reason).toBe("target-duplicate");
    expect(again.detail).toBe(CONFLICT_DETAILS["target-duplicate"]);
    const other = await addTarget(adminB, "dup.acme-shop.io");
    expect(other.target.id).not.toBe(first.target.id);
    expect(other.token).not.toBe(first.token);
    // Proving it for B does not verify A's target.
    publishDns("dup.acme-shop.io", other.token);
    expect((await verify(adminB, other.target.id)).target.status).toBe("verified");
    const mine = await verify(adminA, first.target.id);
    expect(mine.target.status).toBe("pending");
    expect(mine.result).toMatchObject({ verified: false, dns: "mismatch" });
  });

  it("lists the Organization's targets without any token, and shows the token only for one target", async () => {
    const { target, token } = await addTarget(adminA, "list.acme-shop.io");
    const res = await api.app.request("/v1/targets", { headers: bearer(adminA) });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain(token);
    const listed = ListTargetsResponseSchema.parse(JSON.parse(text));
    expect(listed.targets.map((t) => t.id)).toContain(target.id);
    for (const t of listed.targets) expect(Object.keys(t)).not.toContain("token");

    const one = await api.app.request(`/v1/targets/${target.id}`, { headers: bearer(adminA) });
    expect(one.status).toBe(200);
    expect(TargetResponseSchema.parse(await one.json()).verification.file_content).toBe(token);

    const fromB = await api.app.request("/v1/targets", { headers: bearer(adminB) });
    expect(ListTargetsResponseSchema.parse(await fromB.json()).targets.map((t) => t.id)).not.toContain(target.id);
  });

  it("answers 404 for another Organization's target or a malformed id, on every target route", async () => {
    const { target } = await addTarget(adminA, "mine.acme-shop.io");
    for (const id of [target.id, "tgt_nope", "x"]) {
      const admin = id === target.id ? adminB : adminA;
      await expectProblem(await api.app.request(`/v1/targets/${id}`, { headers: bearer(admin) }), 404);
      await expectProblem(
        await api.app.request(`/v1/targets/${id}/verify`, { method: "POST", headers: bearer(admin) }),
        404,
      );
      await expectProblem(
        await api.app.request(`/v1/targets/${id}`, { method: "DELETE", headers: withReason(bearer(admin)) }),
        404,
      );
    }
  });

  it("is for admin keys only: a Shield key is 403, no key 401", async () => {
    const routes: [string, RequestInit][] = [
      ["/v1/targets", {}],
      ["/v1/targets", json({ host: "s.acme-shop.io" })],
      ["/v1/targets/tgt_0123456789abcdef01234567", {}],
      ["/v1/targets/tgt_0123456789abcdef01234567", { method: "DELETE" }],
      ["/v1/targets/tgt_0123456789abcdef01234567/verify", { method: "POST" }],
      ["/v1/rules-of-engagement", {}],
      ["/v1/rules-of-engagement/current", {}],
      ["/v1/rules-of-engagement", json({})],
      ["/v1/prove/authorize", json({})],
    ];
    for (const [path, init] of routes) {
      await expectProblem(await api.app.request(path, init), 401);
      const headers = { ...(init.headers as Record<string, string> | undefined), ...bearer(shieldA) };
      await expectProblem(await api.app.request(path, { ...init, headers }), 403);
    }
  });

  it("refuses more than 50 targets per Organization (409)", async () => {
    const org = await createOrganization(api, "Many");
    const admin = org.admin_key.key;
    for (let index = 0; index < TARGET_LIMITS.targetsPerOrganization; index++) {
      await addTarget(admin, `h${index}.acme-shop.io`);
    }
    const over = await expectProblem(
      await api.app.request("/v1/targets", json({ host: "over.acme-shop.io" }, bearer(admin))),
      409,
    );
    expect(over.type).toMatch(/conflict$/);
    expect(over.reason).toBe("target-limit");
    expect(over.detail).toBe(CONFLICT_DETAILS["target-limit"]);
  });

  it("deletes a target (204) that is not in the current scope", async () => {
    const { target } = await addTarget(adminA, "gone.acme-shop.io");
    const res = await api.app.request(`/v1/targets/${target.id}`, {
      method: "DELETE",
      headers: withReason(bearer(adminA)),
    });
    expect(res.status).toBe(204);
    await expectProblem(await api.app.request(`/v1/targets/${target.id}`, { headers: bearer(adminA) }), 404);
  });
});

describe("verification", () => {
  it("verifies by DNS first and records the method and time", async () => {
    const { target, token } = await addTarget(adminA, "dns.acme-shop.io");
    publishDns("dns.acme-shop.io", token);
    files.set("dns.acme-shop.io", { ok: true, body: token });
    fetched.length = 0;
    clock = T0 + 60_000;
    const { target: after, result } = await verify(adminA, target.id);
    const at = new Date(clock).toISOString();
    expect(result).toEqual({ verified: true, method: "dns", checked_at: at });
    expect(after).toMatchObject({ status: "verified", method: "dns", verified_at: at, last_checked_at: at });
    expect(fetched).toEqual([]);
  });

  it("verifies by the file when DNS fails", async () => {
    const { target, token } = await addTarget(adminA, "file.acme-shop.io");
    files.set("file.acme-shop.io", { ok: true, body: `${token}\n` });
    const { target: after, result } = await verify(adminA, target.id);
    expect(result).toMatchObject({ verified: true, method: "file" });
    expect(after).toMatchObject({ status: "verified", method: "file" });
  });

  it("leaves a pending target pending when both methods fail, and says why", async () => {
    const { target } = await addTarget(adminA, "fail.acme-shop.io");
    files.set("fail.acme-shop.io", { ok: false, reason: "address_not_public" });
    const { target: after, result } = await verify(adminA, target.id);
    // Review F4: "not reachable" for both a name that does not resolve and one that resolves to a private address.
    expect(result).toEqual({
      verified: false,
      dns: "no_record",
      file: "not_reachable",
      checked_at: new Date(T0).toISOString(),
    });
    expect(after).toMatchObject({ status: "pending", method: null, verified_at: null, lapsed_reason: null });
    expect(after.last_checked_at).toBe(new Date(T0).toISOString());
  });

  it("marks a verified target lapsed with the reason when a check fails, and verified again when one passes", async () => {
    const verified = await verifiedTarget(adminA, "lapse.acme-shop.io");
    txt.delete("_airverse-challenge.lapse.acme-shop.io");
    files.set("lapse.acme-shop.io", { ok: false, reason: "timeout" });
    clock = T0 + HOUR;
    const { target: lapsed } = await verify(adminA, verified.id);
    expect(lapsed).toMatchObject({
      status: "lapsed",
      method: "dns",
      verified_at: verified.verified_at,
      last_checked_at: new Date(clock).toISOString(),
    });
    expect(lapsed.lapsed_reason).toMatch(/no_record/);
    expect(lapsed.lapsed_reason).toMatch(/timeout/);

    const token = TargetResponseSchema.parse(
      await (await api.app.request(`/v1/targets/${verified.id}`, { headers: bearer(adminA) })).json(),
    ).verification.file_content;
    files.set("lapse.acme-shop.io", { ok: true, body: token });
    clock = T0 + 2 * HOUR;
    const { target: again } = await verify(adminA, verified.id);
    expect(again).toMatchObject({
      status: "verified",
      method: "file",
      verified_at: new Date(clock).toISOString(),
      lapsed_reason: null,
    });
  });

  it("allows 10 verification attempts per target per hour, then 429 with Retry-After", async () => {
    const { target } = await addTarget(adminA, "rate.acme-shop.io");
    for (let attempt = 0; attempt < TARGET_LIMITS.verifyAttemptsPerHour; attempt++) {
      clock = T0 + attempt * 60_000;
      await verify(adminA, target.id);
    }
    clock = T0 + 30 * 60_000;
    const limited = await api.app.request(`/v1/targets/${target.id}/verify`, {
      method: "POST",
      headers: bearer(adminA),
    });
    await expectProblem(limited, 429);
    expect(Number(limited.headers.get("retry-after"))).toBe(30 * 60);
    // Another target is not limited by this one.
    const { target: other } = await addTarget(adminA, "rate2.acme-shop.io");
    await verify(adminA, other.id);
    clock = T0 + HOUR;
    await verify(adminA, target.id);
  });

  it("keeps the per-host limit across delete and add again (review F2)", async () => {
    const org = await createOrganization(api, "Again");
    const admin = org.admin_key.key;
    const first = await addTarget(admin, "again.acme-shop.io");
    for (let attempt = 0; attempt < TARGET_LIMITS.verifyAttemptsPerHour; attempt++)
      await verify(admin, first.target.id);
    const deleted = await api.app.request(`/v1/targets/${first.target.id}`, {
      method: "DELETE",
      headers: withReason(bearer(admin)),
    });
    expect(deleted.status).toBe(204);
    const second = await addTarget(admin, "again.acme-shop.io");
    clock = T0 + 10 * 60_000;
    const limited = await api.app.request(`/v1/targets/${second.target.id}/verify`, {
      method: "POST",
      headers: bearer(admin),
    });
    await expectProblem(limited, 429);
    expect(Number(limited.headers.get("retry-after"))).toBe(50 * 60);
    // The same host of another Organization is not limited by this one.
    const other = await createOrganization(api, "Again elsewhere");
    const theirs = await addTarget(other.admin_key.key, "again.acme-shop.io");
    await verify(other.admin_key.key, theirs.target.id);
  });

  it("allows 60 verifications per Organization per hour across its targets (review F2)", async () => {
    const org = await createOrganization(api, "Busy");
    const admin = org.admin_key.key;
    for (let host = 0; host < 6; host++) {
      const { target } = await addTarget(admin, `busy${host}.acme-shop.io`);
      for (let attempt = 0; attempt < TARGET_LIMITS.verifyAttemptsPerHour; attempt++) await verify(admin, target.id);
    }
    const { target: fresh } = await addTarget(admin, "busy-fresh.acme-shop.io");
    clock = T0 + 20 * 60_000;
    const limited = await api.app.request(`/v1/targets/${fresh.id}/verify`, { method: "POST", headers: bearer(admin) });
    await expectProblem(limited, 429);
    expect(Number(limited.headers.get("retry-after"))).toBe(40 * 60);
    clock = T0 + HOUR;
    await verify(admin, fresh.id);
  });

  it("records a manual verify only if it started after the target's last recorded check (review F3)", async () => {
    const org = await createOrganization(api, "Race");
    const admin = org.admin_key.key;
    const target = await verifiedTarget(admin, "race.acme-shop.io");
    const name = "_airverse-challenge.race.acme-shop.io";
    const record = txt.get(name);
    let release: (() => void) | undefined;
    txtGate = () =>
      new Promise<void>((resolve) => {
        release = resolve;
      });
    clock = T0 + 60_000;
    // An older verify that will pass, held in its DNS lookup.
    const older = api.app.request(`/v1/targets/${target.id}/verify`, { method: "POST", headers: bearer(admin) });
    while (release === undefined) await new Promise((resolve) => setTimeout(resolve, 5));
    txtGate = null;
    // Meanwhile the record is gone and a newer verify fails: the target lapses.
    txt.delete(name);
    clock = T0 + 120_000;
    const newer = await verify(admin, target.id);
    expect(newer.target.status).toBe("lapsed");
    if (record !== undefined) txt.set(name, record);
    release();
    const late = await older;
    expect((await expectProblem(late, 409)).type).toMatch(/conflict$/);
    const stored = TargetResponseSchema.parse(
      await (await api.app.request(`/v1/targets/${target.id}`, { headers: bearer(admin) })).json(),
    ).target;
    expect(stored).toMatchObject({ status: "lapsed", last_checked_at: new Date(T0 + 120_000).toISOString() });
  });
});

describe("Rules of Engagement", () => {
  it("answers no current version before the first is signed", async () => {
    const org = await createOrganization(api, "Fresh");
    const res = await api.app.request("/v1/rules-of-engagement/current", { headers: bearer(org.admin_key.key) });
    expect(res.status).toBe(200);
    expect(CurrentRulesOfEngagementResponseSchema.parse(await res.json())).toEqual({ version: null });
    const list = await api.app.request("/v1/rules-of-engagement", { headers: bearer(org.admin_key.key) });
    expect(ListRulesOfEngagementResponseSchema.parse(await list.json())).toEqual({ versions: [] });
  });

  it("signs a version over verified targets, recording who, when and the content hash; the newest is current", async () => {
    const org = await createOrganization(api, "Signer");
    const admin = org.admin_key.key;
    const { rows } = await api.db.tx("none", (q) =>
      q.query<{ key_id: string }>("SELECT key_id FROM auth_lookup_key($1)", [hashKey(admin)]),
    );
    const keyId = rows[0]?.key_id;
    const target = await verifiedTarget(admin, "sign.acme-shop.io");
    clock = T0 + 60_000;
    const content = CONTENT([target.id]);
    const res = await sign(admin, content);
    expect(res.status).toBe(201);
    const { version } = RulesOfEngagementResponseSchema.parse(await res.json());
    expect(version).toEqual({
      id: expect.stringMatching(/^roe_/),
      ...content,
      signed_by: keyId,
      signed_at: new Date(clock).toISOString(),
      content_sha256: rulesOfEngagementSha256(content),
    });

    clock = T0 + 120_000;
    const second = RulesOfEngagementResponseSchema.parse(
      await (await sign(admin, { ...CONTENT([target.id], "passive"), exclusions: [] })).json(),
    ).version;
    const current = CurrentRulesOfEngagementResponseSchema.parse(
      await (await api.app.request("/v1/rules-of-engagement/current", { headers: bearer(admin) })).json(),
    );
    expect(current.version).toEqual(second);
    const list = ListRulesOfEngagementResponseSchema.parse(
      await (await api.app.request("/v1/rules-of-engagement", { headers: bearer(admin) })).json(),
    );
    expect(list.versions).toEqual([second, version]);

    // Another Organization sees none of it.
    const fromB = ListRulesOfEngagementResponseSchema.parse(
      await (await api.app.request("/v1/rules-of-engagement", { headers: bearer(adminB) })).json(),
    );
    expect(fromB.versions.map((v) => v.id)).not.toContain(version.id);
  });

  it("refuses a wrong confirmation phrase", async () => {
    const target = await verifiedTarget(adminA, "confirm.acme-shop.io");
    const content = CONTENT([target.id], "full");
    for (const confirm of [
      "I authorise safe-active testing",
      "i authorise full testing",
      "",
      "I authorise full testing ",
    ]) {
      const problem = await expectProblem(await sign(adminA, content, confirm), 400);
      expect(problem.errors?.map((error) => error.path)).toContain("confirm");
    }
  });

  it("refuses a scope with a target that is pending, lapsed, stale, unknown or another Organization's", async () => {
    const verified = await verifiedTarget(adminA, "scope-ok.acme-shop.io");
    const { target: pending } = await addTarget(adminA, "scope-pending.acme-shop.io");
    const lapsed = await verifiedTarget(adminA, "scope-lapsed.acme-shop.io");
    txt.delete("_airverse-challenge.scope-lapsed.acme-shop.io");
    await verify(adminA, lapsed.id);
    const foreign = await verifiedTarget(adminB, "scope-b.acme-shop.io");
    for (const [index, id] of [pending.id, lapsed.id, foreign.id, "tgt_ffffffffffffffffffffffff"].entries()) {
      const problem = await expectProblem(await sign(adminA, CONTENT([verified.id, id])), 400);
      expect(problem.errors).toEqual([{ path: "scope.1", message: expect.any(String) }]);
      expect(index).toBeGreaterThanOrEqual(0);
    }
    // Stale: the last successful check is more than 26 hours old.
    clock = T0 + (TARGET_LIMITS.authorizeFreshnessS + 60) * 1000;
    const stale = await expectProblem(await sign(adminA, CONTENT([verified.id])), 400);
    expect(stale.errors?.[0]?.path).toBe("scope.0");
  });

  it("refuses to delete a target in the current scope (409), and allows it once a new version leaves it out", async () => {
    const org = await createOrganization(api, "Deleter");
    const admin = org.admin_key.key;
    const kept = await verifiedTarget(admin, "kept.acme-shop.io");
    const dropped = await verifiedTarget(admin, "dropped.acme-shop.io");
    expect((await sign(admin, CONTENT([kept.id, dropped.id]))).status).toBe(201);
    const refused = await expectProblem(
      await api.app.request(`/v1/targets/${dropped.id}`, { method: "DELETE", headers: withReason(bearer(admin)) }),
      409,
    );
    expect(refused.type).toMatch(/conflict$/);
    expect(refused.reason).toBe("target-in-scope");
    expect(refused.detail).toBe(CONFLICT_DETAILS["target-in-scope"]);
    expect((await sign(admin, CONTENT([kept.id]))).status).toBe(201);
    const res = await api.app.request(`/v1/targets/${dropped.id}`, {
      method: "DELETE",
      headers: withReason(bearer(admin)),
    });
    expect(res.status).toBe(204);
  });
});

describe("authorization", () => {
  it("allows a test inside everything, and names the rule that refuses otherwise", async () => {
    const org = await createOrganization(api, "Authorizer");
    const admin = org.admin_key.key;
    const inScope = await verifiedTarget(admin, "auth.acme-shop.io");
    const outOfScope = await verifiedTarget(admin, "auth-out.acme-shop.io");
    const { target: pending } = await addTarget(admin, "auth-pending.acme-shop.io");
    const base = { host: "auth.acme-shop.io", path: "/shop", intensity: "passive", at: new Date(T0).toISOString() };

    expect(await authorizeDry(admin, base)).toEqual({ allowed: false, reason: "no_rules_of_engagement" });
    const signed = RulesOfEngagementResponseSchema.parse(await (await sign(admin, CONTENT([inScope.id]))).json());

    expect(await authorizeDry(admin, base)).toEqual({ allowed: true, roe_id: signed.version.id });
    expect(await authorizeDry(admin, { ...base, intensity: "safe-active" })).toEqual({
      allowed: true,
      roe_id: signed.version.id,
    });
    expect(await authorizeDry(admin, { ...base, host: "unknown.acme-shop.io" })).toEqual({
      allowed: false,
      reason: "target_unknown",
    });
    expect(await authorizeDry(admin, { ...base, host: pending.host })).toEqual({
      allowed: false,
      reason: "target_not_verified",
    });
    expect(await authorizeDry(admin, { ...base, host: outOfScope.host })).toEqual({
      allowed: false,
      reason: "out_of_scope",
    });
    for (const path of ["/admin", "/admin/users", "/ADMIN", "/x/../admin", "/%61dmin", "//admin"]) {
      expect(await authorizeDry(admin, { ...base, path })).toEqual({ allowed: false, reason: "path_excluded" });
    }
    expect(await authorizeDry(admin, { ...base, intensity: "full" })).toEqual({
      allowed: false,
      reason: "intensity_exceeds",
    });
    expect(await authorizeDry(admin, { ...base, at: "2026-11-16T17:00:00.000Z" })).toEqual({
      allowed: false,
      reason: "outside_window",
    });
    // Another Organization's dry check knows nothing of these targets.
    expect(await authorizeDry(adminB, base)).toEqual({ allowed: false, reason: "target_unknown" });
    // A target that lapsed is no longer authorised.
    txt.delete("_airverse-challenge.auth.acme-shop.io");
    await verify(admin, inScope.id);
    expect(await authorizeDry(admin, base)).toEqual({ allowed: false, reason: "target_not_verified" });
  });

  it("judges freshness by the API's clock in the dry check; `at` only places the test in the window (review F6)", async () => {
    const org = await createOrganization(api, "Clock");
    const admin = org.admin_key.key;
    const target = await verifiedTarget(admin, "clock.acme-shop.io");
    const signed = RulesOfEngagementResponseSchema.parse(await (await sign(admin, CONTENT([target.id]))).json());
    const base = { host: target.host, path: "/", intensity: "passive" };
    // Without `at`, the test is placed now.
    expect(await authorizeDry(admin, base)).toEqual({ allowed: true, roe_id: signed.version.id });
    clock = T0 + 27 * HOUR;
    expect(await authorizeDry(admin, { ...base, at: new Date(T0).toISOString() })).toEqual({
      allowed: false,
      reason: "target_not_verified",
    });
  });

  it("validates the dry check's body", async () => {
    await expectProblem(
      await api.app.request(
        "/v1/prove/authorize",
        json({ host: "auth.acme-shop.io", path: "no-slash", intensity: "passive", at: "now" }, bearer(adminA)),
      ),
      400,
    );
  });

  it("exports authorize(organizationId, request) for slice 15, the same check as the dry route", async () => {
    const org = await createOrganization(api, "Exported");
    const admin = org.admin_key.key;
    const target = await verifiedTarget(admin, "export.acme-shop.io");
    const signed = RulesOfEngagementResponseSchema.parse(await (await sign(admin, CONTENT([target.id]))).json());
    const authorize = createAuthorize({ db: api.db, now });
    const request = { host: target.host, path: "/", intensity: "passive" as const };
    expect(await authorize(org.organization.id, request)).toEqual({ allowed: true, roe_id: signed.version.id });
    // Review F6: the API's clock decides, whatever time a caller supplies.
    expect(await authorize(org.organization.id, { ...request, at: "2026-11-15T10:00:00.000Z" })).toEqual({
      allowed: true,
      roe_id: signed.version.id,
    });
    clock = T0 + 27 * HOUR; // Tuesday 13:00, inside the window, but the last check is 27 hours old.
    expect(await authorize(org.organization.id, { ...request, at: new Date(T0).toISOString() })).toEqual({
      allowed: false,
      reason: "target_not_verified",
    });
    clock = T0 + 8 * HOUR; // 18:00: fresh, outside the window.
    expect(await authorize(org.organization.id, request)).toEqual({ allowed: false, reason: "outside_window" });
    clock = T0;
    // Another Organization's id sees none of this Organization's targets.
    const other = await createOrganization(api, "Other");
    expect(await authorize(other.organization.id, request)).toEqual({ allowed: false, reason: "target_unknown" });
    await expect(authorize(org.organization.id, { ...request, path: "relative" })).rejects.toThrow(TypeError);
  });
});

describe("logging", () => {
  it("never logs a key or a verification token", () => {
    expect(keyIdA).toMatch(/^key_/);
    expectNoKeyLogged(api);
    expect(tokens.length).toBeGreaterThan(0);
    for (const token of tokens) for (const line of api.logger.lines) expect(line).not.toContain(token);
  });
});
