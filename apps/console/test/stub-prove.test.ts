// @vitest-environment node
import {
  AuthorizeResultSchema,
  authorizeTest,
  CurrentRulesOfEngagementResponseSchema,
  ListRulesOfEngagementResponseSchema,
  ListTargetsResponseSchema,
  normaliseHost,
  ProblemSchema,
  RulesOfEngagementResponseSchema,
  type Target,
  TargetResponseSchema,
  VerifyTargetResponseSchema,
} from "@antireverse/protocol";
import { rulesOfEngagementSha256 } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { createProveStore, stubNormaliseHost } from "../scripts/stub-prove.mjs";

// The stand-in API answers Prove (slice 14) in the shape of the protocol: the Console is looked at against the
// same contract the real API serves. Every 2xx body is parsed with its response schema and must come back unchanged.

const KEY_ID = "key_0123456789abcdef01234567";
/** Wednesday 2026-11-11 10:00 UTC: inside the seeded weekday window. */
const NOW = Date.parse("2026-11-11T10:00:00.000Z");

interface Answer {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

function store(clock: { ms: number } = { ms: NOW }) {
  const prove = createProveStore({ keyId: KEY_ID, now: () => clock.ms });
  return (method: string, path: string, body?: unknown): Answer => {
    const answer = prove.handle(method, path, body);
    if (answer === null) throw new Error(`no answer for ${method} ${path}`);
    return answer as Answer;
  };
}

function parsed<T>(
  schema: { safeParse(value: unknown): { success: boolean; data?: T; error?: unknown } },
  body: unknown,
): T {
  const result = schema.safeParse(body);
  expect(result.success ? [] : (result.error as { issues: unknown[] }).issues).toEqual([]);
  // Nothing the stub sends is stripped by the contract.
  expect(result.data).toEqual(body);
  return result.data as T;
}

const targetsOf = (call: ReturnType<typeof store>): Target[] =>
  parsed(ListTargetsResponseSchema, call("GET", "/v1/targets").body).targets;

describe("stub Prove — targets", () => {
  it("seeds a verified DNS target, a verified file target, a lapsed one and a pending one", () => {
    const call = store();
    const targets = targetsOf(call);
    expect(targets.map((target) => [target.host, target.status, target.method])).toEqual([
      ["shop.acme-shop.io", "verified", "dns"],
      ["api.acme-shop.io", "verified", "file"],
      ["legacy.acme-shop.io", "lapsed", "dns"],
      ["staging.acme-shop.io", "pending", null],
    ]);
    expect(targets[2]?.lapsed_reason).toMatch(/\S/);
    for (const target of targets) {
      const one = call("GET", `/v1/targets/${target.id}`);
      expect(one.status).toBe(200);
      parsed(TargetResponseSchema, one.body);
    }
  });

  it("adds a host in its stored form with the two ways to prove it, and refuses what the protocol refuses", () => {
    const call = store();
    const created = call("POST", "/v1/targets", { host: " Blog.Acme-Shop.IO. " });
    expect(created.status).toBe(201);
    const { target, verification } = parsed(TargetResponseSchema, created.body);
    expect(target).toMatchObject({ host: "blog.acme-shop.io", status: "pending", method: null });
    expect(verification.dns_name).toBe("_airverse-challenge.blog.acme-shop.io");
    for (const host of ["127.0.0.1", "intranet", "db.internal", "shop.example.com", "a..b", "x.0x7f", ""]) {
      const refused = call("POST", "/v1/targets", { host });
      expect([host, refused.status]).toEqual([host, 400]);
      expect(parsed(ProblemSchema, refused.body).errors?.map((error) => error.path)).toEqual(["host"]);
    }
    const duplicate = call("POST", "/v1/targets", { host: "BLOG.acme-shop.io" });
    expect(duplicate.status).toBe(409);
    expect(parsed(ProblemSchema, duplicate.body).reason).toBe("target-duplicate");
  });

  it("normalises hosts exactly as the protocol does", () => {
    const samples = [
      "shop.acme-shop.io",
      "SHOP.acme-shop.io.",
      "xn--bcher-kva.example.de",
      "localhost",
      "a.local",
      "1.2.3.4",
      "foo.123",
      "-bad.io",
      "bad-.io",
      "ok.io",
      "home.arpa",
      "x.home.arpa",
      "under_score.io",
      "shop.example.org",
    ];
    for (const host of samples) expect([host, stubNormaliseHost(host)]).toEqual([host, normaliseHost(host)]);
  });

  it("verifies by the first label of the host: through DNS, through the file, or with each failure reason", () => {
    const call = store();
    const add = (host: string) => (call("POST", "/v1/targets", { host }).body as { target: Target }).target.id;
    const verify = (id: string) => {
      const answer = call("POST", `/v1/targets/${id}/verify`);
      expect(answer.status).toBe(200);
      return parsed(VerifyTargetResponseSchema, answer.body);
    };
    expect(verify(add("dns.acme-shop.io"))).toMatchObject({
      target: { status: "verified", method: "dns" },
      result: { verified: true, method: "dns" },
    });
    expect(verify(add("file.acme-shop.io")).result).toMatchObject({ verified: true, method: "file" });
    expect(verify(add("tls-failed.acme-shop.io")).result).toMatchObject({
      verified: false,
      dns: "no_record",
      file: "tls_failed",
    });
    expect(verify(add("lookup-failed.acme-shop.io")).result).toMatchObject({ dns: "lookup_failed", file: "status" });
    const plain = add("blog.acme-shop.io");
    expect(verify(plain)).toMatchObject({ target: { status: "pending" }, result: { verified: false } });
    expect(verify(plain).result).toMatchObject({ verified: true, method: "dns" });
  });

  it("answers the eleventh check of a target within an hour with 429 and Retry-After", () => {
    const clock = { ms: NOW };
    const call = store(clock);
    const [target] = targetsOf(call);
    for (let n = 0; n < 10; n++) expect(call("POST", `/v1/targets/${target?.id}/verify`).status).toBe(200);
    const limited = call("POST", `/v1/targets/${target?.id}/verify`);
    expect(limited.status).toBe(429);
    expect(Number(limited.headers?.["retry-after"])).toBeGreaterThan(0);
    clock.ms += 3_600_000;
    expect(call("POST", `/v1/targets/${target?.id}/verify`).status).toBe(200);
  });

  it("refuses to remove a target in the current scope with 409, removes any other, and 404s an unknown one", () => {
    const call = store();
    const [shop, , , staging] = targetsOf(call);
    const refused = call("DELETE", `/v1/targets/${shop?.id}`);
    expect(refused.status).toBe(409);
    expect(parsed(ProblemSchema, refused.body).reason).toBe("target-in-scope");
    expect(call("DELETE", `/v1/targets/${staging?.id}`).status).toBe(204);
    expect(call("GET", `/v1/targets/${staging?.id}`).status).toBe(404);
    expect(call("DELETE", "/v1/targets/tgt_ffffffffffffffffffffffff").status).toBe(404);
  });

  it("answers the 51st target with 409 target-limit", () => {
    const call = store();
    for (let n = targetsOf(call).length; n < 50; n++)
      expect(call("POST", "/v1/targets", { host: `h${n}.acme-shop.io` }).status).toBe(201);
    const full = call("POST", "/v1/targets", { host: "one-more.acme-shop.io" });
    expect(full.status).toBe(409);
    expect(parsed(ProblemSchema, full.body).reason).toBe("target-limit");
  });
});

describe("stub Prove — Rules of Engagement", () => {
  it("lists two signed versions newest first, each with its content hash, and the current one", () => {
    const call = store();
    const { versions } = parsed(ListRulesOfEngagementResponseSchema, call("GET", "/v1/rules-of-engagement").body);
    expect(versions.map((version) => version.intensity)).toEqual(["safe-active", "passive"]);
    for (const version of versions) {
      expect(version.signed_by).toBe(KEY_ID);
      expect(version.content_sha256).toBe(rulesOfEngagementSha256(version));
    }
    const current = parsed(CurrentRulesOfEngagementResponseSchema, call("GET", "/v1/rules-of-engagement/current").body);
    expect(current.version).toEqual(versions[0]);
  });

  it("signs a new version with the exact phrase, which becomes current", () => {
    const call = store();
    const [shop, api] = targetsOf(call);
    const content = {
      scope: [api?.id],
      exclusions: ["/admin"],
      intensity: "full",
      window: { days: ["sat"], from: "22:00", to: "24:00" },
      contacts: ["sec@acme-shop.io"],
    };
    const refused = call("POST", "/v1/rules-of-engagement", { ...content, confirm: "I authorise safe-active testing" });
    expect(refused.status).toBe(400);
    expect(parsed(ProblemSchema, refused.body).errors?.map((error) => error.path)).toEqual(["confirm"]);
    const signed = call("POST", "/v1/rules-of-engagement", { ...content, confirm: "I authorise full testing" });
    expect(signed.status).toBe(201);
    const { version } = parsed(RulesOfEngagementResponseSchema, signed.body);
    expect(version.content_sha256).toBe(rulesOfEngagementSha256(version));
    expect((call("GET", "/v1/rules-of-engagement/current").body as { version: { id: string } }).version.id).toBe(
      version.id,
    );
    // shop left the scope, so it can be removed now.
    expect(call("DELETE", `/v1/targets/${shop?.id}`).status).toBe(204);
  });

  it("refuses a scope with a target that is not verified, and malformed fields with their paths", () => {
    const call = store();
    const [, , legacy] = targetsOf(call);
    const content = {
      scope: [legacy?.id],
      exclusions: [],
      intensity: "passive",
      window: { days: ["mon"], from: "09:00", to: "17:00" },
      contacts: ["sec@acme-shop.io"],
      confirm: "I authorise passive testing",
    };
    const refused = call("POST", "/v1/rules-of-engagement", content);
    expect(refused.status).toBe(400);
    expect(parsed(ProblemSchema, refused.body).errors?.map((error) => error.path)).toEqual(["scope.0"]);
    const malformed = call("POST", "/v1/rules-of-engagement", {
      ...content,
      exclusions: ["admin"],
      window: { days: [], from: "9", to: "17:00" },
      contacts: ["nobody"],
    });
    expect(parsed(ProblemSchema, malformed.body).errors?.map((error) => error.path)).toEqual([
      "exclusions.0",
      "window.days",
      "window.from",
      "contacts.0",
    ]);
  });
});

describe("stub Prove — authorize", () => {
  it("agrees with the protocol's authorizeTest on every refusal reason and on an allowed test", () => {
    const call = store();
    const targets = targetsOf(call);
    const current = (call("GET", "/v1/rules-of-engagement/current").body as { version: never }).version;
    const at = "2026-11-11T10:00:00.000Z";
    const requests = [
      { host: "unknown.acme-shop.io", path: "/", intensity: "passive", at },
      { host: "legacy.acme-shop.io", path: "/", intensity: "passive", at },
      { host: "staging.acme-shop.io", path: "/", intensity: "passive", at },
      { host: "shop.acme-shop.io", path: "/admin/users", intensity: "passive", at },
      { host: "shop.acme-shop.io", path: "/ADMIN", intensity: "passive", at },
      { host: "shop.acme-shop.io", path: "/products", intensity: "full", at },
      { host: "shop.acme-shop.io", path: "/products", intensity: "safe-active", at: "2026-11-11T18:00:00.000Z" },
      { host: "shop.acme-shop.io", path: "/products", intensity: "safe-active", at },
      { host: "API.acme-shop.io.", path: "/v2/orders?id=1", intensity: "passive", at },
    ] as const;
    const reasons: string[] = [];
    for (const request of requests) {
      const answer = call("POST", "/v1/prove/authorize", request);
      expect(answer.status).toBe(200);
      const result = parsed(AuthorizeResultSchema, answer.body);
      expect([request, result]).toEqual([request, authorizeTest({ targets, current }, request)]);
      reasons.push(result.allowed ? "allowed" : result.reason);
    }
    expect(reasons).toEqual([
      "target_unknown",
      "target_not_verified",
      "target_not_verified",
      "path_excluded",
      "path_excluded",
      "intensity_exceeds",
      "outside_window",
      "allowed",
      "allowed",
    ]);
  });

  it("refuses a malformed check with field errors", () => {
    const call = store();
    const answer = call("POST", "/v1/prove/authorize", { host: "10.0.0.1", path: "admin", intensity: "loud", at: "" });
    expect(answer.status).toBe(400);
    expect(parsed(ProblemSchema, answer.body).errors?.map((error) => error.path)).toEqual([
      "host",
      "path",
      "intensity",
      "at",
    ]);
  });

  it("leaves every other path to the rest of the stub", () => {
    const prove = createProveStore({ keyId: KEY_ID, now: () => NOW });
    expect(prove.handle("GET", "/v1/apps", undefined)).toBeNull();
  });
});
