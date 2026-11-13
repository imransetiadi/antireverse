import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BundlePayloadSchema,
  type Environment,
  POLICY_LIMITS,
  type PolicyRule,
  SignedBundleSchema,
  SigningKeyResponseSchema,
} from "@antireverse/protocol";
import { bundleAudience, generateKey, hashKey, keyIdOf, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AttestationKeys } from "../src/attestation/keys.ts";
import { createBundleIssuer, type IssuedBundle } from "../src/bundle.ts";
import { createSigner } from "../src/signer.ts";
import { insertKey } from "../src/stores/keys.ts";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  fetchBundle,
  json,
  makeTestApi,
  publishPolicy,
  type TestApi,
  tick,
  verifySignature,
  withReason,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/**
 * A fixed attestation key set, so that these tests see only the Policy's own changes; rotation is tested in
 * attest.test.ts. Public halves only: it signs nothing here.
 */
const ATTESTATION_KEYS = [
  { kid: "0123456789abcdef", public_key: "A".repeat(43) },
  { kid: "fedcba9876543210", public_key: "B".repeat(43) },
];
const fixedAttestation: AttestationKeys = {
  attestationKeys: () => ATTESTATION_KEYS.map((key) => ({ ...key })),
  currentKid: () => "0123456789abcdef",
  sign: () => {
    throw new Error("Not used in these tests.");
  },
};

const monitorRule = { name: "User export", path: "/api/users/*/export", methods: ["GET", "POST"] };
const enforceRule = { name: "Admin area", path: "/api/admin/**", mode: "enforce" };

/** A Rule as a bundle carries it: everything but the name, in this order of members. */
function bundled(rule: PolicyRule): Record<string, unknown> {
  return { id: rule.id, path: rule.path, methods: rule.methods, action: rule.action, mode: rule.mode };
}

interface Tenant {
  organizationId: string;
  adminKey: string;
  appId: string;
  shieldKey: string;
}

describe("Policy Bundle", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-bundle-"));
  const keyFile = join(root, "signing-key.json");
  let api: TestApi;
  let publicKey: string;
  let privateKey: string;
  /** The epoch of this file's database, read from the database itself. */
  let epoch: string;
  const clock = { now: new Date(T0) };
  /** Every response body the API produced in this file, to prove what never leaves it. */
  const bodies: string[] = [];

  async function tenant(name: string, environment: Environment = "development"): Promise<Tenant> {
    const organization = await createOrganization(api, name);
    const created = await createAppFor(api, organization.admin_key.key, { name: "Storefront", environment });
    return {
      organizationId: organization.organization.id,
      adminKey: organization.admin_key.key,
      appId: created.app.id,
      shieldKey: created.shield_key.key,
    };
  }

  /** One more Shield key for an App: there is no route for it yet, the store is used as the route would. */
  async function issueShieldKey(t: Tenant, environment: Environment): Promise<string> {
    const generated = generateKey("shield", environment);
    await api.db.tx({ organizationId: t.organizationId }, (q) =>
      insertKey(q, {
        id: newId("key"),
        organizationId: t.organizationId,
        kind: "shield",
        appId: t.appId,
        environment,
        generated,
      }),
    );
    api.issuedKeys.push(generated.key);
    return generated.key;
  }

  async function get(path: string, headers: Record<string, string> = {}, method = "GET"): Promise<Response> {
    const res = await api.app.request(path, { method, headers });
    bodies.push(await res.clone().text());
    return res;
  }

  beforeAll(async () => {
    const signer = createSigner({ file: keyFile });
    const stored = JSON.parse(readFileSync(keyFile, "utf8")) as { private_key: string };
    privateKey = stored.private_key;
    publicKey = signer.publicKey;
    api = await makeTestApi({ signer, now: () => clock.now, attestation: fixedAttestation });
    const { rows } = await api.db.tx("none", (q) => q.query<{ epoch: string }>("SELECT epoch FROM database_epoch"));
    expect(rows).toHaveLength(1);
    epoch = rows[0]?.epoch ?? "";
  });
  afterAll(async () => {
    await api.close();
    rmSync(root, { recursive: true, force: true });
  });

  describe("signing key", () => {
    it("is public: anyone can read the key that verifies what the signer signs", async () => {
      const res = await get("/v1/signing-key");

      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const raw = (await res.json()) as Record<string, unknown>;
      const body = SigningKeyResponseSchema.parse(raw);
      expect(Object.keys(raw).sort()).toEqual(["algorithm", "key_id", "public_key"]);
      expect(body).toEqual({ key_id: api.signer.keyId, algorithm: "Ed25519", public_key: api.signer.publicKey });
      expect(body.key_id).toBe(keyIdOf(Buffer.from(body.public_key, "base64url")));

      const text = '{"format":1}';
      expect(verifySignature(body.public_key, text, api.signer.sign(Buffer.from(text, "utf8")))).toBe(true);
    });

    it("answers the same with any key, and with none", async () => {
      const t = await tenant("Signing key readers");
      const anonymous = await (await get("/v1/signing-key")).json();
      for (const key of [t.adminKey, t.shieldKey, "not-a-key"]) {
        const res = await get("/v1/signing-key", bearer(key));
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual(anonymous);
      }
    });
  });

  describe("bundle", () => {
    it("is the built-in Policy, version 0 without Rules, before anything is published", async () => {
      const t = await tenant("Unpublished");
      clock.now = new Date(T0 + 1_000);

      const res = await get("/v1/policy-bundle", bearer(t.shieldKey));

      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toMatch(/^application\/json/);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(res.headers.get("etag")).toMatch(/^"[A-Za-z0-9_-]{16,64}"$/);
      const raw = (await res.json()) as Record<string, unknown>;
      const signed = SignedBundleSchema.parse(raw);
      expect(Object.keys(raw).sort()).toEqual(["bundle", "key_id", "signature"]);
      expect(signed.key_id).toBe(api.signer.keyId);
      expect(verifySignature(publicKey, signed.bundle, signed.signature)).toBe(true);
      expect(JSON.parse(signed.bundle)).toEqual({
        format: 1,
        audience: bundleAudience(t.shieldKey),
        epoch,
        app_id: t.appId,
        environment: "development",
        version: 0,
        issued_at: new Date(T0 + 1_000).toISOString(),
        not_after: new Date(T0 + 1_000 + 7 * DAY).toISOString(),
        rules: [],
        attestation_keys: ATTESTATION_KEYS,
      });
    });

    it("carries the current version and its Rules in order, without their names", async () => {
      const t = await tenant("Published", "production");
      await publishPolicy(api, t.adminKey, t.appId, "production", [monitorRule]);
      const policy = await publishPolicy(api, t.adminKey, t.appId, "production", [enforceRule, monitorRule]);
      clock.now = new Date(T0 + 2_000);

      const { signed, payload } = await fetchBundle(api, t.shieldKey, publicKey);

      expect(payload).toEqual({
        format: 1,
        audience: bundleAudience(t.shieldKey),
        epoch,
        app_id: t.appId,
        environment: "production",
        version: 2,
        issued_at: new Date(T0 + 2_000).toISOString(),
        not_after: new Date(T0 + 2_000 + 7 * DAY).toISOString(),
        rules: policy.rules.map(bundled),
        attestation_keys: ATTESTATION_KEYS,
      });
      // The signature covers the string as transmitted, so the string itself is pinned: one serialisation,
      // members in the documented order, no Rule name and no white space.
      expect(signed.bundle).toBe(
        JSON.stringify({
          format: 1,
          audience: bundleAudience(t.shieldKey),
          epoch,
          app_id: t.appId,
          environment: "production",
          version: 2,
          issued_at: new Date(T0 + 2_000).toISOString(),
          not_after: new Date(T0 + 2_000 + 7 * DAY).toISOString(),
          rules: policy.rules.map(bundled),
          attestation_keys: ATTESTATION_KEYS,
        }),
      );
      expect(signed.bundle).not.toMatch(/Admin area|User export|name/);
      expect(Buffer.byteLength(signed.bundle, "utf8")).toBe(signed.bundle.length);
    });

    it("carries the epoch of the database: 16 random bytes as lowercase hex, the same in every bundle", async () => {
      const a = await tenant("Epoch A");
      const b = await tenant("Epoch B", "staging");
      await publishPolicy(api, b.adminKey, b.appId, "staging", [enforceRule]);

      const one = await fetchBundle(api, a.shieldKey, publicKey);
      const two = await fetchBundle(api, b.shieldKey, publicKey);

      expect(epoch).toMatch(/^[0-9a-f]{32}$/);
      expect(one.payload.epoch).toBe(epoch);
      expect(two.payload.epoch).toBe(epoch);
      // In the documented place: after the audience, before the App.
      expect(Object.keys(JSON.parse(one.signed.bundle) as object)).toEqual([
        "format",
        "audience",
        "epoch",
        "app_id",
        "environment",
        "version",
        "issued_at",
        "not_after",
        "rules",
        "attestation_keys",
      ]);
    });

    it("fits the bundle bound with 50 Rules that are each as large as a Rule can be", async () => {
      const t = await tenant("Largest");
      const methods = Array.from({ length: POLICY_LIMITS.methodsMax }, (_, index) =>
        `${String.fromCharCode(65 + index)}`.repeat(16),
      );
      const rules = Array.from({ length: POLICY_LIMITS.rulesMax }, (_, index) => ({
        name: "n".repeat(POLICY_LIMITS.nameMax),
        path: `/${String(index).padStart(2, "0")}${"a".repeat(POLICY_LIMITS.pathMax - 3)}`,
        methods,
        mode: "enforce",
      }));
      await publishPolicy(api, t.adminKey, t.appId, "development", rules);

      const { signed, payload } = await fetchBundle(api, t.shieldKey, publicKey);

      expect(payload.rules).toHaveLength(50);
      expect(payload.rules[49]?.path).toHaveLength(256);
      expect(Buffer.byteLength(signed.bundle, "utf8")).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
    });

    describe("signature_rules (slice 04, amendment A1)", () => {
      const signed = (name: string, path: string, mode = "monitor") => ({
        name,
        path,
        methods: ["POST"],
        mode,
        requires: "signature",
      });

      it("puts Rules with a requirement in signature_rules, never in rules, each in Policy order", async () => {
        const t = await tenant("Signed requests", "production");
        const policy = await publishPolicy(api, t.adminKey, t.appId, "production", [
          signed("Checkout", "/api/checkout/**", "enforce"),
          monitorRule,
          signed("Transfer", "/api/transfer"),
          enforceRule,
          signed("Login", "/api/login", "enforce"),
        ]);
        clock.now = new Date(T0 + 3_000);
        const [checkout, users, transfer, admin, login] = policy.rules as PolicyRule[];

        const { signed: bundle, payload } = await fetchBundle(api, t.shieldKey, publicKey);

        const raw = JSON.parse(bundle.bundle) as { rules: unknown[]; signature_rules: unknown[] };
        expect(raw.rules).toEqual([users, admin].map((rule) => bundled(rule as PolicyRule)));
        expect(raw.signature_rules).toEqual([checkout, transfer, login].map((rule) => bundled(rule as PolicyRule)));
        // The raw string: no requires anywhere, and no requirement Rule in rules.
        expect(bundle.bundle).not.toContain("requires");
        expect(bundle.bundle).not.toContain('"signature"');
        for (const rule of raw.rules as { path: string }[]) expect(rule.path).not.toMatch(/checkout|transfer|login/);
        expect(bundle.bundle).toBe(
          JSON.stringify({
            format: 1,
            audience: bundleAudience(t.shieldKey),
            epoch,
            app_id: t.appId,
            environment: "production",
            version: 1,
            issued_at: new Date(T0 + 3_000).toISOString(),
            not_after: new Date(T0 + 3_000 + 7 * DAY).toISOString(),
            rules: [users, admin].map((rule) => bundled(rule as PolicyRule)),
            signature_rules: [checkout, transfer, login].map((rule) => bundled(rule as PolicyRule)),
            attestation_keys: ATTESTATION_KEYS,
          }),
        );
        expect(payload.signature_rules).toHaveLength(3);
      });

      it("has no signature_rules member for a Policy of plain Rules only, nor with requirement Rules only in rules", async () => {
        const t = await tenant("Plain only");
        const policy = await publishPolicy(api, t.adminKey, t.appId, "development", [monitorRule, enforceRule]);
        const { signed: bundle } = await fetchBundle(api, t.shieldKey, publicKey);
        expect("signature_rules" in JSON.parse(bundle.bundle)).toBe(false);
        expect(bundle.bundle).not.toContain("signature_rules");
        expect((JSON.parse(bundle.bundle) as { rules: unknown[] }).rules).toEqual(policy.rules.map(bundled));

        // Only requirement Rules: rules is empty (always present), signature_rules holds them.
        const only = await tenant("Requirement only");
        await publishPolicy(api, only.adminKey, only.appId, "development", [signed("Checkout", "/api/checkout")]);
        const onlyRaw = JSON.parse((await fetchBundle(api, only.shieldKey, publicKey)).signed.bundle);
        expect(onlyRaw.rules).toEqual([]);
        expect(onlyRaw.signature_rules).toHaveLength(1);
      });

      it("changes the bundle and its ETag when a version moves a Rule between rules and signature_rules", async () => {
        const t = await tenant("Moves");
        await publishPolicy(api, t.adminKey, t.appId, "development", [enforceRule]);
        const before = await fetchBundle(api, t.shieldKey, publicKey);
        const { name, path, mode } = enforceRule;
        await publishPolicy(api, t.adminKey, t.appId, "development", [{ name, path, mode, requires: "signature" }]);
        const after = await fetchBundle(api, t.shieldKey, publicKey);
        expect(after.etag).not.toBe(before.etag);
        expect(after.payload.rules).toEqual([]);
        expect(after.payload.signature_rules?.[0]).toMatchObject({ path: "/api/admin/**", mode: "enforce" });
      });

      it("fits the bundle bound with 50 Rules as large as they can be, split between both members", async () => {
        const t = await tenant("Largest split");
        const methods = Array.from({ length: POLICY_LIMITS.methodsMax }, (_, index) =>
          `${String.fromCharCode(65 + index)}`.repeat(16),
        );
        const rules = Array.from({ length: POLICY_LIMITS.rulesMax }, (_, index) => ({
          name: "n".repeat(POLICY_LIMITS.nameMax),
          path: `/${String(index).padStart(2, "0")}${"a".repeat(POLICY_LIMITS.pathMax - 3)}`,
          methods,
          mode: "enforce",
          ...(index % 2 === 0 ? { requires: "signature" } : {}),
        }));
        await publishPolicy(api, t.adminKey, t.appId, "development", rules);
        const { signed: bundle, payload } = await fetchBundle(api, t.shieldKey, publicKey);
        expect(payload.rules).toHaveLength(25);
        expect(payload.signature_rules).toHaveLength(25);
        expect(Buffer.byteLength(bundle.bundle, "utf8")).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
      });

      it("issuer: splits the subject's Rules and never copies requires or name into the bundle", () => {
        const issuer = createBundleIssuer({ signer: createSigner(), now: () => new Date(T0) });
        const rule = (id: string, requires?: "signature"): PolicyRule => ({
          id,
          name: `Rule ${id}`,
          path: `/api/${id}`,
          methods: [],
          action: "block",
          mode: "enforce",
          ...(requires === undefined ? {} : { requires }),
        });
        const ids = [1, 2, 3].map((n) => `rul_${String(n).padStart(24, "0")}`);
        const issued = issuer.issue({
          audience: "0123456789abcdef0123456789abcdef",
          epoch: "0123456789abcdef0123456789abcdef",
          appId: "app_0123456789abcdef01234567",
          environment: "development",
          version: 1,
          rules: [rule(ids[0] as string, "signature"), rule(ids[1] as string), rule(ids[2] as string, "signature")],
        });
        const raw = JSON.parse(issued.signed.bundle) as Record<string, Record<string, unknown>[]>;
        expect(raw.rules?.map((entry) => entry.id)).toEqual([ids[1]]);
        expect(raw.signature_rules?.map((entry) => entry.id)).toEqual([ids[0], ids[2]]);
        for (const entry of [...(raw.rules ?? []), ...(raw.signature_rules ?? [])]) {
          expect(Object.keys(entry)).toEqual(["id", "path", "methods", "action", "mode"]);
        }
      });
    });

    describe("limit_rules (slice 08)", () => {
      const limited = (name: string, path: string, mode = "monitor", limit: Record<string, unknown> = {}) => ({
        name,
        path,
        methods: ["POST"],
        mode,
        limit: { requests: 10, window_s: 300, key: "ip", count: "failures", ...limit },
      });
      const signedRule = { name: "Checkout", path: "/api/checkout", methods: ["POST"], requires: "signature" };
      /** A limit Rule as a bundle carries it: a bundle Rule plus its limit, complete, in this order of members. */
      const bundledLimit = (rule: PolicyRule): Record<string, unknown> => ({ ...bundled(rule), limit: rule.limit });

      it("puts Rules with a limit in limit_rules, never in rules or signature_rules, each in Policy order", async () => {
        const t = await tenant("Limits", "production");
        const policy = await publishPolicy(api, t.adminKey, t.appId, "production", [
          limited("Login", "/login", "enforce"),
          monitorRule,
          signedRule,
          { name: "Search", path: "/api/search", limit: { requests: 100, window_s: 60, key: "device" } },
          enforceRule,
          limited("Reset", "/password/reset"),
        ]);
        clock.now = new Date(T0 + 4_000);
        const [login, users, checkout, search, admin, reset] = policy.rules as PolicyRule[];

        const { signed: bundle, payload } = await fetchBundle(api, t.shieldKey, publicKey);

        // The string itself: members in the documented order, `limit_rules` after `signature_rules`, `count` written
        // also where the client left it out, and no name.
        expect(bundle.bundle).toBe(
          JSON.stringify({
            format: 1,
            audience: bundleAudience(t.shieldKey),
            epoch,
            app_id: t.appId,
            environment: "production",
            version: 1,
            issued_at: new Date(T0 + 4_000).toISOString(),
            not_after: new Date(T0 + 4_000 + 7 * DAY).toISOString(),
            rules: [users, admin].map((rule) => bundled(rule as PolicyRule)),
            signature_rules: [bundled(checkout as PolicyRule)],
            limit_rules: [
              {
                id: login?.id,
                path: "/login",
                methods: ["POST"],
                action: "throttle",
                mode: "enforce",
                limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
              },
              {
                id: search?.id,
                path: "/api/search",
                methods: [],
                action: "throttle",
                mode: "monitor",
                limit: { requests: 100, window_s: 60, key: "device", count: "requests" },
              },
              bundledLimit(reset as PolicyRule),
            ],
            attestation_keys: ATTESTATION_KEYS,
          }),
        );
        expect(payload.limit_rules).toHaveLength(3);
        // What a Shield from before slice 08 keeps: no throttle and no limit anywhere outside `limit_rules`.
        const raw = JSON.parse(bundle.bundle) as Record<string, Record<string, unknown>[]>;
        for (const entry of [...(raw.rules ?? []), ...(raw.signature_rules ?? [])]) {
          expect(entry.action).toBe("block");
          expect("limit" in entry).toBe(false);
          expect(String(entry.path)).not.toMatch(/login|search|reset/);
        }
        const { limit_rules: _stripped, ...older } = raw;
        expect(JSON.stringify(older)).not.toMatch(/throttle|limit|window_s/);
        expect(bundle.bundle).not.toMatch(/Login|Search|Reset|name/);
      });

      it("has no limit_rules member without limit Rules: the bundle is byte for byte what it was before slice 08", async () => {
        const t = await tenant("No limits", "production");
        const policy = await publishPolicy(api, t.adminKey, t.appId, "production", [
          monitorRule,
          signedRule,
          enforceRule,
        ]);
        clock.now = new Date(T0 + 5_000);
        const [users, checkout, admin] = policy.rules as PolicyRule[];
        const { signed: bundle } = await fetchBundle(api, t.shieldKey, publicKey);
        expect(bundle.bundle).toBe(
          JSON.stringify({
            format: 1,
            audience: bundleAudience(t.shieldKey),
            epoch,
            app_id: t.appId,
            environment: "production",
            version: 1,
            issued_at: new Date(T0 + 5_000).toISOString(),
            not_after: new Date(T0 + 5_000 + 7 * DAY).toISOString(),
            rules: [users, admin].map((rule) => bundled(rule as PolicyRule)),
            signature_rules: [bundled(checkout as PolicyRule)],
            attestation_keys: ATTESTATION_KEYS,
          }),
        );
        expect(bundle.bundle).not.toMatch(/limit|throttle/);

        // The built-in Policy and a Policy of plain Rules only have none either.
        const empty = await tenant("Never published");
        expect((await fetchBundle(api, empty.shieldKey, publicKey)).signed.bundle).not.toContain("limit");

        // Only limit Rules: rules is empty (always present), limit_rules holds them.
        const only = await tenant("Limits only");
        await publishPolicy(api, only.adminKey, only.appId, "development", [limited("Login", "/login")]);
        const onlyRaw = JSON.parse((await fetchBundle(api, only.shieldKey, publicKey)).signed.bundle);
        expect(onlyRaw.rules).toEqual([]);
        expect("signature_rules" in onlyRaw).toBe(false);
        expect(onlyRaw.limit_rules).toHaveLength(1);
      });

      it("changes the bundle and its ETag when a limit changes, is added or is removed", async () => {
        const t = await tenant("Limit changes");
        const first = await publishPolicy(api, t.adminKey, t.appId, "development", [limited("Login", "/login")]);
        const before = await fetchBundle(api, t.shieldKey, publicKey);
        expect((await fetchBundle(api, t.shieldKey, publicKey)).etag).toBe(before.etag);

        const etags = new Set([before.etag]);
        const variants: Record<string, unknown>[] = [
          { requests: 11 },
          { requests: 11, window_s: 60 },
          { requests: 11, window_s: 60, key: "device" },
          { requests: 11, window_s: 60, key: "device", count: "requests" },
        ];
        for (const limit of variants) {
          await publishPolicy(api, t.adminKey, t.appId, "development", [
            { ...limited("Login", "/login", "monitor", limit), id: first.rules[0]?.id },
          ]);
          const next = await fetchBundle(api, t.shieldKey, publicKey);
          expect(etags.has(next.etag)).toBe(false);
          etags.add(next.etag);
          expect(next.payload.limit_rules?.[0]?.limit).toMatchObject(limit);
          const notModified = await get("/v1/policy-bundle", { ...bearer(t.shieldKey), "if-none-match": before.etag });
          expect(notModified.status).toBe(200);
        }

        // The limit removed: the Rule is a plain block Rule in `rules`, and `limit_rules` is gone.
        await publishPolicy(api, t.adminKey, t.appId, "development", [{ name: "Login", path: "/login" }]);
        const after = await fetchBundle(api, t.shieldKey, publicKey);
        expect(etags.has(after.etag)).toBe(false);
        expect(after.payload.rules).toHaveLength(1);
        expect("limit_rules" in JSON.parse(after.signed.bundle)).toBe(false);
      });

      it("fits the bundle bound with 50 Rules as large as they can be, in any split between the three members", async () => {
        const methods = Array.from({ length: POLICY_LIMITS.methodsMax }, (_, index) =>
          `${String.fromCharCode(65 + index)}`.repeat(16),
        );
        const largest = (index: number, kind: number) => ({
          name: "n".repeat(POLICY_LIMITS.nameMax),
          path: `/${String(index).padStart(2, "0")}${"a".repeat(POLICY_LIMITS.pathMax - 3)}`,
          methods,
          mode: "enforce",
          ...(kind === 1 ? { requires: "signature" } : {}),
          ...(kind === 2 ? { limit: { requests: 100_000, window_s: 3_600, key: "device", count: "failures" } } : {}),
        });
        const split = await tenant("Largest in three");
        await publishPolicy(
          api,
          split.adminKey,
          split.appId,
          "development",
          Array.from({ length: POLICY_LIMITS.rulesMax }, (_, index) => largest(index, index % 3)),
        );
        const mixed = await fetchBundle(api, split.shieldKey, publicKey);
        expect(mixed.payload.rules).toHaveLength(17);
        expect(mixed.payload.signature_rules).toHaveLength(17);
        expect(mixed.payload.limit_rules).toHaveLength(16);
        expect(Buffer.byteLength(mixed.signed.bundle, "utf8")).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);

        // All 50 as limit Rules, the longest form of a Rule (plan 08 amendment A2).
        const all = await tenant("Largest limits");
        await publishPolicy(
          api,
          all.adminKey,
          all.appId,
          "development",
          Array.from({ length: POLICY_LIMITS.rulesMax }, (_, index) => largest(index, 2)),
        );
        const limits = await fetchBundle(api, all.shieldKey, publicKey);
        expect(limits.payload.rules).toEqual([]);
        expect(limits.payload.limit_rules).toHaveLength(POLICY_LIMITS.rulesMax);
        expect(Buffer.byteLength(limits.signed.bundle, "utf8")).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);

        // One Rule more is refused when it is published, whatever the members it would travel in.
        const over = await api.app.request(`/v1/apps/${all.appId}/policies/development`, {
          method: "PUT",
          headers: { "content-type": "application/json", ...bearer(all.adminKey) },
          body: JSON.stringify({
            rules: Array.from({ length: POLICY_LIMITS.rulesMax + 1 }, (_, index) => largest(index, index % 3)),
          }),
        });
        await expectProblem(over, 400);
      });

      it("ships a limit Rule only to its own App and Environment", async () => {
        const a = await tenant("Limit owner", "production");
        const staging = await issueShieldKey(a, "staging");
        const otherApp = await createAppFor(api, a.adminKey, { name: "Back office", environment: "production" });
        const b = await tenant("Limit stranger", "production");
        await publishPolicy(api, a.adminKey, a.appId, "production", [limited("Login", "/only/here/login")]);
        await publishPolicy(api, b.adminKey, b.appId, "production", [monitorRule]);

        expect((await fetchBundle(api, a.shieldKey, publicKey)).payload.limit_rules).toHaveLength(1);
        for (const key of [staging, otherApp.shield_key.key, b.shieldKey]) {
          const { signed: bundle } = await fetchBundle(api, key, publicKey);
          expect(bundle.bundle).not.toContain("limit_rules");
          expect(bundle.bundle).not.toContain("/only/here/login");
        }
      });

      it("issuer: splits the subject's Rules in three and writes a limit complete, in the documented order", () => {
        const issuer = createBundleIssuer({ signer: createSigner(), now: () => new Date(T0) });
        const ids = [1, 2, 3, 4, 5].map((n) => `rul_${String(n).padStart(24, "0")}`);
        const base = (id: string) => ({
          id,
          name: `Rule ${id}`,
          path: `/api/${id}`,
          methods: [],
          mode: "enforce" as const,
        });
        const plain = (id: string): PolicyRule => ({ ...base(id), action: "block" });
        const signedOnly = (id: string): PolicyRule => ({ ...base(id), action: "block", requires: "signature" });
        const subject = (rules: PolicyRule[]) => ({
          audience: "0123456789abcdef0123456789abcdef",
          epoch: "0123456789abcdef0123456789abcdef",
          appId: "app_0123456789abcdef01234567",
          environment: "development" as const,
          version: 1,
          rules,
        });
        const issued = issuer.issue(
          subject([
            // Stored with its members in another order: the bundle has the documented one.
            {
              ...base(ids[0] as string),
              action: "throttle",
              limit: { count: "failures", key: "ip", window_s: 300, requests: 10 },
            },
            plain(ids[1] as string),
            signedOnly(ids[2] as string),
            {
              ...base(ids[3] as string),
              action: "throttle",
              limit: { requests: 5, window_s: 1, key: "device", count: "requests" },
            },
            plain(ids[4] as string),
          ]),
        );
        const raw = JSON.parse(issued.signed.bundle) as Record<string, Record<string, unknown>[]>;
        expect(Object.keys(raw)).toEqual([
          "format",
          "audience",
          "epoch",
          "app_id",
          "environment",
          "version",
          "issued_at",
          "not_after",
          "rules",
          "signature_rules",
          "limit_rules",
        ]);
        expect(raw.rules?.map((entry) => entry.id)).toEqual([ids[1], ids[4]]);
        expect(raw.signature_rules?.map((entry) => entry.id)).toEqual([ids[2]]);
        expect(raw.limit_rules?.map((entry) => entry.id)).toEqual([ids[0], ids[3]]);
        for (const entry of raw.limit_rules ?? []) {
          expect(Object.keys(entry)).toEqual(["id", "path", "methods", "action", "mode", "limit"]);
          expect(Object.keys(entry.limit as object)).toEqual(["requests", "window_s", "key", "count"]);
          expect(entry.action).toBe("throttle");
        }
        for (const entry of [...(raw.rules ?? []), ...(raw.signature_rules ?? [])]) {
          expect(Object.keys(entry)).toEqual(["id", "path", "methods", "action", "mode"]);
          expect(entry.action).toBe("block");
        }
        expect(BundlePayloadSchema.safeParse(raw).success).toBe(true);

        // A stored Rule that says throttle without a limit, or block with one, cannot come out of a publish. Should
        // one be stored all the same, it is never shipped as a plain block Rule: the issuer refuses the bundle.
        const broken = { ...base(ids[0] as string), action: "throttle" } as PolicyRule;
        expect(() => createBundleIssuer({ signer: createSigner() }).issue(subject([broken]))).toThrow(TypeError);
        const mislabelled = {
          ...plain(ids[0] as string),
          limit: { requests: 1, window_s: 1, key: "ip", count: "requests" },
        } as PolicyRule;
        expect(() => createBundleIssuer({ signer: createSigner() }).issue(subject([mislabelled]))).toThrow(TypeError);
      });
    });

    it("answers 401 without a key, 403 for an admin key and 401 for a revoked Shield key", async () => {
      const t = await tenant("Wrong keys");

      const none = await get("/v1/policy-bundle");
      await expectProblem(none, 401);
      expect(none.headers.get("www-authenticate")).toBe("Bearer");
      expect(none.headers.get("etag")).toBeNull();

      const admin = await get("/v1/policy-bundle", bearer(t.adminKey));
      await expectProblem(admin, 403);
      expect(admin.headers.get("etag")).toBeNull();

      const revoked = await issueShieldKey(t, "development");
      const { etag } = await fetchBundle(api, revoked, publicKey);
      await api.db.tx({ organizationId: t.organizationId }, (q) =>
        q.query("UPDATE api_keys SET revoked_at = now() WHERE key_hash = $1", [hashKey(revoked)]),
      );
      // A revoked key gets nothing, not even "not modified" for the bundle it already holds.
      await expectProblem(await get("/v1/policy-bundle", { ...bearer(revoked), "if-none-match": etag }), 401);
    });
  });

  describe("caching", () => {
    it("answers the same bundle and ETag while nothing changes, and 304 without a body to If-None-Match", async () => {
      const t = await tenant("Unchanged");
      await publishPolicy(api, t.adminKey, t.appId, "development", [enforceRule]);
      clock.now = new Date(T0 + 10_000);
      const first = await fetchBundle(api, t.shieldKey, publicKey);

      clock.now = new Date(T0 + 10_000 + DAY - 1);
      const second = await fetchBundle(api, t.shieldKey, publicKey);
      expect(second).toEqual(first);

      for (const condition of [first.etag, `W/${first.etag}`, `"other", ${first.etag}`, "*"]) {
        const res = await get("/v1/policy-bundle", { ...bearer(t.shieldKey), "if-none-match": condition });
        expect(res.status, condition).toBe(304);
        expect(res.headers.get("etag")).toBe(first.etag);
        expect(res.headers.get("cache-control")).toBe("no-store");
        expect(await res.text()).toBe("");
      }

      for (const condition of ['"other"', first.etag.slice(1, -1), ""]) {
        const res = await get("/v1/policy-bundle", { ...bearer(t.shieldKey), "if-none-match": condition });
        expect(res.status, condition).toBe(200);
        expect(res.headers.get("etag")).toBe(first.etag);
        expect(SignedBundleSchema.parse(await res.json())).toEqual(first.signed);
      }
    });

    it("changes the ETag when a version is published or rolled back to", async () => {
      const t = await tenant("Changing");
      const before = await fetchBundle(api, t.shieldKey, publicKey);
      expect(before.payload.version).toBe(0);

      await publishPolicy(api, t.adminKey, t.appId, "development", [enforceRule]);
      const res = await get("/v1/policy-bundle", { ...bearer(t.shieldKey), "if-none-match": before.etag });
      expect(res.status).toBe(200);
      const published = await fetchBundle(api, t.shieldKey, publicKey);
      expect(published.etag).toBe(res.headers.get("etag"));
      expect(published.etag).not.toBe(before.etag);
      expect(published.payload.version).toBe(1);
      expect(published.payload.rules.map((rule) => rule.path)).toEqual(["/api/admin/**"]);

      await publishPolicy(api, t.adminKey, t.appId, "development", []);
      const rolledBack = await api.app.request(
        `/v1/apps/${t.appId}/policies/development/rollback`,
        json({ version: 1 }, withReason(bearer(t.adminKey))),
      );
      expect(rolledBack.status).toBe(201);
      const after = await fetchBundle(api, t.shieldKey, publicKey);
      expect(after.payload.version).toBe(3);
      expect(after.payload.rules).toEqual(published.payload.rules);
      expect(new Set([before.etag, published.etag, after.etag]).size).toBe(3);

      // A Policy of another Environment of the same App changes nothing for this key.
      await publishPolicy(api, t.adminKey, t.appId, "production", [monitorRule]);
      expect(await fetchBundle(api, t.shieldKey, publicKey)).toEqual(after);
    });

    it("issues the bundle again, with a new time and ETag, once it is 24 hours old", async () => {
      const t = await tenant("Ageing");
      await publishPolicy(api, t.adminKey, t.appId, "development", [enforceRule]);
      const start = T0 + 30 * DAY;
      clock.now = new Date(start);
      const first = await fetchBundle(api, t.shieldKey, publicKey);
      expect(first.payload.issued_at).toBe(new Date(start).toISOString());

      clock.now = new Date(start + DAY);
      const conditional = await get("/v1/policy-bundle", { ...bearer(t.shieldKey), "if-none-match": first.etag });
      expect(conditional.status).toBe(200);
      const second = await fetchBundle(api, t.shieldKey, publicKey);

      expect(second.etag).toBe(conditional.headers.get("etag"));
      expect(second.etag).not.toBe(first.etag);
      expect(second.payload).toEqual({
        ...first.payload,
        issued_at: new Date(start + DAY).toISOString(),
        not_after: new Date(start + 8 * DAY).toISOString(),
      });
      // The new bundle is the one that is kept from now on.
      clock.now = new Date(start + DAY + HOUR);
      expect(await fetchBundle(api, t.shieldKey, publicKey)).toEqual(second);
    });
  });

  describe("isolation", () => {
    it("gives a key the Rules of its own App and Environment, and of no other", async () => {
      const a = await tenant("Organization A", "production");
      const developmentKey = await issueShieldKey(a, "development");
      const stagingKey = await issueShieldKey(a, "staging");
      const otherApp = await createAppFor(api, a.adminKey, { name: "Back office", environment: "production" });
      const b = await tenant("Organization B", "production");

      await publishPolicy(api, a.adminKey, a.appId, "production", [{ name: "A production", path: "/a/production" }]);
      await publishPolicy(api, a.adminKey, a.appId, "development", [{ name: "A dev 1", path: "/a/development/1" }]);
      await publishPolicy(api, a.adminKey, a.appId, "development", [{ name: "A dev 2", path: "/a/development/2" }]);
      await publishPolicy(api, a.adminKey, otherApp.app.id, "production", [{ name: "Other", path: "/a/other-app" }]);
      await publishPolicy(api, b.adminKey, b.appId, "production", [{ name: "B", path: "/b/production" }]);

      const expected: [string, string, Environment, number, string[]][] = [
        [a.shieldKey, a.appId, "production", 1, ["/a/production"]],
        [developmentKey, a.appId, "development", 2, ["/a/development/2"]],
        [stagingKey, a.appId, "staging", 0, []],
        [otherApp.shield_key.key, otherApp.app.id, "production", 1, ["/a/other-app"]],
        [b.shieldKey, b.appId, "production", 1, ["/b/production"]],
      ];
      for (const [key, appId, environment, version, paths] of expected) {
        const { payload, signed } = await fetchBundle(api, key, publicKey);
        expect(payload).toMatchObject({ audience: bundleAudience(key), app_id: appId, environment, version });
        expect(payload.rules.map((rule) => rule.path)).toEqual(paths);
        for (const [, , , , foreign] of expected) {
          if (foreign !== paths) for (const path of foreign) expect(signed.bundle).not.toContain(path);
        }
      }
    });

    it("takes the App and the Environment from the key, whatever the request claims", async () => {
      const a = await tenant("Claimed from", "development");
      const b = await tenant("Claimed", "production");
      await publishPolicy(api, b.adminKey, b.appId, "production", [{ name: "B only", path: "/b/only" }]);
      const own = await fetchBundle(api, a.shieldKey, publicKey);

      const claims = `app_id=${b.appId}&appId=${b.appId}&environment=production&organization_id=${b.organizationId}`;
      const res = await get(`/v1/policy-bundle?${claims}&audience=${bundleAudience(b.shieldKey)}`, {
        ...bearer(a.shieldKey),
        "x-app-id": b.appId,
        "x-environment": "production",
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("etag")).toBe(own.etag);
      expect(SignedBundleSchema.parse(await res.json())).toEqual(own.signed);
      expect(own.payload).toMatchObject({ app_id: a.appId, environment: "development", version: 0, rules: [] });
    });

    it("issues each Shield key of one App and Environment its own bundle", async () => {
      const t = await tenant("Two Shields");
      const second = await issueShieldKey(t, "development");
      await publishPolicy(api, t.adminKey, t.appId, "development", [enforceRule]);

      const one = await fetchBundle(api, t.shieldKey, publicKey);
      const two = await fetchBundle(api, second, publicKey);

      expect(one.payload.audience).toBe(bundleAudience(t.shieldKey));
      expect(two.payload.audience).toBe(bundleAudience(second));
      expect(two.payload).toEqual({ ...one.payload, audience: two.payload.audience });
      expect(two.etag).not.toBe(one.etag);
      // The ETag of one key's bundle is not "not modified" for the other key.
      const crossed = await get("/v1/policy-bundle", { ...bearer(second), "if-none-match": one.etag });
      expect(crossed.status).toBe(200);
    });
  });

  describe("HEAD", () => {
    it("answers like GET without a body, and holds nothing open", async () => {
      const t = await tenant("Head");
      const { etag } = await fetchBundle(api, t.shieldKey, publicKey);

      for (let index = 0; index < 25; index++) {
        const bundle = await get("/v1/policy-bundle", bearer(t.shieldKey), "HEAD");
        expect(bundle.status).toBe(200);
        expect(bundle.headers.get("etag")).toBe(etag);
        expect(await bundle.text()).toBe("");
        const key = await get("/v1/signing-key", {}, "HEAD");
        expect(key.status).toBe(200);
        expect(await key.text()).toBe("");
      }
      // HEAD needs the key as GET does; its answer has no body, the status and the challenge say it all.
      const anonymous = await get("/v1/policy-bundle", {}, "HEAD");
      expect(anonymous.status).toBe(401);
      expect(anonymous.headers.get("www-authenticate")).toBe("Bearer");
      expect(anonymous.headers.get("etag")).toBeNull();
      await tick();
      expect(api.bus.count()).toBe(0);
    });

    it("has no other method: nothing can be sent to the bundle or the signing key", async () => {
      const t = await tenant("Other methods");
      for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
        for (const path of ["/v1/policy-bundle", "/v1/signing-key"]) {
          const res = await api.app.request(path, { method, headers: bearer(t.shieldKey), body: "{}" });
          await expectProblem(res, 404);
        }
      }
    });
  });

  describe("bundle issuer", () => {
    const signer = createSigner();
    const subject = (audience: string) => ({
      audience,
      epoch: "0123456789abcdef0123456789abcdef",
      appId: "app_0123456789abcdef01234567",
      environment: "development" as const,
      version: 1,
      rules: [],
    });
    const issuedAt = (issued: IssuedBundle): string =>
      (JSON.parse(issued.signed.bundle) as { issued_at: string }).issued_at;

    it("keeps a bounded number of bundles: the one unused for longest makes room", () => {
      let now = T0;
      const issuer = createBundleIssuer({ signer, now: () => new Date(now), maxEntries: 2 });
      const [a, b, c] = ["a".repeat(32), "b".repeat(32), "c".repeat(32)];

      const first = issuer.issue(subject(a));
      now += 1_000;
      issuer.issue(subject(b));
      now += 1_000;
      // Still kept: both fit. Using `a` makes `b` the one unused for longest.
      expect(issuer.issue(subject(a))).toEqual(first);
      issuer.issue(subject(c));
      now += 1_000;

      expect(issuer.issue(subject(a))).toEqual(first);
      // `b` was dropped: it is issued again, at the present time.
      expect(issuedAt(issuer.issue(subject(b)))).toBe(new Date(T0 + 3_000).toISOString());
    });

    it("never hands out a kept bundle of another epoch: the bundle and its ETag carry the epoch", () => {
      const issuer = createBundleIssuer({ signer, now: () => new Date(T0) });
      const before = issuer.issue(subject("e".repeat(32)));
      const after = issuer.issue({ ...subject("e".repeat(32)), epoch: "f".repeat(32) });

      expect(JSON.parse(before.signed.bundle)).toMatchObject({ epoch: "0123456789abcdef0123456789abcdef" });
      expect(JSON.parse(after.signed.bundle)).toMatchObject({ epoch: "f".repeat(32) });
      expect(after.etag).not.toBe(before.etag);
    });

    it("never hands out a bundle that the clock says comes from the future", () => {
      let now = T0;
      const issuer = createBundleIssuer({ signer, now: () => new Date(now) });
      const first = issuer.issue(subject("d".repeat(32)));
      now -= HOUR;
      const second = issuer.issue(subject("d".repeat(32)));
      expect(issuedAt(first)).toBe(new Date(T0).toISOString());
      expect(issuedAt(second)).toBe(new Date(T0 - HOUR).toISOString());
    });
  });

  it("never lets the private key or any other key into a response or a log line", () => {
    expect(privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(bodies.length).toBeGreaterThan(50);
    for (const text of [...bodies, ...api.logger.lines]) expect(text).not.toContain(privateKey);
    expectNoKeyLogged(api);
    const log = api.logger.lines.join("\n");
    expect(log).toContain("route=/v1/policy-bundle status=200");
    expect(log).toContain("route=/v1/policy-bundle status=304");
    expect(log).toContain("route=/v1/signing-key status=200");
    expect(log).not.toMatch(/\/api\/admin|\/a\/production|rul_/);
  });
});
