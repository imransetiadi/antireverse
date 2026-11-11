import {
  AllowlistEntryResponseSchema,
  CONTAINMENT_LIMITS,
  type ConflictReason,
  type Containment,
  ContainmentResponseSchema,
  DETECTION_RULES,
  type Environment,
  type Incident,
  IncidentDetailResponseSchema,
  ListAllowlistResponseSchema,
  ListContainmentsResponseSchema,
  ListIncidentsResponseSchema,
  type ShieldEvent,
} from "@antireverse/protocol";
import { actorHash, generateKey, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createBundleIssuer } from "../src/bundle.ts";
import { createDetector } from "../src/detect/detector.ts";
import { CONFLICT_DETAILS } from "../src/problem.ts";
import { createSigner } from "../src/signer.ts";
import { insertContainment } from "../src/stores/containments.ts";
import { insertKey } from "../src/stores/keys.ts";
import {
  batchOf,
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  fetchBundle,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const PREFIX = "203.0.113.0/24";
const OTHER_PREFIX = "198.51.100.0/24";
const THRESHOLD = DETECTION_RULES[0].threshold;
const CONFLICT = "https://antireverse.dev/problems/conflict";

/** A 409 `conflict` naming `reason`, with that reason's fixed text. */
async function expectConflict(res: Response, reason: ConflictReason) {
  const problem = await expectProblem(res, 409);
  expect(problem).toEqual({
    type: CONFLICT,
    title: "Conflict",
    status: 409,
    detail: CONFLICT_DETAILS[reason],
    reason,
  });
  return problem;
}

interface Tenant {
  organizationId: string;
  adminKey: string;
  adminKeyId: string;
}

interface AppUnderTest {
  appId: string;
  shieldKey: string;
  environment: Environment;
}

/** An enforced block from `address` (hashed with the Shield key) in `prefix`. */
function blockedFrom(shieldKey: string, ms: number, address: string | null, prefix = PREFIX): ShieldEvent {
  return {
    ...shieldEvent(ms),
    decision: {
      action: "block",
      mode: "enforce",
      rule_id: null,
      policy_version: 1,
      containment_id: null,
      patch_id: null,
      patch_body: null,
    },
    actor: { ip_prefix: prefix, ip_hash: address === null ? null : actorHash(shieldKey, address) },
  };
}

describe("Containment", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let stopDetector: () => void;
  let flush: () => Promise<void>;
  let orgA: Tenant;
  let orgB: Tenant;

  const request = (path: string, init?: RequestInit) => Promise.resolve(api.app.request(path, init));

  async function tenant(name: string): Promise<Tenant> {
    const created = await createOrganization(api, name);
    const organizationId = created.organization.id;
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ id: string }>("SELECT id FROM api_keys WHERE kind = 'admin'"),
    );
    const adminKeyId = rows[0]?.id;
    if (adminKeyId === undefined) throw new Error("No admin key.");
    return { organizationId, adminKey: created.admin_key.key, adminKeyId };
  }

  async function newApp(t: Tenant, environment: Environment = "production"): Promise<AppUnderTest> {
    const created = await createAppFor(api, t.adminKey, { name: "Storefront", environment });
    return { appId: created.app.id, shieldKey: created.shield_key.key, environment };
  }

  /** A second Shield key of the same App, for another Environment. */
  async function keyFor(t: Tenant, appId: string, environment: Environment): Promise<AppUnderTest> {
    const generated = generateKey("shield", environment);
    await api.db.tx({ organizationId: t.organizationId }, (q) =>
      insertKey(q, {
        id: newId("key"),
        organizationId: t.organizationId,
        kind: "shield",
        appId,
        environment,
        generated,
      }),
    );
    api.issuedKeys.push(generated.key);
    return { appId, shieldKey: generated.key, environment };
  }

  async function ingest(shieldKey: string, events: ShieldEvent[]): Promise<void> {
    const res = await request("/v1/events", json(batchOf(events), bearer(shieldKey)));
    expect(res.status).toBe(202);
    await flush();
  }

  async function incidentsOf(t: Tenant, appId: string): Promise<Incident[]> {
    const res = await request(`/v1/incidents?app_id=${appId}`, { headers: bearer(t.adminKey) });
    expect(res.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await res.json()).incidents;
  }

  /**
   * A blocked burst from `prefix`: the addresses in turn, `THRESHOLD` Events at one-second steps from
   * `startMs`. Returns the Incident it opened.
   */
  async function attack(
    t: Tenant,
    app: AppUnderTest,
    addresses: (string | null)[],
    startMs = T0,
    prefix = PREFIX,
  ): Promise<Incident> {
    clock.ms += 1_000;
    await ingest(
      app.shieldKey,
      Array.from({ length: THRESHOLD }, (_, i) =>
        blockedFrom(app.shieldKey, startMs + i * 1_000, addresses[i % addresses.length] ?? null, prefix),
      ),
    );
    const found = (await incidentsOf(t, app.appId)).find(
      (i) => i.ip_prefix === prefix && i.environment === app.environment && i.status !== "resolved",
    );
    if (found === undefined) throw new Error("No Incident was opened.");
    return found;
  }

  function contain(t: Tenant, incidentId: string, body: unknown, key = t.adminKey): Promise<Response> {
    return request(`/v1/incidents/${incidentId}/containments`, json(body, bearer(key)));
  }

  async function contained(t: Tenant, incidentId: string, body: unknown, status = 201): Promise<Containment> {
    const res = await contain(t, incidentId, body);
    expect(res.status).toBe(status);
    return ContainmentResponseSchema.parse(await res.json()).containment;
  }

  function lift(t: Tenant, id: string, key = t.adminKey): Promise<Response> {
    return request(`/v1/containments/${id}/lift`, json({}, bearer(key)));
  }

  async function detail(t: Tenant, incidentId: string) {
    const res = await request(`/v1/incidents/${incidentId}`, { headers: bearer(t.adminKey) });
    expect(res.status).toBe(200);
    return IncidentDetailResponseSchema.parse(await res.json());
  }

  async function addAllowlist(t: Tenant, cidr: string, note = ""): Promise<Response> {
    return request("/v1/allowlist", json({ cidr, note }, bearer(t.adminKey)));
  }

  const actor = (shieldKey: string, address: string) => ({
    target: { kind: "actor", ip_hash: actorHash(shieldKey, address) },
    ttl_s: 3600,
  });

  beforeAll(async () => {
    api = await makeTestApi({ now });
    const detector = createDetector({
      db: api.db,
      bus: api.bus,
      notifier: { incidentOpened: () => {} },
      now,
      logger: api.logger,
    });
    stopDetector = detector.start();
    flush = () => detector.flush();
    orgA = await tenant("Organization A");
    orgB = await tenant("Organization B");
  });
  afterAll(async () => {
    stopDetector();
    await api.close();
  });

  describe("Incident detail", () => {
    it("lists the Incident's Actors by event count, then hash, from its evidence only; no containments yet", async () => {
      const app = await newApp(orgA);
      // 20 counted Events: .7 ten times, .9 and .10 five times each; plus Events that are not evidence.
      const addresses = [
        ...Array<string>(10).fill("203.0.113.7"),
        ...Array<string>(5).fill("203.0.113.9"),
        ...Array<string>(5).fill("203.0.113.10"),
      ];
      const incident = await attack(orgA, app, addresses);
      await ingest(app.shieldKey, [
        // Inside the window but not counted by the rule (allowed), and null hashes, and another prefix.
        { ...blockedFrom(app.shieldKey, T0 + 2_000, "203.0.113.50"), decision: shieldEvent(0).decision },
        blockedFrom(app.shieldKey, T0 + 2_000, null),
        blockedFrom(app.shieldKey, T0 + 2_000, "198.51.100.4", OTHER_PREFIX),
        // Outside the time span.
        blockedFrom(app.shieldKey, T0 + 3_600_000, "203.0.113.51"),
      ]);

      const { actors, containments } = await detail(orgA, incident.id);
      const h9 = actorHash(app.shieldKey, "203.0.113.9") ?? "";
      const h10 = actorHash(app.shieldKey, "203.0.113.10") ?? "";
      expect(actors).toEqual([
        { ip_hash: actorHash(app.shieldKey, "203.0.113.7"), events: 10 },
        ...[h9, h10].sort().map((ip_hash) => ({ ip_hash, events: 5 })),
      ]);
      expect(containments).toEqual([]);
    });

    it(`lists at most ${CONTAINMENT_LIMITS.actorsListed} Actors`, async () => {
      const app = await newApp(orgA);
      const incident = await attack(
        orgA,
        app,
        Array.from({ length: THRESHOLD }, (_, i) => `203.0.113.${i + 1}`),
      );
      const { actors } = await detail(orgA, incident.id);
      expect(actors).toHaveLength(CONTAINMENT_LIMITS.actorsListed);
      const hashes = actors.map((a) => a.ip_hash);
      expect(hashes).toEqual([...hashes].sort());
    });
  });

  describe("creating", () => {
    it("blocks an Actor of the Incident's evidence for the chosen TTL, recording who and when; detail lists it", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7"]);
      clock.ms += 1_000;
      const containment = await contained(orgA, incident.id, actor(app.shieldKey, "203.0.113.7"));
      expect(containment).toEqual({
        id: containment.id,
        app_id: app.appId,
        environment: "production",
        incident_id: incident.id,
        target: { kind: "actor", ip_hash: actorHash(app.shieldKey, "203.0.113.7") },
        created_at: new Date(clock.ms).toISOString(),
        expires_at: new Date(clock.ms + 3_600_000).toISOString(),
        created_by: orgA.adminKeyId,
        lifted_at: null,
        lifted_by: null,
        status: "active",
      });
      expect((await detail(orgA, incident.id)).containments).toEqual([containment]);
    });

    it("answers 200 with the existing block for the same active target, whatever the TTL (idempotent)", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7"]);
      const first = await contained(orgA, incident.id, actor(app.shieldKey, "203.0.113.7"));
      clock.ms += 1_000;
      const again = await contained(orgA, incident.id, { ...actor(app.shieldKey, "203.0.113.7"), ttl_s: 900 }, 200);
      expect(again).toEqual(first);
      expect((await detail(orgA, incident.id)).containments).toHaveLength(1);
    });

    it("refuses with 409 an actor hash that is not in the Incident's evidence, without echoing it", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7"]);
      await ingest(app.shieldKey, [
        // In the window but not counted by the rule.
        { ...blockedFrom(app.shieldKey, T0 + 2_000, "203.0.113.20"), decision: shieldEvent(0).decision },
        // Counted, but outside the time span.
        blockedFrom(app.shieldKey, T0 + 3_600_000, "203.0.113.21"),
        // Another prefix.
        blockedFrom(app.shieldKey, T0 + 2_000, "198.51.100.22", OTHER_PREFIX),
      ]);
      // The same address seen by another App (another key): a different hash, also unknown here.
      const other = await newApp(orgA);
      await attack(orgA, other, ["203.0.113.7"]);

      for (const address of ["203.0.113.99", "203.0.113.20", "203.0.113.21", "198.51.100.22"]) {
        const body = actor(app.shieldKey, address);
        const res = await contain(orgA, incident.id, body);
        const problem = await expectConflict(res, "actor-unknown");
        expect(problem.type).toBe(CONFLICT);
        expect(JSON.stringify(problem)).not.toContain(body.target.ip_hash);
      }
      await expectConflict(await contain(orgA, incident.id, actor(other.shieldKey, "203.0.113.7")), "actor-unknown");
      expect((await detail(orgA, incident.id)).containments).toEqual([]);
    });

    it("blocks the Incident's own prefix only with the exact prefix typed as confirmation", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7"]);

      const missing = await expectProblem(
        await contain(orgA, incident.id, { target: { kind: "prefix" }, ttl_s: 900 }),
        400,
      );
      expect(missing.errors?.[0]?.path).toBe("confirm_prefix");
      const wrong = await expectProblem(
        await contain(orgA, incident.id, { target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: OTHER_PREFIX }),
        400,
      );
      expect(wrong.errors?.[0]?.path).toBe("confirm_prefix");
      expect(JSON.stringify(wrong)).not.toMatch(/203\.0\.113|198\.51\.100/);

      // A prefix sent in the target is ignored: the block is always the Incident's own.
      const containment = await contained(orgA, incident.id, {
        target: { kind: "prefix", ip_prefix: OTHER_PREFIX },
        ttl_s: 900,
        confirm_prefix: PREFIX,
      });
      expect(containment.target).toEqual({ kind: "prefix", ip_prefix: PREFIX });
      expect(Date.parse(containment.expires_at) - Date.parse(containment.created_at)).toBe(900_000);
    });

    it("refuses with 409 a prefix block that overlaps the allowlist; an actor block there is still allowed", async () => {
      const t = await tenant("Allowlisted");
      const app = await newApp(t);
      const incident = await attack(t, app, ["203.0.113.7"]);
      expect((await addAllowlist(t, "203.0.113.128/25", "Office")).status).toBe(201);

      const res = await contain(t, incident.id, { target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: PREFIX });
      const problem = await expectConflict(res, "prefix-allowlisted");
      expect(problem.type).toBe(CONFLICT);
      expect(JSON.stringify(problem)).not.toMatch(/203\.0\.113|\/25/);
      // A wider range overlaps too.
      const wide = await tenant("Allowlisted wide");
      const wideApp = await newApp(wide);
      const wideIncident = await attack(wide, wideApp, ["203.0.113.7"]);
      expect((await addAllowlist(wide, "203.0.0.0/16")).status).toBe(201);
      await expectConflict(
        await contain(wide, wideIncident.id, { target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: PREFIX }),
        "prefix-allowlisted",
      );
      // A range elsewhere does not.
      const elsewhere = await tenant("Allowlisted elsewhere");
      const elsewhereApp = await newApp(elsewhere);
      const elsewhereIncident = await attack(elsewhere, elsewhereApp, ["203.0.113.7"]);
      expect((await addAllowlist(elsewhere, "203.0.114.0/24")).status).toBe(201);
      await contained(elsewhere, elsewhereIncident.id, {
        target: { kind: "prefix" },
        ttl_s: 900,
        confirm_prefix: PREFIX,
      });

      await contained(t, incident.id, actor(app.shieldKey, "203.0.113.7"));
    });

    it("refuses with 409 to contain from a resolved Incident", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7"]);
      const resolved = await request(`/v1/incidents/${incident.id}`, {
        ...json({ status: "resolved" }, bearer(orgA.adminKey)),
        method: "PATCH",
      });
      expect(resolved.status).toBe(200);
      const problem = await expectConflict(
        await contain(orgA, incident.id, actor(app.shieldKey, "203.0.113.7")),
        "incident-resolved",
      );
      expect(problem.type).toBe(CONFLICT);
      await expectConflict(
        await contain(orgA, incident.id, { target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: PREFIX }),
        "incident-resolved",
      );
    });

    it(`refuses a new block with 409 once the App and Environment has ${CONTAINMENT_LIMITS.activePerAppEnv} active ones`, async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7", "203.0.113.8"]);
      const existing = await contained(orgA, incident.id, actor(app.shieldKey, "203.0.113.7"));
      // An expired and a lifted block do not count.
      await api.db.tx({ organizationId: orgA.organizationId }, async (q) => {
        const base = {
          organizationId: orgA.organizationId,
          appId: app.appId,
          environment: app.environment,
          incidentId: null,
          createdBy: orgA.adminKeyId,
        };
        for (let i = 1; i < CONTAINMENT_LIMITS.activePerAppEnv; i++) {
          await insertContainment(q, {
            ...base,
            id: newId("cnt"),
            target: { kind: "actor", ip_hash: `iph_${i.toString(16).padStart(32, "0")}` },
            createdAt: now(),
            expiresAt: new Date(clock.ms + 3_600_000),
          });
        }
        await insertContainment(q, {
          ...base,
          id: newId("cnt"),
          target: { kind: "actor", ip_hash: `iph_${"e".repeat(32)}` },
          createdAt: new Date(clock.ms - 7_200_000),
          expiresAt: new Date(clock.ms - 3_600_000),
        });
      });

      const res = await contain(orgA, incident.id, actor(app.shieldKey, "203.0.113.8"));
      expect((await expectConflict(res, "containment-limit")).type).toBe(CONFLICT);
      // The same target as an existing active block is still answered with it.
      expect(await contained(orgA, incident.id, actor(app.shieldKey, "203.0.113.7"), 200)).toEqual(existing);

      // Another Environment of the same App has its own count.
      const staging = await keyFor(orgA, app.appId, "staging");
      const stagingIncident = await attack(orgA, staging, ["203.0.113.8"]);
      await contained(orgA, stagingIncident.id, actor(staging.shieldKey, "203.0.113.8"));

      expect((await lift(orgA, existing.id)).status).toBe(200);
      await contained(orgA, incident.id, actor(app.shieldKey, "203.0.113.8"));

      const { payload } = await fetchBundle(api, app.shieldKey, api.signer.publicKey);
      expect(payload.blocks).toHaveLength(CONTAINMENT_LIMITS.activePerAppEnv);
    });
  });

  describe("lifting and listing", () => {
    it("lifts an active block once, recording who and when; an expired or lifted block is 409", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7", "203.0.113.8"]);
      const one = await contained(orgA, incident.id, actor(app.shieldKey, "203.0.113.7"));
      // A later created_at, so that the newest-first order below does not rest on the id tiebreak.
      clock.ms += 1_000;
      const short = await contained(orgA, incident.id, { ...actor(app.shieldKey, "203.0.113.8"), ttl_s: 900 });

      clock.ms += 1_000;
      const res = await lift(orgA, one.id);
      expect(res.status).toBe(200);
      const lifted = ContainmentResponseSchema.parse(await res.json()).containment;
      expect(lifted).toEqual({
        ...one,
        status: "lifted",
        lifted_at: new Date(clock.ms).toISOString(),
        lifted_by: orgA.adminKeyId,
      });
      expect((await expectConflict(await lift(orgA, one.id), "containment-ended")).type).toBe(CONFLICT);

      // Lifted, a new block of the same target can be created.
      const renewed = await contained(orgA, incident.id, actor(app.shieldKey, "203.0.113.7"));
      expect(renewed.id).not.toBe(one.id);

      clock.ms = Date.parse(short.expires_at);
      await expectConflict(await lift(orgA, short.id), "containment-ended");
      const { containments } = await detail(orgA, incident.id);
      expect(containments.map((c) => [c.id, c.status])).toEqual([
        [renewed.id, "active"],
        [short.id, "expired"],
        [one.id, "lifted"],
      ]);
    });

    it("answers 404 for an unknown, malformed or another Organization's block", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7"]);
      const block = await contained(orgA, incident.id, actor(app.shieldKey, "203.0.113.7"));
      await expectProblem(await lift(orgA, newId("cnt")), 404);
      await expectProblem(await lift(orgA, "not-a-containment"), 404);
      await expectProblem(await lift(orgB, block.id), 404);
      expect((await detail(orgA, incident.id)).containments[0]?.status).toBe("active");
    });

    it("lists blocks newest first, filtered by App, Environment and status; another Organization sees none", async () => {
      const t = await tenant("Lister");
      const app = await newApp(t);
      const other = await newApp(t);
      const incident = await attack(t, app, ["203.0.113.7", "203.0.113.8"]);
      const otherIncident = await attack(t, other, ["203.0.113.7"]);
      const a = await contained(t, incident.id, actor(app.shieldKey, "203.0.113.7"));
      clock.ms += 1_000;
      const b = await contained(t, incident.id, actor(app.shieldKey, "203.0.113.8"));
      clock.ms += 1_000;
      const c = await contained(t, otherIncident.id, actor(other.shieldKey, "203.0.113.7"));
      clock.ms += 1_000;
      expect((await lift(t, b.id)).status).toBe(200);

      const list = async (query: string, key = t.adminKey) => {
        const res = await request(`/v1/containments${query}`, { headers: bearer(key) });
        expect(res.status).toBe(200);
        return ListContainmentsResponseSchema.parse(await res.json()).containments.map((x) => x.id);
      };
      expect(await list("")).toEqual([c.id, b.id, a.id]);
      expect(await list(`?app_id=${app.appId}`)).toEqual([b.id, a.id]);
      expect(await list(`?app_id=${app.appId}&environment=production&status=active`)).toEqual([a.id]);
      expect(await list("?status=lifted")).toEqual([b.id]);
      expect(await list("?environment=staging")).toEqual([]);
      expect(await list("", orgB.adminKey)).not.toContain(a.id);

      const bad = await expectProblem(
        await request("/v1/containments?status=gone", { headers: bearer(t.adminKey) }),
        400,
      );
      expect(bad.errors?.[0]?.path).toBe("status");
      await expectProblem(await request("/v1/containments?app_id=nope", { headers: bearer(t.adminKey) }), 400);
    });
  });

  describe("tenancy and keys", () => {
    it("lets only an admin key of the Incident's Organization act: Shield key 403, another Organization 404", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7"]);
      const body = actor(app.shieldKey, "203.0.113.7");

      await expectProblem(await contain(orgA, incident.id, body, app.shieldKey), 403);
      await expectProblem(await contain(orgB, incident.id, body), 404);
      await expectProblem(await contain(orgA, newId("inc"), body), 404);
      await expectProblem(await contain(orgA, "not-an-incident", body), 404);
      await expectProblem(await request(`/v1/incidents/${incident.id}/containments`, json(body)), 401);

      const block = await contained(orgA, incident.id, body);
      await expectProblem(await lift(orgA, block.id, app.shieldKey), 403);
      await expectProblem(await request("/v1/containments", { headers: bearer(app.shieldKey) }), 403);
      await expectProblem(await request("/v1/allowlist", { headers: bearer(app.shieldKey) }), 403);
      await expectProblem(
        await request("/v1/allowlist", json({ cidr: "10.0.0.0/8", note: "" }, bearer(app.shieldKey))),
        403,
      );
      await expectProblem(
        await request(`/v1/allowlist/${newId("alw")}`, { method: "DELETE", headers: bearer(app.shieldKey) }),
        403,
      );
    });

    it("ships a block only to its own App and Environment, never to another App, Environment or Organization", async () => {
      const t = await tenant("Scoped");
      const appA = await newApp(t);
      const appB = await newApp(t);
      const stagingA = await keyFor(t, appA.appId, "staging");
      const elsewhere = await newApp(orgB);
      const incident = await attack(t, appA, ["203.0.113.7"]);
      const block = await contained(t, incident.id, actor(appA.shieldKey, "203.0.113.7"));

      const own = await fetchBundle(api, appA.shieldKey, api.signer.publicKey);
      expect(own.payload.blocks?.map((b) => b.id)).toEqual([block.id]);
      for (const key of [appB.shieldKey, stagingA.shieldKey, elsewhere.shieldKey]) {
        const { payload, signed } = await fetchBundle(api, key, api.signer.publicKey);
        expect(payload.blocks).toBeUndefined();
        expect(signed.bundle).not.toContain(block.id);
      }
    });
  });

  describe("Policy Bundle", () => {
    it("carries the active blocks and the Organization's allowlist; both are omitted when empty", async () => {
      const t = await tenant("Bundled");
      const app = await newApp(t);
      const empty = await fetchBundle(api, app.shieldKey, api.signer.publicKey);
      expect(empty.payload).not.toHaveProperty("blocks");
      expect(empty.payload).not.toHaveProperty("allowlist");
      expect(empty.signed.bundle).not.toMatch(/"blocks"|"allowlist"/);

      const incident = await attack(t, app, ["203.0.113.7"]);
      const actorBlock = await contained(t, incident.id, actor(app.shieldKey, "203.0.113.7"));
      clock.ms += 1_000;
      const prefixBlock = await contained(t, incident.id, {
        target: { kind: "prefix" },
        ttl_s: 86_400,
        confirm_prefix: PREFIX,
      });
      expect((await addAllowlist(t, "198.51.100.0/24")).status).toBe(201);
      clock.ms += 1_000;
      expect((await addAllowlist(t, "2001:db8::/32")).status).toBe(201);

      const { payload } = await fetchBundle(api, app.shieldKey, api.signer.publicKey);
      expect(payload.blocks).toEqual([
        {
          id: actorBlock.id,
          kind: "actor",
          ip_hash: actorHash(app.shieldKey, "203.0.113.7"),
          expires_at: actorBlock.expires_at,
        },
        { id: prefixBlock.id, kind: "prefix", ip_prefix: PREFIX, expires_at: prefixBlock.expires_at },
      ]);
      expect(payload.allowlist).toEqual(["198.51.100.0/24", "2001:db8::/32"]);
      // The allowlist is the Organization's: every App gets it, without the blocks of others.
      const sibling = await newApp(t);
      const siblingBundle = await fetchBundle(api, sibling.shieldKey, api.signer.publicKey);
      expect(siblingBundle.payload.allowlist).toEqual(["198.51.100.0/24", "2001:db8::/32"]);
      expect(siblingBundle.payload).not.toHaveProperty("blocks");
    });

    it("re-issues the same Policy version with a later issued_at and a new ETag on create, lift, expiry and allowlist change", async () => {
      const t = await tenant("ETags");
      const app = await newApp(t);
      const incident = await attack(t, app, ["203.0.113.7", "203.0.113.8"]);
      const fetch = () => fetchBundle(api, app.shieldKey, api.signer.publicKey);
      const notModified = async (etag: string) =>
        (await request("/v1/policy-bundle", { headers: { ...bearer(app.shieldKey), "if-none-match": etag } })).status;

      const start = await fetch();
      clock.ms += 1_000;
      expect(await fetch()).toEqual(start);
      expect(await notModified(start.etag)).toBe(304);

      const steps: Array<{ name: string; act: () => Promise<void> }> = [];
      let short: Containment | undefined;
      let long: Containment | undefined;
      steps.push({
        name: "create",
        act: async () => {
          short = await contained(t, incident.id, { ...actor(app.shieldKey, "203.0.113.7"), ttl_s: 900 });
          long = await contained(t, incident.id, actor(app.shieldKey, "203.0.113.8"));
        },
      });
      steps.push({
        name: "lift",
        act: async () => {
          expect((await lift(t, long?.id ?? "")).status).toBe(200);
        },
      });
      steps.push({
        name: "expiry",
        act: async () => {
          clock.ms = Date.parse(short?.expires_at ?? "");
        },
      });
      steps.push({
        name: "allowlist",
        act: async () => {
          expect((await addAllowlist(t, "192.0.2.0/24")).status).toBe(201);
        },
      });

      let previous = start;
      const blockCounts: number[] = [];
      for (const step of steps) {
        await step.act();
        const next = await fetch();
        expect(next.etag, step.name).not.toBe(previous.etag);
        expect(next.payload.version, step.name).toBe(start.payload.version);
        expect(Date.parse(next.payload.issued_at), step.name).toBeGreaterThan(Date.parse(previous.payload.issued_at));
        expect(await notModified(previous.etag), step.name).toBe(200);
        blockCounts.push(next.payload.blocks?.length ?? 0);
        previous = next;
      }
      // create: two; lift: one; expiry: none (the short one expired at its expires_at); allowlist: none.
      expect(blockCounts).toEqual([2, 1, 0, 0]);
      expect(previous.payload.allowlist).toEqual(["192.0.2.0/24"]);

      // Removing the allowlist entry changes it again.
      const listed = ListAllowlistResponseSchema.parse(
        await (await request("/v1/allowlist", { headers: bearer(t.adminKey) })).json(),
      );
      const removed = await request(`/v1/allowlist/${listed.entries[0]?.id}`, {
        method: "DELETE",
        headers: bearer(t.adminKey),
      });
      expect(removed.status).toBe(204);
      const last = await fetch();
      expect(last.etag).not.toBe(previous.etag);
      expect(last.payload).not.toHaveProperty("allowlist");
    });

    it("the issuer dates a re-issue in the same millisecond strictly later, and drops a block past its expiry itself", () => {
      const at = { ms: T0 };
      const issuer = createBundleIssuer({ signer: createSigner(), now: () => new Date(at.ms) });
      const subject = {
        audience: "b".repeat(32),
        epoch: "0123456789abcdef0123456789abcdef",
        appId: "app_0123456789abcdef01234567",
        environment: "production" as const,
        version: 3,
        rules: [],
      };
      const issued = (bundle: { signed: { bundle: string } }) =>
        JSON.parse(bundle.signed.bundle) as { issued_at: string; blocks?: unknown[]; allowlist?: string[] };
      const block = {
        id: "cnt_0123456789abcdef01234567",
        kind: "actor" as const,
        ip_hash: `iph_${"a".repeat(32)}`,
        expires_at: new Date(T0 + 60_000).toISOString(),
      };
      const none = issuer.issue(subject);
      const one = issuer.issue({ ...subject, blocks: [block] });
      const both = issuer.issue({ ...subject, blocks: [block], allowlist: ["10.0.0.0/8"] });
      expect(new Set([none.etag, one.etag, both.etag]).size).toBe(3);
      expect(Date.parse(issued(one).issued_at)).toBeGreaterThan(Date.parse(issued(none).issued_at));
      expect(Date.parse(issued(both).issued_at)).toBeGreaterThan(Date.parse(issued(one).issued_at));
      // Unchanged: the same bundle.
      expect(issuer.issue({ ...subject, blocks: [{ ...block }], allowlist: ["10.0.0.0/8"] })).toEqual(both);

      // The caller still passes the block, but its expiry has come: the issuer leaves it out.
      at.ms = T0 + 60_000;
      const expired = issuer.issue({ ...subject, blocks: [block], allowlist: ["10.0.0.0/8"] });
      expect(expired.etag).not.toBe(both.etag);
      expect(issued(expired)).not.toHaveProperty("blocks");
      expect(issued(expired).allowlist).toEqual(["10.0.0.0/8"]);
    });

    it("never hands out a block past its expiry, even from a bundle issued a moment before", async () => {
      const t = await tenant("Expiry");
      const app = await newApp(t);
      const incident = await attack(t, app, ["203.0.113.7"]);
      const block = await contained(t, incident.id, { ...actor(app.shieldKey, "203.0.113.7"), ttl_s: 900 });
      clock.ms = Date.parse(block.expires_at) - 1;
      expect((await fetchBundle(api, app.shieldKey, api.signer.publicKey)).payload.blocks).toHaveLength(1);
      clock.ms += 1;
      const after = await fetchBundle(api, app.shieldKey, api.signer.publicKey);
      expect(after.payload).not.toHaveProperty("blocks");
      expect(after.signed.bundle).not.toContain(block.id);
    });
  });

  describe("detection", () => {
    const containmentBlock = (shieldKey: string, ms: number, prefix: string): ShieldEvent => {
      const event = blockedFrom(shieldKey, ms, "203.0.113.7", prefix);
      return { ...event, decision: { ...event.decision, containment_id: newId("cnt") } };
    };

    it("never opens a Blocked-burst Incident from containment blocks, while ordinary blocks still do", async () => {
      const app = await newApp(orgA);
      clock.ms += 1_000;
      await ingest(
        app.shieldKey,
        Array.from({ length: 25 }, (_, i) => containmentBlock(app.shieldKey, T0 + i * 1_000, PREFIX)),
      );
      expect(await incidentsOf(orgA, app.appId)).toEqual([]);

      const incident = await attack(orgA, app, ["203.0.113.7"], T0, OTHER_PREFIX);
      expect(incident).toMatchObject({ rule: "blocked-burst", ip_prefix: OTHER_PREFIX, detection_count: 1 });
      expect(await incidentsOf(orgA, app.appId)).toHaveLength(1);
    });

    it("shows no containment block as evidence or as an Actor of an Incident", async () => {
      const app = await newApp(orgA);
      const incident = await attack(orgA, app, ["203.0.113.7"]);
      await ingest(app.shieldKey, [
        {
          ...containmentBlock(app.shieldKey, T0 + 1_500, PREFIX),
          actor: blockedFrom(app.shieldKey, 0, "203.0.113.30").actor,
        },
      ]);
      const { evidence, actors } = await detail(orgA, incident.id);
      expect(evidence.every((event) => event.decision.containment_id === null)).toBe(true);
      expect(actors.map((a) => a.ip_hash)).toEqual([actorHash(app.shieldKey, "203.0.113.7")]);
      await expectConflict(await contain(orgA, incident.id, actor(app.shieldKey, "203.0.113.30")), "actor-unknown");
    });
  });

  describe("allowlist", () => {
    it("adds, lists oldest first and removes canonical CIDRs, recording who added them", async () => {
      const t = await tenant("Allowlist");
      const empty = await request("/v1/allowlist", { headers: bearer(t.adminKey) });
      expect(empty.status).toBe(200);
      expect(await empty.json()).toEqual({ entries: [] });

      clock.ms += 1_000;
      const res = await addAllowlist(t, "198.51.100.0/24", "  Office network  ");
      expect(res.status).toBe(201);
      const office = AllowlistEntryResponseSchema.parse(await res.json()).entry;
      expect(office).toEqual({
        id: office.id,
        cidr: "198.51.100.0/24",
        note: "Office network",
        created_at: new Date(clock.ms).toISOString(),
        created_by: t.adminKeyId,
      });
      clock.ms += 1_000;
      expect((await addAllowlist(t, "2001:db8::/32")).status).toBe(201);

      const listed = ListAllowlistResponseSchema.parse(
        await (await request("/v1/allowlist", { headers: bearer(t.adminKey) })).json(),
      );
      expect(listed.entries.map((e) => e.cidr)).toEqual(["198.51.100.0/24", "2001:db8::/32"]);
      expect(listed.entries[0]).toEqual(office);

      // Another Organization neither sees nor removes it.
      const other = ListAllowlistResponseSchema.parse(
        await (await request("/v1/allowlist", { headers: bearer(orgB.adminKey) })).json(),
      );
      expect(other.entries.map((e) => e.id)).not.toContain(office.id);
      await expectProblem(
        await request(`/v1/allowlist/${office.id}`, { method: "DELETE", headers: bearer(orgB.adminKey) }),
        404,
      );

      const removed = await request(`/v1/allowlist/${office.id}`, { method: "DELETE", headers: bearer(t.adminKey) });
      expect(removed.status).toBe(204);
      await expectProblem(
        await request(`/v1/allowlist/${office.id}`, { method: "DELETE", headers: bearer(t.adminKey) }),
        404,
      );
      await expectProblem(
        await request("/v1/allowlist/not-an-entry", { method: "DELETE", headers: bearer(t.adminKey) }),
        404,
      );
    });

    it("refuses a non-canonical CIDR with 400 and a duplicate with 409", async () => {
      const t = await tenant("Allowlist rules");
      for (const cidr of ["203.0.113.1/24", "2001:DB8::/32", "10.0.0.0/7", "203.0.113.0", "::ffff:0:0/96"]) {
        const problem = await expectProblem(await addAllowlist(t, cidr), 400);
        expect(problem.errors?.[0]?.path).toBe("cidr");
      }
      await expectProblem(await addAllowlist(t, "10.0.0.0/8", "x".repeat(CONTAINMENT_LIMITS.noteMax + 1)), 400);
      expect((await addAllowlist(t, "10.0.0.0/8")).status).toBe(201);
      const duplicate = await expectConflict(await addAllowlist(t, "10.0.0.0/8", "again"), "allowlist-duplicate");
      expect(duplicate.type).toBe(CONFLICT);
      expect(JSON.stringify(duplicate)).not.toContain("10.0.0.0");
    });

    it(`holds at most ${CONTAINMENT_LIMITS.allowlistMax} entries per Organization`, async () => {
      const t = await tenant("Allowlist full");
      for (let i = 0; i < CONTAINMENT_LIMITS.allowlistMax; i++) {
        expect((await addAllowlist(t, `10.${i}.0.0/16`)).status).toBe(201);
      }
      await expectConflict(await addAllowlist(t, "192.0.2.0/24"), "allowlist-limit");
      const app = await newApp(t);
      const { payload, signed } = await fetchBundle(api, app.shieldKey, api.signer.publicKey);
      expect(payload.allowlist).toHaveLength(CONTAINMENT_LIMITS.allowlistMax);
      expect(Buffer.byteLength(signed.bundle)).toBeLessThan(65_536);
    });
  });

  it("logs no key, actor hash or address", () => {
    expectNoKeyLogged(api);
    for (const line of api.logger.lines) {
      expect(line).not.toMatch(/iph_|203\.0\.113|198\.51\.100|2001:db8/);
    }
  });
});
