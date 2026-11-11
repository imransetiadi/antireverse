import { randomBytes } from "node:crypto";
import {
  type BuildManifest,
  BuildResponseSchema,
  CANARY_LIMITS,
  type Canary,
  canarySignalId,
  DETECTION_RULES,
  type Environment,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_CANARIES,
  type Incident,
  IncidentDetailResponseSchema,
  IncidentSchema,
  ListBuildsResponseSchema,
  ListIncidentsResponseSchema,
  POLICY_LIMITS,
  type ShieldEvent,
} from "@antireverse/protocol";
import { generateKey, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createBundleIssuer } from "../src/bundle.ts";
import { createDetector } from "../src/detect/detector.ts";
import { matchingRules } from "../src/detect/rules.ts";
import { createSigner } from "../src/signer.ts";
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
  publishPolicy,
  shieldEvent,
  type TestApi,
} from "./helpers.ts";

// Slice 07, API lane: Canaries stored with their Build, carried in the signed Policy Bundle of their App and
// Environment, and the `canary-touched` rule that opens a High "Canary used" Incident.

const T0 = Date.parse("2026-11-11T12:00:00.000Z");
const PREFIX = "203.0.113.0/24";
const OTHER_PREFIX = "198.51.100.0/24";
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz";

const pick = (alphabet: string, length: number) =>
  Array.from(randomBytes(length), (byte) => alphabet[byte % alphabet.length]).join("");

/** A fresh, valid Canary of `kind` with a random id and value. */
function canary(kind: Canary["kind"] = "key"): Canary {
  const id = `cny_${randomBytes(12).toString("hex")}`;
  return kind === "key"
    ? { id, kind, value: `ak_live_${pick(BASE62, 32)}` }
    : { id, kind, value: `/api/internal/${pick(BASE36, 8)}/export` };
}

const manifestFor = (appId: string, overrides: Partial<BuildManifest> = {}): BuildManifest => ({
  ...EXAMPLE_BUILD_MANIFEST,
  build_id: newId("bld"),
  app_id: appId,
  ...overrides,
});

const signalled = (ms: number, ids: string[], prefix: string | null = PREFIX): ShieldEvent => ({
  ...shieldEvent(ms),
  actor: { ip_prefix: prefix, ip_hash: null },
  signals: ids.map((id) => ({ id: canarySignalId(id), confidence: 1 })),
});

describe("Canaries", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let flush: () => Promise<void>;
  let stopDetector: () => void;
  const opened: { incident: Incident; organizationId: string }[] = [];
  /** Every response body the API produced in this file, to prove what never leaves it. */
  const bodies: string[] = [];

  let orgA: string;
  let orgB: string;
  let adminA: string;
  let adminB: string;

  async function request(path: string, init: RequestInit = {}): Promise<Response> {
    const res = await api.app.request(path, init);
    bodies.push(await res.clone().text());
    return res;
  }

  /** Registers a Build of `manifest` with `adminKey`; returns the raw response. Each registration is 1 s later. */
  async function register(adminKey: string, manifest: BuildManifest): Promise<Response> {
    clock.ms += 1_000;
    return request(`/v1/apps/${manifest.app_id}/builds`, json({ manifest }, bearer(adminKey)));
  }

  async function registered(adminKey: string, manifest: BuildManifest): Promise<void> {
    expect((await register(adminKey, manifest)).status).toBe(201);
  }

  async function ingest(shieldKey: string, events: ShieldEvent[]): Promise<void> {
    const res = await request("/v1/events", json(batchOf(events), bearer(shieldKey)));
    expect(res.status).toBe(202);
    await flush();
  }

  async function incidentsOfApp(adminKey: string, appId: string): Promise<Incident[]> {
    const res = await request(`/v1/incidents?app_id=${appId}`, { headers: bearer(adminKey) });
    expect(res.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await res.json()).incidents;
  }

  async function shieldKeyFor(organizationId: string, appId: string, environment: Environment): Promise<string> {
    const generated = generateKey("shield", environment);
    await api.db.tx({ organizationId }, (q) =>
      insertKey(q, { id: newId("key"), organizationId, kind: "shield", appId, environment, generated }),
    );
    api.issuedKeys.push(generated.key);
    return generated.key;
  }

  beforeAll(async () => {
    api = await makeTestApi({ now });
    const detector = createDetector({
      db: api.db,
      bus: api.bus,
      notifier: { incidentOpened: (incident, organizationId) => opened.push({ incident, organizationId }) },
      now,
      logger: api.logger,
    });
    stopDetector = detector.start();
    flush = () => detector.flush();
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    orgA = a.organization.id;
    orgB = b.organization.id;
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
  });
  afterAll(async () => {
    stopDetector();
    await api.close();
  });

  describe("registration", () => {
    it("stores the Manifest's Canaries with the Build, in the same transaction, for its own Organization only", async () => {
      const app = await createAppFor(api, adminA, { name: "Stores" });
      const canaries = [canary("key"), canary("route"), canary("route")];
      const manifest = manifestFor(app.app.id, { canaries });
      await registered(adminA, manifest);

      const rows = await api.db.tx({ organizationId: orgA }, (q) =>
        q.query<{ id: string; kind: string; value: string; build_id: string; app_id: string; environment: string }>(
          "SELECT id, kind, value, build_id, app_id, environment FROM canaries WHERE build_id = $1 ORDER BY position",
          [manifest.build_id],
        ),
      );
      expect(rows.rows).toEqual(
        canaries.map((c) => ({ ...c, build_id: manifest.build_id, app_id: app.app.id, environment: "development" })),
      );
      // Row-level security: another Organization and no Organization see none of them.
      for (const scope of [{ organizationId: orgB }, "none"] as const) {
        const other = await api.db.tx(scope, (q) =>
          q.query("SELECT 1 FROM canaries WHERE build_id = $1", [manifest.build_id]),
        );
        expect(other.rows).toEqual([]);
      }
    });

    it("refuses a Canary id already registered to another Build of the Organization with 409, storing neither", async () => {
      const app = await createAppFor(api, adminA, { name: "Duplicate" });
      const shared = canary("key");
      await registered(adminA, manifestFor(app.app.id, { canaries: [shared] }));
      const second = manifestFor(app.app.id, { canaries: [canary("route"), shared] });
      const problem = await expectProblem(await register(adminA, second), 409);
      expect(problem.type).toBe("https://antireverse.dev/problems/conflict");

      // The transaction rolled back: no Build, and not the other Canary either.
      await expectProblem(
        await request(`/v1/apps/${app.app.id}/builds/${second.build_id}`, { headers: bearer(adminA) }),
        404,
      );
      const rows = await api.db.tx({ organizationId: orgA }, (q) =>
        q.query("SELECT 1 FROM canaries WHERE build_id = $1", [second.build_id]),
      );
      expect(rows.rows).toEqual([]);
    });

    it("lets another Organization register the same Canary id: an id is unique within an Organization", async () => {
      const appA = await createAppFor(api, adminA, { name: "Same id A" });
      const appB = await createAppFor(api, adminB, { name: "Same id B" });
      const shared = canary("key");
      await registered(adminA, manifestFor(appA.app.id, { canaries: [shared] }));
      await registered(adminB, manifestFor(appB.app.id, { canaries: [{ ...shared, value: canary("key").value }] }));
    });

    it("refuses a Canary whose value does not match its kind, and a Canary listed twice, with 400", async () => {
      const app = await createAppFor(api, adminA, { name: "Malformed" });
      const key = canary("key");
      await expectProblem(
        await register(adminA, manifestFor(app.app.id, { canaries: [{ ...key, kind: "route" } as Canary] })),
        400,
      );
      await expectProblem(await register(adminA, manifestFor(app.app.id, { canaries: [key, key] })), 400);
      const tooMany = Array.from({ length: CANARY_LIMITS.perBuild + 1 }, () => canary("key"));
      await expectProblem(await register(adminA, manifestFor(app.app.id, { canaries: tooMany })), 400);
    });

    it("returns leak_scan and the Canaries as id and kind only on register, list and detail; never a value", async () => {
      const app = await createAppFor(api, adminA, { name: "Exposed" });
      const canaries = [canary("key"), canary("route")];
      const manifest = manifestFor(app.app.id, { canaries, leak_scan: { status: "suppressed", suppressed: 2 } });
      const res = await register(adminA, manifest);
      expect(res.status).toBe(201);
      const text = await res.text();
      const summary = canaries.map(({ id, kind }) => ({ id, kind }));
      expect(BuildResponseSchema.parse(JSON.parse(text)).build).toMatchObject({
        leak_scan: { status: "suppressed", suppressed: 2 },
        canaries: summary,
      });

      const detail = await request(`/v1/apps/${app.app.id}/builds/${manifest.build_id}`, { headers: bearer(adminA) });
      const detailText = await detail.text();
      const raw = JSON.parse(detailText) as { build: { canaries: unknown[] } };
      expect(raw.build.canaries).toEqual(summary);
      expect(BuildResponseSchema.parse(raw).build.leak_scan).toEqual({ status: "suppressed", suppressed: 2 });

      const list = await request(`/v1/apps/${app.app.id}/builds`, { headers: bearer(adminA) });
      const listText = await list.text();
      expect(ListBuildsResponseSchema.parse(JSON.parse(listText)).builds[0]?.canaries).toEqual(summary);
      expect((JSON.parse(listText) as { builds: { canaries: unknown[] }[] }).builds[0]?.canaries).toEqual(summary);

      for (const body of [text, detailText, listText]) {
        for (const c of canaries) expect(body).not.toContain(c.value);
      }
    });

    it("keeps a Manifest without Canaries or leak_scan as it was: the fields stay absent", async () => {
      const app = await createAppFor(api, adminA, { name: "Older harden" });
      const manifest = manifestFor(app.app.id);
      const res = await register(adminA, manifest);
      const raw = (await res.json()) as { build: Record<string, unknown> };
      expect(raw.build).not.toHaveProperty("canaries");
      expect(raw.build).not.toHaveProperty("leak_scan");
    });
  });

  describe("Policy Bundle", () => {
    it("carries the App and Environment's Canaries, newest Build first, never another Environment's or Organization's", async () => {
      const app = await createAppFor(api, adminA, { name: "Bundled" });
      const shieldKey = app.shield_key.key;
      const older = [canary("key"), canary("route")];
      const newer = [canary("key")];
      const staging = [canary("route")];
      await registered(adminA, manifestFor(app.app.id, { canaries: older }));
      await registered(adminA, manifestFor(app.app.id, { canaries: newer }));
      await registered(adminA, manifestFor(app.app.id, { environment: "staging", canaries: staging }));
      // Another App of the same Organization and an App of another Organization.
      const sibling = await createAppFor(api, adminA, { name: "Sibling" });
      const foreignApp = await createAppFor(api, adminB, { name: "Foreign" });
      const siblingCanaries = [canary("key")];
      // The same id as one of A's, with another value.
      const foreign = [{ ...older[0], value: canary("key").value } as Canary, canary("route")];
      await registered(adminA, manifestFor(sibling.app.id, { canaries: siblingCanaries }));
      await registered(adminB, manifestFor(foreignApp.app.id, { canaries: foreign }));

      const { payload, signed } = await fetchBundle(api, shieldKey, api.signer.publicKey);
      expect(payload.canaries).toEqual([...newer, ...older]);
      // In the signed bytes, after the Rules (and before the attestation keys).
      const members = Object.keys(JSON.parse(signed.bundle) as object);
      expect(members.slice(members.indexOf("rules"))).toEqual(["rules", "canaries", "attestation_keys"]);

      const stagingKey = await shieldKeyFor(orgA, app.app.id, "staging");
      expect((await fetchBundle(api, stagingKey, api.signer.publicKey)).payload.canaries).toEqual(staging);

      const foreignBundle = await fetchBundle(api, foreignApp.shield_key.key, api.signer.publicKey);
      expect(foreignBundle.payload.canaries).toEqual(foreign);
      expect(foreignBundle.signed.bundle).not.toContain(older[0]?.value);
      expect(signed.bundle).not.toContain(foreign[0]?.value);
      for (const c of [...siblingCanaries, ...staging, ...foreign]) expect(signed.bundle).not.toContain(c.value);
    });

    it("has no canaries member while the App and Environment have no Canary", async () => {
      const app = await createAppFor(api, adminA, { name: "No Canaries" });
      await registered(adminA, manifestFor(app.app.id));
      const { signed, payload } = await fetchBundle(api, app.shield_key.key, api.signer.publicKey);
      expect(payload.canaries).toBeUndefined();
      expect(JSON.parse(signed.bundle)).not.toHaveProperty("canaries");
    });

    it("carries only the Canaries of the 20 most recent Builds", async () => {
      const app = await createAppFor(api, adminA, { name: "Twenty" });
      const perBuild: Canary[][] = [];
      for (let i = 0; i < CANARY_LIMITS.buildsInBundle + 1; i++) {
        const canaries = [canary("key")];
        perBuild.push(canaries);
        await registered(adminA, manifestFor(app.app.id, { canaries }));
      }
      const { payload } = await fetchBundle(api, app.shield_key.key, api.signer.publicKey);
      expect(payload.canaries).toHaveLength(CANARY_LIMITS.buildsInBundle);
      expect(payload.canaries).toEqual(perBuild.slice(1).reverse().flat());
    });

    it("carries at most 100 Canaries: those of the newest Builds, in Manifest order within a Build", async () => {
      const app = await createAppFor(api, adminA, { name: "Hundred" });
      const perBuild: Canary[][] = [];
      for (let i = 0; i < 11; i++) {
        const canaries = Array.from({ length: CANARY_LIMITS.perBuild }, (_, k) =>
          canary(k % 2 === 0 ? "key" : "route"),
        );
        perBuild.push(canaries);
        await registered(adminA, manifestFor(app.app.id, { canaries }));
      }
      const first = await fetchBundle(api, app.shield_key.key, api.signer.publicKey);
      expect(first.payload.canaries).toHaveLength(CANARY_LIMITS.perBundle);
      expect(first.payload.canaries).toEqual(perBuild.slice(1).reverse().flat());
    });

    it("fits the bundle bound with 50 of the largest Rules and 100 Canaries", async () => {
      const app = await createAppFor(api, adminA, { name: "Largest with Canaries" });
      const methods = Array.from({ length: POLICY_LIMITS.methodsMax }, (_, index) =>
        `${String.fromCharCode(65 + index)}`.repeat(16),
      );
      const rules = Array.from({ length: POLICY_LIMITS.rulesMax }, (_, index) => ({
        name: "n".repeat(POLICY_LIMITS.nameMax),
        path: `/${String(index).padStart(2, "0")}${"a".repeat(POLICY_LIMITS.pathMax - 3)}`,
        methods,
        mode: "enforce",
      }));
      await publishPolicy(api, adminA, app.app.id, "development", rules);
      for (let i = 0; i < 10; i++) {
        const canaries = Array.from({ length: CANARY_LIMITS.perBuild }, () => canary("route"));
        await registered(adminA, manifestFor(app.app.id, { canaries }));
      }
      const { signed, payload } = await fetchBundle(api, app.shield_key.key, api.signer.publicKey);
      expect(payload.rules).toHaveLength(50);
      expect(payload.canaries).toHaveLength(100);
      expect(Buffer.byteLength(signed.bundle, "utf8")).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
    });

    it("changes the ETag when the Canary set changes, and keeps it while it does not", async () => {
      const app = await createAppFor(api, adminA, { name: "ETag" });
      const key = app.shield_key.key;
      await registered(adminA, manifestFor(app.app.id, { canaries: [canary("key")] }));
      const one = await fetchBundle(api, key, api.signer.publicKey);

      // Nothing changed: the same bundle, and "not modified" to a Shield that has it.
      clock.ms += 1_000;
      expect(await fetchBundle(api, key, api.signer.publicKey)).toEqual(one);
      const notModified = await request("/v1/policy-bundle", {
        headers: { ...bearer(key), "if-none-match": one.etag },
      });
      expect(notModified.status).toBe(304);

      // A Build without Canaries leaves the set as it was.
      await registered(adminA, manifestFor(app.app.id));
      expect(await fetchBundle(api, key, api.signer.publicKey)).toEqual(one);

      // A Build with new Canaries: same Policy version, new bundle and new ETag.
      const added = [canary("route")];
      await registered(adminA, manifestFor(app.app.id, { canaries: added }));
      const two = await fetchBundle(api, key, api.signer.publicKey);
      expect(two.etag).not.toBe(one.etag);
      expect(two.payload.version).toBe(one.payload.version);
      expect(two.payload.canaries?.[0]).toEqual(added[0]);
      const modified = await request("/v1/policy-bundle", { headers: { ...bearer(key), "if-none-match": one.etag } });
      expect(modified.status).toBe(200);
      expect(modified.headers.get("etag")).toBe(two.etag);
    });

    it("the issuer keeps a bundle while the Canary set is the same, and signs a new one when it changes", () => {
      const issuer = createBundleIssuer({ signer: createSigner(), now: () => new Date(T0) });
      const subject = {
        audience: "a".repeat(32),
        epoch: "0123456789abcdef0123456789abcdef",
        appId: "app_0123456789abcdef01234567",
        environment: "development" as const,
        version: 1,
        rules: [],
      };
      const none = issuer.issue(subject);
      expect(issuer.issue({ ...subject, canaries: [] })).toEqual(none);
      const some = issuer.issue({ ...subject, canaries: [...EXAMPLE_CANARIES] });
      expect(some.etag).not.toBe(none.etag);
      expect(issuer.issue({ ...subject, canaries: EXAMPLE_CANARIES.map((c) => ({ ...c })) })).toEqual(some);
      const reordered = issuer.issue({ ...subject, canaries: [...EXAMPLE_CANARIES].reverse() });
      expect(reordered.etag).not.toBe(some.etag);
    });
  });

  describe("detection", () => {
    it("counts an Event carrying a Canary signal toward canary-touched, and a block with it toward blocked-burst too", () => {
      const base = {
        ...signalled(T0, [EXAMPLE_CANARIES[0]?.id ?? ""]),
        organization_id: orgA,
        app_id: "app_0123456789abcdef01234567",
        environment: "development" as const,
        received_at: new Date(T0).toISOString(),
      };
      expect(matchingRules(base).map((rule) => rule.key)).toEqual(["canary-touched"]);
      const blocked = {
        ...base,
        decision: { action: "block", mode: "enforce", rule_id: null, policy_version: 1, containment_id: null } as const,
      };
      expect(matchingRules(blocked).map((rule) => rule.key)).toEqual(["blocked-burst", "canary-touched"]);
      // A near miss is no Canary signal.
      const near = { ...base, signals: [{ id: "canary.touched:cny_0123", confidence: 1 }] };
      expect(matchingRules(near)).toEqual([]);
    });

    it("opens one High 'Canary used' Incident from one signalled Event, naming the Canary and its Build", async () => {
      const app = await createAppFor(api, adminA, { name: "Touched" });
      const canaries = [canary("key"), canary("route")];
      const manifest = manifestFor(app.app.id, { canaries });
      await registered(adminA, manifest);
      const before = opened.length;

      clock.ms += 1_000;
      const at = clock.ms;
      await ingest(app.shield_key.key, [signalled(at, [canaries[0]?.id ?? ""])]);

      const incidents = await incidentsOfApp(adminA, app.app.id);
      expect(incidents).toHaveLength(1);
      const incident = IncidentSchema.parse(incidents[0]);
      expect(incident).toMatchObject({
        rule: "canary-touched",
        title: "Canary used",
        severity: "high",
        status: "open",
        ip_prefix: PREFIX,
        detection_count: 1,
        canary_id: canaries[0]?.id,
        build_id: manifest.build_id,
        first_seen: new Date(at).toISOString(),
        last_seen: new Date(at).toISOString(),
      });
      // Alerted once, with the new fields.
      const alerts = opened.slice(before);
      expect(alerts).toHaveLength(1);
      expect(alerts[0]?.organizationId).toBe(orgA);
      expect(alerts[0]?.incident).toMatchObject({ canary_id: canaries[0]?.id, build_id: manifest.build_id });

      const detail = await request(`/v1/incidents/${incident.id}`, { headers: bearer(adminA) });
      const text = await detail.text();
      const parsed = IncidentDetailResponseSchema.parse(JSON.parse(text));
      expect(parsed.incident).toEqual(incident);
      expect(parsed.detections).toHaveLength(1);
      expect(parsed.detections[0]).toMatchObject({ rule: "canary-touched", canary_id: canaries[0]?.id, count: 1 });
      expect(parsed.evidence).toHaveLength(1);
      for (const c of canaries) expect(text).not.toContain(c.value);
    });

    it("joins a repeat of the same Canary and prefix to the open Incident, without a second alert", async () => {
      const app = await createAppFor(api, adminA, { name: "Repeat" });
      const touched = canary("key");
      const other = canary("route");
      await registered(adminA, manifestFor(app.app.id, { canaries: [touched, other] }));
      const before = opened.length;

      clock.ms += 1_000;
      await ingest(app.shield_key.key, [signalled(clock.ms, [touched.id])]);
      clock.ms += 1_000;
      await ingest(app.shield_key.key, [signalled(clock.ms, [touched.id])]);

      let incidents = await incidentsOfApp(adminA, app.app.id);
      expect(incidents).toHaveLength(1);
      expect(incidents[0]?.detection_count).toBe(2);
      expect(opened.length - before).toBe(1);

      // Another Canary, or another prefix, is another Incident.
      clock.ms += 1_000;
      await ingest(app.shield_key.key, [
        signalled(clock.ms, [other.id]),
        signalled(clock.ms, [touched.id], OTHER_PREFIX),
      ]);
      incidents = await incidentsOfApp(adminA, app.app.id);
      expect(incidents).toHaveLength(3);
      expect(new Set(incidents.map((i) => `${i.canary_id} ${i.ip_prefix}`)).size).toBe(3);
      expect(opened.length - before).toBe(3);

      // After resolve, a new use opens a new Incident.
      const first = incidents.find((i) => i.canary_id === touched.id && i.ip_prefix === PREFIX);
      const res = await request(`/v1/incidents/${first?.id}`, {
        ...json({ status: "resolved" }, bearer(adminA)),
        method: "PATCH",
      });
      expect(res.status).toBe(200);
      clock.ms += 1_000;
      await ingest(app.shield_key.key, [signalled(clock.ms, [touched.id])]);
      incidents = await incidentsOfApp(adminA, app.app.id);
      expect(incidents.filter((i) => i.canary_id === touched.id && i.ip_prefix === PREFIX)).toHaveLength(2);
    });

    it("shows as evidence only the Events of that prefix carrying that Canary's signal", async () => {
      const app = await createAppFor(api, adminA, { name: "Evidence" });
      const touched = canary("key");
      const other = canary("route");
      await registered(adminA, manifestFor(app.app.id, { canaries: [touched, other] }));
      clock.ms += 1_000;
      const at = clock.ms;
      await ingest(app.shield_key.key, [
        signalled(at, [touched.id]),
        signalled(at + 1, [other.id]),
        { ...shieldEvent(at + 2), actor: { ip_prefix: PREFIX, ip_hash: null } },
        signalled(at + 3, [touched.id], OTHER_PREFIX),
        signalled(at + 4, [touched.id]),
      ]);
      const incident = (await incidentsOfApp(adminA, app.app.id)).find(
        (i) => i.canary_id === touched.id && i.ip_prefix === PREFIX,
      );
      expect(incident?.detection_count).toBe(2);
      const detail = IncidentDetailResponseSchema.parse(
        await (await request(`/v1/incidents/${incident?.id}`, { headers: bearer(adminA) })).json(),
      );
      expect(detail.evidence.map((event) => event.ts)).toEqual([
        new Date(at + 4).toISOString(),
        new Date(at).toISOString(),
      ]);
    });

    it("shows as evidence only Events that counted toward the Canary: never one naming it past the per-Event cap", async () => {
      const app = await createAppFor(api, adminA, { name: "Evidence cap" });
      const five = [canary("key"), canary("key"), canary("key"), canary("route"), canary("route")];
      await registered(adminA, manifestFor(app.app.id, { canaries: five }));
      const fifth = five[4];
      clock.ms += 1_000;
      const at = clock.ms;
      await ingest(app.shield_key.key, [
        // The fifth on its own opens its Incident; a second use at +2 keeps the span open past +1.
        signalled(at, [fifth?.id ?? ""]),
        // Names all five, inside that span: only the first MAX_CANARIES_PER_EVENT (4) are counted, not the fifth.
        signalled(
          at + 1,
          five.map((c) => c.id),
        ),
        signalled(at + 2, [fifth?.id ?? ""]),
      ]);
      const incident = (await incidentsOfApp(adminA, app.app.id)).find((i) => i.canary_id === fifth?.id);
      expect(incident?.detection_count).toBe(2);
      const detail = IncidentDetailResponseSchema.parse(
        await (await request(`/v1/incidents/${incident?.id}`, { headers: bearer(adminA) })).json(),
      );
      expect(detail.evidence.map((event) => event.ts)).toEqual([
        new Date(at + 2).toISOString(),
        new Date(at).toISOString(),
      ]);

      // The first Canary's Incident still shows the five-signal Event, which counted toward it.
      const first = (await incidentsOfApp(adminA, app.app.id)).find((i) => i.canary_id === five[0]?.id);
      const firstDetail = IncidentDetailResponseSchema.parse(
        await (await request(`/v1/incidents/${first?.id}`, { headers: bearer(adminA) })).json(),
      );
      expect(firstDetail.evidence.map((event) => event.ts)).toEqual([new Date(at + 1).toISOString()]);
    });

    it("ignores an unknown Canary id, another Organization's, another App's and another Environment's", async () => {
      const app = await createAppFor(api, adminA, { name: "Ignores" });
      const sibling = await createAppFor(api, adminA, { name: "Ignores sibling" });
      const foreignApp = await createAppFor(api, adminB, { name: "Ignores foreign" });
      const own = canary("key");
      const siblings = canary("key");
      const foreign = canary("key");
      const staging = canary("route");
      await registered(adminA, manifestFor(app.app.id, { canaries: [own] }));
      await registered(adminA, manifestFor(app.app.id, { environment: "staging", canaries: [staging] }));
      await registered(adminA, manifestFor(sibling.app.id, { canaries: [siblings] }));
      await registered(adminB, manifestFor(foreignApp.app.id, { canaries: [foreign] }));
      const before = opened.length;

      clock.ms += 1_000;
      await ingest(app.shield_key.key, [
        signalled(clock.ms, [canary("key").id]),
        signalled(clock.ms, [siblings.id]),
        signalled(clock.ms, [foreign.id]),
        signalled(clock.ms, [staging.id]),
      ]);
      expect(await incidentsOfApp(adminA, app.app.id)).toEqual([]);
      expect(await incidentsOfApp(adminB, foreignApp.app.id)).toEqual([]);
      expect(await incidentsOfApp(adminA, sibling.app.id)).toEqual([]);
      expect(opened.length).toBe(before);
      const detections = await api.db.tx({ organizationId: orgA }, (q) =>
        q.query("SELECT 1 FROM detections WHERE app_id = $1", [app.app.id]),
      );
      expect(detections.rows).toEqual([]);

      // Its own Canary in the same Event as a foreign one still counts, once.
      clock.ms += 1_000;
      await ingest(app.shield_key.key, [signalled(clock.ms, [foreign.id, own.id, own.id])]);
      const incidents = await incidentsOfApp(adminA, app.app.id);
      expect(incidents.map((i) => i.canary_id)).toEqual([own.id]);
      expect(incidents[0]?.detection_count).toBe(1);
    });

    it("ignores a Canary signal without a network prefix", async () => {
      const app = await createAppFor(api, adminA, { name: "No prefix" });
      const own = canary("key");
      await registered(adminA, manifestFor(app.app.id, { canaries: [own] }));
      clock.ms += 1_000;
      await ingest(app.shield_key.key, [signalled(clock.ms, [own.id], null)]);
      expect(await incidentsOfApp(adminA, app.app.id)).toEqual([]);
    });

    it("still counts an enforced block carrying a Canary signal toward blocked-burst", async () => {
      const app = await createAppFor(api, adminA, { name: "Block and Canary" });
      const own = canary("key");
      await registered(adminA, manifestFor(app.app.id, { canaries: [own] }));
      clock.ms += 1_000;
      const blocked = DETECTION_RULES[0].threshold;
      await ingest(
        app.shield_key.key,
        Array.from({ length: blocked }, (_, i) => ({
          ...signalled(clock.ms + i, [own.id]),
          decision: {
            action: "block" as const,
            mode: "enforce" as const,
            rule_id: null,
            policy_version: 1,
            containment_id: null,
          },
        })),
      );
      const incidents = await incidentsOfApp(adminA, app.app.id);
      const burst = incidents.find((i) => i.rule === "blocked-burst");
      const used = incidents.find((i) => i.rule === "canary-touched");
      expect(burst).toMatchObject({ detection_count: 1, canary_id: null, build_id: null });
      expect(used).toMatchObject({ detection_count: blocked, canary_id: own.id });
      // A blocked-burst Incident's evidence is its blocks, as before.
      const detail = IncidentDetailResponseSchema.parse(
        await (await request(`/v1/incidents/${burst?.id}`, { headers: bearer(adminA) })).json(),
      );
      expect(detail.evidence.length).toBeGreaterThan(0);
      expect(detail.detections[0]?.canary_id).toBeNull();
    });
  });

  describe("tables", () => {
    it("allows one active canary-touched Incident per (App, Environment, Canary, prefix), and keeps the old groups", async () => {
      const app = await createAppFor(api, adminA, { name: "Index" });
      const one = canary("key");
      const two = canary("key");
      const manifest = manifestFor(app.app.id, { canaries: [one, two] });
      await registered(adminA, manifest);
      const T = new Date(T0).toISOString();
      const insert = (rule: string, canaryId: string | null, buildId: string | null) =>
        api.db.tx({ organizationId: orgA }, (q) =>
          q.query(
            `INSERT INTO incidents (id, organization_id, app_id, environment, rule, severity, title, status, ip_prefix,
               first_seen, last_seen, detection_count, created_at, updated_at, canary_id, build_id)
             VALUES ($1, $2, $3, 'development', $4, 'high', 'x', 'open', '192.0.2.0/24', $5, $5, 1, $5, $5, $6, $7)`,
            [newId("inc"), orgA, app.app.id, rule, T, canaryId, buildId],
          ),
        );
      await insert("canary-touched", one.id, manifest.build_id);
      await insert("canary-touched", two.id, manifest.build_id);
      await expect(insert("canary-touched", one.id, manifest.build_id)).rejects.toThrow(/duplicate key/);
      await insert("blocked-burst", null, null);
      await expect(insert("blocked-burst", null, null)).rejects.toThrow(/duplicate key/);
      // The rule and the Canary go together.
      await expect(insert("canary-touched", null, null)).rejects.toThrow(/check constraint/);
      await expect(insert("failed-signin-burst", one.id, manifest.build_id)).rejects.toThrow(/check constraint/);
    });

    it("lets the request role add Canaries and read them, never change or delete one", async () => {
      const app = await createAppFor(api, adminA, { name: "Immutable" });
      const own = canary("key");
      await registered(adminA, manifestFor(app.app.id, { canaries: [own] }));
      await expect(
        api.db.tx({ organizationId: orgA }, (q) => q.query("UPDATE canaries SET value = 'x' WHERE id = $1", [own.id])),
      ).rejects.toThrow(/permission denied/);
      await expect(
        api.db.tx({ organizationId: orgA }, (q) => q.query("DELETE FROM canaries WHERE id = $1", [own.id])),
      ).rejects.toThrow(/permission denied/);
    });
  });

  it("never logs a key or a Canary value, and no admin response carries a Canary value", async () => {
    expectNoKeyLogged(api);
    const values = await api.db.tx({ organizationId: orgA }, (q) =>
      q.query<{ value: string }>("SELECT value FROM canaries"),
    );
    expect(values.rows.length).toBeGreaterThan(0);
    const log = api.logger.lines.join("\n");
    const adminBodies = bodies.filter((body) => !body.includes('"signature"'));
    for (const { value } of values.rows) {
      expect(log).not.toContain(value);
      for (const body of adminBodies) expect(body).not.toContain(value);
    }
  });
});
