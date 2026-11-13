import {
  type AppSetup,
  AppSetupResponseSchema,
  type BuildManifest,
  type Environment,
  EXAMPLE_BUILD_MANIFEST,
  type ShieldEvent,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { insertEvents } from "../src/stores/events.ts";
import { APP_SETUP_SQL } from "../src/stores/setup.ts";
import {
  batchOf,
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-13T09:00:00.000Z");
const iso = (ms: number): string => new Date(ms).toISOString();
const NOTHING_DONE = { shield: { done_at: null }, guard: { done_at: null }, harden: { done_at: null } };

describe("App set-up", () => {
  let api: TestApi;
  const clock = { now: new Date(T0) };
  let organizationA: string;
  let adminA: string;
  let adminB: string;

  beforeAll(async () => {
    api = await makeTestApi({ now: () => clock.now });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    organizationA = a.organization.id;
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
  });
  afterAll(async () => {
    await api.close();
  });

  async function freshApp(environment: Environment = "development") {
    const created = await createAppFor(api, adminA, { name: "Storefront", environment });
    return { appId: created.app.id, shieldKey: created.shield_key.key };
  }

  async function setupOf(appId: string, query = "", key = adminA): Promise<AppSetup> {
    const res = await api.app.request(`/v1/apps/${appId}/setup${query}`, { headers: bearer(key) });
    expect(res.status).toBe(200);
    return AppSetupResponseSchema.parse(await res.json()).setup;
  }

  async function ingest(shieldKey: string, at: number, events: ShieldEvent[]): Promise<void> {
    clock.now = new Date(at);
    const res = await api.app.request("/v1/events", json(batchOf(events), bearer(shieldKey)));
    expect(res.status).toBe(202);
  }

  async function register(appId: string, at: number, overrides: Partial<BuildManifest> = {}): Promise<void> {
    clock.now = new Date(at);
    const manifest = { ...EXAMPLE_BUILD_MANIFEST, build_id: newId("bld"), app_id: appId, ...overrides };
    const res = await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(adminA)));
    expect(res.status).toBe(201);
  }

  const attested = (ms: number, status: "valid" | "missing" | "invalid" | "expired" = "valid"): ShieldEvent =>
    shieldEvent(ms, {
      attestation:
        status === "valid" ? { status, verdict: "suspect", risk: 70 } : { status, verdict: null, risk: null },
    });

  it("starts with nothing done, in the Environment of the App's first Shield key", async () => {
    const { appId } = await freshApp("staging");
    expect(await setupOf(appId)).toEqual({ environment: "staging", ...NOTHING_DONE });
    expect(await setupOf(appId, "?environment=production")).toEqual({ environment: "production", ...NOTHING_DONE });
  });

  it("dates each step by when it was first done as data arrives", async () => {
    const { appId, shieldKey } = await freshApp();

    // Shield: the first Event received, whatever the Event's own time.
    await ingest(shieldKey, T0 + 10_000, [shieldEvent(T0 - 60_000)]);
    expect(await setupOf(appId)).toEqual({
      environment: "development",
      ...NOTHING_DONE,
      shield: { done_at: iso(T0 + 10_000) },
    });
    await ingest(shieldKey, T0 + 20_000, [shieldEvent(T0 + 19_000)]);
    expect((await setupOf(appId)).shield.done_at).toBe(iso(T0 + 10_000));

    // Guard: the first Event received with an Attestation Token that Shield verified.
    await ingest(shieldKey, T0 + 30_000, [attested(T0 + 29_000)]);
    expect((await setupOf(appId)).guard.done_at).toBe(iso(T0 + 30_000));
    await ingest(shieldKey, T0 + 40_000, [attested(T0 + 39_000)]);
    expect((await setupOf(appId)).guard.done_at).toBe(iso(T0 + 30_000));

    // Harden: the first Build registered.
    await register(appId, T0 + 50_000, { environment: "development" });
    await register(appId, T0 + 60_000, { environment: "development" });
    expect(await setupOf(appId)).toEqual({
      environment: "development",
      shield: { done_at: iso(T0 + 10_000) },
      guard: { done_at: iso(T0 + 30_000) },
      harden: { done_at: iso(T0 + 50_000) },
    });
  });

  it("does not count an Event without a verified attestation toward Guard", async () => {
    const { appId, shieldKey } = await freshApp();
    const { attestation: _none, ...withoutMember } = shieldEvent(T0 + 1_000);
    await ingest(shieldKey, T0 + 2_000, [
      shieldEvent(T0 + 1_000),
      withoutMember as ShieldEvent,
      attested(T0 + 1_000, "missing"),
      attested(T0 + 1_000, "invalid"),
      attested(T0 + 1_000, "expired"),
    ]);
    const setup = await setupOf(appId);
    expect(setup.shield.done_at).toBe(iso(T0 + 2_000));
    expect(setup.guard.done_at).toBeNull();
  });

  it("counts only the Environment asked for", async () => {
    const { appId, shieldKey } = await freshApp("development");
    // Production data, written as Shield and Harden would for that Environment.
    await api.db.tx({ organizationId: organizationA }, (q) =>
      insertEvents(q, { organizationId: organizationA, appId, environment: "production", receivedAt: new Date(T0) }, [
        attested(T0),
      ]),
    );
    await register(appId, T0 + 1_000, { environment: "production" });

    expect(await setupOf(appId)).toEqual({ environment: "development", ...NOTHING_DONE });
    expect(await setupOf(appId, "?environment=staging")).toEqual({ environment: "staging", ...NOTHING_DONE });
    expect(await setupOf(appId, "?environment=production")).toEqual({
      environment: "production",
      shield: { done_at: iso(T0) },
      guard: { done_at: iso(T0) },
      harden: { done_at: iso(T0 + 1_000) },
    });

    await ingest(shieldKey, T0 + 5_000, [attested(T0 + 5_000)]);
    expect(await setupOf(appId)).toEqual({
      environment: "development",
      ...NOTHING_DONE,
      shield: { done_at: iso(T0 + 5_000) },
      guard: { done_at: iso(T0 + 5_000) },
    });
  });

  it("is tenant-isolated: another Organization's App, an unknown App and a malformed id are not found", async () => {
    const { appId, shieldKey } = await freshApp();
    await ingest(shieldKey, T0 + 1_000, [attested(T0 + 1_000)]);
    await register(appId, T0 + 2_000, { environment: "development" });

    const other = await api.app.request(`/v1/apps/${appId}/setup`, { headers: bearer(adminB) });
    const unknown = await api.app.request(`/v1/apps/${newId("app")}/setup`, { headers: bearer(adminA) });
    const malformed = await api.app.request("/v1/apps/app_1/setup", { headers: bearer(adminA) });
    const bodies = await Promise.all([other, unknown, malformed].map((res) => expectProblem(res, 404)));
    // The same answer whether the App exists elsewhere or nowhere: nothing tells them apart.
    expect(bodies[0]).toEqual(bodies[1]);

    // Organization B's own App of the same Environment sees none of A's data.
    const created = await createAppFor(api, adminB, { name: "Storefront" });
    expect(await setupOf(created.app.id, "", adminB)).toEqual({ environment: "development", ...NOTHING_DONE });
  });

  it("is for admin keys only: a Shield key gets 403, no key 401", async () => {
    const { appId, shieldKey } = await freshApp();
    await expectProblem(await api.app.request(`/v1/apps/${appId}/setup`, { headers: bearer(shieldKey) }), 403);
    await expectProblem(await api.app.request(`/v1/apps/${appId}/setup`), 401);
  });

  it("refuses an unknown Environment with 400", async () => {
    const { appId } = await freshApp();
    for (const query of ["?environment=qa", "?environment=", "?environment=Production"]) {
      const problem = await expectProblem(
        await api.app.request(`/v1/apps/${appId}/setup${query}`, { headers: bearer(adminA) }),
        400,
      );
      expect(problem.errors?.map((error) => error.path)).toEqual(["environment"]);
    }
  });

  it("computes each step through an index, under row-level security", async () => {
    const { appId, shieldKey } = await freshApp();
    await ingest(
      shieldKey,
      T0 + 1_000,
      Array.from({ length: 200 }, (_, n) => (n % 50 === 0 ? attested(T0 + n) : shieldEvent(T0 + n))),
    );
    await register(appId, T0 + 2_000, { environment: "development" });
    await api.db.owner(async (q) => {
      await q.query("ANALYZE events");
      await q.query("ANALYZE builds");
    });
    const plan = await api.db.tx({ organizationId: organizationA }, async (q) => {
      await q.query("SET LOCAL enable_seqscan = off");
      const { rows } = await q.query<Record<string, string>>(
        `EXPLAIN ${APP_SETUP_SQL.replaceAll("$1", `'${organizationA}'`)
          .replaceAll("$2", `'${appId}'`)
          .replaceAll("$3", "'development'")}`,
      );
      return rows.map((row) => Object.values(row)[0]).join("\n");
    });
    expect(APP_SETUP_SQL).not.toContain("$4");
    expect(plan).not.toContain("Seq Scan");
    expect(plan).not.toContain("Sort");
    expect(plan).toContain("events_recent");
    expect(plan).toContain("events_first_attested");
    expect(plan).toContain("builds_recent_by_environment");
  });

  it("never logs a key", () => {
    expectNoKeyLogged(api);
  });
});
