import {
  DETECTION_RULES,
  INCIDENT_LIMITS,
  type Incident,
  IncidentDetailResponseSchema,
  IncidentSchema,
  ListIncidentsResponseSchema,
  type ShieldEvent,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDetector } from "../src/detect/detector.ts";
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

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const PREFIX = "203.0.113.0/24";
const OTHER_PREFIX = "198.51.100.0/24";
const THRESHOLD = DETECTION_RULES[0].threshold;

const blocked = (ms: number, prefix = PREFIX): ShieldEvent => ({
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
  actor: { ip_prefix: prefix, ip_hash: null },
});
const allowed = (ms: number, prefix = PREFIX): ShieldEvent => ({
  ...shieldEvent(ms),
  actor: { ip_prefix: prefix, ip_hash: null },
});

function patch(body: unknown, key: string): RequestInit {
  return { ...json(body, bearer(key)), method: "PATCH" };
}

describe("Incidents", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let stopDetector: () => void;
  let flush: () => Promise<void>;
  let adminA: string;
  let adminB: string;
  let shieldA: string;
  let shieldA2: string;
  let appA: string;
  let appA2: string;

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
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    const first = await createAppFor(api, adminA, { name: "Storefront" });
    appA = first.app.id;
    shieldA = first.shield_key.key;
    const second = await createAppFor(api, adminA, { name: "Back office" });
    appA2 = second.app.id;
    shieldA2 = second.shield_key.key;
  });
  afterAll(async () => {
    stopDetector();
    await api.close();
  });

  async function ingest(shieldKey: string, events: ShieldEvent[]): Promise<void> {
    const res = await api.app.request("/v1/events", json(batchOf(events), bearer(shieldKey)));
    expect(res.status).toBe(202);
    await flush();
  }

  /** Ingests a blocked burst from `prefix` with Event times from `startMs` at one-second steps; returns the Incident. */
  async function burst(shieldKey: string, startMs: number, prefix = PREFIX): Promise<Incident> {
    clock.ms += 1_000;
    await ingest(
      shieldKey,
      Array.from({ length: THRESHOLD }, (_, i) => blocked(startMs + i * 1_000, prefix)),
    );
    const res = await api.app.request("/v1/incidents", { headers: bearer(adminA) });
    const { incidents } = ListIncidentsResponseSchema.parse(await res.json());
    const found = incidents.find((incident) => incident.ip_prefix === prefix && incident.status !== "resolved");
    if (found === undefined) throw new Error("No Incident was opened.");
    return found;
  }

  let first: Incident;
  let second: Incident;
  let third: Incident;

  it("lists Incidents newest first by last_seen, with app_id and status filters", async () => {
    first = await burst(shieldA, T0);
    second = await burst(shieldA, T0 + 100_000, OTHER_PREFIX);
    third = await burst(shieldA2, T0 + 200_000);

    const res = await api.app.request("/v1/incidents", { headers: bearer(adminA) });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const { incidents } = ListIncidentsResponseSchema.parse(await res.json());
    expect(incidents.map((incident) => incident.id)).toEqual([third.id, second.id, first.id]);
    expect(incidents[2]).toEqual(IncidentSchema.parse(first));
    expect(first).toMatchObject({
      app_id: appA,
      environment: "development",
      rule: "blocked-burst",
      severity: "high",
      title: "Blocked burst",
      status: "open",
      ip_prefix: PREFIX,
      detection_count: 1,
      first_seen: new Date(T0).toISOString(),
      last_seen: new Date(T0 + (THRESHOLD - 1) * 1_000).toISOString(),
    });

    const byApp = await api.app.request(`/v1/incidents?app_id=${appA2}`, { headers: bearer(adminA) });
    expect(ListIncidentsResponseSchema.parse(await byApp.json()).incidents.map((i) => i.id)).toEqual([third.id]);

    const unknownApp = await api.app.request(`/v1/incidents?app_id=${newId("app")}`, { headers: bearer(adminA) });
    expect(await unknownApp.json()).toEqual({ incidents: [] });

    const open = await api.app.request("/v1/incidents?status=open", { headers: bearer(adminA) });
    expect(ListIncidentsResponseSchema.parse(await open.json()).incidents).toHaveLength(3);
    const resolved = await api.app.request("/v1/incidents?status=resolved", { headers: bearer(adminA) });
    expect(await resolved.json()).toEqual({ incidents: [] });
  });

  it("refuses a bad status or app_id filter with 400 naming the parameter", async () => {
    const badStatus = await expectProblem(
      await api.app.request("/v1/incidents?status=closed", { headers: bearer(adminA) }),
      400,
    );
    expect(badStatus.errors?.[0]?.path).toBe("status");
    const badApp = await expectProblem(
      await api.app.request("/v1/incidents?app_id=not-an-app", { headers: bearer(adminA) }),
      400,
    );
    expect(badApp.errors?.[0]?.path).toBe("app_id");
  });

  it("orders Incidents with the same last_seen by id, descending", async () => {
    const fresh = await createAppFor(api, adminA, { name: "Ties" });
    const at = T0 + 400_000;
    await ingest(fresh.shield_key.key, [
      ...Array.from({ length: THRESHOLD }, () => blocked(at, "192.0.2.0/24")),
      ...Array.from({ length: THRESHOLD }, () => blocked(at, "192.0.3.0/24")),
    ]);
    const res = await api.app.request(`/v1/incidents?app_id=${fresh.app.id}`, { headers: bearer(adminA) });
    const ids = ListIncidentsResponseSchema.parse(await res.json()).incidents.map((i) => i.id);
    expect(ids).toHaveLength(2);
    expect(ids).toEqual([...ids].sort().reverse());
  });

  it("returns one Incident with its Detections and up to 20 Events of evidence, newest first", async () => {
    // Inside first's time span: three more blocked Events from the same prefix (they match the rule)...
    await ingest(shieldA, [blocked(T0 + 500), blocked(T0 + 1_500), blocked(T0 + 2_500)]);
    // ...and Events that are not evidence: Events the rule does not count (an allow, a block in Monitor mode),
    // another prefix, another App, outside the span.
    await ingest(shieldA, [
      allowed(T0 + 18_500),
      {
        ...blocked(T0 + 18_600),
        decision: {
          action: "block",
          mode: "monitor",
          rule_id: null,
          policy_version: 1,
          containment_id: null,
          patch_id: null,
          patch_body: null,
        },
      },
    ]);
    await ingest(shieldA, [allowed(T0 + 3_500, OTHER_PREFIX), allowed(T0 + 900_000)]);
    await ingest(shieldA2, [allowed(T0 + 4_500)]);

    const res = await api.app.request(`/v1/incidents/${first.id}`, { headers: bearer(adminA) });
    expect(res.status).toBe(200);
    const detail = IncidentDetailResponseSchema.parse(await res.json());
    expect(detail.incident).toEqual(first);
    expect(detail.detections).toHaveLength(1);
    expect(detail.detections[0]).toMatchObject({
      rule: "blocked-burst",
      app_id: appA,
      environment: "development",
      ip_prefix: PREFIX,
      count: THRESHOLD,
      window_start: first.first_seen,
      window_end: first.last_seen,
    });
    // 23 Events match; the newest 20 are returned.
    expect(detail.evidence).toHaveLength(INCIDENT_LIMITS.evidence);
    for (const event of detail.evidence) {
      expect(event.app_id).toBe(appA);
      expect(event.actor.ip_prefix).toBe(PREFIX);
      // Only Events that match the Incident's rule (F5).
      expect(event.decision).toMatchObject({ action: "block", mode: "enforce" });
      expect(Date.parse(event.ts)).toBeGreaterThanOrEqual(Date.parse(first.first_seen));
      expect(Date.parse(event.ts)).toBeLessThanOrEqual(Date.parse(first.last_seen));
    }
    const times = detail.evidence.map((event) => event.ts);
    expect(times).toEqual([...times].sort().reverse());
    expect(times[0]).toBe(first.last_seen);
  });

  it("answers 404 for an unknown or malformed Incident id", async () => {
    await expectProblem(await api.app.request(`/v1/incidents/${newId("inc")}`, { headers: bearer(adminA) }), 404);
    await expectProblem(await api.app.request("/v1/incidents/not-an-incident", { headers: bearer(adminA) }), 404);
    await expectProblem(
      await api.app.request(`/v1/incidents/${newId("inc")}`, patch({ status: "resolved" }, adminA)),
      404,
    );
  });

  describe("status transitions", () => {
    it("open → acknowledged → resolved, stamping updated_at; anything else is 409", async () => {
      clock.ms = T0 + 1_000_000;
      const ack = await api.app.request(`/v1/incidents/${first.id}`, patch({ status: "acknowledged" }, adminA));
      expect(ack.status).toBe(200);
      const acknowledged = IncidentSchema.parse(((await ack.json()) as { incident: unknown }).incident);
      expect(acknowledged).toEqual({ ...first, status: "acknowledged", updated_at: new Date(clock.ms).toISOString() });

      const again = await api.app.request(`/v1/incidents/${first.id}`, patch({ status: "acknowledged" }, adminA));
      const conflict = await expectProblem(again, 409);
      expect(conflict.type).toBe("https://antireverse.dev/problems/conflict");
      // A conflict without a named reason carries none.
      expect(conflict).not.toHaveProperty("reason");

      clock.ms += 1_000;
      const resolve = await api.app.request(`/v1/incidents/${first.id}`, patch({ status: "resolved" }, adminA));
      expect(resolve.status).toBe(200);
      expect(await resolve.json()).toEqual({
        incident: { ...first, status: "resolved", updated_at: new Date(clock.ms).toISOString() },
      });

      await expectProblem(
        await api.app.request(`/v1/incidents/${first.id}`, patch({ status: "acknowledged" }, adminA)),
        409,
      );
      await expectProblem(
        await api.app.request(`/v1/incidents/${first.id}`, patch({ status: "resolved" }, adminA)),
        409,
      );

      const detail = IncidentDetailResponseSchema.parse(
        await (await api.app.request(`/v1/incidents/${first.id}`, { headers: bearer(adminA) })).json(),
      );
      expect(detail.incident.status).toBe("resolved");
    });

    it("open → resolved directly", async () => {
      const res = await api.app.request(`/v1/incidents/${second.id}`, patch({ status: "resolved" }, adminA));
      expect(res.status).toBe(200);
      const filtered = await api.app.request("/v1/incidents?status=resolved", { headers: bearer(adminA) });
      expect(ListIncidentsResponseSchema.parse(await filtered.json()).incidents.map((i) => i.id)).toEqual([
        second.id,
        first.id,
      ]);
    });

    it("refuses a status that is not a transition target with 400", async () => {
      for (const body of [{ status: "open" }, { status: "closed" }, {}]) {
        const problem = await expectProblem(
          await api.app.request(`/v1/incidents/${third.id}`, patch(body, adminA)),
          400,
        );
        expect(problem.errors?.[0]?.path).toBe("status");
      }
    });
  });

  describe("tenancy and keys", () => {
    it("shows another Organization nothing, and lets it change nothing", async () => {
      const list = await api.app.request("/v1/incidents", { headers: bearer(adminB) });
      expect(await list.json()).toEqual({ incidents: [] });
      const filtered = await api.app.request(`/v1/incidents?app_id=${appA}`, { headers: bearer(adminB) });
      expect(await filtered.json()).toEqual({ incidents: [] });
      await expectProblem(await api.app.request(`/v1/incidents/${third.id}`, { headers: bearer(adminB) }), 404);
      await expectProblem(
        await api.app.request(`/v1/incidents/${third.id}`, patch({ status: "resolved" }, adminB)),
        404,
      );
      const detail = IncidentDetailResponseSchema.parse(
        await (await api.app.request(`/v1/incidents/${third.id}`, { headers: bearer(adminA) })).json(),
      );
      expect(detail.incident.status).toBe("open");
    });

    it("answers 403 to a Shield key and 401 without a key", async () => {
      await expectProblem(await api.app.request("/v1/incidents", { headers: bearer(shieldA) }), 403);
      await expectProblem(await api.app.request(`/v1/incidents/${third.id}`, { headers: bearer(shieldA) }), 403);
      await expectProblem(
        await api.app.request(`/v1/incidents/${third.id}`, patch({ status: "resolved" }, shieldA)),
        403,
      );
      await expectProblem(await api.app.request("/v1/incidents"), 401);
      await expectProblem(await api.app.request(`/v1/incidents/${third.id}`), 401);
    });
  });

  it("shows a failed sign-in Incident only its failed sign-ins as evidence, never an enforced block (F5, F6)", async () => {
    const fresh = await createAppFor(api, adminA, { name: "Sign-in evidence" });
    const prefix = "192.0.2.0/24";
    const base = T0 + 2_000_000;
    const signin = (ms: number): ShieldEvent => ({
      ...allowed(ms, prefix),
      request: { ...shieldEvent(ms).request, status: 401 },
    });
    clock.ms += 1_000;
    await ingest(fresh.shield_key.key, [
      ...Array.from({ length: DETECTION_RULES[1].threshold }, (_, i) => signin(base + i * 1_000)),
      // Inside the span, not failed sign-ins: a 200, and Shield's own enforced block answered 403.
      allowed(base + 28_500, prefix),
      { ...blocked(base + 28_600, prefix), request: { ...shieldEvent(base).request, status: 403 } },
    ]);
    const list = ListIncidentsResponseSchema.parse(
      await (await api.app.request(`/v1/incidents?app_id=${fresh.app.id}`, { headers: bearer(adminA) })).json(),
    );
    expect(list.incidents.map((incident) => incident.rule)).toEqual(["failed-signin-burst"]);
    const detail = IncidentDetailResponseSchema.parse(
      await (await api.app.request(`/v1/incidents/${list.incidents[0]?.id}`, { headers: bearer(adminA) })).json(),
    );
    expect(detail.evidence).toHaveLength(INCIDENT_LIMITS.evidence);
    for (const event of detail.evidence) {
      expect(event.request.status).toBe(401);
      expect(event.decision.mode === "enforce" && event.decision.action === "block").toBe(false);
    }
  });

  it("never logs a key", () => {
    expectNoKeyLogged(api);
  });
});
