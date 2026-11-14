import {
  DETECTION_RULES,
  DetectionSchema,
  type Environment,
  EXAMPLE_SHIELD_EVENT,
  type Incident,
  IncidentSchema,
  type StoredEvent,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Db } from "../src/db/db.ts";
import { createDetector, type Detector } from "../src/detect/detector.ts";
import { matchingRules } from "../src/detect/rules.ts";
import { recordDetection } from "../src/stores/incidents.ts";
import {
  batchOf,
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
  uuidv7,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const PREFIX = "203.0.113.0/24";
const OTHER_PREFIX = "198.51.100.0/24";
const BLOCKED = DETECTION_RULES[0];
const SIGNIN = DETECTION_RULES[1];

interface Target {
  organizationId: string;
  appId: string;
  environment: Environment;
}

/** A stored Event of `target` at `ms` (its `ts`), from `prefix`, blocked in Enforce mode unless overridden. */
function event(target: Target, ms: number, overrides: Partial<StoredEvent> = {}, prefix: string | null = PREFIX) {
  return {
    ...EXAMPLE_SHIELD_EVENT,
    event_id: uuidv7(ms),
    ts: new Date(ms).toISOString(),
    decision: {
      action: "block",
      mode: "enforce",
      rule_id: "rul_0123456789abcdef01234567",
      policy_version: 1,
      containment_id: null,
      patch_id: null,
      patch_body: null,
    },
    actor: { ip_prefix: prefix, ip_hash: null },
    organization_id: target.organizationId,
    app_id: target.appId,
    environment: target.environment,
    received_at: new Date(ms).toISOString(),
    ...overrides,
  } satisfies StoredEvent;
}

const signin = (target: Target, ms: number, status = 401, prefix: string | null = PREFIX) =>
  event(
    target,
    ms,
    {
      request: { ...EXAMPLE_SHIELD_EVENT.request, status },
      decision: EXAMPLE_SHIELD_EVENT.decision,
    },
    prefix,
  );

interface OpenedCall {
  incident: Incident;
  organizationId: string;
}

function fakeNotifier() {
  const opened: OpenedCall[] = [];
  return {
    opened,
    incidentOpened: (incident: Incident, organizationId: string) => opened.push({ incident, organizationId }),
  };
}

async function detectionsOf(db: Db, organizationId: string) {
  const { rows } = await db.tx({ organizationId }, (q) =>
    q.query<{
      id: string;
      incident_id: string;
      rule: string;
      app_id: string;
      environment: string;
      ip_prefix: string;
      count: number;
      window_start: Date;
      window_end: Date;
      detected_at: Date;
    }>("SELECT * FROM detections ORDER BY detected_at, id"),
  );
  return rows;
}

async function incidentsOf(db: Db, organizationId: string) {
  const { rows } = await db.tx({ organizationId }, (q) =>
    q.query<{
      id: string;
      status: string;
      detection_count: number;
      first_seen: Date;
      last_seen: Date;
      rule: string;
      ip_prefix: string;
      app_id: string;
    }>("SELECT * FROM incidents ORDER BY created_at, id"),
  );
  return rows;
}

describe("managed rules", () => {
  const target: Target = {
    organizationId: "org_0123456789abcdef01234567",
    appId: "app_89abcdef0123456789abcdef",
    environment: "development",
  };

  it("counts a block in Enforce mode for blocked-burst only", () => {
    expect(matchingRules(event(target, T0)).map((rule) => rule.key)).toEqual(["blocked-burst"]);
    const monitored = event(target, T0, {
      decision: {
        action: "block",
        mode: "monitor",
        rule_id: null,
        policy_version: 1,
        containment_id: null,
        patch_id: null,
        patch_body: null,
      },
    });
    expect(matchingRules(monitored)).toEqual([]);
    const throttled = event(target, T0, {
      decision: {
        action: "throttle",
        mode: "enforce",
        rule_id: null,
        policy_version: 1,
        containment_id: null,
        patch_id: null,
        patch_body: null,
      },
    });
    expect(matchingRules(throttled)).toEqual([]);
  });

  it("counts a containment block (Shield enforcing a Containment) toward no rule", () => {
    const containmentBlock = event(target, T0, {
      request: { ...EXAMPLE_SHIELD_EVENT.request, status: 403 },
      decision: {
        action: "block",
        mode: "enforce",
        rule_id: null,
        policy_version: 1,
        containment_id: "cnt_0123456789abcdef01234567",
        patch_id: null,
        patch_body: null,
      },
    });
    expect(matchingRules(containmentBlock)).toEqual([]);
  });

  it("counts a 401 or 403 for failed-signin-burst", () => {
    expect(matchingRules(signin(target, T0, 401)).map((rule) => rule.key)).toEqual(["failed-signin-burst"]);
    expect(matchingRules(signin(target, T0, 403)).map((rule) => rule.key)).toEqual(["failed-signin-burst"]);
    expect(matchingRules(signin(target, T0, 404))).toEqual([]);
  });

  it("does not count Shield's own enforced block (answered 403) as a failed sign-in (F6)", () => {
    const enforced = event(target, T0, { request: { ...EXAMPLE_SHIELD_EVENT.request, status: 403 } });
    expect(matchingRules(enforced).map((rule) => rule.key)).toEqual(["blocked-burst"]);
    const enforced401 = event(target, T0, { request: { ...EXAMPLE_SHIELD_EVENT.request, status: 401 } });
    expect(matchingRules(enforced401).map((rule) => rule.key)).toEqual(["blocked-burst"]);
  });

  it("still counts a 403 under a block in Monitor mode as a failed sign-in: Shield did not answer it (F6)", () => {
    const monitored = event(target, T0, {
      request: { ...EXAMPLE_SHIELD_EVENT.request, status: 403 },
      decision: {
        action: "block",
        mode: "monitor",
        rule_id: null,
        policy_version: 1,
        containment_id: null,
        patch_id: null,
        patch_body: null,
      },
    });
    expect(matchingRules(monitored).map((rule) => rule.key)).toEqual(["failed-signin-burst"]);
  });
});

describe("detector", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let orgA: string;
  let orgB: string;
  let adminA: string;
  let shieldA: string;
  let appA: string;
  let appA2: string;
  let appB: string;

  beforeAll(async () => {
    api = await makeTestApi({ now });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    orgA = a.organization.id;
    orgB = b.organization.id;
    adminA = a.admin_key.key;
    const createdA = await createAppFor(api, adminA, { name: "Storefront" });
    appA = createdA.app.id;
    shieldA = createdA.shield_key.key;
    appA2 = (await createAppFor(api, adminA, { name: "Back office" })).app.id;
    appB = (await createAppFor(api, b.admin_key.key, { name: "Other" })).app.id;
  });
  afterAll(async () => {
    await api.close();
  });

  /** A detector on the test API's bus with a fresh fake notifier; stopped by the caller. */
  function detector(options: { maxKeys?: number; maxKeysPerOrg?: number; db?: Db; nowFn?: () => Date } = {}) {
    const notifier = fakeNotifier();
    const logger = captureLogger();
    const instance: Detector = createDetector({
      db: options.db ?? api.db,
      bus: api.bus,
      notifier,
      now: options.nowFn ?? now,
      logger,
      ...(options.maxKeys === undefined ? {} : { maxKeys: options.maxKeys }),
      ...(options.maxKeysPerOrg === undefined ? {} : { maxKeysPerOrg: options.maxKeysPerOrg }),
    });
    const stop = instance.start();
    return { instance, notifier, logger, stop };
  }

  /** Publishes `count` Events from `make(i)` at one-second steps of the clock. */
  function burst(count: number, make: (ms: number) => StoredEvent): void {
    for (let i = 0; i < count; i++) {
      clock.ms += 1_000;
      api.bus.publish(make(clock.ms));
    }
  }

  it("records exactly one Detection per threshold crossing, then starts counting again", async () => {
    // A fresh App so that this test's counts are its own.
    const appId = (await createAppFor(api, adminA, { name: "Crossing" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const { instance, notifier, stop } = detector();
    try {
      const start = clock.ms;
      burst(BLOCKED.threshold - 1, (ms) => event(target, ms));
      await instance.flush();
      expect((await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId)).toHaveLength(0);

      burst(1, (ms) => event(target, ms));
      await instance.flush();
      let detections = (await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId);
      expect(detections).toHaveLength(1);
      expect(detections[0]).toMatchObject({
        rule: "blocked-burst",
        environment: "development",
        ip_prefix: PREFIX,
        count: BLOCKED.threshold,
      });
      expect(detections[0]?.window_start.toISOString()).toBe(new Date(start + 1_000).toISOString());
      expect(detections[0]?.window_end.toISOString()).toBe(new Date(clock.ms).toISOString());
      expect(detections[0]?.detected_at.toISOString()).toBe(new Date(clock.ms).toISOString());

      // The window was cleared: 19 more Events cross nothing, the 20th crosses again.
      burst(BLOCKED.threshold - 1, (ms) => event(target, ms));
      await instance.flush();
      expect((await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId)).toHaveLength(1);
      burst(1, (ms) => event(target, ms));
      await instance.flush();
      detections = (await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId);
      expect(detections).toHaveLength(2);
      // Both crossings belong to one Incident, which alerted once.
      expect(new Set(detections.map((d) => d.incident_id)).size).toBe(1);
      expect(notifier.opened.filter((call) => call.incident.app_id === appId)).toHaveLength(1);
    } finally {
      stop();
    }
  });

  it("records SLO-05 per Detection: good when recorded within 10 s of its triggering Event's receipt (slice 18d)", async () => {
    const appId = (await createAppFor(api, adminA, { name: "Latency" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const recorded: [string, boolean, number][] = [];
    const instance = createDetector({
      db: api.db,
      bus: api.bus,
      notifier: fakeNotifier(),
      now,
      logger: captureLogger(),
      slo: { record: (id, good, ms) => recorded.push([id, good, ms]) },
    });
    const stop = instance.start();
    try {
      // The crossing Event was received 3 s before the Detector saw it: good. Events before it are not Detections.
      burst(BLOCKED.threshold - 1, (ms) => event(target, ms));
      burst(1, (ms) => event(target, ms, { received_at: new Date(ms - 3_000).toISOString() }));
      await instance.flush();
      // The next crossing's Event was received 11 s before: bad.
      burst(BLOCKED.threshold - 1, (ms) => event(target, ms));
      burst(1, (ms) => event(target, ms, { received_at: new Date(ms - 11_000).toISOString() }));
      await instance.flush();
      expect(recorded).toEqual([
        ["SLO-05", true, 3_000],
        ["SLO-05", false, 11_000],
      ]);
    } finally {
      stop();
    }
  });

  it("forgets Events older than the window", async () => {
    const appId = (await createAppFor(api, adminA, { name: "Window" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const { instance, stop } = detector();
    try {
      burst(BLOCKED.threshold - 1, (ms) => event(target, ms));
      // The window is 300 s: after it has passed, the 19 Events no longer count.
      clock.ms += BLOCKED.window_s * 1_000;
      burst(1, (ms) => event(target, ms));
      await instance.flush();
      expect((await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId)).toHaveLength(0);

      burst(BLOCKED.threshold - 2, (ms) => event(target, ms));
      await instance.flush();
      expect((await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId)).toHaveLength(0);
      burst(1, (ms) => event(target, ms));
      await instance.flush();
      expect((await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId)).toHaveLength(1);
    } finally {
      stop();
    }
  });

  it("never counts across Organization, App, Environment, rule or prefix", async () => {
    const appId = (await createAppFor(api, adminA, { name: "Isolation" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const { instance, stop } = detector();
    const before = (await detectionsOf(api.db, orgA)).length;
    const beforeB = (await detectionsOf(api.db, orgB)).length;
    try {
      // Ten each of six neighbouring keys: 60 Events, none of them 20 for one key.
      const half = BLOCKED.threshold / 2;
      burst(half, (ms) => event(target, ms));
      burst(half, (ms) => event({ ...target, appId: appA2 }, ms));
      burst(half, (ms) => event({ ...target, environment: "production" }, ms));
      burst(half, (ms) => event(target, ms, {}, OTHER_PREFIX));
      // Another Organization's Events, even ones naming this App, never count toward this one.
      burst(half, (ms) => event({ organizationId: orgB, appId: appB, environment: "development" }, ms));
      // The same prefix under the other rule.
      burst(half, (ms) => signin(target, ms));
      await instance.flush();
      expect((await detectionsOf(api.db, orgA)).length).toBe(before);
      expect((await detectionsOf(api.db, orgB)).length).toBe(beforeB);

      // The tenth of the original key's second half crosses it, and only it.
      burst(half, (ms) => event(target, ms));
      await instance.flush();
      const detections = (await detectionsOf(api.db, orgA)).slice(before);
      expect(detections).toHaveLength(1);
      expect(detections[0]).toMatchObject({ app_id: appId, environment: "development", ip_prefix: PREFIX });
    } finally {
      stop();
    }
  });

  it("opens only a blocked-burst Incident for 40 enforced blocks answered 403; app 401s still open a failed sign-in Incident (F6)", async () => {
    const appId = (await createAppFor(api, adminA, { name: "One attack" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const { instance, notifier, stop } = detector();
    try {
      burst(40, (ms) => event(target, ms, { request: { ...EXAMPLE_SHIELD_EVENT.request, status: 403 } }));
      await instance.flush();
      expect(notifier.opened.map((call) => call.incident.rule)).toEqual(["blocked-burst"]);
      const detections = (await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId);
      expect(detections.map((d) => d.rule)).toEqual(["blocked-burst", "blocked-burst"]);

      burst(SIGNIN.threshold, (ms) => signin(target, ms, 401));
      await instance.flush();
      expect(notifier.opened.map((call) => call.incident.rule)).toEqual(["blocked-burst", "failed-signin-burst"]);
    } finally {
      stop();
    }
  });

  it("detects failed sign-ins at their own threshold", async () => {
    const appId = (await createAppFor(api, adminA, { name: "Sign-in" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const { instance, notifier, stop } = detector();
    try {
      burst(SIGNIN.threshold - 1, (ms) => signin(target, ms, ms % 2 === 0 ? 401 : 403));
      await instance.flush();
      expect(notifier.opened).toHaveLength(0);
      burst(1, (ms) => signin(target, ms));
      await instance.flush();
      expect(notifier.opened).toHaveLength(1);
      expect(notifier.opened[0]?.incident).toMatchObject({
        rule: "failed-signin-burst",
        severity: "medium",
        title: "Failed sign-in burst",
      });
    } finally {
      stop();
    }
  });

  it("ignores Events without a network prefix", async () => {
    const appId = (await createAppFor(api, adminA, { name: "No prefix" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const { instance, notifier, stop } = detector();
    try {
      burst(BLOCKED.threshold * 2, (ms) => event(target, ms, {}, null));
      await instance.flush();
      expect(instance.trackedKeys()).toBe(0);
      expect(notifier.opened).toHaveLength(0);
      expect((await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId)).toHaveLength(0);
    } finally {
      stop();
    }
  });

  it("keeps at most maxKeys windows, evicting the least recently updated", async () => {
    const appId = (await createAppFor(api, adminA, { name: "Bounded" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const { instance, notifier, stop } = detector({ maxKeys: 2 });
    try {
      burst(BLOCKED.threshold - 1, (ms) => event(target, ms, {}, "192.0.2.0/24"));
      burst(1, (ms) => event(target, ms, {}, "198.51.100.0/24"));
      burst(1, (ms) => event(target, ms, {}, "203.0.113.0/24"));
      expect(instance.trackedKeys()).toBe(2);
      // The first key was the least recently updated: evicted, so its 20th Event starts a new count.
      burst(1, (ms) => event(target, ms, {}, "192.0.2.0/24"));
      await instance.flush();
      expect(notifier.opened).toHaveLength(0);
      expect(instance.trackedKeys()).toBe(2);
      // Many distinct prefixes never grow the map past its bound.
      for (let i = 0; i < 50; i++) burst(1, (ms) => event(target, ms, {}, `10.0.${i}.0/24`));
      expect(instance.trackedKeys()).toBe(2);
    } finally {
      stop();
    }
  });

  describe("bounds per Organization (F1)", () => {
    /** B counts 19 blocks, A floods distinct prefixes, then B's 20th block must still open B's Incident. */
    async function floodScenario(bounds: { maxKeys?: number; maxKeysPerOrg?: number }, victimPrefix: string) {
      const appA3 = (await createAppFor(api, adminA, { name: "Flooder" })).app.id;
      const flooder: Target = { organizationId: orgA, appId: appA3, environment: "development" };
      const victim: Target = { organizationId: orgB, appId: appB, environment: "staging" };
      const { instance, notifier, stop } = detector(bounds);
      try {
        burst(BLOCKED.threshold - 1, (ms) => event(victim, ms, {}, victimPrefix));
        for (let i = 0; i < 200; i++)
          burst(1, (ms) => event(flooder, ms, {}, `10.${Math.floor(i / 256)}.${i % 256}.0/24`));
        burst(1, (ms) => event(victim, ms, {}, victimPrefix));
        await instance.flush();
        expect(notifier.opened.map((call) => call.organizationId)).toEqual([orgB]);
        expect(notifier.opened[0]?.incident).toMatchObject({
          app_id: appB,
          environment: "staging",
          ip_prefix: victimPrefix,
        });
        return instance;
      } finally {
        stop();
      }
    }

    it("keeps another Organization's window when one Organization exceeds its own bound", async () => {
      await floodScenario({ maxKeys: 10, maxKeysPerOrg: 5 }, "192.0.2.0/24");
    });

    it("at the global bound, evicts from the Organization holding the most windows", async () => {
      await floodScenario({ maxKeys: 4, maxKeysPerOrg: 100 }, "192.0.3.0/24");
    });

    it("never holds more than maxKeysPerOrg windows for one Organization", async () => {
      const appId = (await createAppFor(api, adminA, { name: "Per-org bound" })).app.id;
      const target: Target = { organizationId: orgA, appId, environment: "development" };
      const { instance, stop } = detector({ maxKeys: 1_000, maxKeysPerOrg: 3 });
      try {
        for (let i = 0; i < 20; i++) burst(1, (ms) => event(target, ms, {}, `10.1.${i}.0/24`));
        expect(instance.trackedKeys()).toBe(3);
        burst(1, (ms) => event({ organizationId: orgB, appId: appB, environment: "development" }, ms));
        expect(instance.trackedKeys()).toBe(4);
      } finally {
        stop();
      }
    });
  });

  it("stops counting after stop()", async () => {
    const appId = (await createAppFor(api, adminA, { name: "Stopped" })).app.id;
    const target: Target = { organizationId: orgA, appId, environment: "development" };
    const { instance, notifier, stop } = detector();
    stop();
    stop();
    burst(BLOCKED.threshold, (ms) => event(target, ms));
    await instance.flush();
    expect(notifier.opened).toHaveLength(0);
    expect(instance.trackedKeys()).toBe(0);
  });

  describe("grouping", () => {
    it("joins repeated bursts into one Incident; acknowledged still groups without a new alert; after resolve a new Incident opens and alerts", async () => {
      const appId = (await createAppFor(api, adminA, { name: "Grouping" })).app.id;
      const target: Target = { organizationId: orgA, appId, environment: "development" };
      const { instance, notifier, stop } = detector();
      const mine = async () => (await incidentsOf(api.db, orgA)).filter((incident) => incident.app_id === appId);
      try {
        const firstStart = clock.ms + 1_000;
        burst(BLOCKED.threshold, (ms) => event(target, ms));
        await instance.flush();
        expect(notifier.opened).toHaveLength(1);
        const opened = notifier.opened[0];
        expect(opened?.organizationId).toBe(orgA);
        const incident = IncidentSchema.parse(opened?.incident);
        expect(incident).toMatchObject({
          app_id: appId,
          environment: "development",
          rule: "blocked-burst",
          severity: "high",
          title: "Blocked burst",
          status: "open",
          ip_prefix: PREFIX,
          detection_count: 1,
          first_seen: new Date(firstStart).toISOString(),
          last_seen: new Date(clock.ms).toISOString(),
        });

        // A second burst joins the open Incident and does not alert.
        burst(BLOCKED.threshold, (ms) => event(target, ms));
        await instance.flush();
        let incidents = await mine();
        expect(incidents).toHaveLength(1);
        expect(incidents[0]).toMatchObject({ id: incident.id, status: "open", detection_count: 2 });
        expect(incidents[0]?.first_seen.toISOString()).toBe(new Date(firstStart).toISOString());
        expect(incidents[0]?.last_seen.toISOString()).toBe(new Date(clock.ms).toISOString());
        expect(notifier.opened).toHaveLength(1);

        // Acknowledged still groups, and does not alert.
        const ack = await api.app.request(`/v1/incidents/${incident.id}`, {
          ...json({ status: "acknowledged" }, bearer(adminA)),
          method: "PATCH",
        });
        expect(ack.status).toBe(200);
        burst(BLOCKED.threshold, (ms) => event(target, ms));
        await instance.flush();
        incidents = await mine();
        expect(incidents).toHaveLength(1);
        expect(incidents[0]).toMatchObject({ status: "acknowledged", detection_count: 3 });
        expect(notifier.opened).toHaveLength(1);

        // A resolved Incident is never reopened: the next burst opens a new one, which alerts.
        const resolved = await api.app.request(`/v1/incidents/${incident.id}`, {
          ...json({ status: "resolved" }, bearer(adminA)),
          method: "PATCH",
        });
        expect(resolved.status).toBe(200);
        burst(BLOCKED.threshold, (ms) => event(target, ms));
        await instance.flush();
        incidents = await mine();
        expect(incidents).toHaveLength(2);
        expect(incidents[0]).toMatchObject({ id: incident.id, status: "resolved", detection_count: 3 });
        expect(incidents[1]).toMatchObject({ status: "open", detection_count: 1 });
        expect(notifier.opened).toHaveLength(2);
        expect(notifier.opened[1]?.incident.id).toBe(incidents[1]?.id);

        // Every Detection belongs to its Incident and parses as the protocol's Detection.
        const detections = (await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId);
        expect(detections.map((d) => d.incident_id)).toEqual([incident.id, incident.id, incident.id, incidents[1]?.id]);
        for (const d of detections) {
          DetectionSchema.parse({
            ...d,
            window_start: d.window_start.toISOString(),
            window_end: d.window_end.toISOString(),
            detected_at: d.detected_at.toISOString(),
          });
        }
      } finally {
        stop();
      }
    });

    it("keeps separate Incidents for separate prefixes and rules", async () => {
      const appId = (await createAppFor(api, adminA, { name: "Separate" })).app.id;
      const target: Target = { organizationId: orgA, appId, environment: "development" };
      const { instance, notifier, stop } = detector();
      try {
        burst(BLOCKED.threshold, (ms) => event(target, ms));
        burst(BLOCKED.threshold, (ms) => event(target, ms, {}, OTHER_PREFIX));
        burst(SIGNIN.threshold, (ms) => signin(target, ms));
        await instance.flush();
        expect(notifier.opened).toHaveLength(3);
        expect((await incidentsOf(api.db, orgA)).filter((incident) => incident.app_id === appId)).toHaveLength(3);
      } finally {
        stop();
      }
    });
  });

  describe("failures", () => {
    it("never fails ingest: a database error in the detector is logged without data and swallowed", async () => {
      const failing: Db = {
        tx: () => Promise.reject(new Error(`detector store failed for ${PREFIX}`)),
        close: () => Promise.resolve(),
      };
      const { instance, logger, notifier, stop } = detector({ db: failing });
      try {
        const events = Array.from({ length: BLOCKED.threshold }, (_, i) => ({
          ...shieldEvent(T0 + i),
          decision: {
            action: "block",
            mode: "enforce",
            rule_id: null,
            policy_version: 1,
            containment_id: null,
            patch_id: null,
            patch_body: null,
          },
        }));
        const res = await api.app.request("/v1/events", json(batchOf(events), bearer(shieldA)));
        expect(res.status).toBe(202);
        expect(await res.json()).toEqual({ accepted: BLOCKED.threshold, duplicates: 0 });
        await instance.flush();
        expect(notifier.opened).toHaveLength(0);
        expect(logger.lines.some((line) => line.startsWith("detector failed"))).toBe(true);
        for (const line of logger.lines) {
          expect(line).not.toContain(PREFIX);
          expect(line).not.toContain(appA);
          expect(line).not.toContain("detector store failed");
        }
      } finally {
        stop();
      }
    });

    it("never fails ingest when the detector itself throws, and logs that it did", async () => {
      const { logger, stop } = detector({
        nowFn: () => {
          throw new Error(`clock failed for ${PREFIX}`);
        },
      });
      try {
        const events = [
          {
            ...shieldEvent(T0 + 500),
            decision: {
              action: "block",
              mode: "enforce",
              rule_id: null,
              policy_version: 1,
              containment_id: null,
              patch_id: null,
              patch_body: null,
            },
          },
        ];
        const res = await api.app.request("/v1/events", json(batchOf(events), bearer(shieldA)));
        expect(res.status).toBe(202);
        expect(logger.lines.some((line) => line.startsWith("detector failed"))).toBe(true);
        for (const line of logger.lines) expect(line).not.toContain(PREFIX);
      } finally {
        stop();
      }
    });

    it("keeps the Detection when the notifier throws, and logs that it did", async () => {
      const appId = (await createAppFor(api, adminA, { name: "Notifier throws" })).app.id;
      const target: Target = { organizationId: orgA, appId, environment: "development" };
      const logger = captureLogger();
      const instance = createDetector({
        db: api.db,
        bus: api.bus,
        notifier: {
          incidentOpened: () => {
            throw new Error("notifier failed");
          },
        },
        now,
        logger,
      });
      const stop = instance.start();
      try {
        burst(BLOCKED.threshold, (ms) => event(target, ms));
        await instance.flush();
        expect((await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId)).toHaveLength(1);
        expect(logger.lines.some((line) => line.startsWith("detector failed"))).toBe(true);
      } finally {
        stop();
      }
    });
    describe("race on the one-active-Incident index", () => {
      /** A unique violation as PostgreSQL reports it (SQL state 23505). */
      const uniqueViolation = () =>
        Object.assign(new Error("duplicate key value violates unique constraint"), { code: "23505" });

      it("retries once when another writer opened the group's Incident first: the Detection joins it, no second alert", async () => {
        const appId = (await createAppFor(api, adminA, { name: "Race won elsewhere" })).app.id;
        const target: Target = { organizationId: orgA, appId, environment: "development" };
        let calls = 0;
        // The first transaction loses the race: the competing writer commits its Incident in between, and ours
        // fails on the unique index. Every later transaction runs normally.
        const racing: Db = {
          tx: async (scope, fn) => {
            calls++;
            if (calls === 1) {
              const ts = new Date(clock.ms).toISOString();
              await api.db.tx({ organizationId: orgA }, (q) =>
                recordDetection(q, {
                  organizationId: orgA,
                  appId,
                  environment: "development",
                  rule: BLOCKED,
                  ipPrefix: PREFIX,
                  count: BLOCKED.threshold,
                  windowStart: ts,
                  windowEnd: ts,
                  detectedAt: now(),
                }),
              );
              throw uniqueViolation();
            }
            return api.db.tx(scope, fn);
          },
          close: () => Promise.resolve(),
        };
        const { instance, notifier, logger, stop } = detector({ db: racing });
        try {
          burst(BLOCKED.threshold, (ms) => event(target, ms));
          await instance.flush();
          expect(calls).toBe(2);
          const incidents = (await incidentsOf(api.db, orgA)).filter((incident) => incident.app_id === appId);
          expect(incidents).toHaveLength(1);
          expect(incidents[0]).toMatchObject({ status: "open", detection_count: 2 });
          const detections = (await detectionsOf(api.db, orgA)).filter((d) => d.app_id === appId);
          expect(detections.map((d) => d.incident_id)).toEqual([incidents[0]?.id, incidents[0]?.id]);
          // The winner alerted for the Incident it opened; the joining Detection alerts nobody.
          expect(notifier.opened).toHaveLength(0);
          expect(logger.lines.filter((line) => line.startsWith("detector failed"))).toEqual([]);
        } finally {
          stop();
        }
      });

      it("drops the Detection after a second unique violation, logging without data", async () => {
        const appId = (await createAppFor(api, adminA, { name: "Race lost twice" })).app.id;
        const target: Target = { organizationId: orgA, appId, environment: "development" };
        let calls = 0;
        const failing: Db = {
          tx: async () => {
            calls++;
            throw Object.assign(uniqueViolation(), { message: `duplicate key for ${PREFIX}` });
          },
          close: () => Promise.resolve(),
        };
        const { instance, notifier, logger, stop } = detector({ db: failing });
        try {
          burst(BLOCKED.threshold, (ms) => event(target, ms));
          await instance.flush();
          expect(calls).toBe(2);
          expect(notifier.opened).toHaveLength(0);
          expect(logger.lines.filter((line) => line.startsWith("detector failed"))).toHaveLength(1);
          for (const line of logger.lines) {
            expect(line).not.toContain(PREFIX);
            expect(line).not.toContain(appId);
          }
        } finally {
          stop();
        }
      });

      it("does not retry an error that is not a unique violation", async () => {
        let calls = 0;
        const failing: Db = {
          tx: async () => {
            calls++;
            throw Object.assign(new Error("connection lost"), { code: "08006" });
          },
          close: () => Promise.resolve(),
        };
        const appId = (await createAppFor(api, adminA, { name: "Other error" })).app.id;
        const { instance, stop } = detector({ db: failing });
        try {
          burst(BLOCKED.threshold, (ms) => event({ organizationId: orgA, appId, environment: "development" }, ms));
          await instance.flush();
          expect(calls).toBe(1);
        } finally {
          stop();
        }
      });
    });
  });
});
