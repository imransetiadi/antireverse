import {
  type BuildManifest,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_SHIELD_EVENT,
  type StoredEvent,
} from "@antireverse/protocol";
import { deriveBeaconToken, generateVerificationToken, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPurgeJob } from "../src/data/purge.ts";
import { type OwnedDb, openDb, type Queryable } from "../src/db/db.ts";
import { type BeaconRecorder, createBeaconRecorder } from "../src/detect/beacon.ts";
import { createDetector } from "../src/detect/detector.ts";
import type { ProveNetwork } from "../src/prove/deps.ts";
import { createRecheckJob } from "../src/prove/recheck.ts";
import { createSigner } from "../src/signer.ts";
import { insertTarget } from "../src/stores/targets.ts";
import { artifactFor, type FakeAssessor, fakeAssessor } from "./fake-assessor.ts";
import {
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  json,
  makeTestApi,
  sseReader,
  type TestApi,
  uuidv7,
  within,
  withReason,
} from "./helpers.ts";

// Slice 18b review: what runs outside a request while an Organization's deletion is pending or after its purge — the
// Assessment runner, the Prove re-check, live streams, the Clone Beacon (kept open by D-082), the purge job's backlog
// and the in-memory state the purge must evict.

const T0 = Date.parse("2026-11-13T09:00:00.000Z");
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const PEER_HEADER = "x-test-peer";

async function organization(api: TestApi, name: string) {
  const created = await createOrganization(api, name);
  return { organizationId: created.organization.id, admin: created.admin_key.key, name };
}

async function requestDeletion(api: TestApi, org: { admin: string; name: string }) {
  const res = await api.app.request(
    "/v1/organization/deletion",
    json({ confirm_name: org.name }, withReason(bearer(org.admin))),
  );
  expect(res.status, await res.clone().text()).toBe(201);
}

describe("Assessment runner during a pending deletion", () => {
  let api: TestApi;
  let assessor: FakeAssessor;
  beforeAll(async () => {
    assessor = fakeAssessor();
    api = await makeTestApi({ now: () => new Date(T0), assessor });
  });
  afterAll(async () => {
    await api.close();
  });

  it("does not start a queued Assessment of the Organization; it stays queued", async () => {
    const org = await organization(api, "Acme");
    const appId = (await createAppFor(api, org.admin)).app.id;
    const { manifest, files } = artifactFor(appId);
    const post = (path: string, body: unknown) => api.app.request(path, json(body, bearer(org.admin)));
    expect((await post(`/v1/apps/${appId}/builds`, { manifest })).status).toBe(201);
    const path = `/v1/apps/${appId}/builds/${manifest.build_id}/assessments`;
    expect((await post(path, { tier: "T1", files })).status).toBe(202);
    const first = await within(assessor.run(0), 5000, "the first run");
    expect((await post(path, { tier: "T1", files })).status).toBe(202); // queued behind the first

    await requestDeletion(api, org);
    first.reject(new Error("engine stopped"));
    const second = await within(assessor.run(1), 1500, "a second run").then(
      () => "started",
      () => "not started",
    );
    expect(second).toBe("not started");
    expect(assessor.runs).toHaveLength(1);
    const statuses = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ status: string }>(
        "SELECT status FROM assessments WHERE organization_id = $1 ORDER BY created_at, id",
        [org.organizationId],
      );
      return rows.map((row) => row.status).sort();
    });
    expect(statuses).toEqual(["failed", "queued"]);
  });
});

describe("Prove re-check during a pending deletion", () => {
  it("probes no target of an Organization pending deletion", async () => {
    const now = () => new Date(T0 + 2 * DAY);
    const api = await makeTestApi({ now });
    try {
      const probed: string[] = [];
      const network: ProveNetwork = {
        resolver: {
          txt: async (name) => {
            probed.push(name);
            throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
          },
          addresses: async () => [],
        },
        fetcher: async (host) => {
          probed.push(host);
          return { ok: false, reason: "status" };
        },
      };
      const verified = async (org: { organizationId: string }, host: string) => {
        const id = newId("tgt");
        await api.db.tx({ organizationId: org.organizationId }, (q) =>
          insertTarget(q, {
            organizationId: org.organizationId,
            id,
            host,
            token: generateVerificationToken(),
            createdAt: new Date(T0),
          }),
        );
        await api.db.owner((q) =>
          q.query(
            "UPDATE targets SET status = 'verified', method = 'dns', verified_at = $2, last_checked_at = $2 WHERE id = $1",
            [id, new Date(T0)],
          ),
        );
      };
      const pending = await organization(api, "Pending");
      const live = await organization(api, "Live");
      await verified(pending, "pending.acme-shop.io");
      await verified(live, "live.acme-shop.io");
      await requestDeletion(api, pending);
      const counts = await createRecheckJob({ db: api.db, network, now, logger: captureLogger() }).runOnce();
      expect(counts.due).toBe(1);
      expect(probed.some((name) => name.includes("pending.acme-shop.io"))).toBe(false);
      expect(probed.some((name) => name.includes("live.acme-shop.io"))).toBe(true);
    } finally {
      await api.close();
    }
  });
});

describe("live Event stream across a deletion", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const signer = createSigner();
  beforeAll(async () => {
    api = await makeTestApi({ now, heartbeatMs: 20, auditSigner: signer });
  });
  afterAll(async () => {
    await api.close();
  });

  async function open(admin: string, appId: string) {
    const res = await api.app.request(`/v1/apps/${appId}/events/stream`, { headers: bearer(admin) });
    expect(res.status).toBe(200);
    const sse = sseReader(res.body as ReadableStream<Uint8Array>);
    expect(await within(sse.next(), 2000, "connected")).toBe(": connected");
    return sse;
  }
  /** Frames until the stream ends; "closed" once it has. */
  async function untilClosed(sse: ReturnType<typeof sseReader>): Promise<string> {
    for (let i = 0; i < 50; i++) {
      const frame = await within(sse.next(), 2000, "a frame").catch((error: Error) => `closed: ${error.message}`);
      if (frame.startsWith("closed")) return frame;
    }
    return "still open";
  }

  it("ends the stream and unsubscribes at the first heartbeat after a deletion request", async () => {
    const org = await organization(api, "Acme");
    const appId = (await createAppFor(api, org.admin)).app.id;
    const sse = await open(org.admin, appId);
    expect(api.bus.count(org.organizationId)).toBe(1);
    await requestDeletion(api, org);
    expect(await untilClosed(sse)).toBe("closed: The stream ended.");
    expect(api.bus.count(org.organizationId)).toBe(0);
  });

  it("ends the stream of a key that no longer exists after the purge", async () => {
    const org = await organization(api, "Bravo");
    const appId = (await createAppFor(api, org.admin)).app.id;
    // Opened before the request; requested and purged before the next heartbeat check can run.
    const sse = await open(org.admin, appId);
    await requestDeletion(api, org);
    clock.ms += 7 * DAY + 1;
    // (The first test's Organization is due too.)
    expect(await createPurgeJob({ db: api.db, signer, now, logger: captureLogger() }).runOnce()).toMatchObject({
      failed: 0,
    });
    expect(await api.app.request("/v1/organization", { headers: bearer(org.admin) })).toHaveProperty("status", 401);
    expect(await untilClosed(sse)).toBe("closed: The stream ended.");
    expect(api.bus.count(org.organizationId)).toBe(0);
  });

  it("keeps the stream of a live Organization open", async () => {
    const org = await organization(api, "Charlie");
    const appId = (await createAppFor(api, org.admin)).app.id;
    const sse = await open(org.admin, appId);
    expect(await within(sse.next(), 2000, "a heartbeat")).toBe(": heartbeat");
    expect(await within(sse.next(), 2000, "a heartbeat")).toBe(": heartbeat");
    await sse.cancel();
  });
});

describe("Clone Beacon during a pending deletion (kept open, D-082) and after the purge", () => {
  let api: TestApi;
  let recorder: BeaconRecorder;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const signer = createSigner();
  const opened: string[] = [];

  beforeAll(async () => {
    const db = await openDb();
    recorder = createBeaconRecorder({
      db,
      notifier: { incidentOpened: (_incident, organizationId) => opened.push(organizationId) },
      now,
      logger: captureLogger(),
    });
    api = await makeTestApi({ db, now, beacon: recorder, clientAddress: (c) => c.req.header(PEER_HEADER) });
  });
  afterAll(async () => {
    await api.close();
  });

  const report = (appId: string, token: string, origin: string) =>
    api.app.request("/v1/beacon", {
      method: "POST",
      headers: { "content-type": "text/plain", origin, [PEER_HEADER]: "203.0.113.77" },
      body: JSON.stringify({ a: appId, t: token, o: origin }),
    });

  it("still records a clone Incident while pending; the purge removes it and forgets the cached token", async () => {
    const org = await organization(api, "Acme");
    const appId = (await createAppFor(api, org.admin)).app.id;
    const token = deriveBeaconToken(1, { appId, version: "1.0.1" });
    const manifest: BuildManifest = {
      ...EXAMPLE_BUILD_MANIFEST,
      build_id: newId("bld"),
      app_id: appId,
      environment: "production",
      version: "1.0.1",
      beacon: { token, origins: ["https://shop.example"] },
    };
    expect((await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(org.admin)))).status).toBe(201);
    await requestDeletion(api, org);
    const incidents = () =>
      api.db.owner(async (q) => {
        const { rows } = await q.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM incidents WHERE organization_id = $1",
          [org.organizationId],
        );
        return rows[0]?.n ?? 0;
      });
    // The decided behaviour (D-082): the public beacon stays open while the deletion is pending.
    expect((await report(appId, token, "https://clone.example")).status).toBe(204);
    await recorder.flush();
    expect(await incidents()).toBe(1);
    expect(opened).toEqual([org.organizationId]);
    expect(recorder.trackedBuilds()).toBe(1);

    clock.ms += 7 * DAY + 1;
    const purged: string[] = [];
    const job = createPurgeJob({
      db: api.db,
      signer,
      now,
      logger: captureLogger(),
      onPurged: (organizationId) => {
        purged.push(organizationId);
        recorder.forget(organizationId);
      },
    });
    expect(await job.runOnce()).toMatchObject({ purged: 1 });
    expect(purged).toEqual([org.organizationId]);
    expect(await incidents()).toBe(0);
    // Evicted: no limits kept for its Builds, and its token is looked up again (and is unknown now).
    expect(recorder.trackedBuilds()).toBe(0);
    const before = recorder.dropped()["unknown-token"];
    clock.ms += 2 * HOUR;
    expect((await report(appId, token, "https://other-clone.example")).status).toBe(204);
    await recorder.flush();
    expect(recorder.dropped()["unknown-token"]).toBe(before + 1);
    expect(recorder.dropped().failed).toBe(0);
  });
});

describe("Detector after a purge", () => {
  it("forgets the windows of a purged Organization", async () => {
    const api = await makeTestApi({ now: () => new Date(T0) });
    try {
      const org = await organization(api, "Acme");
      const other = await organization(api, "Bravo");
      const appA = (await createAppFor(api, org.admin)).app.id;
      const appB = (await createAppFor(api, other.admin)).app.id;
      const detector = createDetector({
        db: api.db,
        bus: api.bus,
        notifier: { incidentOpened: () => {} },
        now: () => new Date(T0),
        logger: captureLogger(),
      });
      const stop = detector.start();
      try {
        const blocked = (organizationId: string, appId: string): StoredEvent => ({
          ...EXAMPLE_SHIELD_EVENT,
          event_id: uuidv7(T0),
          ts: new Date(T0).toISOString(),
          decision: { ...EXAMPLE_SHIELD_EVENT.decision, action: "block", mode: "enforce", policy_version: 1 },
          actor: { ip_prefix: "203.0.113.0/24", ip_hash: null },
          organization_id: organizationId,
          app_id: appId,
          environment: "development",
          received_at: new Date(T0).toISOString(),
        });
        api.bus.publish(blocked(org.organizationId, appA));
        api.bus.publish(blocked(other.organizationId, appB));
        await detector.flush();
        expect(detector.trackedKeys()).toBe(2);
        detector.forget(org.organizationId);
        expect(detector.trackedKeys()).toBe(1);
      } finally {
        stop();
      }
    } finally {
      await api.close();
    }
  });
});

describe("purge backlog", () => {
  it("records failures and lets later deletions through instead of retrying the failing ones first", async () => {
    const clock = { ms: T0 };
    const now = () => new Date(clock.ms);
    const failing = new Set<string>();
    const inner = await openDb();
    const wrap = (q: Queryable): Queryable => ({
      async query(sql, params) {
        if (sql.includes("organization_purge(") && failing.has(String(params?.[0]))) {
          throw Object.assign(new Error("injected"), { name: "InjectedPurgeError" });
        }
        return q.query(sql, params) as never;
      },
    });
    const db: OwnedDb = {
      tx: (scope, fn) => inner.tx(scope, fn),
      owner: (fn) => inner.owner((q) => fn(wrap(q))),
      close: () => inner.close(),
    };
    const api = await makeTestApi({ db, now });
    try {
      const bad = [];
      for (const name of ["F1", "F2", "F3"]) {
        const org = await organization(api, name);
        failing.add(org.organizationId);
        await requestDeletion(api, org);
        bad.push(org);
        clock.ms += 1_000;
      }
      const good = await organization(api, "Good");
      await requestDeletion(api, good);
      clock.ms += 7 * DAY + HOUR;
      const purged: string[] = [];
      const job = createPurgeJob({
        db,
        signer: createSigner(),
        now,
        logger: captureLogger(),
        batchMax: 2,
        onPurged: (organizationId) => purged.push(organizationId),
      });
      expect(await job.runOnce()).toEqual({ due: 2, purged: 0, failed: 2 });
      // The two that just failed wait an hour; the next two are taken.
      expect(await job.runOnce()).toEqual({ due: 2, purged: 1, failed: 1 });
      expect(purged).toEqual([good.organizationId]);
      const state = await api.db.owner(async (q) => {
        const { rows } = await q.query<{
          organization_id: string;
          purge_attempts: number;
          last_failed_at: Date | null;
        }>(
          "SELECT organization_id, purge_attempts, last_failed_at FROM organization_deletions WHERE purged_at IS NULL",
        );
        return Object.fromEntries(rows.map((row) => [row.organization_id, row]));
      });
      for (const org of bad) {
        expect(state[org.organizationId]?.purge_attempts).toBe(1);
        expect(state[org.organizationId]?.last_failed_at).toBeInstanceOf(Date);
      }
      // Nothing due within the hour; after it, the failed ones are retried.
      expect(await job.runOnce()).toEqual({ due: 0, purged: 0, failed: 0 });
      clock.ms += HOUR;
      failing.clear();
      expect(await job.runOnce()).toEqual({ due: 2, purged: 2, failed: 0 });
      expect(await job.runOnce()).toEqual({ due: 1, purged: 1, failed: 0 });
    } finally {
      await api.close();
    }
  });
});
