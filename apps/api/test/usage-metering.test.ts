import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AttestResponseSchema, ChallengeResponseSchema, UsageResponseSchema } from "@antireverse/protocol";
import { jwkThumbprint } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createRetentionJob } from "../src/data/retention.ts";
import { type RunningApi, startApi } from "../src/server.ts";
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
} from "./helpers.ts";

vi.setConfig({ testTimeout: 30_000, hookTimeout: 30_000 });

// Slice 17a: what is metered, through the API. Requests at ingest (newly stored Events only, in the insert's
// transaction, per App, Environment and UTC day of receipt, exact after retention removes the Events); Guard devices
// at `POST /v1/attest` (a failure to record never fails the attestation).

const T0 = Date.parse("2026-11-14T09:00:00.000Z");
const DAY = 86_400_000;

describe("usage metering", () => {
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let api: TestApi;
  let organizationId = "";
  let admin = "";
  let appId = "";
  let shield = "";
  let stagingAppId = "";
  let stagingShield = "";

  const daily = () =>
    api.db.owner(async (q) => {
      const { rows } = await q.query<{ app_id: string; environment: string; day: string; requests: number }>(
        `SELECT app_id, environment, to_char(day, 'YYYY-MM-DD') AS day, requests::int AS requests
         FROM usage_daily WHERE organization_id = $1 AND requests > 0 ORDER BY app_id, environment, day`,
        [organizationId],
      );
      return rows;
    });
  const total = async () => (await daily()).reduce((sum, row) => sum + row.requests, 0);
  const ingest = (events: unknown[], key = shield) => api.app.request("/v1/events", json(batchOf(events), bearer(key)));

  beforeAll(async () => {
    api = await makeTestApi({ now, clientAddress: (c) => c.req.header("x-test-address") });
    const created = await createOrganization(api, "Acme");
    organizationId = created.organization.id;
    admin = created.admin_key.key;
    const app = await createAppFor(api, admin);
    appId = app.app.id;
    shield = app.shield_key.key;
    const staging = await createAppFor(api, admin, { name: "Back office", environment: "staging" });
    stagingAppId = staging.app.id;
    stagingShield = staging.shield_key.key;
  });
  afterAll(async () => {
    await api.close();
  });

  describe("requests", () => {
    it("counts the Events newly stored, per App, Environment and UTC day of receipt", async () => {
      const events = Array.from({ length: 5 }, (_, i) => shieldEvent(T0 + i));
      expect((await ingest(events)).status).toBe(202);
      expect((await ingest([shieldEvent(T0 + 10), shieldEvent(T0 + 11)], stagingShield)).status).toBe(202);
      clock.ms = Date.parse("2026-11-15T00:00:00.000Z");
      expect((await ingest([shieldEvent(clock.ms)])).status).toBe(202);
      expect(await daily()).toEqual(
        [
          { app_id: appId, environment: "development", day: "2026-11-14", requests: 5 },
          { app_id: appId, environment: "development", day: "2026-11-15", requests: 1 },
          { app_id: stagingAppId, environment: "staging", day: "2026-11-14", requests: 2 },
        ].sort((a, b) => (a.app_id < b.app_id ? -1 : a.app_id > b.app_id ? 1 : 0)),
      );
    });

    it("adds nothing for a batch sent again, and only the new Events of a batch that repeats some", async () => {
      const before = await total();
      const events = Array.from({ length: 4 }, (_, i) => shieldEvent(T0 + 100 + i));
      expect((await ingest(events)).status).toBe(202);
      expect(await total()).toBe(before + 4);
      const again = await ingest(events);
      expect(await again.json()).toEqual({ accepted: 0, duplicates: 4 });
      expect(await total()).toBe(before + 4);
      // Two old, one new, and the new one twice inside the batch.
      const fresh = shieldEvent(T0 + 200);
      const mixed = await ingest([events[0], events[1], fresh, fresh]);
      expect(await mixed.json()).toEqual({ accepted: 1, duplicates: 3 });
      expect(await total()).toBe(before + 5);
    });

    it("stays exact after the retention job removes the Events it counted", async () => {
      const before = await total();
      const stored = await api.db.owner(async (q) => {
        const { rows } = await q.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM events WHERE organization_id = $1",
          [organizationId],
        );
        return rows[0]?.n ?? 0;
      });
      expect(stored).toBe(before);
      clock.ms = T0 + 40 * DAY;
      const job = createRetentionJob({ db: api.db, now, logger: captureLogger() });
      expect((await job.runOnce()).rows.events).toBe(before);
      expect(await total()).toBe(before);
    });
  });

  describe("Guard devices", () => {
    let address = 0;
    /** A caller address in its own /24, so that no test spends the prefix budget of another call. */
    const freshAddress = () => `10.${Math.floor(++address / 250)}.${address % 250}.1`;
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const { x, y } = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    const jwk = { kty: "EC" as const, crv: "P-256" as const, x, y };

    async function attest(device: string, app = appId, signals: string[] = [], on = api): Promise<Response> {
      const from = freshAddress();
      const headers = { "x-test-address": from };
      const challenged = await on.app.request("/v1/attest/challenge", json({ app_id: app }, headers));
      const { nonce } = ChallengeResponseSchema.parse(await challenged.json());
      return on.app.request(
        "/v1/attest",
        json({ app_id: app, nonce, device, signals, cnf: { jkt: jwkThumbprint(jwk), jwk } }, headers),
      );
    }
    const randomDevice = () => randomBytes(16).toString("base64url");
    const devices = () =>
      api.db.owner(async (q) => {
        const { rows } = await q.query<{ app_id: string; month: string; n: number }>(
          `SELECT app_id, to_char(month, 'YYYY-MM') AS month, count(*)::int AS n FROM usage_devices
           WHERE organization_id = $1 GROUP BY app_id, month ORDER BY app_id, month`,
          [organizationId],
        );
        return rows;
      });

    it("counts each device once per App and UTC month at POST /v1/attest", async () => {
      clock.ms = T0;
      const a = "AAECAwQFBgcICQoLDA0ODw";
      const b = "BBECAwQFBgcICQoLDA0ODw";
      for (const device of [a, a, b]) {
        const res = await attest(device);
        expect(res.status).toBe(200);
        AttestResponseSchema.parse(await res.json());
      }
      expect((await attest(a, stagingAppId)).status).toBe(200);
      clock.ms = Date.parse("2026-12-01T00:00:00.000Z");
      expect((await attest(a)).status).toBe(200);
      expect(await devices()).toEqual(
        [
          { app_id: appId, month: "2026-11", n: 2 },
          { app_id: appId, month: "2026-12", n: 1 },
          { app_id: stagingAppId, month: "2026-11", n: 1 },
        ].sort((p, q) => (p.app_id < q.app_id ? -1 : p.app_id > q.app_id ? 1 : p.month < q.month ? -1 : 1)),
      );
    });

    it("answers the token when recording fails, and logs only the kind of error", async () => {
      clock.ms = T0;
      const before = api.logger.lines.length;
      await api.db.owner((q) =>
        q.query("REVOKE EXECUTE ON FUNCTION usage_record_device(text, bytea, timestamptz, integer) FROM ar_app"),
      );
      try {
        const res = await attest("CCECAwQFBgcICQoLDA0ODw");
        expect(res.status).toBe(200);
        AttestResponseSchema.parse(await res.json());
      } finally {
        await api.db.owner((q) =>
          q.query("GRANT EXECUTE ON FUNCTION usage_record_device(text, bytea, timestamptz, integer) TO ar_app"),
        );
      }
      const lines = api.logger.lines.slice(before).filter((line) => line.includes("usage"));
      expect(lines).toEqual(["usage device record error error sqlstate=42501"]);
      expect(lines.join("\n")).not.toContain(appId);
    });

    it("counts trusted and suspect attestations, not hostile ones; the token is issued either way", async () => {
      clock.ms = Date.parse("2026-11-16T10:00:00.000Z");
      const count = async () =>
        (await devices()).find((row) => row.app_id === stagingAppId && row.month === "2026-11")?.n ?? 0;
      const before = await count();
      for (let i = 0; i < 100; i++) {
        const signals = i % 2 === 0 ? [] : ["automation.webdriver"];
        expect((await attest(randomDevice(), stagingAppId, signals)).status).toBe(200);
      }
      expect(await count()).toBe(before + 100);
      for (let i = 0; i < 5; i++) {
        const res = await attest(randomDevice(), stagingAppId, ["automation.webdriver", "automation.headless"]);
        expect(res.status).toBe(200);
        AttestResponseSchema.parse(await res.json());
      }
      expect(await count()).toBe(before + 100);
    });

    it("stops recording at the daily cap per App, flags the month, and still issues the token", async () => {
      const capped = await makeTestApi({
        now,
        clientAddress: (c) => c.req.header("x-test-address"),
        usageDeviceDailyCap: 3,
      });
      try {
        clock.ms = T0;
        const org = await createOrganization(capped, "Capped");
        const app = (await createAppFor(capped, org.admin_key.key)).app.id;
        for (let i = 0; i < 5; i++) {
          const res = await attest(randomDevice(), app, [], capped);
          expect(res.status).toBe(200);
          AttestResponseSchema.parse(await res.json());
        }
        const usage = UsageResponseSchema.parse(
          await (await capped.app.request("/v1/usage", { headers: bearer(org.admin_key.key) })).json(),
        );
        expect(usage.totals.guard_devices).toBe(3);
        expect(usage.totals.guard_devices_capped).toBe(true);
        expect(usage.apps[0]?.guard_devices_capped).toBe(true);
      } finally {
        await capped.close();
      }
    });
  });
});

describe("usage salts across restarts (review M3)", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-usage-restart-"));
  const dataDir = join(root, "data");
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let address = 0;
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const jwk = { kty: "EC" as const, crv: "P-256" as const, x, y };
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const start = () =>
    startApi({
      dataDir,
      now,
      logger: { info() {}, warn() {} },
      smtp: null,
      retention: { firstRunMs: 3_600_000 },
      purge: { firstRunMs: 3_600_000 },
    });
  async function attest(api: RunningApi, app: string, device: string): Promise<void> {
    const headers = { "content-type": "application/json", "x-test-address": `203.0.${++address}.1` };
    const challenged = await fetch(`${api.url}/v1/attest/challenge`, {
      method: "POST",
      headers,
      body: JSON.stringify({ app_id: app }),
    });
    const { nonce } = ChallengeResponseSchema.parse(await challenged.json());
    const res = await fetch(`${api.url}/v1/attest`, {
      method: "POST",
      headers,
      body: JSON.stringify({ app_id: app, nonce, device, signals: [], cnf: { jkt: jwkThumbprint(jwk), jwk } }),
    });
    expect(res.status).toBe(200);
  }
  const guardDevices = async (api: RunningApi, key: string, month = "2026-11") =>
    UsageResponseSchema.parse(
      await (await fetch(`${api.url}/v1/usage?month=${month}`, { headers: bearer(key) })).json(),
    ).totals.guard_devices;
  /** Every file under `dir`, with its bytes. */
  const files = (dir: string): [string, Buffer][] =>
    readdirSync(dir, { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => {
        const path = join(entry.parentPath, entry.name);
        return [path, readFileSync(path)] as [string, Buffer];
      });

  it("keeps a month's count across a restart (the salt reloaded from its file), and never writes a salt to the database", async () => {
    let api = await start();
    const created = await (
      await fetch(`${api.url}/v1/organizations`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Restart" }),
      })
    ).json();
    const key = (created as { admin_key: { key: string } }).admin_key.key;
    const appRes = await fetch(`${api.url}/v1/apps`, {
      method: "POST",
      headers: { "content-type": "application/json", ...bearer(key) },
      body: JSON.stringify({ name: "Shop" }),
    });
    const app = ((await appRes.json()) as { app: { id: string } }).app.id;
    await attest(api, app, "AAECAwQFBgcICQoLDA0ODw");
    expect(await guardDevices(api, key)).toBe(1);
    await api.close();

    const saltFile = join(root, "usage-salts.json");
    const salts = (JSON.parse(readFileSync(saltFile, "utf8")) as { salts: Record<string, string> }).salts;
    const salt = Buffer.from(salts["2026-11"] ?? "", "base64url");
    expect(salt.length).toBe(32);

    api = await start();
    await attest(api, app, "AAECAwQFBgcICQoLDA0ODw");
    await attest(api, app, "BBECAwQFBgcICQoLDA0ODw");
    expect(await guardDevices(api, key)).toBe(2);

    // December: the rollup closes November and its salt goes from the file.
    clock.ms = Date.parse("2026-12-02T00:00:00.000Z");
    await api.retention.runOnce();
    expect(await guardDevices(api, key)).toBe(2);
    expect(Object.keys((JSON.parse(readFileSync(saltFile, "utf8")) as { salts: object }).salts)).toEqual([]);
    await api.close();

    // The salt's bytes, in any encoding, are nowhere in the database's files.
    const needles = [salt, Buffer.from(salt.toString("base64url")), Buffer.from(salt.toString("hex"))];
    const found = files(dataDir).filter(([, bytes]) => needles.some((needle) => bytes.includes(needle)));
    expect(found.map(([path]) => path)).toEqual([]);
  }, 60_000);
});
