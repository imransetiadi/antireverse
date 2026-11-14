import { type BuildManifest, DETECTION_RULES, EXAMPLE_BUILD_MANIFEST } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Queryable } from "../src/db/db.ts";
import { recordDetection } from "../src/stores/incidents.ts";
import { armBuild, findIntegrityBuilds } from "../src/stores/integrity.ts";
import { bearer, createAppFor, createOrganization, json, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 21a, migration 0038: what the database itself holds to — the arming column's grant, the definer lookup, the
// shape of a `tampered-build` Incident and Detection, and one active Incident per (App, Environment, Build).

const AT = new Date("2026-11-14T12:00:00.000Z");
const SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const TAMPER = DETECTION_RULES.find((rule) => rule.key === "tampered-build") ?? DETECTION_RULES[0];
const CLONE = DETECTION_RULES.find((rule) => rule.key === "clone-origin") ?? DETECTION_RULES[0];

describe("migration 0038: tamper detection in the database", () => {
  let api: TestApi;
  let organizationId: string;
  let otherOrganizationId: string;
  let admin: string;
  let appId: string;

  const scope = <T>(fn: (q: Queryable) => Promise<T>, organization = organizationId) =>
    api.db.tx({ organizationId: organization }, fn);
  const sqlState = async (work: Promise<unknown>): Promise<string | undefined> => {
    try {
      await work;
      return undefined;
    } catch (error) {
      return String((error as { code?: unknown }).code);
    }
  };

  async function build(files: string[] | null = ["b.js", "a.js"]): Promise<string> {
    const manifest: BuildManifest = {
      ...EXAMPLE_BUILD_MANIFEST,
      build_id: newId("bld"),
      app_id: appId,
      environment: "production",
      artifacts: [
        { path: "a.js", sha256: "a".repeat(64), bytes: 1 },
        { path: "b.js", sha256: "b".repeat(64), bytes: 2 },
        { path: "c.js", sha256: "c".repeat(64), bytes: 3 },
      ],
      ...(files === null ? {} : { integrity: { files } }),
    };
    const res = await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)));
    expect(res.status).toBe(201);
    return manifest.build_id;
  }

  const tamper = (buildId: string, path = "a.js", sha = SHA) =>
    scope((q) =>
      recordDetection(q, {
        organizationId,
        appId,
        environment: "production",
        rule: TAMPER,
        ipPrefix: "203.0.113.0/24",
        count: 1,
        windowStart: AT.toISOString(),
        windowEnd: AT.toISOString(),
        detectedAt: AT,
        tamper: { buildId, artifactPath: path, observedSha256: sha, origin: "https://shop.example" },
      }),
    );

  beforeAll(async () => {
    api = await makeTestApi();
    const org = await createOrganization(api, "Acme");
    organizationId = org.organization.id;
    admin = org.admin_key.key;
    appId = (await createAppFor(api, admin)).app.id;
    otherOrganizationId = (await createOrganization(api, "Other")).organization.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("the lookup needs no tenant and answers the marker's files in order with their digests, and nothing else", async () => {
    const buildId = await build();
    const find = (app: string, id: string) => api.db.tx("none", (q) => findIntegrityBuilds(q, app, id));
    const found = await find(appId, buildId);
    expect(found.organizationId).toBe(organizationId);
    expect(found.builds.find((one) => one.buildId === buildId)).toEqual({
      organizationId,
      appId,
      environment: "production",
      buildId,
      files: [
        { path: "b.js", sha256: "b".repeat(64) },
        { path: "a.js", sha256: "a".repeat(64) },
      ],
      armed: false,
    });
    const { rows } = await api.db.tx("none", (q) =>
      q.query<{ digests: Record<string, string> }>("SELECT * FROM integrity_lookup_builds($1, $2)", [appId, buildId]),
    );
    expect(Object.keys(rows[0] as object).sort()).toEqual([
      "build_id",
      "digests",
      "environment",
      "files",
      "first_match_at",
      "organization_id",
    ]);
    // Only the digests of the marker's own files leave the Manifest: c.js is an artifact, not a marker file.
    for (const row of rows) expect(Object.keys(row.digests).every((path) => path !== "c.js")).toBe(true);
    // An unknown Build of the App: the App's Organization and its recent Builds, not the named one.
    const ghost = newId("bld");
    const other = await find(appId, ghost);
    expect(other.organizationId).toBe(organizationId);
    expect(other.builds.some((one) => one.buildId === ghost)).toBe(false);
    expect(other.builds.some((one) => one.buildId === buildId)).toBe(true);
    // An unknown App answers nothing, whatever Build it names.
    expect(await find(newId("app"), buildId)).toEqual({ organizationId: null, builds: [] });
    const unmarked = await build(null);
    expect((await find(appId, unmarked)).builds.find((one) => one.buildId === unmarked)?.files).toEqual([]);
    // Without a tenant the table itself stays invisible: only the function answers.
    const direct = await api.db.tx("none", (q) =>
      q.query("SELECT build_id FROM builds WHERE build_id = $1", [buildId]),
    );
    expect(direct.rows).toEqual([]);
  });

  it("one lookup answers the named Build and the App's newest 20, however old the named one is", async () => {
    const created = await createAppFor(api, admin, { name: "Many builds" });
    const own = appId;
    appId = created.app.id;
    try {
      const ids: string[] = [];
      for (let n = 0; n < 23; n++) ids.push(await build());
      const found = await api.db.tx("none", (q) => findIntegrityBuilds(q, appId, ids[0] as string));
      const got = found.builds.map((one) => one.buildId);
      expect(got).toHaveLength(21);
      expect(got).toContain(ids[0]);
      // The two that are neither named nor among the newest 20 (Builds of one millisecond may swap places).
      expect(ids.slice(1, 6).filter((id) => !got.includes(id))).toHaveLength(2);
      for (const id of ids.slice(6)) expect(got).toContain(id);
    } finally {
      appId = own;
    }
  });

  it("arms a Build once, in its Organization's scope only", async () => {
    const buildId = await build();
    const target = { organizationId, appId, buildId };
    expect(await scope((q) => armBuild(q, target, AT), otherOrganizationId)).toBe("gone");
    expect(await api.db.tx("none", (q) => armBuild(q, target, AT))).toBe("gone");
    expect(await scope((q) => armBuild(q, target, AT))).toBe("armed");
    expect(await scope((q) => armBuild(q, target, new Date(AT.getTime() + 1000)))).toBe("already");
    const found = await api.db.tx("none", (q) => findIntegrityBuilds(q, appId, buildId));
    expect(found.builds.find((one) => one.buildId === buildId)?.armed).toBe(true);
    const { rows } = await scope((q) =>
      q.query<{ at: Date }>("SELECT integrity_first_match_at AS at FROM builds WHERE build_id = $1", [buildId]),
    );
    expect(rows[0]?.at.toISOString()).toBe(AT.toISOString());
  });

  it("F6: an armed Build can be neither disarmed nor re-dated, by the request role or the owner", async () => {
    const buildId = await build();
    expect(await scope((q) => armBuild(q, { organizationId, appId, buildId }, AT))).toBe("armed");
    const set = (value: string, run: typeof scope | typeof api.db.owner = scope) =>
      sqlState(
        (run as typeof scope)((q) =>
          q.query(`UPDATE builds SET integrity_first_match_at = ${value} WHERE build_id = $1`, [buildId]),
        ),
      );
    expect(await set("NULL")).toBe("23514");
    expect(await set("now()")).toBe("23514");
    expect(await set("integrity_first_match_at + interval '1 day'")).toBe("23514");
    expect(
      await sqlState(
        api.db.owner((q) =>
          q.query("UPDATE builds SET integrity_first_match_at = NULL WHERE build_id = $1", [buildId]),
        ),
      ),
    ).toBe("23514");
    // Setting it to what it is changes nothing and is let through.
    expect(await set("integrity_first_match_at")).toBeUndefined();
    const { rows } = await scope((q) =>
      q.query<{ at: Date }>("SELECT integrity_first_match_at AS at FROM builds WHERE build_id = $1", [buildId]),
    );
    expect(rows[0]?.at.toISOString()).toBe(AT.toISOString());
  });

  it("stores when an Incident's Detections were capped: the request role may set that column", async () => {
    const buildId = await build();
    const { incident } = await tamper(buildId);
    expect(incident.detections_capped).toBe(false);
    await scope((q) => q.query("UPDATE incidents SET capped_at = $2 WHERE id = $1", [incident.id, AT.toISOString()]));
    const again = await tamper(buildId, "b.js", "e".repeat(64));
    expect(again.incident).toMatchObject({ id: incident.id, detections_capped: true });
  });

  it("leaves a Build immutable otherwise: the request role may set the arming column and nothing else", async () => {
    const buildId = await build();
    const denied = "42501";
    expect(
      await sqlState(scope((q) => q.query("UPDATE builds SET version = 'x' WHERE build_id = $1", [buildId]))),
    ).toBe(denied);
    expect(
      await sqlState(scope((q) => q.query("UPDATE builds SET manifest = '{}'::jsonb WHERE build_id = $1", [buildId]))),
    ).toBe(denied);
    expect(await sqlState(scope((q) => q.query("DELETE FROM builds WHERE build_id = $1", [buildId])))).toBe(denied);
  });

  it("holds a tampered-build Detection and Incident to their shape", async () => {
    const buildId = await build();
    const { incident, detection, opened } = await tamper(buildId);
    expect(opened).toBe(true);
    expect(incident).toMatchObject({
      rule: "tampered-build",
      build_id: buildId,
      ip_prefix: null,
      origin: null,
      artifact_path: "a.js",
      observed_sha256: SHA,
    });
    expect(detection).toMatchObject({
      rule: "tampered-build",
      ip_prefix: "203.0.113.0/24",
      origin: "https://shop.example",
      artifact_path: "a.js",
      observed_sha256: SHA,
    });
    const check = "23514";
    // As the owner: the request role may not rewrite these columns at all.
    const set = (sql: string) => sqlState(api.db.owner((q) => q.query(sql, [incident.id])));
    expect(await set("UPDATE incidents SET build_id = NULL WHERE id = $1")).toBe(check);
    expect(await set("UPDATE incidents SET ip_prefix = '203.0.113.0/24' WHERE id = $1")).toBe(check);
    expect(await set("UPDATE incidents SET origin = 'https://shop.example' WHERE id = $1")).toBe(check);
    expect(await set("UPDATE detections SET artifact_path = NULL WHERE incident_id = $1")).toBe(check);
    expect(await set("UPDATE detections SET observed_sha256 = NULL WHERE incident_id = $1")).toBe(check);
    expect(await set("UPDATE detections SET origin = NULL WHERE incident_id = $1")).toBe(check);
    expect(await set("UPDATE detections SET observed_sha256 = 'ABC' WHERE incident_id = $1")).toBe(check);
    expect(await set("UPDATE detections SET artifact_path = '' WHERE incident_id = $1")).toBe(check);
    expect(await set("UPDATE detections SET rule = 'blocked-burst', origin = NULL WHERE incident_id = $1")).toBe(check);
    // The reporter's prefix may be unknown.
    expect(await set("UPDATE detections SET ip_prefix = NULL WHERE incident_id = $1")).toBeUndefined();
  });

  it("keeps one active Incident per Build for this rule, and leaves the other rules' groups as they were", async () => {
    const first = await build();
    const second = await build();
    const a = await tamper(first, "a.js");
    const b = await tamper(first, "b.js", "d".repeat(64));
    const c = await tamper(second, "a.js");
    expect(b.opened).toBe(false);
    expect(b.incident.id).toBe(a.incident.id);
    expect(b.incident).toMatchObject({ detection_count: 2, artifact_path: "a.js", observed_sha256: SHA });
    expect(c.opened).toBe(true);
    expect(c.incident.id).not.toBe(a.incident.id);
    // The index itself refuses a second active Incident of the Build.
    const duplicate = (buildId: string) =>
      sqlState(
        scope((q) =>
          q.query(
            `INSERT INTO incidents (id, organization_id, app_id, environment, rule, severity, title, status,
               first_seen, last_seen, detection_count, created_at, updated_at, build_id)
             VALUES ($1, $2, $3, 'production', 'tampered-build', 'high', 'Tampered Build', 'open', $4, $4, 1, $4, $4, $5)`,
            [newId("inc"), organizationId, appId, AT.toISOString(), buildId],
          ),
        ),
      );
    expect(await duplicate(first)).toBe("23505");
    expect(await duplicate(await build())).toBeUndefined();

    // A clone Incident is still one per origin, whichever Build reported it.
    const clone = (buildId: string) =>
      scope((q) =>
        recordDetection(q, {
          organizationId,
          appId,
          environment: "production",
          rule: CLONE,
          ipPrefix: null,
          count: 1,
          windowStart: AT.toISOString(),
          windowEnd: AT.toISOString(),
          detectedAt: AT,
          clone: { origin: "https://clone.example", buildId },
        }),
      );
    const one = await clone(first);
    const two = await clone(second);
    expect(two.opened).toBe(false);
    expect(two.incident.id).toBe(one.incident.id);
    expect(two.incident).toMatchObject({ build_id: first, artifact_path: null, observed_sha256: null });
    expect(two.detection).toMatchObject({ artifact_path: null, observed_sha256: null });
  });
});
