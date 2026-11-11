import { readFileSync } from "node:fs";
import {
  type AdvisoryInput,
  type BuildManifest,
  BuildResponseSchema,
  type Component,
  EXAMPLE_BUILD_MANIFEST,
  EXPOSURE_LIMITS,
  type Finding,
  FindingDetailResponseSchema,
  FindingResponseSchema,
  type Incident,
  IncidentSchema,
  ListFindingsResponseSchema,
  ListIncidentsResponseSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { componentsDigest, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { rematchAll } from "../src/exposure/match.ts";
import { type AlertFetch, createNotifier, type Notifier } from "../src/notify/notifier.ts";
import { insertChannel } from "../src/stores/alert-channels.ts";
import { FIXTURE_ADVISORIES_FILE, fixtureSource } from "../src/vulns/source.ts";
import { syncAdvisories } from "../src/vulns/sync.ts";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
  tick,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-11T09:00:00.000Z");
const DAY = 86_400_000;
const FIXTURES = JSON.parse(readFileSync(FIXTURE_ADVISORIES_FILE, "utf8")) as AdvisoryInput[];

const c = (name: string, version: string, dev = false): Component => ({ name, version, dev });

/** A Manifest for `appId` with a fresh Build id that summarises `components` (count and digest). */
function manifestFor(appId: string, components?: Component[], overrides: Partial<BuildManifest> = {}): BuildManifest {
  return {
    ...EXAMPLE_BUILD_MANIFEST,
    build_id: newId("bld"),
    app_id: appId,
    environment: "production",
    ...(components === undefined
      ? {}
      : { component_count: components.length, components_digest: componentsDigest(components) }),
    ...overrides,
  };
}

describe("Findings", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let adminA: string;
  let adminB: string;
  let shieldA: string;
  let shieldB: string;
  let orgA: string;
  let appA: string;
  let appB: string;
  const opened: Incident[] = [];
  /** Bodies the alert transport was asked to send. */
  const sent: string[] = [];
  let realNotifier: Notifier;

  beforeAll(async () => {
    const holder: { notifier?: Notifier } = {};
    const fetch: AlertFetch = async (_url, init) => {
      sent.push(init.body);
      return { status: 200, body: null };
    };
    const notifier: Notifier = {
      incidentOpened: (incident, organizationId) => {
        opened.push(incident);
        holder.notifier?.incidentOpened(incident, organizationId);
      },
      test: (channelId, organizationId) => (holder.notifier as Notifier).test(channelId, organizationId),
      drain: () => (holder.notifier as Notifier).drain(),
    };
    api = await makeTestApi({ now, notifier });
    realNotifier = createNotifier({
      db: api.db,
      now,
      fetch,
      resolve: async () => [{ address: "127.0.0.1", family: 4 }],
      allowPrivate: true,
      logger: api.logger,
    });
    holder.notifier = realNotifier;
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    orgA = a.organization.id;
    const createdA = await createAppFor(api, adminA, { name: "Storefront", environment: "production" });
    appA = createdA.app.id;
    shieldA = createdA.shield_key.key;
    const createdB = await createAppFor(api, adminB, { name: "Other", environment: "production" });
    appB = createdB.app.id;
    shieldB = createdB.shield_key.key;
    await syncAdvisories(api.db, fixtureSource(FIXTURES));
  });
  afterAll(async () => {
    await realNotifier.drain();
    // Privacy: no package name or version of any inventory reached a log line, and no key either.
    for (const line of api.logger.lines) expect(line).not.toMatch(/vuln-|VulnCaps|fixture\/|safe-pkg|GHSA-/);
    expectNoKeyLogged(api);
    await api.close();
  });

  function register(adminKey: string, appId: string, manifest: BuildManifest, components?: Component[]) {
    return Promise.resolve(
      api.app.request(
        `/v1/apps/${appId}/builds`,
        json(components === undefined ? { manifest } : { manifest, components }, bearer(adminKey)),
      ),
    );
  }

  function postInventory(key: string, body: unknown) {
    return Promise.resolve(api.app.request("/v1/inventory", json(body, bearer(key))));
  }

  async function list(adminKey: string, query = ""): Promise<Finding[]> {
    const res = await api.app.request(`/v1/findings${query}`, { headers: bearer(adminKey) });
    expect(res.status).toBe(200);
    return ListFindingsResponseSchema.parse(await res.json()).findings;
  }

  async function incidents(adminKey: string): Promise<Incident[]> {
    // Incidents are written after the response (second review L-C): wait for the queue, never sleep.
    await api.flushIncidents();
    const res = await api.app.request("/v1/incidents", { headers: bearer(adminKey) });
    expect(res.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await res.json()).incidents;
  }

  describe("POST /v1/inventory", () => {
    it("stores a runtime inventory for the key's App Environment, matches it and answers 202 {}", async () => {
      clock.ms = T0;
      const res = await postInventory(shieldA, { components: [c("vuln-last", "1.2.0"), c("safe-pkg", "1.0.0")] });
      expect(res.status).toBe(202);
      expect(await res.json()).toEqual({});
      const findings = await list(adminA, `?app_id=${appA}&source=runtime`);
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        app_id: appA,
        environment: "production",
        source: "runtime",
        build_id: null,
        package: "vuln-last",
        version: "1.2.0",
        advisory_id: "GHSA-fx01-0002-last",
        aliases: ["CVE-2026-90002"],
        severity: "medium",
        fixed_versions: [],
        status: "open",
        ignore: null,
        first_seen: new Date(T0).toISOString(),
      });
    });

    it("refuses an admin key with 403 and no key with 401", async () => {
      await expectProblem(await postInventory(adminA, { components: [] }), 403);
      await expectProblem(await api.app.request("/v1/inventory", json({ components: [] })), 401);
    });

    it("refuses an invalid inventory with 400", async () => {
      await expectProblem(
        await postInventory(shieldA, { components: [{ name: "x", version: "latest", dev: false }] }),
        400,
      );
      await expectProblem(await postInventory(shieldA, { components: [c("a", "1.0.0"), c("a", "1.0.0")] }), 400);
      await expectProblem(await postInventory(shieldA, {}), 400);
    });

    it("refuses a body larger than 2 MB with 413", async () => {
      const big = JSON.stringify({ components: [], pad: "x".repeat(EXPOSURE_LIMITS.componentsBytesMax) });
      const res = await api.app.request("/v1/inventory", {
        method: "POST",
        headers: { "content-type": "application/json", ...bearer(shieldA) },
        body: big,
      });
      const problem = await expectProblem(res, 413);
      expect(problem.detail).toContain(String(EXPOSURE_LIMITS.componentsBytesMax));
    });

    it("accepts a body near the 2 MB cap (beyond the default 256 KB)", async () => {
      const components = Array.from({ length: 4_000 }, (_, i) => c(`pkg-${i}-${"n".repeat(150)}`, "1.0.0"));
      const res = await postInventory(shieldB, { components });
      expect(res.status).toBe(202);
    });

    it("marks the runtime Finding fixed when the next inventory lacks the version", async () => {
      clock.ms = T0 + 1_000;
      expect((await postInventory(shieldA, { components: [c("vuln-last", "1.6.0")] })).status).toBe(202);
      const findings = await list(adminA, `?app_id=${appA}&source=runtime`);
      expect(findings.map((f) => f.status)).toEqual(["fixed"]);
    });
  });

  describe("Build registration with components", () => {
    let firstBuild: string;

    it("registers without components as before: no findings member", async () => {
      const res = await register(adminA, appA, manifestFor(appA));
      expect(res.status).toBe(201);
      const body = BuildResponseSchema.parse(await res.json());
      expect(body.findings).toBeUndefined();
    });

    it("stores the build inventory, matches it and answers the summary of this Build's open Findings", async () => {
      clock.ms = T0 + 10_000;
      const components = [
        c("vuln-range", "1.1.0"),
        c("@fixture/vuln-scoped", "4.0.0"),
        c("vuln-explicit", "3.0.0", true),
        c("vuln-unknown", "1.0.0"),
        c("safe-pkg", "2.0.0"),
      ];
      const manifest = manifestFor(appA, components);
      firstBuild = manifest.build_id;
      const res = await register(adminA, appA, manifest, components);
      expect(res.status).toBe(201);
      const raw = (await res.json()) as Record<string, unknown>;
      expect(JSON.stringify(raw)).not.toContain("safe-pkg");
      const body = BuildResponseSchema.parse(raw);
      expect(body.build).not.toHaveProperty("components");
      expect(body.build.component_count).toBe(5);
      expect(body.findings).toEqual({
        open: { critical: 1, high: 1, medium: 1, low: 1, unknown: 1 },
        items: [
          {
            advisory: "GHSA-fx01-0005-scop",
            package: "@fixture/vuln-scoped",
            version: "4.0.0",
            severity: "critical",
            fixed: ["5.0.0"],
          },
          {
            advisory: "GHSA-fx01-0001-rang",
            package: "vuln-range",
            version: "1.1.0",
            severity: "high",
            fixed: ["1.2.4", "2.1.1"],
          },
          {
            advisory: "GHSA-fx01-0009-medi",
            package: "vuln-range",
            version: "1.1.0",
            severity: "medium",
            fixed: ["1.2.0"],
          },
          { advisory: "GHSA-fx01-0003-expl", package: "vuln-explicit", version: "3.0.0", severity: "low", fixed: [] },
          {
            advisory: "GHSA-fx01-0007-unkn",
            package: "vuln-unknown",
            version: "1.0.0",
            severity: "unknown",
            fixed: [],
          },
        ],
      });
      const findings = await list(adminA, `?build_id=${firstBuild}`);
      expect(findings).toHaveLength(5);
      expect(findings.every((f) => f.source === "build" && f.build_id === firstBuild)).toBe(true);
      expect(findings.find((f) => f.package === "vuln-explicit")?.dev).toBe(true);
    });

    it("opens one vulnerable-component Incident per Critical or High advisory, none for medium, low or unknown", async () => {
      const own = (await incidents(adminA)).filter((i) => i.rule === "vulnerable-component");
      expect(own.map((i) => [i.advisory_id, i.severity]).sort()).toEqual([
        ["GHSA-fx01-0001-rang", "high"],
        ["GHSA-fx01-0005-scop", "critical"],
      ]);
      for (const incident of own) {
        expect(incident).toMatchObject({
          title: "Vulnerable component",
          status: "open",
          ip_prefix: null,
          origin: null,
          canary_id: null,
          build_id: firstBuild,
          environment: "production",
          app_id: appA,
        });
      }
      expect(opened.filter((i) => i.rule === "vulnerable-component")).toHaveLength(2);
      const detail = await api.app.request(`/v1/incidents/${own[0]?.id}`, { headers: bearer(adminA) });
      expect(detail.status).toBe(200);
    });

    it("sends the alert with the advisory id in the payload", async () => {
      await api.db.tx({ organizationId: orgA }, (q) =>
        insertChannel(q, {
          id: newId("chn"),
          organizationId: orgA,
          kind: "webhook",
          name: "hook",
          url: "http://hooks.test/ar",
          signingSecret: `whsec_${"A".repeat(43)}`,
        }),
      );
      clock.ms = T0 + 15_000;
      // A new advisory group: a pre-release of vuln-pre (High).
      const components = [c("vuln-pre", "2.0.0-rc.1")];
      const res = await register(adminA, appA, manifestFor(appA, components, { environment: "staging" }), components);
      expect(res.status).toBe(201);
      for (let i = 0; i < 100 && sent.length === 0; i++) await tick(10);
      const payload = WebhookAlertPayloadSchema.parse(JSON.parse(sent[0] ?? "null"));
      expect(payload.type).toBe("incident.opened");
      expect(IncidentSchema.parse(payload.incident)).toMatchObject({
        rule: "vulnerable-component",
        advisory_id: "GHSA-fx01-0008-prer",
        severity: "high",
        environment: "staging",
      });
    });

    it("does not open a second Incident for an advisory whose Incident is still open (another Build, the runtime)", async () => {
      clock.ms = T0 + 20_000;
      const before = (await incidents(adminA)).filter((i) => i.rule === "vulnerable-component");
      const openedBefore = opened.length;
      const components = [c("vuln-range", "1.1.0"), c("@fixture/vuln-scoped", "4.0.0"), c("vuln-unknown", "1.0.0")];
      const res = await register(adminA, appA, manifestFor(appA, components), components);
      expect(res.status).toBe(201);
      expect((await postInventory(shieldA, { components: [c("vuln-range", "2.0.0")] })).status).toBe(202);
      const after = (await incidents(adminA)).filter((i) => i.rule === "vulnerable-component");
      expect(after.map((i) => i.id).sort()).toEqual(before.map((i) => i.id).sort());
      expect(opened.length).toBe(openedBefore);
      const range = after.find((i) => i.advisory_id === "GHSA-fx01-0001-rang");
      // A7 (M2): the second Build ships what the first did, so it opens nothing; the runtime Finding is new: 2.
      expect(range?.detection_count).toBe(2);
    });

    it("marks an older Build's open Findings fixed when a newer Build of the App Environment no longer has the version", async () => {
      clock.ms = T0 + 30_000;
      const components = [c("vuln-range", "2.1.1"), c("@fixture/vuln-scoped", "5.0.0"), c("vuln-unknown", "1.0.0")];
      const manifest = manifestFor(appA, components);
      const res = await register(adminA, appA, manifest, components);
      const body = BuildResponseSchema.parse(await res.json());
      expect(body.findings?.open).toEqual({ critical: 0, high: 0, medium: 0, low: 0, unknown: 1 });
      // Second review M-A: an identity a newer Build carries moves to it, so every build Finding of the App
      // Environment is on the Build where it ended (fixed) or on the newest one (open), one row per identity.
      const all = (await list(adminA, `?app_id=${appA}&environment=production&source=build`)).filter(
        (f) => f.package !== "safe-pkg" && !f.package.startsWith("pkg-"),
      );
      const status = Object.fromEntries(
        all.map((f) => [`${f.package} ${f.advisory_id}`, [f.status, f.build_id === manifest.build_id]]),
      );
      expect(status).toEqual({
        "@fixture/vuln-scoped GHSA-fx01-0005-scop": ["fixed", false],
        "vuln-range GHSA-fx01-0001-rang": ["fixed", false],
        "vuln-range GHSA-fx01-0009-medi": ["fixed", false],
        "vuln-explicit GHSA-fx01-0003-expl": ["fixed", false],
        // Still shipped by the newer Build: open, and now on it.
        "vuln-unknown GHSA-fx01-0007-unkn": ["open", true],
      });
      expect((await list(adminA, `?build_id=${firstBuild}`)).map((f) => [f.package, f.status])).toEqual([
        ["vuln-explicit", "fixed"],
      ]);
    });

    it("keeps another Environment's build Findings as they are", async () => {
      const staging = await list(adminA, `?app_id=${appA}&environment=staging`);
      expect(staging.map((f) => f.status)).toEqual(["open"]);
    });

    it("refuses components whose digest differs from the Manifest's with 400", async () => {
      const components = [c("vuln-range", "1.1.0")];
      const manifest = manifestFor(appA, [c("vuln-range", "1.2.4")]);
      const problem = await expectProblem(await register(adminA, appA, manifest, components), 400);
      expect(problem.errors?.[0]?.path).toBe("manifest.components_digest");
    });

    it("refuses components whose count differs from the Manifest's with 400", async () => {
      const components = [c("vuln-range", "1.1.0")];
      const manifest = manifestFor(appA, components, { component_count: 2 });
      await expectProblem(await register(adminA, appA, manifest, components), 400);
    });

    it("refuses components without a digest or count in the Manifest with 400", async () => {
      const components = [c("vuln-range", "1.1.0")];
      const manifest = manifestFor(appA);
      const problem = await expectProblem(await register(adminA, appA, manifest, components), 400);
      expect(problem.errors?.map((e) => e.path)).toContain("manifest.components_digest");
    });

    it("stores nothing when the registration is refused", async () => {
      const components = [c("vuln-pre", "1.0.0")];
      const manifest = manifestFor(appA, [c("vuln-pre", "1.0.1")]);
      await expectProblem(await register(adminA, appA, manifest, components), 400);
      const findings = await list(adminA, `?build_id=${manifest.build_id}`);
      expect(findings).toEqual([]);
    });

    it("accepts components beyond the default body limit, and refuses a component list over 2 MB with 413", async () => {
      const many = Array.from({ length: 2_000 }, (_, i) => c(`pkg-${i}-${"n".repeat(150)}`, "1.0.0"));
      const ok = await register(adminA, appA, manifestFor(appA, many), many);
      expect(ok.status).toBe(201);
      const huge = Array.from({ length: 5_000 }, (_, i) =>
        c(`pkg-${i}-${"n".repeat(200)}`, `1.0.0-${"r".repeat(240)}`),
      );
      expect(Buffer.byteLength(JSON.stringify(huge))).toBeGreaterThan(EXPOSURE_LIMITS.componentsBytesMax);
      await expectProblem(await register(adminA, appA, manifestFor(appA, huge), huge), 413);
    });
  });

  describe("GET /v1/findings and /v1/findings/:id", () => {
    it("lists newest first, filtered, and within the Organization only", async () => {
      const all = await list(adminA);
      expect(all.length).toBeGreaterThan(5);
      const seen = all.map((f) => f.last_seen);
      expect([...seen].sort().reverse()).toEqual(seen);
      expect((await list(adminA, "?severity=critical")).every((f) => f.severity === "critical")).toBe(true);
      expect((await list(adminA, "?status=fixed")).every((f) => f.status === "fixed")).toBe(true);
      expect((await list(adminA, "?source=build")).every((f) => f.source === "build")).toBe(true);
      expect((await list(adminA, "?environment=staging")).every((f) => f.environment === "staging")).toBe(true);
      expect(await list(adminB, `?app_id=${appA}`)).toEqual([]);
      expect((await list(adminB)).every((f) => f.app_id === appB)).toBe(true);
    });

    it("filters by advisory id or any alias, exactly, combined with the other filters", async () => {
      const byId = await list(adminA, "?advisory_id=GHSA-fx01-0001-rang");
      expect(byId.length).toBeGreaterThan(0);
      expect(byId.every((f) => f.advisory_id === "GHSA-fx01-0001-rang")).toBe(true);
      const byAlias = await list(adminA, "?advisory_id=CVE-2026-90001");
      expect(byAlias.map((f) => f.id).sort()).toEqual(byId.map((f) => f.id).sort());
      const combined = await list(adminA, "?advisory_id=CVE-2026-90001&source=runtime");
      expect(combined.length).toBeGreaterThan(0);
      expect(combined.every((f) => f.source === "runtime" && f.advisory_id === "GHSA-fx01-0001-rang")).toBe(true);
      // Exact only: a prefix of an alias matches nothing.
      expect(await list(adminA, "?advisory_id=CVE-2026-9000")).toEqual([]);
      expect(await list(adminB, "?advisory_id=CVE-2026-90001")).toEqual([]);
    });

    it("filters by Build: build Findings of that Build only; another Organization's Build gives an empty list", async () => {
      const [build] = await list(adminA, "?source=build&severity=critical");
      if (build?.build_id == null) throw new Error("No build Finding.");
      const own = await list(adminA, `?build_id=${build.build_id}`);
      expect(own.length).toBeGreaterThan(0);
      expect(own.every((f) => f.source === "build" && f.build_id === build.build_id)).toBe(true);
      expect(await list(adminA, `?build_id=${build.build_id}&source=runtime`)).toEqual([]);
      expect(await list(adminB, `?build_id=${build.build_id}`)).toEqual([]);
    });

    it("refuses invalid filters with 400 and a Shield key with 403", async () => {
      for (const query of [
        "?severity=severe",
        "?status=gone",
        "?source=disk",
        "?app_id=nope",
        "?environment=prod",
        "?advisory_id=not%20an%20id",
        "?advisory_id=",
        "?build_id=bld_nope",
      ]) {
        await expectProblem(await api.app.request(`/v1/findings${query}`, { headers: bearer(adminA) }), 400);
      }
      await expectProblem(await api.app.request("/v1/findings", { headers: bearer(shieldA) }), 403);
    });

    it("answers one Finding with its advisory; 404 for another Organization's or a malformed id", async () => {
      const [first] = await list(adminA, "?severity=critical");
      if (first === undefined) throw new Error("No critical Finding.");
      const res = await api.app.request(`/v1/findings/${first.id}`, { headers: bearer(adminA) });
      expect(res.status).toBe(200);
      const detail = FindingDetailResponseSchema.parse(await res.json());
      expect(detail.finding.id).toBe(first.id);
      expect(detail.advisory.id).toBe(first.advisory_id);
      expect(detail.advisory.affected[0]?.package.name).toBe(first.package);
      await expectProblem(await api.app.request(`/v1/findings/${first.id}`, { headers: bearer(adminB) }), 404);
      await expectProblem(await api.app.request("/v1/findings/fnd_nope", { headers: bearer(adminA) }), 404);
      await expectProblem(await api.app.request(`/v1/findings/${newId("fnd")}`, { headers: bearer(adminA) }), 404);
      await expectProblem(await api.app.request(`/v1/findings/${first.id}`, { headers: bearer(shieldA) }), 403);
    });
  });

  describe("ignore and reopen", () => {
    let target: Finding;
    const ignore = (key: string, id: string, body: unknown) =>
      Promise.resolve(api.app.request(`/v1/findings/${id}/ignore`, json(body, bearer(key))));
    const reopen = (key: string, id: string) =>
      Promise.resolve(api.app.request(`/v1/findings/${id}/reopen`, json({}, bearer(key))));

    beforeAll(async () => {
      const [found] = await list(adminA, "?environment=staging&status=open");
      if (found === undefined) throw new Error("No open Finding.");
      target = found;
    });

    it("ignores an open Finding with a reason and an expiry at most 90 days ahead", async () => {
      clock.ms = T0 + DAY;
      const until = new Date(clock.ms + 30 * DAY).toISOString();
      const res = await ignore(adminA, target.id, { reason: "  Not reachable from user input  ", until });
      expect(res.status).toBe(200);
      const { finding } = FindingResponseSchema.parse(await res.json());
      expect(finding.status).toBe("ignored");
      expect(finding.ignore?.reason).toBe("Not reachable from user input");
      expect(finding.ignore?.until).toBe(until);
      expect(finding.ignore?.by).toMatch(/^key_/);
    });

    it("refuses an expiry in the past or more than 90 days ahead, and an empty reason, with 400", async () => {
      const past = new Date(clock.ms - 1_000).toISOString();
      const far = new Date(clock.ms + 90 * DAY + 60_000).toISOString();
      expect(
        (await expectProblem(await ignore(adminA, target.id, { reason: "x", until: past }), 400)).errors?.[0]?.path,
      ).toBe("until");
      expect(
        (await expectProblem(await ignore(adminA, target.id, { reason: "x", until: far }), 400)).errors?.[0]?.path,
      ).toBe("until");
      await expectProblem(
        await ignore(adminA, target.id, { reason: "   ", until: new Date(clock.ms + DAY).toISOString() }),
        400,
      );
    });

    it("answers 404 to another Organization and 403 to a Shield key", async () => {
      const until = new Date(clock.ms + DAY).toISOString();
      await expectProblem(await ignore(adminB, target.id, { reason: "x", until }), 404);
      await expectProblem(await ignore(shieldA, target.id, { reason: "x", until }), 403);
      await expectProblem(await reopen(adminB, target.id), 404);
    });

    it("leaves an ignored Finding out of the open counts and returns it to open after its expiry", async () => {
      clock.ms = T0 + 32 * DAY;
      const res = await api.app.request(`/v1/findings/${target.id}`, { headers: bearer(adminA) });
      const { finding } = FindingDetailResponseSchema.parse(await res.json());
      expect(finding.status).toBe("open");
      expect(finding.ignore).toBeNull();
    });

    it("refuses to ignore or reopen a withdrawn Finding with 409, and filters by status withdrawn", async () => {
      // A fresh runtime inventory: the earlier instances expired with the clock (A7: 24 hours without a POST).
      expect((await postInventory(shieldA, { components: [c("vuln-range", "2.0.0")] })).status).toBe(202);
      const [open] = await list(adminA, "?source=runtime&status=open");
      if (open === undefined) throw new Error("No open runtime Finding.");
      const advisory = FIXTURES.find((a) => a.id === open.advisory_id);
      await syncAdvisories(
        api.db,
        fixtureSource([{ ...advisory, modified: "2026-11-05T00:00:00Z", withdrawn: "2026-11-05T00:00:00Z" }]),
      );
      await rematchAll({ db: api.db, notifier: { incidentOpened: () => {} }, now, logger: api.logger });
      const withdrawn = await list(adminA, "?status=withdrawn");
      expect(withdrawn.map((f) => f.id)).toContain(open.id);
      expect(withdrawn.every((f) => f.status === "withdrawn" && f.ignore === null)).toBe(true);
      const until = new Date(clock.ms + DAY).toISOString();
      await expectProblem(await ignore(adminA, open.id, { reason: "x", until }), 409);
      await expectProblem(await reopen(adminA, open.id), 409);
    });

    it("reopens an ignored Finding by hand, and refuses to ignore or reopen a fixed one with 409", async () => {
      const until = new Date(clock.ms + DAY).toISOString();
      expect((await ignore(adminA, target.id, { reason: "later", until })).status).toBe(200);
      const res = await reopen(adminA, target.id);
      expect(res.status).toBe(200);
      expect(FindingResponseSchema.parse(await res.json()).finding).toMatchObject({ status: "open", ignore: null });

      const [fixed] = await list(adminA, "?status=fixed");
      if (fixed === undefined) throw new Error("No fixed Finding.");
      await expectProblem(await ignore(adminA, fixed.id, { reason: "x", until }), 409);
      await expectProblem(await reopen(adminA, fixed.id), 409);
    });
  });
});
