import { readFileSync } from "node:fs";
import {
  type AdvisoryInput,
  AdvisorySchema,
  type Component,
  EXAMPLE_ADVISORY,
  type Incident,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { matchInventory, rematchAll } from "../src/exposure/match.ts";
import { FIXTURE_ADVISORIES_FILE, fixtureSource } from "../src/vulns/source.ts";
import { syncAdvisories } from "../src/vulns/sync.ts";
import { captureLogger, createAppFor, createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

const T0 = Date.parse("2026-11-11T09:00:00.000Z");
const DAY_MS = 86_400_000;
const FIXTURES = JSON.parse(readFileSync(FIXTURE_ADVISORIES_FILE, "utf8")) as AdvisoryInput[];

const component = (name: string, version: string, dev = false): Component => ({ name, version, dev });

describe("exposure: advisories, matching and lifecycle", () => {
  let api: TestApi;
  let orgA: string;
  let orgB: string;
  let appA: string;
  let appB: string;
  const opened: { incident: Incident; organizationId: string }[] = [];
  const notifier = {
    incidentOpened: (incident: Incident, organizationId: string) => opened.push({ incident, organizationId }),
  };

  beforeAll(async () => {
    api = await makeTestApi();
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    orgA = a.organization.id;
    orgB = b.organization.id;
    appA = (await createAppFor(api, a.admin_key.key, { name: "A" })).app.id;
    appB = (await createAppFor(api, b.admin_key.key, { name: "B" })).app.id;
    const counts = await syncAdvisories(api.db, fixtureSource(FIXTURES));
    expect(counts).toMatchObject({ received: 10, inserted: 10, updated: 0, unchanged: 0, invalid: 0 });
  });
  afterAll(async () => {
    await api.close();
  });

  /** Matches a runtime inventory of a fresh scope and returns its open Findings as `package@version advisory`. */
  async function matches(components: Component[], environment: "production" | "staging" | "development" = "staging") {
    await api.db.tx({ organizationId: orgA }, (q) =>
      matchInventory(q, {
        organizationId: orgA,
        appId: appA,
        environment,
        source: "runtime",
        buildId: null,
        components,
        at: new Date(T0),
      }),
    );
    const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
      q.query<{ key: string }>(
        `SELECT package || '@' || version || ' ' || advisory_id AS key FROM findings
         WHERE app_id = $1 AND environment = $2 AND source = 'runtime' AND status = 'open' ORDER BY 1`,
        [appA, environment],
      ),
    );
    return rows.map((row) => row.key);
  }

  describe("advisories store", () => {
    it("is readable by the request role without a tenant and by every tenant", async () => {
      for (const scope of ["none", { organizationId: orgA }, { organizationId: orgB }] as const) {
        const { rows } = await api.db.tx(scope, (q) => q.query("SELECT id FROM advisories"));
        expect(rows).toHaveLength(10);
      }
    });

    it("cannot be written by the request role except through the sync function", async () => {
      await expect(
        api.db.tx("none", (q) =>
          q.query(
            "INSERT INTO advisories (id, severity, affected, published, modified) VALUES ('GHSA-x', 'low', '[]', now(), now())",
          ),
        ),
      ).rejects.toThrow(/permission denied/);
      await expect(api.db.tx("none", (q) => q.query("UPDATE advisories SET summary = 'x'"))).rejects.toThrow(
        /permission denied/,
      );
      await expect(api.db.tx("none", (q) => q.query("DELETE FROM advisory_packages"))).rejects.toThrow(
        /permission denied/,
      );
    });

    it("counts a repeated sync as unchanged, and a changed `modified` as updated", async () => {
      const again = await syncAdvisories(api.db, fixtureSource(FIXTURES.slice(0, 2)));
      expect(again).toMatchObject({ received: 2, inserted: 0, updated: 0, unchanged: 2 });
      const changed = { ...FIXTURES[0], summary: "Two ranges, HIGH (revised)", modified: "2026-10-05T00:00:00Z" };
      const updated = await syncAdvisories(api.db, fixtureSource([changed]));
      expect(updated).toMatchObject({ received: 1, updated: 1 });
      const { rows } = await api.db.tx("none", (q) =>
        q.query<{ summary: string }>("SELECT summary FROM advisories WHERE id = $1", [changed.id]),
      );
      expect(rows[0]?.summary).toBe("Two ranges, HIGH (revised)");
    });

    it("indexes advisories by npm package name only", async () => {
      const { rows } = await api.db.tx("none", (q) =>
        q.query<{ package: string }>("SELECT package FROM advisory_packages ORDER BY package"),
      );
      expect(rows.map((row) => row.package)).not.toContain("vuln-pypi");
      expect(rows.map((row) => row.package)).toContain("@fixture/vuln-scoped");
    });
  });

  describe("matching table", () => {
    it.each([
      ["first range, below the fix", component("vuln-range", "1.2.3"), ["GHSA-fx01-0001-rang"]],
      ["at the first fix", component("vuln-range", "1.2.4"), []],
      ["between the ranges", component("vuln-range", "1.9.0"), []],
      ["second range", component("vuln-range", "2.0.5"), ["GHSA-fx01-0001-rang"]],
      ["at the second fix", component("vuln-range", "2.1.1"), []],
      [
        "two advisories on one version",
        component("vuln-range", "1.1.0"),
        ["GHSA-fx01-0001-rang", "GHSA-fx01-0009-medi"],
      ],
      ["last_affected itself", component("vuln-last", "1.5.0"), ["GHSA-fx01-0002-last"]],
      ["after last_affected", component("vuln-last", "1.5.1"), []],
      ["before introduced", component("vuln-last", "0.9.9"), []],
      ["pre-release of last_affected's successor", component("vuln-last", "1.5.1-rc.1"), []],
      ["explicit version", component("vuln-explicit", "3.0.0"), ["GHSA-fx01-0003-expl"]],
      ["explicit pre-release", component("vuln-explicit", "3.0.1-beta.1"), ["GHSA-fx01-0003-expl"]],
      ["not an explicit version", component("vuln-explicit", "3.0.1"), []],
      ["withdrawn advisory", component("vuln-withdrawn", "1.0.0"), []],
      ["scoped name", component("@fixture/vuln-scoped", "4.9.9"), ["GHSA-fx01-0005-scop"]],
      ["scoped name, fixed", component("@fixture/vuln-scoped", "5.0.0"), []],
      ["the unscoped name is another package", component("vuln-scoped", "1.0.0"), []],
      ["capitals as published", component("VulnCaps", "0.9.0"), ["GHSA-fx01-0006-caps"]],
      ["capitals differ: another package", component("vulncaps", "0.9.0"), []],
      ["introduced 0, unbounded", component("vuln-unknown", "999.0.0"), ["GHSA-fx01-0007-unkn"]],
      ["pre-release below the fix", component("vuln-pre", "2.0.0-rc.1"), ["GHSA-fx01-0008-prer"]],
      ["the fix itself", component("vuln-pre", "2.0.0"), []],
      ["build metadata ignored", component("vuln-pre", "1.0.0+build.7"), ["GHSA-fx01-0008-prer"]],
      ["another ecosystem's package", component("vuln-pypi", "1.0.0"), []],
      ["an unknown package", component("left-pad", "1.0.0"), []],
    ])("%s", async (_, item, advisories) => {
      const keys = await matches([item]);
      expect(keys).toEqual(advisories.map((id) => `${item.name}@${item.version} ${id}`));
    });
  });

  describe("findings", () => {
    async function finding(environment: string, pkg: string) {
      const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
        q.query<{ status: string; severity: string; fixed_versions: string[]; dev: boolean }>(
          "SELECT status, severity, fixed_versions, dev FROM findings WHERE environment = $1 AND package = $2 AND source = 'runtime'",
          [environment, pkg],
        ),
      );
      return rows;
    }

    it("stores the severity, the fixed versions and the dev flag", async () => {
      await matches([component("vuln-range", "2.0.0", true)], "production");
      const rows = await finding("production", "vuln-range");
      expect(rows).toEqual([{ status: "open", severity: "high", fixed_versions: ["1.2.4", "2.1.1"], dev: true }]);
    });

    it("marks a runtime Finding fixed when the latest inventory no longer has the version, and opens it again when it returns", async () => {
      await matches([component("vuln-range", "2.1.1")], "production");
      expect((await finding("production", "vuln-range"))[0]?.status).toBe("fixed");
      await matches([component("vuln-range", "2.0.0")], "production");
      expect((await finding("production", "vuln-range"))[0]?.status).toBe("open");
    });

    it("keeps the Findings of another Organization invisible, and refuses rows planted into it", async () => {
      const { rows } = await api.db.tx({ organizationId: orgB }, (q) => q.query("SELECT id FROM findings"));
      expect(rows).toHaveLength(0);
      const inventories = await api.db.tx({ organizationId: orgB }, (q) => q.query("SELECT id FROM inventories"));
      expect(inventories.rows).toHaveLength(0);
      await expect(
        api.db.tx({ organizationId: orgB }, (q) =>
          q.query(
            `INSERT INTO inventories (organization_id, app_id, environment, source, build_id, components, received_at)
             VALUES ($1, $2, 'production', 'runtime', NULL, '[]', now())`,
            [orgA, appA],
          ),
        ),
      ).rejects.toThrow(/row-level security/);
    });
  });

  describe("re-match after a sync", () => {
    it("matches every Organization's latest inventories against new advisories and opens Incidents for Critical/High", async () => {
      // Organization B runs a package no advisory names yet.
      await api.db.tx({ organizationId: orgB }, (q) =>
        matchInventory(q, {
          organizationId: orgB,
          appId: appB,
          environment: "production",
          source: "runtime",
          buildId: null,
          components: [component("late-vuln", "1.0.0")],
          at: new Date(T0),
        }),
      );
      const late = AdvisorySchema.parse({
        ...EXAMPLE_ADVISORY,
        id: "GHSA-late-0000-0001",
        aliases: ["CVE-2026-99999"],
        database_specific: { severity: "CRITICAL" },
        affected: [
          {
            package: { ecosystem: "npm", name: "late-vuln" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.1" }] }],
          },
        ],
      });
      await syncAdvisories(api.db, fixtureSource([late]));
      opened.length = 0;
      const logger = captureLogger();
      const result = await rematchAll({ db: api.db, notifier, now: () => new Date(T0 + 60_000), logger });
      expect(result.organizations).toBeGreaterThanOrEqual(2);
      const { rows } = await api.db.tx({ organizationId: orgB }, (q) =>
        q.query<{ advisory_id: string; status: string }>("SELECT advisory_id, status FROM findings"),
      );
      expect(rows).toEqual([{ advisory_id: "GHSA-late-0000-0001", status: "open" }]);
      const forB = opened.filter((entry) => entry.organizationId === orgB);
      expect(forB).toHaveLength(1);
      expect(forB[0]?.incident).toMatchObject({
        rule: "vulnerable-component",
        severity: "critical",
        advisory_id: "GHSA-late-0000-0001",
        ip_prefix: null,
        origin: null,
        build_id: null,
      });
      // Counts only: no package name, version or advisory reaches the log.
      for (const line of logger.lines) expect(line).not.toMatch(/late-vuln|vuln-|GHSA-/);
    });
  });

  describe("withdrawn (D-060)", () => {
    const WD = "GHSA-wdrn-0000-0001";
    const base = {
      ...EXAMPLE_ADVISORY,
      id: WD,
      aliases: [],
      database_specific: { severity: "CRITICAL" as const },
      affected: [
        {
          package: { ecosystem: "npm", name: "wd-pkg" },
          ranges: [{ type: "SEMVER" as const, events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
        },
      ],
    };
    let modified = Date.parse("2026-10-10T00:00:00Z");
    /** Syncs a new revision of the advisory (a later `modified`) and re-matches everything. */
    async function revise(patch: Record<string, unknown>) {
      modified += DAY_MS;
      await syncAdvisories(api.db, fixtureSource([{ ...base, ...patch, modified: new Date(modified).toISOString() }]));
      await rematchAll({ db: api.db, notifier, now: () => new Date(T0 + 120_000), logger: captureLogger() });
    }
    async function runtime(components: Component[]) {
      await api.db.tx({ organizationId: orgA }, (q) =>
        matchInventory(q, {
          organizationId: orgA,
          appId: appA,
          environment: "development",
          source: "runtime",
          buildId: null,
          components,
          at: new Date(T0),
        }),
      );
    }
    async function status(version: string) {
      const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
        q.query<{ status: string }>(
          "SELECT status FROM findings WHERE advisory_id = $1 AND environment = 'development' AND version = $2",
          [WD, version],
        ),
      );
      return rows.map((row) => row.status);
    }
    const incidentsFor = () => opened.filter((entry) => entry.incident.advisory_id === WD);

    it("sets a Finding withdrawn when its advisory is withdrawn, without an Incident, and open again when it returns", async () => {
      await revise({});
      opened.length = 0;
      await runtime([component("wd-pkg", "1.0.0")]);
      expect(await status("1.0.0")).toEqual(["open"]);

      await revise({ withdrawn: "2026-11-01T00:00:00Z" });
      expect(await status("1.0.0")).toEqual(["withdrawn"]);

      // Back: open again, and it opens or joins an Incident like a new Finding.
      await revise({});
      expect(await status("1.0.0")).toEqual(["open"]);
      const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
        q.query<{ detection_count: number }>(
          "SELECT detection_count FROM incidents WHERE advisory_id = $1 AND status = 'open'",
          [WD],
        ),
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]?.detection_count).toBe(1);
    });

    it("sets a Finding withdrawn when a sync's ranges no longer cover the installed version", async () => {
      opened.length = 0;
      await revise({
        affected: [
          {
            package: { ecosystem: "npm", name: "wd-pkg" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.9.0" }] }],
          },
        ],
      });
      expect(await status("1.0.0")).toEqual(["withdrawn"]);
      expect(incidentsFor()).toHaveLength(0);
    });

    it("sets a withdrawn Finding fixed when its version leaves the inventory", async () => {
      await runtime([component("wd-pkg", "2.5.0")]);
      expect(await status("1.0.0")).toEqual(["fixed"]);
    });

    it("sets an older Build's Finding withdrawn, not fixed, when a newer Build ships the same version the advisory no longer covers", async () => {
      await revise({});
      const builds = [newId("bld"), newId("bld")];
      for (const [index, buildId] of builds.entries()) {
        await api.db.tx({ organizationId: orgA }, async (q) => {
          await q.query(
            `INSERT INTO builds (organization_id, app_id, build_id, environment, version, profile, manifest, registered_at)
             VALUES ($1, $2, $3, 'staging', '1', 'light', '{}', now())`,
            [orgA, appA, buildId],
          );
          if (index === 1) {
            // Between the two Builds, the advisory narrows.
            return;
          }
          await matchInventory(q, {
            organizationId: orgA,
            appId: appA,
            environment: "staging",
            source: "build",
            buildId,
            components: [component("wd-pkg", "1.0.0")],
            at: new Date(T0),
          });
        });
      }
      // Synced without a re-match: only the newer Build's own match decides for the older one.
      modified += DAY_MS;
      await syncAdvisories(
        api.db,
        fixtureSource([
          {
            ...base,
            modified: new Date(modified).toISOString(),
            affected: [
              {
                package: { ecosystem: "npm", name: "wd-pkg" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.9.0" }] }],
              },
            ],
          },
        ]),
      );
      await api.db.tx({ organizationId: orgA }, (q) =>
        matchInventory(q, {
          organizationId: orgA,
          appId: appA,
          environment: "staging",
          source: "build",
          buildId: builds[1] as string,
          components: [component("wd-pkg", "1.0.0")],
          at: new Date(T0 + 1),
        }),
      );
      const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
        q.query<{ status: string }>("SELECT status FROM findings WHERE advisory_id = $1 AND build_id = $2", [
          WD,
          builds[0],
        ]),
      );
      expect(rows.map((row) => row.status)).toEqual(["withdrawn"]);
    });
  });
});
