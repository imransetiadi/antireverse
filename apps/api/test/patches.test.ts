import { readFileSync } from "node:fs";
import {
  type AdvisoryInput,
  BundlePatchSchema,
  type Component,
  EXAMPLE_SHIELD_EVENT,
  EXAMPLE_VIRTUAL_PATCH,
  FINDING_SEVERITIES,
  type Finding,
  type Incident,
  IncidentDetailResponseSchema,
  ListEventsResponseSchema,
  ListFindingsResponseSchema,
  ListIncidentsResponseSchema,
  ListPatchesResponseSchema,
  PATCH_LIMITS,
  PatchModeResponseSchema,
  type PatchSummary,
  type ShieldEvent,
  type StoredEvent,
  type VirtualPatch,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDetector } from "../src/detect/detector.ts";
import { matchingRules } from "../src/detect/rules.ts";
import { type PatchState, selectShipped } from "../src/patches/activation.ts";
import { createPatchCatalog } from "../src/patches/catalog.ts";
import { FIXTURE_ADVISORIES_FILE, fixtureSource } from "../src/vulns/source.ts";
import { syncAdvisories } from "../src/vulns/sync.ts";
import { FIXTURE_PATCH_CATALOG } from "./fixtures/patch-catalog.ts";
import {
  batchOf,
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  fetchBundle,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
  withReason,
} from "./helpers.ts";

const ACTOR = `iph_${"a".repeat(32)}`;
const T0 = Date.parse("2026-11-11T09:00:00.000Z");
const FIXTURES = JSON.parse(readFileSync(FIXTURE_ADVISORIES_FILE, "utf8")) as AdvisoryInput[];
const c = (name: string, version: string): Component => ({ name, version, dev: false });

type PatchItem = PatchSummary;

/** An Event that a patch decided, in `mode` (monitor records; enforce blocked). */
function patchEvent(
  ms: number,
  patchId: string,
  mode: "monitor" | "enforce",
  prefix: string | null = "203.0.113.0/24",
  ipHash: string | null = null,
) {
  return shieldEvent(ms, {
    request: { ...EXAMPLE_SHIELD_EVENT.request, status: mode === "enforce" ? 403 : 200 },
    decision: {
      action: "block",
      mode,
      rule_id: null,
      policy_version: 1,
      containment_id: null,
      patch_id: patchId,
      patch_body: "checked",
    },
    actor: { ip_prefix: prefix, ip_hash: ipHash },
  });
}

/**
 * An Event whose patch's body condition was never checked (no `verifyBody`): Shield records it as allow with the
 * patch and `patch_body: "unchecked"` (A6 F2). It is not an exploit attempt: it never counts.
 */
function uncheckedEvent(ms: number, patchId: string, ipHash: string | null = null) {
  const event = patchEvent(ms, patchId, "monitor", "203.0.113.0/24", ipHash);
  return { ...event, decision: { ...event.decision, action: "allow" as const, patch_body: "unchecked" as const } };
}

/**
 * An Event whose body was in a character set Shield cannot read (plan A11 M2): recorded with the patch and
 * `patch_body: "undecodable"`, refused under enforce. Not a recognised exploit: it never counts.
 */
function undecodableEvent(ms: number, patchId: string, mode: "monitor" | "enforce", ipHash: string | null = null) {
  const event = patchEvent(ms, patchId, mode, "203.0.113.0/24", ipHash);
  // As Shield records it: allow in monitor, block under enforce.
  const action = mode === "enforce" ? ("block" as const) : ("allow" as const);
  return { ...event, decision: { ...event.decision, action, patch_body: "undecodable" as const } };
}

describe("exploit-attempt rule", () => {
  const stored = (event: ShieldEvent): StoredEvent => ({
    ...event,
    organization_id: "org_0123456789abcdef01234567",
    app_id: "app_89abcdef0123456789abcdef",
    environment: "production",
    received_at: event.ts,
  });

  it("counts an Event naming a patch, in monitor and in enforce, and only for exploit-attempt", () => {
    expect(matchingRules(stored(patchEvent(T0, "vp_fixture_range_query", "monitor"))).map((r) => r.key)).toEqual([
      "exploit-attempt",
    ]);
    // An enforced patch block is the response to a known exploit, not a burst: one attack, one Incident.
    expect(matchingRules(stored(patchEvent(T0, "vp_fixture_range_query", "enforce"))).map((r) => r.key)).toEqual([
      "exploit-attempt",
    ]);
    expect(matchingRules(stored(shieldEvent(T0))).map((r) => r.key)).toEqual([]);
    // A body never checked is not an exploit attempt (A6 F2), even under an enforced patch.
    expect(matchingRules(stored(uncheckedEvent(T0, "vp_fixture_range_query"))).map((r) => r.key)).toEqual([]);
    // Nor is a body in an unreadable character set (A11 M2), recorded in monitor or refused under enforce.
    for (const mode of ["monitor", "enforce"] as const) {
      const keys = matchingRules(stored(undecodableEvent(T0, "vp_fixture_range_query", mode))).map((r) => r.key);
      expect(keys).not.toContain("exploit-attempt");
    }
    const enforcedUnchecked = uncheckedEvent(T0, "vp_fixture_range_query");
    expect(
      matchingRules(stored({ ...enforcedUnchecked, decision: { ...enforcedUnchecked.decision, mode: "enforce" } })),
    ).toEqual([]);
  });
});

describe("selectShipped", () => {
  const big = (i: number): VirtualPatch => ({
    ...EXAMPLE_VIRTUAL_PATCH,
    id: `vp_big_${String(i).padStart(3, "0")}`,
    conditions: Array.from({ length: PATCH_LIMITS.conditionsMax }, (_, k) => ({
      target: "query_key" as const,
      op: "contains" as const,
      value: `${"x".repeat(250)}${k}`,
    })),
  });
  const state = (patch: VirtualPatch): PatchState => ({
    patch,
    mode: "monitor",
    active: true,
    shipped: false,
    findings: ["fnd_0123456789abcdef01234567"],
    advisory: "GHSA-2c3m-4p5q-6r7v",
    severity: "high",
  });

  it("ships in order within the byte budget, skips what does not fit and keeps filling with later patches", () => {
    const small = (i: number) => state({ ...EXAMPLE_VIRTUAL_PATCH, id: `vp_small_${String(i).padStart(3, "0")}` });
    // Big patches until the budget is exceeded, then small ones: a big one that does not fit is skipped, the small
    // ones after it still ship.
    const states = [...Array.from({ length: 12 }, (_, i) => state(big(i))), small(0), small(1)];
    const { shipped, notShipped } = selectShipped(states);
    const shippedIds = shipped.map((p) => p.id);
    expect(notShipped.length).toBeGreaterThan(0);
    expect(notShipped.every((id) => id.startsWith("vp_big_"))).toBe(true);
    expect(shippedIds).toContain("vp_small_000");
    expect(shippedIds).toContain("vp_small_001");
    expect(shipped.length + notShipped.length).toBe(states.length);
    expect(new TextEncoder().encode(JSON.stringify(shipped)).length).toBeLessThanOrEqual(PATCH_LIMITS.bundleBytesMax);
    // Order is kept: shipped and not shipped are each a subsequence of the input order.
    const order = states.map((s) => s.patch.id);
    expect(shippedIds).toEqual(order.filter((id) => shippedIds.includes(id)));
    expect(notShipped).toEqual(order.filter((id) => notShipped.includes(id)));
    for (const patch of shipped) expect(BundlePatchSchema.parse(patch)).toEqual(patch);
  });

  it("ships a later patch that fits the remaining budget after a larger one that does not", () => {
    // Fill most of the budget, then one big (does not fit), then one small (fits).
    const fill = Array.from({ length: 5 }, (_, i) => state(big(i)));
    const bytes = new TextEncoder().encode(JSON.stringify(selectShipped(fill).shipped)).length;
    expect(bytes).toBeLessThan(PATCH_LIMITS.bundleBytesMax);
    const states = [...fill, state(big(90)), state(big(91)), state({ ...EXAMPLE_VIRTUAL_PATCH, id: "vp_small_tail" })];
    const { shipped, notShipped } = selectShipped(states);
    expect(shipped.at(-1)?.id).toBe("vp_small_tail");
    expect(notShipped).toContain("vp_big_091");
  });

  it("ships at most PATCH_LIMITS.perBundle patches", () => {
    const states = Array.from({ length: PATCH_LIMITS.perBundle + 5 }, (_, i) =>
      state({ ...EXAMPLE_VIRTUAL_PATCH, id: `vp_small_${String(i).padStart(3, "0")}` }),
    );
    const { shipped, notShipped } = selectShipped(states);
    expect(shipped).toHaveLength(PATCH_LIMITS.perBundle);
    expect(notShipped).toHaveLength(5);
  });

  it("never ships an inactive patch", () => {
    const { shipped, notShipped } = selectShipped([{ ...state(EXAMPLE_VIRTUAL_PATCH), active: false }]);
    expect(shipped).toEqual([]);
    expect(notShipped).toEqual([]);
  });
});

describe("Virtual patches", () => {
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
  const opened: { incident: Incident; organizationId: string }[] = [];
  const notifier = {
    incidentOpened: (incident: Incident, organizationId: string) => opened.push({ incident, organizationId }),
    test: async () => null,
    confirmations: () => {},
    drain: async () => {},
  };

  beforeAll(async () => {
    api = await makeTestApi({ now, notifier, patches: FIXTURE_PATCH_CATALOG });
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
    for (const line of api.logger.lines) expect(line).not.toMatch(/vuln-|GHSA-|vp_fixture|__proto__/);
    expectNoKeyLogged(api);
    await api.close();
  });

  async function inventory(key: string, components: Component[]) {
    clock.ms += 1_000;
    const res = await api.app.request("/v1/inventory", json({ components }, bearer(key)));
    expect(res.status).toBeLessThan(300);
  }

  async function patches(adminKey: string, appId: string, environment = "production"): Promise<PatchItem[]> {
    const res = await api.app.request(`/v1/apps/${appId}/patches?environment=${environment}`, {
      headers: bearer(adminKey),
    });
    expect(res.status).toBe(200);
    return ListPatchesResponseSchema.parse(await res.json()).patches;
  }

  function setMode(adminKey: string, appId: string, patchId: string, body: unknown) {
    return Promise.resolve(
      api.app.request(`/v1/apps/${appId}/patches/${patchId}/mode`, json(body, withReason(bearer(adminKey)))),
    );
  }

  async function findings(adminKey: string): Promise<Finding[]> {
    const res = await api.app.request("/v1/findings?status=open", { headers: bearer(adminKey) });
    return ListFindingsResponseSchema.parse(await res.json()).findings;
  }

  const bundle = () => fetchBundle(api, shieldA, api.signer.publicKey);

  it("lists every catalog patch, inactive in monitor, and ships none before a Finding", async () => {
    const listed = await patches(adminA, appA);
    expect(listed.map((p) => p.id).sort()).toEqual(FIXTURE_PATCH_CATALOG.patches.map((p) => p.id).sort());
    for (const item of listed) {
      expect(item).toMatchObject({ mode: "monitor", active: false, shipped: false, findings: [], hits_24h: 0 });
      expect(item.last_hit).toBeNull();
    }
    expect((await bundle()).payload.patches).toBeUndefined();
  });

  it("activates patches from open Findings by advisory id or alias and package, ships them in monitor by severity then id", async () => {
    const before = await bundle();
    await inventory(shieldA, [c("vuln-range", "1.0.0"), c("vuln-last", "1.2.0"), c("safe-pkg", "1.0.0")]);
    const open = await findings(adminA);
    const listed = await patches(adminA, appA);
    const active = listed.filter((p) => p.active).map((p) => p.id);
    expect(active.sort()).toEqual(["vp_fixture_last_header", "vp_fixture_range_medium", "vp_fixture_range_query"]);
    // Same advisory, other package: never active.
    expect(listed.find((p) => p.id === "vp_fixture_wrong_package")?.active).toBe(false);
    const rangeFinding = open.find((f) => f.advisory_id === "GHSA-fx01-0001-rang");
    expect(listed.find((p) => p.id === "vp_fixture_range_query")?.findings).toEqual([rangeFinding?.id]);

    const after = await bundle();
    expect(after.etag).not.toBe(before.etag);
    const shipped = after.payload.patches ?? [];
    const rank = (id: string) => {
      const advisory = shipped.find((p) => p.id === id)?.advisory;
      const severity = open.find((f) => f.advisory_id === advisory)?.severity ?? "unknown";
      return FINDING_SEVERITIES.indexOf(severity);
    };
    const expected = [...active].sort((x, y) => rank(x) - rank(y) || (x < y ? -1 : 1));
    expect(shipped.map((p) => p.id)).toEqual(expected);
    expect(shipped.every((p) => p.mode === "monitor")).toBe(true);
    // The advisory is the activating Finding's: the alias-only patch ships the Finding's GHSA id.
    expect(shipped.find((p) => p.id === "vp_fixture_last_header")?.advisory).toBe("GHSA-fx01-0002-last");
    expect(shipped.find((p) => p.id === "vp_fixture_range_query")).toEqual({
      id: "vp_fixture_range_query",
      mode: "monitor",
      methods: ["GET"],
      conditions: [{ target: "query_key", op: "contains", value: "__proto__" }],
      advisory: "GHSA-fx01-0001-rang",
    });
    for (const item of listed.filter((p) => p.active)) expect(item.shipped).toBe(true);
    // Another Organization's App sees none of it.
    expect((await patches(adminB, appB)).every((p) => !p.active)).toBe(true);
  });

  it("refuses enforce without the patch id as confirmation, with a fixed text", async () => {
    for (const body of [
      { environment: "production", mode: "enforce" },
      { environment: "production", mode: "enforce", confirm: "vp_fixture_last_header" },
    ]) {
      const problem = await expectProblem(await setMode(adminA, appA, "vp_fixture_range_query", body), 400);
      expect(problem.errors).toEqual([{ path: "confirm", message: "Must equal the id of the patch." }]);
    }
    await expectProblem(
      await setMode(adminA, appA, "vp_fixture_range_query", { environment: "x", mode: "enforce" }),
      400,
    );
    await expectProblem(
      await setMode(adminA, appA, "vp_fixture_range_query", { environment: "production", mode: "block" }),
      400,
    );
  });

  it("promotes to enforce, re-issues the bundle, and returns to monitor in one action", async () => {
    const before = await bundle();
    const res = await setMode(adminA, appA, "vp_fixture_range_query", {
      environment: "production",
      mode: "enforce",
      confirm: "vp_fixture_range_query",
    });
    expect(res.status).toBe(200);
    const body = PatchModeResponseSchema.parse(await res.json());
    expect(body.patch).toMatchObject({ id: "vp_fixture_range_query", mode: "enforce", active: true, shipped: true });
    const after = await bundle();
    expect(after.etag).not.toBe(before.etag);
    expect(after.payload.patches?.find((p) => p.id === "vp_fixture_range_query")?.mode).toBe("enforce");

    const back = await setMode(adminA, appA, "vp_fixture_range_query", { environment: "production", mode: "monitor" });
    expect(back.status).toBe(200);
    expect(PatchModeResponseSchema.parse(await back.json()).patch.mode).toBe("monitor");
    expect((await bundle()).payload.patches?.find((p) => p.id === "vp_fixture_range_query")?.mode).toBe("monitor");
    // Each environment has its own mode.
    expect((await patches(adminA, appA, "staging")).every((p) => p.mode === "monitor" && !p.active)).toBe(true);
  });

  it("answers 404 for an unknown patch and another Organization's App, 403 for a Shield key", async () => {
    const enforce = { environment: "production", mode: "monitor" };
    await expectProblem(await setMode(adminA, appA, "vp_not_in_catalog", enforce), 404);
    await expectProblem(await setMode(adminA, appA, "not-a-patch", enforce), 404);
    await expectProblem(await setMode(adminA, appB, "vp_fixture_range_query", enforce), 404);
    await expectProblem(
      await api.app.request(`/v1/apps/${appB}/patches?environment=production`, { headers: bearer(adminA) }),
      404,
    );
    await expectProblem(await setMode(shieldA, appA, "vp_fixture_range_query", enforce), 403);
    await expectProblem(
      await api.app.request(`/v1/apps/${appA}/patches?environment=production`, { headers: bearer(shieldA) }),
      403,
    );
    await expectProblem(
      await api.app.request(`/v1/apps/${appA}/patches?environment=nowhere`, { headers: bearer(adminA) }),
      400,
    );
    await expectProblem(await api.app.request(`/v1/apps/${appA}/patches`, { headers: bearer(adminA) }), 400);
  });

  it("stores patch decisions, a patch id unknown to the catalog as is, and counts hits", async () => {
    clock.ms += 1_000;
    const events = [
      patchEvent(clock.ms, "vp_fixture_range_query", "monitor"),
      patchEvent(clock.ms + 1, "vp_unknown_patch", "enforce"),
      uncheckedEvent(clock.ms + 2, "vp_fixture_range_query"),
      undecodableEvent(clock.ms + 3, "vp_fixture_range_query", "monitor"),
    ];
    const res = await api.app.request("/v1/events", json(batchOf(events), bearer(shieldA)));
    expect(res.status).toBe(202);
    const listed = await api.app.request(`/v1/apps/${appA}/events`, { headers: bearer(adminA) });
    const stored = ListEventsResponseSchema.parse(await listed.json()).events;
    expect(stored.map((e) => e.decision.patch_id).sort()).toEqual([
      "vp_fixture_range_query",
      "vp_fixture_range_query",
      "vp_fixture_range_query",
      "vp_unknown_patch",
    ]);
    expect(stored.filter((e) => e.decision.patch_body === "undecodable")).toHaveLength(1);
    expect(stored.filter((e) => e.decision.patch_body === "unchecked")).toHaveLength(1);

    const item = (await patches(adminA, appA)).find((p) => p.id === "vp_fixture_range_query");
    expect(item?.hits_24h).toBe(1);
    expect(item?.last_hit).toBe(new Date(clock.ms).toISOString());
    // Older than 24 hours: no longer in hits_24h, still the last hit.
    clock.ms += 25 * 3_600_000;
    const later = (await patches(adminA, appA)).find((p) => p.id === "vp_fixture_range_query");
    expect(later?.hits_24h).toBe(0);
    expect(later?.last_hit).toBe(item?.last_hit);
  });

  it("opens one High Exploit attempt Incident per App, Environment and advisory, with one alert", async () => {
    const detector = createDetector({
      db: api.db,
      bus: api.bus,
      notifier,
      now,
      logger: captureLogger(),
      patches: FIXTURE_PATCH_CATALOG,
    });
    const stop = detector.start();
    try {
      opened.length = 0;
      clock.ms += 1_000;
      const batch = [
        patchEvent(clock.ms, "vp_fixture_range_query", "monitor", "203.0.113.0/24", ACTOR),
        patchEvent(clock.ms + 1, "vp_fixture_range_query", "enforce", null, ACTOR),
        patchEvent(clock.ms + 2, "vp_fixture_last_header", "monitor", "198.51.100.0/24"),
        patchEvent(clock.ms + 3, "vp_unknown_patch", "enforce"),
        // Never checked: no Detection, no evidence, no Actor (A6 F2).
        uncheckedEvent(clock.ms + 1, "vp_fixture_range_query", `iph_${"b".repeat(32)}`),
        // Unreadable character set: likewise (A11 M2).
        undecodableEvent(clock.ms + 1, "vp_fixture_range_query", "monitor", `iph_${"c".repeat(32)}`),
      ];
      const res = await api.app.request("/v1/events", json(batchOf(batch), bearer(shieldA)));
      expect(res.status).toBe(202);
      await detector.flush();
    } finally {
      stop();
    }
    const res = await api.app.request("/v1/incidents", { headers: bearer(adminA) });
    const incidents = ListIncidentsResponseSchema.parse(await res.json()).incidents.filter(
      (i) => i.rule === "exploit-attempt",
    );
    expect(incidents.map((i) => i.advisory_id).sort()).toEqual(["GHSA-fx01-0001-rang", "GHSA-fx01-0002-last"]);
    for (const incident of incidents) {
      expect(incident).toMatchObject({
        app_id: appA,
        environment: "production",
        severity: "high",
        title: "Exploit attempt",
        status: "open",
        ip_prefix: null,
        build_id: null,
      });
    }
    expect(incidents.find((i) => i.advisory_id === "GHSA-fx01-0001-rang")?.detection_count).toBe(2);
    // One alert per new Incident, none for the joined Detection or the unknown patch.
    expect(opened.map((o) => o.incident.advisory_id).sort()).toEqual(["GHSA-fx01-0001-rang", "GHSA-fx01-0002-last"]);
    expect(opened.every((o) => o.organizationId === orgA)).toBe(true);
    const detail = await api.app.request(`/v1/incidents/${incidents[0]?.id}`, { headers: bearer(adminA) });
    expect(detail.status).toBe(200);
  });

  it("gives an Exploit attempt Incident its Events as evidence and their Actors, and lets an admin contain an Actor", async () => {
    const res = await api.app.request("/v1/incidents", { headers: bearer(adminA) });
    const incidents = ListIncidentsResponseSchema.parse(await res.json()).incidents;
    const range = incidents.find((i) => i.rule === "exploit-attempt" && i.advisory_id === "GHSA-fx01-0001-rang");
    const last = incidents.find((i) => i.rule === "exploit-attempt" && i.advisory_id === "GHSA-fx01-0002-last");
    const detail = IncidentDetailResponseSchema.parse(
      await (await api.app.request(`/v1/incidents/${range?.id}`, { headers: bearer(adminA) })).json(),
    );
    // Only the Events of patches covering this advisory, in the Incident's span: not the earlier hit, not the
    // other advisory's patch, not the unknown patch.
    expect(detail.evidence.map((e) => e.decision.patch_id)).toEqual([
      "vp_fixture_range_query",
      "vp_fixture_range_query",
    ]);
    expect(detail.actors).toEqual([{ ip_hash: ACTOR, events: 2 }]);
    const other = IncidentDetailResponseSchema.parse(
      await (await api.app.request(`/v1/incidents/${last?.id}`, { headers: bearer(adminA) })).json(),
    );
    expect(other.evidence.map((e) => e.decision.patch_id)).toEqual(["vp_fixture_last_header"]);
    expect(other.actors).toEqual([]);

    const actor = await api.app.request(
      `/v1/incidents/${range?.id}/containments`,
      json({ target: { kind: "actor", ip_hash: ACTOR }, ttl_s: 900 }, withReason(bearer(adminA))),
    );
    expect(actor.status).toBe(201);
    const unknown = await api.app.request(
      `/v1/incidents/${range?.id}/containments`,
      json({ target: { kind: "actor", ip_hash: `iph_${"9".repeat(32)}` }, ttl_s: 900 }, withReason(bearer(adminA))),
    );
    expect((await expectProblem(unknown, 409)).reason).toBe("actor-unknown");
    // No single network: the Incident is grouped by advisory, so a prefix block does not apply.
    const prefix = await api.app.request(
      `/v1/incidents/${range?.id}/containments`,
      json({ target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: "203.0.113.0/24" }, withReason(bearer(adminA))),
    );
    expect((await expectProblem(prefix, 409)).reason).toBe("containment-not-applicable");
  });

  it("keeps an ignored Finding's patch active", async () => {
    const last = (await findings(adminA)).find((f) => f.advisory_id === "GHSA-fx01-0002-last");
    const ignore = await api.app.request(
      `/v1/findings/${last?.id}/ignore`,
      json({ reason: "Accepted for now", until: new Date(clock.ms + 86_400_000).toISOString() }, bearer(adminA)),
    );
    expect(ignore.status).toBe(200);
    expect((await patches(adminA, appA)).find((p) => p.id === "vp_fixture_last_header")?.active).toBe(true);
    expect((await bundle()).payload.patches?.map((p) => p.id)).toContain("vp_fixture_last_header");
  });

  it("drops patches when their Findings are fixed, keeps the mode, and brings it back with the Finding", async () => {
    const enforce = await setMode(adminA, appA, "vp_fixture_range_query", {
      environment: "production",
      mode: "enforce",
      confirm: "vp_fixture_range_query",
    });
    expect(enforce.status).toBe(200);
    const before = await bundle();
    await inventory(shieldA, [c("vuln-range", "2.5.0"), c("safe-pkg", "1.0.0")]);
    const after = await bundle();
    expect(after.etag).not.toBe(before.etag);
    expect(after.payload.patches).toBeUndefined();
    const listed = await patches(adminA, appA);
    expect(listed.every((p) => !p.active && !p.shipped && p.findings.length === 0)).toBe(true);
    expect(listed.find((p) => p.id === "vp_fixture_range_query")?.mode).toBe("enforce");

    await inventory(shieldA, [c("vuln-range", "1.0.0")]);
    expect((await bundle()).payload.patches?.find((p) => p.id === "vp_fixture_range_query")?.mode).toBe("enforce");
  });

  it("never lets a Shield of another Organization see the patches", async () => {
    const other = await fetchBundle(api, shieldB, api.signer.publicKey);
    expect(other.payload.patches).toBeUndefined();
  });

  it("a catalog built from entries passes the reference check (sanity of the test catalog)", () => {
    expect(() => createPatchCatalog("2026-11-11.0", FIXTURE_PATCH_CATALOG.patches)).not.toThrow();
  });
});
