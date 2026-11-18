import { readFileSync } from "node:fs";
import {
  type AdvisoryInput,
  type AlertDelivery,
  AUDIT_REASON_HEADER,
  type AuditAction,
  type AuditEntry,
  AuditExportLineSchema,
  AuditVerifyResponseSchema,
  type BuildManifest,
  type Component,
  ContainmentResponseSchema,
  CreateAlertChannelResponseSchema,
  campaignAuthorisationPhrase,
  confirmationPhrase,
  DETECTION_RULES,
  EXAMPLE_CANARIES,
  ListAuditResponseSchema,
  ListFindingsResponseSchema,
  PolicyResponseSchema,
  TargetResponseSchema,
} from "@antireverse/protocol";
import { generateVerificationToken, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { MailEnvelope, MailResult } from "../src/mail/smtp.ts";
import type { Notifier } from "../src/notify/notifier.ts";
import type { Resolve } from "../src/notify/ssrf.ts";
import { PATCH_CATALOG } from "../src/patches/catalog.ts";
import type { Fetcher, Resolver } from "../src/prove/verify.ts";
import { auditEntriesAfter } from "../src/stores/audit.ts";
import { recordDetection } from "../src/stores/incidents.ts";
import { insertTarget } from "../src/stores/targets.ts";
import { FIXTURE_ADVISORIES_FILE, fixtureSource } from "../src/vulns/source.ts";
import { syncAdvisories } from "../src/vulns/sync.ts";
import { artifactFor, fakeAssessor } from "./fake-assessor.ts";
import {
  bearer,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  put,
  type TestApi,
} from "./helpers.ts";

// Slice 18a, TC-CON-004 part 1: every mutating route of the API either writes exactly one audit entry when it
// succeeds, or is listed below as not administrative, with the reason. A route added without either fails the first
// test. The sensitive ones refuse a change without a reason. No summary holds a secret.

/** Mutating routes that are not administrative changes, and why. */
const EXCLUDED: Readonly<Record<string, string>> = {
  "POST /v1/events": "Shield key: telemetry ingest, not an administrative change",
  "POST /v1/inventory": "Shield key: the runtime component inventory, not an administrative change",
  "POST /v1/beacon": "public: a Clone Beacon report",
  "POST /v1/attest/challenge": "public: an attestation challenge",
  "POST /v1/attest": "public: an attestation",
  "POST /v1/alert-recipients/confirm": "public: the link of a confirmation mail",
  "POST /v1/apps/:appId/policy/simulate": "admin, but a dry replay: it changes nothing",
  "POST /v1/prove/authorize": "admin, but a dry check: it changes nothing",
  // Slice 15a: the operator's switches take the operator token, not a key. A kill or a suspension writes its entry
  // into the chain of each Organization it affects (campaign-routes.test.ts and the scope-escape suite check them).
  "POST /v1/ops/prove/kill": "operator token: one operator entry per affected Organization, checked elsewhere",
  "POST /v1/ops/prove/enable": "operator token: affects no Organization; recorded with the switch",
  "POST /v1/ops/prove/organizations/:id/suspend": "operator token: an operator entry in that Organization's chain",
  "POST /v1/ops/prove/organizations/:id/resume": "operator token: an operator entry in that Organization's chain",
};

/** The Organization signup: public, and its entry is the new Organization's first (checked on its own below). */
const SIGNUP = "POST /v1/organizations";

const T0 = Date.parse("2026-11-16T10:00:00.000Z"); // a Monday, 10:00 UTC
const DAY = 86_400_000;
const REASON = "Change ticket OPS-1234";
const FIXTURES = JSON.parse(readFileSync(FIXTURE_ADVISORIES_FILE, "utf8")) as AdvisoryInput[];
const PATCH_ID = PATCH_CATALOG.patches[0]?.id ?? "";
const PREFIX = "192.0.2.0/24";
const WEBHOOK_URL = "https://hooks.example.com/services/T0KEN-webhook-secret-path";
const RECIPIENTS = ["oncall@acme.test", "Second.Person@acme.test"];
const CONTACT = "security@acme.test";
const ORGANIZATION_NAME = "Acme for owner@acme.test";
const SUBJECT_HASH = "iph_0123456789abcdef0123456789abcdef";

type Headers = Record<string, string>;

interface Case {
  /** `METHOD template`, as Hono's route table has it. */
  route: string;
  action: AuditAction;
  /** Refused with `reason-required` unless the request carries a reason. */
  sensitive?: boolean;
  status: number;
  run(headers: Headers): Response | Promise<Response>;
  /** Reads what later cases need from the successful response. */
  after?(res: Response): Promise<void>;
}

describe("audit coverage", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  /** Every secret, token, address or Canary value the run hands out: none may appear in an entry's summary. */
  const secrets: string[] = [...RECIPIENTS.map((r) => r.toLowerCase()), CONTACT, WEBHOOK_URL];
  const txt = new Map<string, string[][]>();
  const resolver: Resolver = {
    async txt(name) {
      const records = txt.get(name);
      if (records === undefined) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      return records;
    },
    async addresses() {
      throw new Error("not used");
    },
  };
  const fetcher: Fetcher = async () => ({ ok: false, reason: "status" });
  const resolve: Resolve = async () => [{ address: "93.184.216.34", family: 4 }];
  const notifier: Notifier = {
    incidentOpened: () => {},
    confirmations: () => {},
    drain: async () => {},
    async test(channelId) {
      return {
        id: newId("dlv"),
        channel_id: channelId,
        incident_id: null,
        attempt: 1,
        outcome: "delivered",
        status_code: 200,
        at: now().toISOString(),
      } satisfies AlertDelivery;
    },
  };
  const mailer = {
    async send(messages: readonly MailEnvelope[]): Promise<MailResult[]> {
      return messages.map(() => ({ ok: true, code: 250 }));
    },
  };

  let organizationId = "";
  let admin = "";
  const s = {
    appId: "",
    shield: "",
    manifest: undefined as BuildManifest | undefined,
    files: [] as { path: string; base64: string }[],
    findingId: "",
    ruleId: "",
    incidentId: "",
    containmentId: "",
    allowlistId: "",
    webhookId: "",
    emailId: "",
    recipientId: "",
    targetId: "",
    spareTargetId: "",
    host: "shop.acme-shop.io",
    token: "",
    campaignId: "",
  };

  beforeAll(async () => {
    api = await makeTestApi({
      now,
      assessor: fakeAssessor(),
      notifier,
      resolve,
      allowPrivateAlertUrls: false,
      email: { mailer, sender: { address: "alerts@airverse.test", name: "Airverse" } },
      prove: { resolver, fetcher },
      // Slice 15a: Campaigns on, with a runner that takes nothing: a created Campaign stays queued.
      campaigns: {
        enabled: true,
        wake() {},
        abort: async () => {},
        isActive: () => false,
        cut: async () => {},
        operatorStop: async () => 0,
        activeCount: async () => 0,
      },
      auditReadsPerMinute: 10_000,
    });
    await syncAdvisories(api.db, fixtureSource(FIXTURES));
    const created = await createOrganization(api, ORGANIZATION_NAME);
    organizationId = created.organization.id;
    admin = created.admin_key.key;
    secrets.push(admin);
  });
  afterAll(async () => {
    expectNoKeyLogged(api);
    await api.close();
  });

  const post = (path: string, body: unknown, headers: Headers = {}) =>
    api.app.request(path, json(body, { ...bearer(admin), ...headers }));
  const bare = (method: string, path: string, headers: Headers = {}) =>
    api.app.request(path, { method, headers: { ...bearer(admin), ...headers } });

  // Read from the store, not through /v1/audit/export: while the Organization's deletion is pending (slice 18b),
  // its key is refused on the audit routes.
  async function entries(): Promise<AuditEntry[]> {
    const page = await api.db.tx({ organizationId }, (q) => auditEntriesAfter(q, 0, 10_000));
    return page.map((entry) => AuditExportLineSchema.parse(entry));
  }

  const CASES: Case[] = [
    {
      route: "POST /v1/apps",
      action: "app.create",
      status: 201,
      run: (h) => post("/v1/apps", { name: "Shop of buyer@acme.test" }, h),
      async after(res) {
        const body = (await res.json()) as { app: { id: string }; shield_key: { key: string } };
        s.appId = body.app.id;
        s.shield = body.shield_key.key;
        api.issuedKeys.push(s.shield);
        secrets.push(s.shield);
      },
    },
    {
      route: "POST /v1/apps/:appId/builds",
      action: "build.register",
      status: 201,
      run(h) {
        const { manifest, files } = artifactFor(s.appId, { canaries: [...EXAMPLE_CANARIES] });
        s.manifest = manifest;
        s.files = files;
        for (const canary of EXAMPLE_CANARIES) secrets.push(canary.value);
        return post(`/v1/apps/${s.appId}/builds`, { manifest }, h);
      },
    },
    {
      route: "POST /v1/apps/:appId/builds/:buildId/assessments",
      action: "assessment.create",
      status: 202,
      run: (h) =>
        post(`/v1/apps/${s.appId}/builds/${s.manifest?.build_id}/assessments`, { tier: "T1", files: s.files }, h),
    },
    {
      route: "POST /v1/findings/:findingId/ignore",
      action: "finding.ignore",
      status: 200,
      async run(h) {
        const components: Component[] = [{ name: "vuln-last", version: "1.2.0", dev: false }];
        const inventory = await api.app.request("/v1/inventory", json({ components }, bearer(s.shield)));
        expect(inventory.status).toBe(202);
        await api.flushIncidents();
        const listed = await api.app.request("/v1/findings", { headers: bearer(admin) });
        const finding = ListFindingsResponseSchema.parse(await listed.json()).findings[0];
        s.findingId = finding?.id ?? "";
        const until = new Date(T0 + DAY).toISOString();
        return post(`/v1/findings/${s.findingId}/ignore`, { reason: "Not reachable", until }, h);
      },
    },
    {
      route: "POST /v1/findings/:findingId/reopen",
      action: "finding.reopen",
      status: 200,
      run: (h) => bare("POST", `/v1/findings/${s.findingId}/reopen`, h),
    },
    {
      route: "PUT /v1/apps/:appId/policies/:environment",
      action: "policy.publish",
      status: 201,
      run: (h) =>
        api.app.request(
          `/v1/apps/${s.appId}/policies/production`,
          put(
            { rules: [{ name: "Login", path: "/login", methods: ["POST"], mode: "monitor" }] },
            { ...bearer(admin), ...h },
          ),
        ),
      async after(res) {
        s.ruleId = PolicyResponseSchema.parse(await res.json()).policy.rules[0]?.id ?? "";
      },
    },
    {
      route: "PUT /v1/apps/:appId/policies/:environment",
      action: "policy.rule.promote",
      sensitive: true,
      status: 201,
      run: (h) =>
        api.app.request(
          `/v1/apps/${s.appId}/policies/production`,
          put(
            {
              rules: [{ id: s.ruleId, name: "Login", path: "/login", methods: ["POST"], mode: "enforce" }],
              expected_version: 1,
            },
            { ...bearer(admin), ...h },
          ),
        ),
    },
    {
      route: "POST /v1/apps/:appId/policies/:environment/rollback",
      action: "policy.rollback",
      status: 201,
      run: (h) => post(`/v1/apps/${s.appId}/policies/production/rollback`, { version: 1, expected_version: 2 }, h),
    },
    {
      route: "POST /v1/apps/:appId/patches/:patchId/mode",
      action: "patch.promote",
      sensitive: true,
      status: 200,
      run: (h) =>
        post(
          `/v1/apps/${s.appId}/patches/${PATCH_ID}/mode`,
          { environment: "production", mode: "enforce", confirm: PATCH_ID },
          h,
        ),
    },
    {
      route: "POST /v1/apps/:appId/patches/:patchId/mode",
      action: "patch.demote",
      status: 200,
      run: (h) =>
        post(`/v1/apps/${s.appId}/patches/${PATCH_ID}/mode`, { environment: "production", mode: "monitor" }, h),
    },
    {
      route: "PATCH /v1/incidents/:incidentId",
      action: "incident.acknowledge",
      status: 200,
      async run(h) {
        const ts = now().toISOString();
        const opened = await api.db.tx({ organizationId }, (q) =>
          recordDetection(q, {
            organizationId,
            appId: s.appId,
            environment: "development",
            rule: DETECTION_RULES[0],
            ipPrefix: PREFIX,
            count: 20,
            windowStart: ts,
            windowEnd: ts,
            detectedAt: now(),
          }),
        );
        s.incidentId = opened.incident.id;
        return api.app.request(`/v1/incidents/${s.incidentId}`, {
          ...json({ status: "acknowledged" }, { ...bearer(admin), ...h }),
          method: "PATCH",
        });
      },
    },
    {
      route: "POST /v1/incidents/:incidentId/containments",
      action: "containment.create",
      sensitive: true,
      status: 201,
      run: (h) =>
        post(
          `/v1/incidents/${s.incidentId}/containments`,
          { target: { kind: "prefix" }, ttl_s: 3600, confirm_prefix: PREFIX },
          h,
        ),
      async after(res) {
        s.containmentId = ContainmentResponseSchema.parse(await res.json()).containment.id;
      },
    },
    {
      route: "POST /v1/containments/:containmentId/lift",
      action: "containment.lift",
      status: 200,
      run: (h) => bare("POST", `/v1/containments/${s.containmentId}/lift`, h),
    },
    {
      route: "PATCH /v1/incidents/:incidentId",
      action: "incident.resolve",
      status: 200,
      run: (h) =>
        api.app.request(`/v1/incidents/${s.incidentId}`, {
          ...json({ status: "resolved" }, { ...bearer(admin), ...h }),
          method: "PATCH",
        }),
    },
    {
      route: "POST /v1/allowlist",
      action: "allowlist_entry.create",
      status: 201,
      run: (h) => post("/v1/allowlist", { cidr: "10.0.0.0/8", note: "Office of it@acme.test" }, h),
      async after(res) {
        s.allowlistId = ((await res.json()) as { entry: { id: string } }).entry.id;
      },
    },
    {
      route: "DELETE /v1/allowlist/:entryId",
      action: "allowlist_entry.delete",
      status: 204,
      run: (h) => bare("DELETE", `/v1/allowlist/${s.allowlistId}`, h),
    },
    {
      route: "POST /v1/alert-channels",
      action: "alert_channel.create",
      status: 201,
      run: (h) => post("/v1/alert-channels", { kind: "webhook", name: "Pager", url: WEBHOOK_URL }, h),
      async after(res) {
        const body = CreateAlertChannelResponseSchema.parse(await res.json());
        s.webhookId = body.channel.id;
        if (body.signing_secret !== undefined) secrets.push(body.signing_secret);
      },
    },
    {
      route: "POST /v1/alert-channels/:channelId/test",
      action: "alert_channel.test",
      status: 200,
      run: (h) => bare("POST", `/v1/alert-channels/${s.webhookId}/test`, h),
    },
    {
      route: "POST /v1/alert-channels",
      action: "alert_channel.create",
      status: 201,
      run: (h) => post("/v1/alert-channels", { kind: "email", name: "On-call", recipients: RECIPIENTS }, h),
      async after(res) {
        const body = CreateAlertChannelResponseSchema.parse(await res.json());
        s.emailId = body.channel.id;
        s.recipientId = body.channel.kind === "email" ? (body.channel.recipients[0]?.id ?? "") : "";
      },
    },
    {
      route: "POST /v1/alert-channels/:channelId/recipients/:recipientId/resend",
      action: "alert_recipient.resend",
      status: 202,
      run: (h) => bare("POST", `/v1/alert-channels/${s.emailId}/recipients/${s.recipientId}/resend`, h),
    },
    {
      route: "DELETE /v1/alert-channels/:channelId",
      action: "alert_channel.delete",
      status: 204,
      run: (h) => bare("DELETE", `/v1/alert-channels/${s.emailId}`, h),
    },
    {
      route: "POST /v1/targets",
      action: "target.create",
      status: 201,
      run: (h) => post("/v1/targets", { host: s.host }, h),
      async after(res) {
        const body = TargetResponseSchema.parse(await res.json());
        s.targetId = body.target.id;
        s.token = body.verification.file_content;
        secrets.push(s.token);
      },
    },
    {
      route: "POST /v1/targets/:targetId/verify",
      action: "target.verify",
      status: 200,
      run(h) {
        txt.set(`_airverse-challenge.${s.host}`, [[`airverse-verification=${s.token}`]]);
        return bare("POST", `/v1/targets/${s.targetId}/verify`, h);
      },
    },
    {
      route: "POST /v1/rules-of-engagement",
      action: "rules_of_engagement.sign",
      sensitive: true,
      status: 201,
      run: (h) =>
        post(
          "/v1/rules-of-engagement",
          {
            scope: [s.targetId],
            exclusions: ["/admin"],
            intensity: "passive",
            window: { days: ["mon", "tue", "wed", "thu", "fri"], from: "09:00", to: "17:00" },
            contacts: [CONTACT],
            confirm: confirmationPhrase("passive"),
          },
          h,
        ),
    },
    // Slice 15a: a Campaign against the verified target under the Rules just signed, then its stop.
    {
      route: "POST /v1/campaigns",
      action: "campaign.create",
      sensitive: true,
      status: 202,
      run: (h) =>
        post(
          "/v1/campaigns",
          {
            target_id: s.targetId,
            intensity: "passive",
            confirm: campaignAuthorisationPhrase(s.host),
            staging: true,
          },
          h,
        ),
      async after(res) {
        s.campaignId = ((await res.json()) as { campaign: { id: string } }).campaign.id;
      },
    },
    {
      route: "POST /v1/campaigns/:id/stop",
      action: "campaign.stop",
      sensitive: true,
      status: 200,
      run: (h) => bare("POST", `/v1/campaigns/${s.campaignId}/stop`, h),
    },
    {
      route: "DELETE /v1/targets/:targetId",
      action: "target.delete",
      sensitive: true,
      status: 204,
      async run(h) {
        if (s.spareTargetId === "") {
          s.spareTargetId = newId("tgt");
          const spare = {
            organizationId,
            id: s.spareTargetId,
            host: "old.acme-shop.io",
            token: generateVerificationToken(),
            createdAt: now(),
          };
          secrets.push(spare.token);
          await api.db.tx({ organizationId }, (q) => insertTarget(q, spare));
        }
        return bare("DELETE", `/v1/targets/${s.spareTargetId}`, h);
      },
    },
    // Slice 18c: the Event retention. Lengthening needs no reason; shortening does.
    {
      route: "PUT /v1/organization/retention",
      action: "organization.retention.update",
      status: 200,
      run: (h) =>
        api.app.request("/v1/organization/retention", put({ event_retention_days: 90 }, { ...bearer(admin), ...h })),
    },
    {
      route: "PUT /v1/organization/retention",
      action: "organization.retention.update",
      sensitive: true,
      status: 200,
      run: (h) =>
        api.app.request("/v1/organization/retention", put({ event_retention_days: 7 }, { ...bearer(admin), ...h })),
    },
    // Slice 18b: data controls. The deletion request comes last but one: until it is cancelled, the key is refused
    // everywhere else.
    {
      route: "POST /v1/subjects/export",
      action: "subject.export",
      status: 200,
      run: (h) => post("/v1/subjects/export", { ip_hash: SUBJECT_HASH }, h),
    },
    {
      route: "POST /v1/subjects/erase",
      action: "subject.erase",
      sensitive: true,
      status: 200,
      run: (h) => post("/v1/subjects/erase", { ip_hash: SUBJECT_HASH }, h),
    },
    {
      route: "POST /v1/organization/deletion",
      action: "organization.deletion.request",
      sensitive: true,
      status: 201,
      run: (h) => post("/v1/organization/deletion", { confirm_name: ORGANIZATION_NAME }, h),
    },
    {
      route: "DELETE /v1/organization/deletion",
      action: "organization.deletion.cancel",
      sensitive: true,
      status: 200,
      run: (h) => bare("DELETE", "/v1/organization/deletion", h),
    },
  ];

  it("covers every mutating route: each writes an entry or is excluded with a reason", () => {
    const mutating = new Set(
      api.app.routes
        .filter((route) => ["POST", "PUT", "PATCH", "DELETE"].includes(route.method))
        .map((route) => `${route.method} ${route.path}`),
    );
    const covered = new Set([SIGNUP, ...CASES.map((kase) => kase.route)]);
    const unaccounted = [...mutating].filter((route) => !covered.has(route) && !(route in EXCLUDED));
    expect(unaccounted).toEqual([]);
    // No stale names: everything listed is a real route.
    expect([...covered, ...Object.keys(EXCLUDED)].filter((route) => !mutating.has(route))).toEqual([]);
    expect([...covered].filter((route) => route in EXCLUDED)).toEqual([]);
  });

  it(`${SIGNUP} → organization.create, the new Organization's first entry`, async () => {
    const [first, ...rest] = await entries();
    expect(rest).toEqual([]);
    expect(first).toMatchObject({ seq: 1, action: "organization.create", target: { id: organizationId } });
  });

  for (const kase of CASES) {
    it(`${kase.route} → ${kase.action}${kase.sensitive === true ? " (reason required)" : ""}`, async () => {
      const before = await entries();
      if (kase.sensitive === true) {
        const refused = await expectProblem(await kase.run({}), 400);
        expect(refused.type).toBe("https://antireverse.dev/problems/reason-required");
        expect(await entries()).toEqual(before);
      }
      const headers: Headers = kase.sensitive === true ? { [AUDIT_REASON_HEADER]: REASON } : {};
      const res = await kase.run(headers);
      expect(res.status, await res.clone().text()).toBe(kase.status);
      await kase.after?.(res);
      const after = await entries();
      expect(after).toHaveLength(before.length + 1);
      const entry = after.at(-1) as AuditEntry;
      expect(entry.action).toBe(kase.action);
      expect(entry.request_id).toBe(res.headers.get("x-request-id"));
      if (kase.sensitive === true) expect(entry.reason).toBe(REASON);
      else expect(entry.reason).toBeUndefined();
    });
  }

  it("leaves a valid chain with one entry per change", async () => {
    const res = await api.app.request("/v1/audit/verify", { headers: bearer(admin) });
    const { verify } = AuditVerifyResponseSchema.parse(await res.json());
    expect(verify).toEqual({
      valid: true,
      entries: CASES.length + 1,
      last_seq: CASES.length + 1,
      first_broken_seq: null,
    });
    const listed = await api.app.request("/v1/audit?limit=200", { headers: bearer(admin) });
    expect(ListAuditResponseSchema.parse(await listed.json()).entries.map((entry) => entry.action)).toEqual(
      ["organization.create", ...CASES.map((kase) => kase.action)].reverse(),
    );
  });

  it("holds no key, token, secret, email address or Canary value in any summary", async () => {
    const all = await entries();
    expect(all).toHaveLength(CASES.length + 1);
    expect(secrets.length).toBeGreaterThan(10);
    for (const entry of all) {
      const text = JSON.stringify(entry);
      for (const secret of secrets) expect(text).not.toContain(secret);
      expect(entry.summary).not.toMatch(/@/);
      expect(entry.summary).not.toMatch(/\b(?:aro|ark)_/);
      expect(entry.summary.length).toBeGreaterThan(0);
    }
  });
});
