import { describe, expect, it } from "vitest";
import {
  ALERT_CHANNEL_KINDS,
  type AlertChannel,
  type AlertChannelKind,
  AlertChannelSchema,
  type AlertDelivery,
  AlertDeliverySchema,
  CONTAINMENT_LIMITS,
  type CreateAlertChannelRequest,
  CreateAlertChannelRequestSchema,
  type CreateAlertChannelResponse,
  CreateAlertChannelResponseSchema,
  DETECTION_RULES,
  type Detection,
  type DetectionRuleKey,
  DetectionSchema,
  EXAMPLE_ADVISORY,
  EXAMPLE_ALERT_CHANNEL,
  EXAMPLE_CANARIES,
  EXAMPLE_CANARY_INCIDENT,
  EXAMPLE_CLONE_INCIDENT,
  EXAMPLE_CONTAINMENT,
  EXAMPLE_DETECTION,
  EXAMPLE_FINDING,
  EXAMPLE_FINDING_INCIDENT,
  EXAMPLE_INCIDENT,
  EXAMPLE_STORED_EVENT,
  INCIDENT_LIMITS,
  INCIDENT_STATUSES,
  type Incident,
  type IncidentDetailResponse,
  IncidentDetailResponseSchema,
  IncidentSchema,
  type IncidentStatus,
  type ListAlertChannelsResponse,
  ListAlertChannelsResponseSchema,
  type ListIncidentsResponse,
  ListIncidentsResponseSchema,
  SEVERITIES,
  type Severity,
  type TestAlertChannelResponse,
  TestAlertChannelResponseSchema,
  type UpdateIncidentRequest,
  UpdateIncidentRequestSchema,
  type WebhookAlertPayload,
  WebhookAlertPayloadSchema,
} from "../src/index.ts";

const ok = (schema: { safeParse: (value: unknown) => { success: boolean } }, value: unknown): boolean =>
  schema.safeParse(value).success;
const iso = (year: number): string => new Date(Date.UTC(year, 0, 1)).toISOString();
const SECRET = `whsec_${"A".repeat(43)}`;
const DELIVERY: AlertDelivery = {
  id: "dlv_0123456789abcdef01234567",
  channel_id: EXAMPLE_ALERT_CHANNEL.id,
  incident_id: EXAMPLE_INCIDENT.id,
  attempt: 1,
  outcome: "delivered",
  status_code: 200,
  at: "2026-11-10T08:20:01.000Z",
};

describe("incident constants", () => {
  it("lists severities, statuses and channel kinds of contract P1", () => {
    const severity: Severity = "high";
    const status: IncidentStatus = "open";
    const kind: AlertChannelKind = "webhook";
    expect(SEVERITIES).toEqual(["critical", severity, "medium", "low", "info"]);
    expect(INCIDENT_STATUSES).toEqual([status, "acknowledged", "resolved"]);
    expect(ALERT_CHANNEL_KINDS).toEqual([kind, "slack", "email"]);
  });

  it("has the eight managed rules of the plans' tables", () => {
    const key: DetectionRuleKey = "blocked-burst";
    expect(DETECTION_RULES).toEqual([
      { key, title: "Blocked burst", severity: "high", threshold: 20, window_s: 300 },
      { key: "failed-signin-burst", title: "Failed sign-in burst", severity: "medium", threshold: 30, window_s: 300 },
      { key: "canary-touched", title: "Canary used", severity: "high", threshold: 1, window_s: 300 },
      { key: "clone-origin", title: "Clone detected", severity: "high", threshold: 1, window_s: 3600 },
      { key: "vulnerable-component", title: "Vulnerable component", severity: "high", threshold: 1, window_s: 3600 },
      { key: "exploit-attempt", title: "Exploit attempt", severity: "high", threshold: 1, window_s: 3600 },
      { key: "credential-stuffing", title: "Credential stuffing", severity: "high", threshold: 50, window_s: 300 },
      { key: "tampered-build", title: "Tampered Build", severity: "high", threshold: 1, window_s: 3600 },
    ]);
    for (const rule of DETECTION_RULES) expect(SEVERITIES).toContain(rule.severity);
  });

  it("freezes the managed rule table so no consumer can change a threshold", () => {
    expect(Object.isFrozen(DETECTION_RULES)).toBe(true);
    expect(DETECTION_RULES.every((rule) => Object.isFrozen(rule))).toBe(true);
  });

  it("has the limits of contract P1", () => {
    expect(INCIDENT_LIMITS).toEqual({
      listed: 50,
      detectionsListed: 100,
      evidence: 20,
      channelsMax: 10,
      urlMax: 2048,
      nameMax: 80,
    });
  });
});

describe("DetectionSchema", () => {
  const detection = (patch: Record<string, unknown>) => ({ ...EXAMPLE_DETECTION, ...patch });

  it("parses the documented example unchanged", () => {
    const parsed: Detection = DetectionSchema.parse(EXAMPLE_DETECTION);
    expect(parsed).toEqual(EXAMPLE_DETECTION);
  });

  it("requires id to match dtc_<24 hex>", () => {
    expect(ok(DetectionSchema, detection({ id: "inc_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(DetectionSchema, detection({ id: "dtc_0123" }))).toBe(false);
  });

  it("requires rule to be a managed rule key", () => {
    for (const rule of DETECTION_RULES) expect(ok(DetectionSchema, detection({ rule: rule.key }))).toBe(true);
    expect(ok(DetectionSchema, detection({ rule: "custom" }))).toBe(false);
  });

  it("requires a known App id and Environment", () => {
    expect(ok(DetectionSchema, detection({ app_id: "org_89abcdef0123456789abcdef" }))).toBe(false);
    expect(ok(DetectionSchema, detection({ environment: "qa" }))).toBe(false);
  });

  it("requires ip_prefix to be a /24 or /48 prefix, or null (a clone reporter without a prefix)", () => {
    expect(ok(DetectionSchema, detection({ ip_prefix: "2001:db8:1::/48" }))).toBe(true);
    expect(ok(DetectionSchema, detection({ ip_prefix: "203.0.113.7" }))).toBe(false);
    expect(ok(DetectionSchema, detection({ ip_prefix: null }))).toBe(true);
    const { ip_prefix: _prefix, ...withoutPrefix } = EXAMPLE_DETECTION;
    expect(ok(DetectionSchema, withoutPrefix)).toBe(false);
  });

  it("carries origin: null for other rules, or a canonical origin for clone-origin (slice 10)", () => {
    expect(EXAMPLE_DETECTION.origin).toBeNull();
    const clone = detection({ rule: "clone-origin", count: 1, origin: "https://clone.example" });
    expect(DetectionSchema.parse(clone)).toEqual(clone);
    expect(ok(DetectionSchema, detection({ origin: "https://Clone.example" }))).toBe(false);
    expect(ok(DetectionSchema, detection({ origin: "https://clone.example/path" }))).toBe(false);
    expect(ok(DetectionSchema, detection({ origin: "" }))).toBe(false);
    const { origin: _origin, ...older } = EXAMPLE_DETECTION;
    expect(ok(DetectionSchema, older)).toBe(false);
  });

  it("requires count to be an integer of at least 0", () => {
    expect(ok(DetectionSchema, detection({ count: 0 }))).toBe(true);
    expect(ok(DetectionSchema, detection({ count: -1 }))).toBe(false);
    expect(ok(DetectionSchema, detection({ count: 1.5 }))).toBe(false);
  });

  it("bounds the event-derived window times and accepts any ISO time for detected_at", () => {
    expect(ok(DetectionSchema, detection({ window_start: iso(1999) }))).toBe(false);
    expect(ok(DetectionSchema, detection({ window_end: iso(2100) }))).toBe(false);
    expect(ok(DetectionSchema, detection({ window_start: "soon" }))).toBe(false);
    expect(ok(DetectionSchema, detection({ detected_at: iso(2101) }))).toBe(true);
    expect(ok(DetectionSchema, detection({ detected_at: "2026-11-10T08:20:00+07:00" }))).toBe(false);
  });

  it("carries canary_id: null for other rules, or a cny id", () => {
    expect(EXAMPLE_DETECTION.canary_id).toBeNull();
    const canary = detection({ rule: "canary-touched", count: 1, canary_id: EXAMPLE_CANARIES[0]?.id });
    expect(DetectionSchema.parse(canary)).toEqual(canary);
    expect(ok(DetectionSchema, detection({ canary_id: "cny_0123" }))).toBe(false);
    expect(ok(DetectionSchema, detection({ canary_id: "bld_0123456789abcdef01234567" }))).toBe(false);
    const { canary_id: _canary, ...older } = EXAMPLE_DETECTION;
    expect(ok(DetectionSchema, older)).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = DetectionSchema.parse(detection({ organization_id: "org_0123456789abcdef01234567" }));
    expect(parsed).toEqual(EXAMPLE_DETECTION);
    expect(parsed).not.toHaveProperty("organization_id");
  });
});

describe("IncidentSchema", () => {
  const incident = (patch: Record<string, unknown>) => ({ ...EXAMPLE_INCIDENT, ...patch });

  it("parses the documented example unchanged", () => {
    const parsed: Incident = IncidentSchema.parse(EXAMPLE_INCIDENT);
    expect(parsed).toEqual(EXAMPLE_INCIDENT);
  });

  it("requires id to match inc_<24 hex>", () => {
    expect(ok(IncidentSchema, incident({ id: "dtc_0123456789abcdef01234567" }))).toBe(false);
  });

  it("requires a managed rule, a known severity and a known status", () => {
    for (const severity of SEVERITIES) expect(ok(IncidentSchema, incident({ severity }))).toBe(true);
    for (const status of INCIDENT_STATUSES) expect(ok(IncidentSchema, incident({ status }))).toBe(true);
    expect(ok(IncidentSchema, incident({ rule: "custom" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ severity: "urgent" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ status: "closed" }))).toBe(false);
  });

  it("limits title to 1..80 storable characters", () => {
    expect(ok(IncidentSchema, incident({ title: "a".repeat(80) }))).toBe(true);
    expect(ok(IncidentSchema, incident({ title: "a".repeat(81) }))).toBe(false);
    expect(ok(IncidentSchema, incident({ title: "" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ title: "a\u0000b" }))).toBe(false);
  });

  it("requires a network prefix or null, and an integer detection_count of at least 0", () => {
    expect(ok(IncidentSchema, incident({ ip_prefix: null }))).toBe(true);
    const { ip_prefix: _prefix, ...withoutPrefix } = EXAMPLE_INCIDENT;
    expect(ok(IncidentSchema, withoutPrefix)).toBe(false);
    expect(ok(IncidentSchema, incident({ ip_prefix: "10.0.0.1/32" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ detection_count: -1 }))).toBe(false);
    expect(ok(IncidentSchema, incident({ detection_count: 2.5 }))).toBe(false);
  });

  it("bounds first_seen and last_seen (from Events) and accepts any ISO time for the server stamps", () => {
    expect(ok(IncidentSchema, incident({ first_seen: iso(1999) }))).toBe(false);
    expect(ok(IncidentSchema, incident({ last_seen: iso(2100) }))).toBe(false);
    expect(ok(IncidentSchema, incident({ created_at: iso(2101), updated_at: iso(2101) }))).toBe(true);
    expect(ok(IncidentSchema, incident({ created_at: "yesterday" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ updated_at: "2026-11-10T08:20:00+07:00" }))).toBe(false);
  });

  it("carries canary_id and build_id: null for other rules", () => {
    expect(EXAMPLE_INCIDENT.canary_id).toBeNull();
    expect(EXAMPLE_INCIDENT.build_id).toBeNull();
    const { canary_id: _canary, ...withoutCanary } = EXAMPLE_INCIDENT;
    const { build_id: _build, ...withoutBuild } = EXAMPLE_INCIDENT;
    expect(ok(IncidentSchema, withoutCanary)).toBe(false);
    expect(ok(IncidentSchema, withoutBuild)).toBe(false);
  });

  it("parses the documented Canary Incident: High, Canary used, naming the Canary and its Build", () => {
    expect(IncidentSchema.parse(EXAMPLE_CANARY_INCIDENT)).toEqual(EXAMPLE_CANARY_INCIDENT);
    expect(EXAMPLE_CANARY_INCIDENT).toMatchObject({
      rule: "canary-touched",
      severity: "high",
      title: "Canary used",
      canary_id: EXAMPLE_CANARIES[0]?.id,
      build_id: "bld_0123456789abcdef01234567",
    });
    expect(Object.isFrozen(EXAMPLE_CANARY_INCIDENT)).toBe(true);
  });

  it("carries origin: null for other rules, and requires the key", () => {
    expect(EXAMPLE_INCIDENT.origin).toBeNull();
    expect(EXAMPLE_CANARY_INCIDENT.origin).toBeNull();
    const { origin: _origin, ...withoutOrigin } = EXAMPLE_INCIDENT;
    expect(ok(IncidentSchema, withoutOrigin)).toBe(false);
    expect(ok(IncidentSchema, incident({ origin: "https://Clone.example" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ origin: "x".repeat(256) }))).toBe(false);
  });

  it("parses the documented clone Incident: High, Clone detected, naming the origin and the Build", () => {
    expect(IncidentSchema.parse(EXAMPLE_CLONE_INCIDENT)).toEqual(EXAMPLE_CLONE_INCIDENT);
    expect(EXAMPLE_CLONE_INCIDENT).toMatchObject({
      rule: "clone-origin",
      severity: "high",
      title: "Clone detected",
      ip_prefix: null,
      origin: "https://clone.example",
      canary_id: null,
      build_id: "bld_0123456789abcdef01234567",
    });
    expect(Object.isFrozen(EXAMPLE_CLONE_INCIDENT)).toBe(true);
    const payload = {
      type: "incident.opened",
      incident: EXAMPLE_CLONE_INCIDENT,
      console_url: "https://console.example/i",
    };
    expect(WebhookAlertPayloadSchema.parse(payload).incident).toEqual(EXAMPLE_CLONE_INCIDENT);
  });

  it("carries advisory_id: null for other rules, and requires the key (slice 19)", () => {
    expect(EXAMPLE_INCIDENT.advisory_id).toBeNull();
    expect(EXAMPLE_CANARY_INCIDENT.advisory_id).toBeNull();
    expect(EXAMPLE_CLONE_INCIDENT.advisory_id).toBeNull();
    const { advisory_id: _advisory, ...withoutAdvisory } = EXAMPLE_INCIDENT;
    expect(ok(IncidentSchema, withoutAdvisory)).toBe(false);
    expect(ok(IncidentSchema, incident({ advisory_id: "GHSA-2c3m-4p5q-6r7v" }))).toBe(true);
    expect(ok(IncidentSchema, incident({ advisory_id: "not an advisory" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ advisory_id: "" }))).toBe(false);
  });

  it("parses the documented vulnerable-component Incident: the Finding's severity, its advisory, no prefix", () => {
    expect(IncidentSchema.parse(EXAMPLE_FINDING_INCIDENT)).toEqual(EXAMPLE_FINDING_INCIDENT);
    expect(EXAMPLE_FINDING_INCIDENT).toMatchObject({
      rule: "vulnerable-component",
      title: "Vulnerable component",
      severity: EXAMPLE_FINDING.severity,
      advisory_id: EXAMPLE_ADVISORY.id,
      app_id: EXAMPLE_FINDING.app_id,
      environment: EXAMPLE_FINDING.environment,
      build_id: EXAMPLE_FINDING.build_id,
      ip_prefix: null,
      canary_id: null,
      origin: null,
    });
    expect(Object.isFrozen(EXAMPLE_FINDING_INCIDENT)).toBe(true);
  });

  it("parses an exploit-attempt Incident and Detection: High, grouped per advisory, no prefix (slice 20)", () => {
    const rule = DETECTION_RULES.find((candidate) => candidate.key === "exploit-attempt");
    expect(rule).toEqual({
      key: "exploit-attempt",
      title: "Exploit attempt",
      severity: "high",
      threshold: 1,
      window_s: 3600,
    });
    const exploit = {
      ...EXAMPLE_FINDING_INCIDENT,
      rule: "exploit-attempt",
      title: "Exploit attempt",
      severity: "high",
      build_id: null,
    };
    expect(IncidentSchema.parse(exploit)).toEqual(exploit);
    expect(ok(DetectionSchema, { ...EXAMPLE_DETECTION, rule: "exploit-attempt" })).toBe(true);
  });

  it("lets a vulnerable-component Incident carry the Finding's severity, Critical included", () => {
    expect(ok(IncidentSchema, { ...EXAMPLE_FINDING_INCIDENT, severity: "critical" })).toBe(true);
  });

  it("requires canary_id to be a cny id and build_id a bld id when set", () => {
    expect(ok(IncidentSchema, incident({ canary_id: "cny_0123" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ canary_id: "bld_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ build_id: "cny_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(IncidentSchema, incident({ build_id: "bld_0123" }))).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = IncidentSchema.parse(incident({ organization_id: "org_0123456789abcdef01234567" }));
    expect(parsed).toEqual(EXAMPLE_INCIDENT);
    expect(parsed).not.toHaveProperty("organization_id");
  });
});

describe("Incident list, detail and update", () => {
  it("wraps a list of Incidents, at most 50", () => {
    const list: ListIncidentsResponse = ListIncidentsResponseSchema.parse({ incidents: [EXAMPLE_INCIDENT] });
    expect(list.incidents).toEqual([EXAMPLE_INCIDENT]);
    expect(ok(ListIncidentsResponseSchema, { incidents: [] })).toBe(true);
    const many = (count: number) => ({ incidents: Array.from({ length: count }, () => EXAMPLE_INCIDENT) });
    expect(ok(ListIncidentsResponseSchema, many(INCIDENT_LIMITS.listed))).toBe(true);
    expect(ok(ListIncidentsResponseSchema, many(INCIDENT_LIMITS.listed + 1))).toBe(false);
  });

  it("carries an Incident, at most 100 Detections and at most 20 stored Events as evidence", () => {
    const detail: IncidentDetailResponse = IncidentDetailResponseSchema.parse({
      incident: EXAMPLE_INCIDENT,
      detections: [EXAMPLE_DETECTION],
      evidence: [EXAMPLE_STORED_EVENT],
      actors: [],
      containments: [],
    });
    expect(detail).toEqual({
      incident: EXAMPLE_INCIDENT,
      detections: [EXAMPLE_DETECTION],
      evidence: [EXAMPLE_STORED_EVENT],
      actors: [],
      containments: [],
    });
    const of = <T>(value: T, count: number): T[] => Array.from({ length: count }, () => value);
    const body = (detections: number, evidence: number) => ({
      incident: EXAMPLE_INCIDENT,
      detections: of(EXAMPLE_DETECTION, detections),
      evidence: of(EXAMPLE_STORED_EVENT, evidence),
      actors: [],
      containments: [],
    });
    expect(ok(IncidentDetailResponseSchema, body(100, 20))).toBe(true);
    expect(ok(IncidentDetailResponseSchema, body(101, 0))).toBe(false);
    expect(ok(IncidentDetailResponseSchema, body(0, 21))).toBe(false);
  });

  it("validates evidence with the stored Event allowlist", () => {
    const detail = { incident: EXAMPLE_INCIDENT, detections: [], actors: [], containments: [] };
    const evidence = [{ ...EXAMPLE_STORED_EVENT, actor: { ip_prefix: "203.0.113.7" } }];
    expect(ok(IncidentDetailResponseSchema, { ...detail, evidence })).toBe(false);
    const hashed = [{ ...EXAMPLE_STORED_EVENT, actor: { ip_prefix: null, ip_hash: "203.0.113.7" } }];
    expect(ok(IncidentDetailResponseSchema, { ...detail, evidence: hashed })).toBe(false);
    const extra = [{ ...EXAMPLE_STORED_EVENT, headers: { cookie: "synthetic" } }];
    const parsed = IncidentDetailResponseSchema.parse({ ...detail, evidence: extra });
    expect(parsed.evidence[0]).not.toHaveProperty("headers");
  });

  describe("actors and containments (slice 09)", () => {
    const HASH = "iph_0123456789abcdef0123456789abcdef";
    const base = { incident: EXAMPLE_INCIDENT, detections: [EXAMPLE_DETECTION], evidence: [EXAMPLE_STORED_EVENT] };
    const actor = (n: number, events = 1) => ({ ip_hash: `iph_${n.toString(16).padStart(32, "0")}`, events });
    const withActors = (actors: unknown) => ({ ...base, actors, containments: [] });
    const withContainments = (containments: unknown) => ({ ...base, actors: [], containments });

    it("carries the Incident's Actors with their Event counts and its Containments", () => {
      const lifted = {
        ...EXAMPLE_CONTAINMENT,
        id: "cnt_89abcdef0123456789abcdef",
        target: { kind: "prefix", ip_prefix: EXAMPLE_INCIDENT.ip_prefix },
        lifted_at: "2026-11-10T08:30:00.000Z",
        lifted_by: "key_0123456789abcdef01234567",
        status: "lifted",
      };
      const body = {
        ...base,
        actors: [
          { ip_hash: HASH, events: 19 },
          { ip_hash: "iph_89abcdef0123456789abcdef01234567", events: 1 },
        ],
        containments: [EXAMPLE_CONTAINMENT, lifted],
      };
      const detail: IncidentDetailResponse = IncidentDetailResponseSchema.parse(body);
      expect(detail).toEqual(body);
      expect(IncidentDetailResponseSchema.parse(JSON.parse(JSON.stringify(body)))).toEqual(body);
    });

    it("requires both keys, even when they are empty", () => {
      expect(ok(IncidentDetailResponseSchema, { ...base, actors: [], containments: [] })).toBe(true);
      expect(ok(IncidentDetailResponseSchema, { ...base, containments: [] })).toBe(false);
      expect(ok(IncidentDetailResponseSchema, { ...base, actors: [] })).toBe(false);
      expect(ok(IncidentDetailResponseSchema, base)).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors(null))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withContainments(null))).toBe(false);
    });

    it("lists at most 10 Actors", () => {
      const many = (count: number) => Array.from({ length: count }, (_, n) => actor(n));
      expect(CONTAINMENT_LIMITS.actorsListed).toBe(10);
      expect(ok(IncidentDetailResponseSchema, withActors(many(10)))).toBe(true);
      expect(ok(IncidentDetailResponseSchema, withActors(many(11)))).toBe(false);
    });

    it("requires each Actor to be a well-formed hash with a whole count of at least 1", () => {
      expect(ok(IncidentDetailResponseSchema, withActors([actor(1, 1)]))).toBe(true);
      expect(ok(IncidentDetailResponseSchema, withActors([actor(1, 1_000_000)]))).toBe(true);
      expect(ok(IncidentDetailResponseSchema, withActors([actor(1, 0)]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors([actor(1, -1)]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors([actor(1, 1.5)]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors([{ ip_hash: HASH, events: "3" }]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors([{ ip_hash: HASH }]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors([{ events: 3 }]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors([{ ip_hash: null, events: 3 }]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors([{ ip_hash: "203.0.113.7", events: 3 }]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withActors([{ ip_hash: "iph_0123", events: 3 }]))).toBe(false);
    });

    it("strips unknown keys from an Actor: no address rides along", () => {
      const parsed = IncidentDetailResponseSchema.parse(
        withActors([{ ip_hash: HASH, events: 3, ip: "203.0.113.7", ip_prefix: "203.0.113.0/24" }]),
      );
      expect(parsed.actors).toEqual([{ ip_hash: HASH, events: 3 }]);
    });

    it("validates each Containment", () => {
      expect(ok(IncidentDetailResponseSchema, withContainments([EXAMPLE_CONTAINMENT]))).toBe(true);
      expect(ok(IncidentDetailResponseSchema, withContainments([{ ...EXAMPLE_CONTAINMENT, id: "cnt_1" }]))).toBe(false);
      expect(ok(IncidentDetailResponseSchema, withContainments([{ ...EXAMPLE_CONTAINMENT, status: "lifted" }]))).toBe(
        false,
      );
      expect(ok(IncidentDetailResponseSchema, withContainments([{ id: EXAMPLE_CONTAINMENT.id }]))).toBe(false);
    });
  });

  it("allows only acknowledged and resolved as a requested status", () => {
    const request: UpdateIncidentRequest = UpdateIncidentRequestSchema.parse({ status: "acknowledged" });
    expect(request).toEqual({ status: "acknowledged" });
    expect(ok(UpdateIncidentRequestSchema, { status: "resolved" })).toBe(true);
    expect(ok(UpdateIncidentRequestSchema, { status: "open" })).toBe(false);
    expect(ok(UpdateIncidentRequestSchema, {})).toBe(false);
  });

  it("strips unknown keys from an update", () => {
    const parsed = UpdateIncidentRequestSchema.parse({ status: "resolved", severity: "low" });
    expect(parsed).toEqual({ status: "resolved" });
  });
});

describe("AlertChannelSchema", () => {
  const channel = (patch: Record<string, unknown>) => ({ ...EXAMPLE_ALERT_CHANNEL, ...patch });

  it("parses the documented example unchanged", () => {
    const parsed: AlertChannel = AlertChannelSchema.parse(EXAMPLE_ALERT_CHANNEL);
    expect(parsed).toEqual(EXAMPLE_ALERT_CHANNEL);
  });

  it("has no url field: a parsed channel never carries the URL", () => {
    const parsed = AlertChannelSchema.parse(channel({ url: "https://hooks.example.com/secret-path" }));
    expect(parsed).not.toHaveProperty("url");
    expect(Object.keys(parsed).sort()).toEqual(["active", "created_at", "host", "id", "kind", "name", "url_last4"]);
  });

  it("never carries the signing secret", () => {
    expect(AlertChannelSchema.parse(channel({ signing_secret: SECRET }))).not.toHaveProperty("signing_secret");
  });

  it("requires id chn_<24 hex> and a known kind", () => {
    expect(ok(AlertChannelSchema, channel({ id: "dlv_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(AlertChannelSchema, channel({ kind: "slack" }))).toBe(true);
    expect(ok(AlertChannelSchema, channel({ kind: "email" }))).toBe(false);
  });

  it("limits name to 1..80 and host to 1..253 storable characters", () => {
    expect(ok(AlertChannelSchema, channel({ name: "a".repeat(80) }))).toBe(true);
    expect(ok(AlertChannelSchema, channel({ name: "a".repeat(81) }))).toBe(false);
    expect(ok(AlertChannelSchema, channel({ name: "" }))).toBe(false);
    expect(ok(AlertChannelSchema, channel({ host: "a".repeat(253) }))).toBe(true);
    expect(ok(AlertChannelSchema, channel({ host: "a".repeat(254) }))).toBe(false);
    expect(ok(AlertChannelSchema, channel({ host: "" }))).toBe(false);
    expect(ok(AlertChannelSchema, channel({ host: "a\u0007b" }))).toBe(false);
  });

  it("requires url_last4 to be exactly 4 characters", () => {
    expect(ok(AlertChannelSchema, channel({ url_last4: "abc" }))).toBe(false);
    expect(ok(AlertChannelSchema, channel({ url_last4: "abcde" }))).toBe(false);
  });

  it("requires a boolean active flag and an ISO created_at", () => {
    expect(ok(AlertChannelSchema, channel({ active: "yes" }))).toBe(false);
    expect(ok(AlertChannelSchema, channel({ created_at: "now" }))).toBe(false);
  });
});

describe("CreateAlertChannelRequestSchema", () => {
  const request = (patch: Record<string, unknown>) => ({
    kind: "webhook",
    name: "Ops webhook",
    url: "https://hooks.example.com/ar",
    ...patch,
  });

  it("parses a webhook and a Slack request", () => {
    const parsed: CreateAlertChannelRequest = CreateAlertChannelRequestSchema.parse(request({}));
    expect(parsed).toEqual(request({}));
    expect(ok(CreateAlertChannelRequestSchema, request({ kind: "slack", url: "https://hooks.slack.com/x" }))).toBe(
      true,
    );
  });

  it("trims the name, then requires 1..80 characters", () => {
    expect(CreateAlertChannelRequestSchema.parse(request({ name: "  Ops  " })).name).toBe("Ops");
    expect(ok(CreateAlertChannelRequestSchema, request({ name: "   " }))).toBe(false);
    expect(ok(CreateAlertChannelRequestSchema, request({ name: "a".repeat(81) }))).toBe(false);
  });

  it("requires a known kind", () => {
    expect(ok(CreateAlertChannelRequestSchema, request({ kind: "pagerduty" }))).toBe(false);
  });

  it("accepts an http: or https: URL of up to 2,048 characters", () => {
    expect(ok(CreateAlertChannelRequestSchema, request({ url: "http://127.0.0.1:9999/hook" }))).toBe(true);
    const base = "https://hooks.example.com/";
    const at = (length: number) => base + "a".repeat(length - base.length);
    expect(ok(CreateAlertChannelRequestSchema, request({ url: at(2048) }))).toBe(true);
    expect(ok(CreateAlertChannelRequestSchema, request({ url: at(2049) }))).toBe(false);
  });

  it("refuses an empty, unparseable or non-http(s) URL", () => {
    for (const url of [
      "",
      "hooks.example.com/ar",
      "not a url",
      "ftp://hooks.example.com/ar",
      "file:///etc/passwd",
      "javascript:alert(1)",
      "data:text/plain,hi",
    ]) {
      expect(ok(CreateAlertChannelRequestSchema, request({ url })), url).toBe(false);
    }
  });

  it("refuses a URL with control characters", () => {
    expect(ok(CreateAlertChannelRequestSchema, request({ url: "https://hooks.example.com/a\u0000b" }))).toBe(false);
  });

  it("reports a refused URL at path url", () => {
    const result = CreateAlertChannelRequestSchema.safeParse(request({ url: "ftp://x.example" }));
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((issue) => issue.path)).toEqual([["url"]]);
  });

  it("strips unknown keys", () => {
    const parsed = CreateAlertChannelRequestSchema.parse(request({ signing_secret: SECRET, active: false }));
    expect(parsed).toEqual(request({}));
  });
});

describe("CreateAlertChannelResponseSchema", () => {
  it("carries the signing secret once for a webhook channel", () => {
    const response: CreateAlertChannelResponse = CreateAlertChannelResponseSchema.parse({
      channel: EXAMPLE_ALERT_CHANNEL,
      signing_secret: SECRET,
    });
    expect(response).toEqual({ channel: EXAMPLE_ALERT_CHANNEL, signing_secret: SECRET });
  });

  it("requires the secret to be whsec_<43 base64url characters>", () => {
    for (const signing_secret of [`whsec_${"A".repeat(42)}`, `whsec_${"A".repeat(44)}`, `whsk_${"A".repeat(43)}`]) {
      expect(ok(CreateAlertChannelResponseSchema, { channel: EXAMPLE_ALERT_CHANNEL, signing_secret })).toBe(false);
    }
    expect(
      ok(CreateAlertChannelResponseSchema, {
        channel: EXAMPLE_ALERT_CHANNEL,
        signing_secret: `whsec_${"-_".repeat(21)}a`,
      }),
    ).toBe(true);
  });

  it("requires a secret for a webhook channel and refuses one for a Slack channel", () => {
    const slack = { ...EXAMPLE_ALERT_CHANNEL, kind: "slack" };
    expect(ok(CreateAlertChannelResponseSchema, { channel: EXAMPLE_ALERT_CHANNEL })).toBe(false);
    expect(ok(CreateAlertChannelResponseSchema, { channel: slack })).toBe(true);
    expect(ok(CreateAlertChannelResponseSchema, { channel: slack, signing_secret: SECRET })).toBe(false);
  });
});

describe("channel list, delivery and test response", () => {
  it("wraps a list of channels", () => {
    const list: ListAlertChannelsResponse = ListAlertChannelsResponseSchema.parse({
      channels: [EXAMPLE_ALERT_CHANNEL],
      smtp_configured: true,
    });
    expect(list.channels).toEqual([EXAMPLE_ALERT_CHANNEL]);
    expect(ok(ListAlertChannelsResponseSchema, { channels: [], smtp_configured: false })).toBe(true);
  });

  it("parses a delivery and a failed delivery without a status code", () => {
    expect(AlertDeliverySchema.parse(DELIVERY)).toEqual(DELIVERY);
    const failed = { ...DELIVERY, incident_id: null, outcome: "failed", status_code: null };
    expect(AlertDeliverySchema.parse(failed)).toEqual(failed);
  });

  it("requires dlv/chn/inc identifiers, an attempt of at least 1 and a known outcome", () => {
    const delivery = (patch: Record<string, unknown>) => ({ ...DELIVERY, ...patch });
    expect(ok(AlertDeliverySchema, delivery({ id: "chn_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(AlertDeliverySchema, delivery({ channel_id: "dlv_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(AlertDeliverySchema, delivery({ incident_id: "dtc_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(AlertDeliverySchema, delivery({ attempt: 0 }))).toBe(false);
    expect(ok(AlertDeliverySchema, delivery({ attempt: 1.5 }))).toBe(false);
    expect(ok(AlertDeliverySchema, delivery({ outcome: "pending" }))).toBe(false);
    expect(ok(AlertDeliverySchema, delivery({ status_code: 99 }))).toBe(false);
    expect(ok(AlertDeliverySchema, delivery({ status_code: 600 }))).toBe(false);
    expect(ok(AlertDeliverySchema, delivery({ at: "later" }))).toBe(false);
  });

  it("strips unknown keys from a delivery (no URL, no secret, no body)", () => {
    const parsed = AlertDeliverySchema.parse({
      ...DELIVERY,
      url: "https://hooks.example.com/x",
      signing_secret: SECRET,
      body: "synthetic",
    });
    expect(parsed).toEqual(DELIVERY);
  });

  it("wraps a delivery as the test response", () => {
    const response: TestAlertChannelResponse = TestAlertChannelResponseSchema.parse({ delivery: DELIVERY });
    expect(response.delivery).toEqual(DELIVERY);
  });
});

describe("WebhookAlertPayloadSchema", () => {
  const opened = {
    type: "incident.opened",
    incident: EXAMPLE_INCIDENT,
    console_url: `http://127.0.0.1:3000/incidents/${EXAMPLE_INCIDENT.id}`,
  };

  it("parses an incident.opened payload and a test payload", () => {
    const parsed: WebhookAlertPayload = WebhookAlertPayloadSchema.parse(opened);
    expect(parsed).toEqual(opened);
    const test = { type: "test", incident: null, console_url: null };
    expect(WebhookAlertPayloadSchema.parse(test)).toEqual(test);
  });

  it("requires a known type", () => {
    expect(ok(WebhookAlertPayloadSchema, { ...opened, type: "incident.resolved" })).toBe(false);
  });

  it("requires an Incident and a console URL for incident.opened", () => {
    expect(ok(WebhookAlertPayloadSchema, { ...opened, incident: null })).toBe(false);
    expect(ok(WebhookAlertPayloadSchema, { ...opened, console_url: null })).toBe(false);
    expect(ok(WebhookAlertPayloadSchema, { ...opened, console_url: "not a url" })).toBe(false);
  });

  it("strips unknown keys", () => {
    expect(WebhookAlertPayloadSchema.parse({ ...opened, signing_secret: SECRET })).toEqual(opened);
  });

  it("carries a Canary Incident with its canary_id and build_id", () => {
    const canary = {
      ...opened,
      incident: EXAMPLE_CANARY_INCIDENT,
      console_url: `http://127.0.0.1:3000/incidents/${EXAMPLE_CANARY_INCIDENT.id}`,
    };
    const parsed = WebhookAlertPayloadSchema.parse(canary);
    expect(parsed.incident?.canary_id).toBe(EXAMPLE_CANARY_INCIDENT.canary_id);
    expect(parsed.incident?.build_id).toBe(EXAMPLE_CANARY_INCIDENT.build_id);
  });
});

describe("incident examples", () => {
  it("are deeply frozen", () => {
    expect(Object.isFrozen(EXAMPLE_INCIDENT)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_DETECTION)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_ALERT_CHANNEL)).toBe(true);
  });

  it("describe one burst: the Detection belongs to the Incident's App, Environment, rule and prefix", () => {
    expect(EXAMPLE_DETECTION.app_id).toBe(EXAMPLE_INCIDENT.app_id);
    expect(EXAMPLE_DETECTION.environment).toBe(EXAMPLE_INCIDENT.environment);
    expect(EXAMPLE_DETECTION.rule).toBe(EXAMPLE_INCIDENT.rule);
    expect(EXAMPLE_DETECTION.ip_prefix).toBe(EXAMPLE_INCIDENT.ip_prefix);
    const rule = DETECTION_RULES.find((candidate) => candidate.key === EXAMPLE_INCIDENT.rule);
    expect(rule?.title).toBe(EXAMPLE_INCIDENT.title);
    expect(rule?.severity).toBe(EXAMPLE_INCIDENT.severity);
    expect(EXAMPLE_DETECTION.count).toBe(rule?.threshold);
  });

  it("show a webhook channel without its URL", () => {
    expect(EXAMPLE_ALERT_CHANNEL.kind).toBe("webhook");
    expect(EXAMPLE_ALERT_CHANNEL).not.toHaveProperty("url");
  });
});
