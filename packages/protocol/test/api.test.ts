import { describe, expect, it } from "vitest";
import {
  type App,
  AppResponseSchema,
  AppSchema,
  type AppSetup,
  type AppSetupResponse,
  AppSetupResponseSchema,
  type CreateAppRequest,
  type CreateAppRequestInput,
  CreateAppRequestSchema,
  type CreateAppResponse,
  CreateAppResponseSchema,
  type CreateOrganizationRequest,
  CreateOrganizationRequestSchema,
  type CreateOrganizationResponse,
  CreateOrganizationResponseSchema,
  ENVIRONMENTS,
  EXAMPLE_STORED_EVENT,
  type IngestResponse,
  IngestResponseSchema,
  ListAppsResponseSchema,
  ListEventsResponseSchema,
  type Organization,
  OrganizationResponseSchema,
} from "../src/index.ts";
import { generateKey, newId } from "../src/server.ts";
import { SAFE_NAMES, UNSAFE_NAMES } from "./names.ts";

const createdAt = "2026-11-10T08:15:30.123Z";
const organization: Organization = { id: newId("org"), name: "Acme", created_at: createdAt };
const app: App = { id: newId("app"), name: "Storefront", created_at: createdAt };

describe("CreateOrganizationRequestSchema", () => {
  it("trims the name", () => {
    const parsed: CreateOrganizationRequest = CreateOrganizationRequestSchema.parse({ name: "  Acme \n" });
    expect(parsed).toEqual({ name: "Acme" });
  });

  it("rejects an empty name, also when it is only whitespace", () => {
    expect(CreateOrganizationRequestSchema.safeParse({ name: "" }).success).toBe(false);
    expect(CreateOrganizationRequestSchema.safeParse({ name: "   " }).success).toBe(false);
    expect(CreateOrganizationRequestSchema.safeParse({}).success).toBe(false);
    expect(CreateOrganizationRequestSchema.safeParse({ name: 42 }).success).toBe(false);
    expect(CreateOrganizationRequestSchema.safeParse(undefined).success).toBe(false);
  });

  it("accepts 80 characters after trimming and rejects 81", () => {
    expect(CreateOrganizationRequestSchema.parse({ name: ` ${"a".repeat(80)} ` })).toEqual({ name: "a".repeat(80) });
    expect(CreateOrganizationRequestSchema.safeParse({ name: "a".repeat(81) }).success).toBe(false);
  });

  it("strips unknown keys", () => {
    expect(CreateOrganizationRequestSchema.parse({ name: "Acme", id: "org_synthetic" })).toEqual({ name: "Acme" });
  });
});

describe("CreateAppRequestSchema", () => {
  it("defaults the Environment to development", () => {
    const input: CreateAppRequestInput = { name: "Storefront" };
    const parsed: CreateAppRequest = CreateAppRequestSchema.parse(input);
    expect(parsed).toEqual({ name: "Storefront", environment: "development" });
  });

  it("accepts each Environment and rejects an unknown one", () => {
    for (const environment of ENVIRONMENTS) {
      expect(CreateAppRequestSchema.parse({ name: "Storefront", environment }).environment).toBe(environment);
    }
    expect(CreateAppRequestSchema.safeParse({ name: "Storefront", environment: "qa" }).success).toBe(false);
    expect(CreateAppRequestSchema.safeParse({ name: "Storefront", environment: "prod" }).success).toBe(false);
    expect(CreateAppRequestSchema.safeParse({ name: "Storefront", environment: null }).success).toBe(false);
  });

  it("trims the name and limits it to 1..80 characters", () => {
    expect(CreateAppRequestSchema.parse({ name: " Storefront " }).name).toBe("Storefront");
    expect(CreateAppRequestSchema.safeParse({ name: "" }).success).toBe(false);
    expect(CreateAppRequestSchema.safeParse({ name: "a".repeat(81) }).success).toBe(false);
  });

  it("refuses control characters, line separators, bidi overrides and zero-width space in an App name", () => {
    for (const name of UNSAFE_NAMES) {
      const result = CreateAppRequestSchema.safeParse({ name });
      expect(result.success, JSON.stringify(name)).toBe(false);
      expect(result.error?.issues.map((issue) => issue.path)).toEqual([["name"]]);
    }
    for (const name of SAFE_NAMES) expect(CreateAppRequestSchema.safeParse({ name }).success, name).toBe(true);
    // A name stored before this rule is still a valid App in a response.
    expect(AppSchema.parse({ ...app, name: "old\r\nname" }).name).toBe("old\r\nname");
  });
});

describe("response schemas", () => {
  it("parses an Organization with its admin key", () => {
    const body: CreateOrganizationResponse = { organization, admin_key: generateKey("admin") };
    expect(CreateOrganizationResponseSchema.parse({ ...body, internal: true })).toEqual(body);
    expect(OrganizationResponseSchema.parse({ organization })).toEqual({ organization });
  });

  it("parses an App with its Shield key", () => {
    for (const environment of ENVIRONMENTS) {
      const body: CreateAppResponse = { app, shield_key: { ...generateKey("shield", environment), environment } };
      expect(CreateAppResponseSchema.parse(body)).toEqual(body);
    }
    expect(AppResponseSchema.parse({ app })).toEqual({ app });
    expect(ListAppsResponseSchema.parse({ apps: [] })).toEqual({ apps: [] });
    expect(ListAppsResponseSchema.parse({ apps: [app, { ...app, key_hash: "synthetic" }] })).toEqual({
      apps: [app, app],
    });
  });

  it("rejects identifiers and keys of the wrong form", () => {
    const adminKey = generateKey("admin");
    const shieldKey = { ...generateKey("shield", "staging"), environment: "staging" };
    expect(OrganizationResponseSchema.safeParse({ organization: { ...organization, id: app.id } }).success).toBe(false);
    expect(AppResponseSchema.safeParse({ app: { ...app, id: "app_1" } }).success).toBe(false);
    expect(AppResponseSchema.safeParse({ app: { ...app, created_at: "today" } }).success).toBe(false);
    expect(CreateOrganizationResponseSchema.safeParse({ organization, admin_key: shieldKey }).success).toBe(false);
    expect(CreateAppResponseSchema.safeParse({ app, shield_key: adminKey }).success).toBe(false);
    expect(CreateAppResponseSchema.safeParse({ app, shield_key: { ...shieldKey, environment: "qa" } }).success).toBe(
      false,
    );
  });

  it("parses a list of stored Events", () => {
    const body = { events: [EXAMPLE_STORED_EVENT] };
    expect(ListEventsResponseSchema.parse(body)).toEqual(body);
    expect(ListEventsResponseSchema.parse({ events: [] })).toEqual({ events: [] });
    expect(
      ListEventsResponseSchema.safeParse({ events: [{ ...EXAMPLE_STORED_EVENT, app_id: undefined }] }).success,
    ).toBe(false);
  });

  it("parses the ingest result as two non-negative integers", () => {
    const body: IngestResponse = { accepted: 3, duplicates: 0 };
    expect(IngestResponseSchema.parse(body)).toEqual(body);
    expect(IngestResponseSchema.safeParse({ accepted: -1, duplicates: 0 }).success).toBe(false);
    expect(IngestResponseSchema.safeParse({ accepted: 1.5, duplicates: 0 }).success).toBe(false);
    expect(IngestResponseSchema.safeParse({ accepted: 1 }).success).toBe(false);
  });
});

describe("AppSetupResponseSchema", () => {
  const setup: AppSetup = {
    environment: "development",
    shield: { done_at: createdAt },
    guard: { done_at: null },
    harden: { done_at: null },
  };

  it("parses each step's time, null while it is not done, and strips unknown keys", () => {
    const body: AppSetupResponse = { setup };
    expect(AppSetupResponseSchema.parse(body)).toEqual(body);
    expect(
      AppSetupResponseSchema.parse({ setup: { ...setup, internal: true, guard: { done_at: null, n: 1 } } }),
    ).toEqual(body);
    for (const environment of ENVIRONMENTS) {
      expect(AppSetupResponseSchema.parse({ setup: { ...setup, environment } }).setup.environment).toBe(environment);
    }
  });

  it("rejects an unknown Environment, a missing step, a missing time and a time that is not ISO", () => {
    expect(AppSetupResponseSchema.safeParse({ setup: { ...setup, environment: "qa" } }).success).toBe(false);
    const { harden: _harden, ...withoutHarden } = setup;
    expect(AppSetupResponseSchema.safeParse({ setup: withoutHarden }).success).toBe(false);
    expect(AppSetupResponseSchema.safeParse({ setup: { ...setup, guard: {} } }).success).toBe(false);
    expect(AppSetupResponseSchema.safeParse({ setup: { ...setup, shield: { done_at: "today" } } }).success).toBe(false);
  });
});
