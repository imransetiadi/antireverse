// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ADMIN_KEY_PATTERN, ENVIRONMENTS, ID_PATTERNS, LIMITS, SHIELD_KEY_PATTERN } from "./constants.ts";
import { StoredEventSchema } from "./events.ts";
import { nameText } from "./shared.ts";

/** A name as a client sends it: trimmed first, then 1..80 characters. */
const NameInputSchema = z.string().trim().min(1).max(LIMITS.nameMax);
/** An App name as a client sends it: the one rule of names (`nameText`). */
const AppNameInputSchema = nameText(LIMITS.nameMax);
const NameSchema = z.string().min(1).max(LIMITS.nameMax);
const EnvironmentSchema = z.enum(ENVIRONMENTS);

/** What stays visible of a key after creation: the scheme plus 6 secret characters, and the last 4. */
const keyDisplay = { prefix: z.string().min(1).max(16), last4: z.string().length(4) };

export const OrganizationSchema = z.object({
  id: z.string().regex(ID_PATTERNS.org),
  name: NameSchema,
  created_at: z.iso.datetime(),
});
export type Organization = z.infer<typeof OrganizationSchema>;

export const AppSchema = z.object({
  id: z.string().regex(ID_PATTERNS.app),
  name: NameSchema,
  created_at: z.iso.datetime(),
});
export type App = z.infer<typeof AppSchema>;

/** Body of `POST /v1/organizations`. */
export const CreateOrganizationRequestSchema = z.object({ name: NameInputSchema });
export type CreateOrganizationRequestInput = z.input<typeof CreateOrganizationRequestSchema>;
export type CreateOrganizationRequest = z.infer<typeof CreateOrganizationRequestSchema>;

/** 201 of `POST /v1/organizations`. `admin_key.key` is returned exactly once. */
export const CreateOrganizationResponseSchema = z.object({
  organization: OrganizationSchema,
  admin_key: z.object({ key: z.string().regex(ADMIN_KEY_PATTERN), ...keyDisplay }),
});
export type CreateOrganizationResponse = z.infer<typeof CreateOrganizationResponseSchema>;

/** 200 of `GET /v1/organization`. */
export const OrganizationResponseSchema = z.object({ organization: OrganizationSchema });
export type OrganizationResponse = z.infer<typeof OrganizationResponseSchema>;

/** Body of `POST /v1/apps`. The Environment of the App's first Shield key defaults to development. */
export const CreateAppRequestSchema = z.object({
  name: AppNameInputSchema,
  environment: EnvironmentSchema.default("development"),
});
/** What a client may send: `environment` is optional. */
export type CreateAppRequestInput = z.input<typeof CreateAppRequestSchema>;
/** What the API works with after parsing: `environment` is always set. */
export type CreateAppRequest = z.infer<typeof CreateAppRequestSchema>;

/** 201 of `POST /v1/apps`. `shield_key.key` is returned exactly once. */
export const CreateAppResponseSchema = z.object({
  app: AppSchema,
  shield_key: z.object({ key: z.string().regex(SHIELD_KEY_PATTERN), ...keyDisplay, environment: EnvironmentSchema }),
});
export type CreateAppResponse = z.infer<typeof CreateAppResponseSchema>;

/** 200 of `GET /v1/apps/:appId`. */
export const AppResponseSchema = z.object({ app: AppSchema });
export type AppResponse = z.infer<typeof AppResponseSchema>;

/** One step of an App's set-up: when it was first done, null while it is not. */
const AppSetupStepSchema = z.object({ done_at: z.iso.datetime().nullable() });
export type AppSetupStep = z.infer<typeof AppSetupStepSchema>;

/**
 * The set-up of one App Environment (slice 16), each step dated by when it was first done. Shield: the first Event
 * received. Guard: the first Event received whose Attestation Token Shield verified. Harden: the first Build
 * registered.
 */
const AppSetupSchema = z.object({
  environment: EnvironmentSchema,
  shield: AppSetupStepSchema,
  guard: AppSetupStepSchema,
  harden: AppSetupStepSchema,
});
export type AppSetup = z.infer<typeof AppSetupSchema>;

/** 200 of `GET /v1/apps/:appId/setup`. */
export const AppSetupResponseSchema = z.object({ setup: AppSetupSchema });
export type AppSetupResponse = z.infer<typeof AppSetupResponseSchema>;

/** 200 of `GET /v1/apps`, newest first. */
export const ListAppsResponseSchema = z.object({ apps: z.array(AppSchema) });
export type ListAppsResponse = z.infer<typeof ListAppsResponseSchema>;

/** 200 of `GET /v1/apps/:appId/events`, newest first. */
export const ListEventsResponseSchema = z.object({ events: z.array(StoredEventSchema) });
export type ListEventsResponse = z.infer<typeof ListEventsResponseSchema>;

/** 202 of `POST /v1/events`. */
export const IngestResponseSchema = z.object({
  accepted: z.int().min(0),
  duplicates: z.int().min(0),
});
export type IngestResponse = z.infer<typeof IngestResponseSchema>;
