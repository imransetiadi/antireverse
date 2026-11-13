import "server-only";
import {
  type AllowlistEntryResponse,
  AllowlistEntryResponseSchema,
  type AppResponse,
  AppResponseSchema,
  type AuthorizeRequest,
  type AuthorizeResult,
  AuthorizeResultSchema,
  type BuildResponse,
  BuildResponseSchema,
  type ConfirmAlertRecipientResponse,
  ConfirmAlertRecipientResponseSchema,
  type ConflictReason,
  type ContainmentResponse,
  ContainmentResponseSchema,
  type ContainmentStatus,
  type CreateAlertChannelRequestInput,
  type CreateAlertChannelResponse,
  CreateAlertChannelResponseSchema,
  type CreateAllowlistEntryRequest,
  type CreateAppRequestInput,
  type CreateAppResponse,
  CreateAppResponseSchema,
  type CreateContainmentRequest,
  type CreateOrganizationRequestInput,
  type CreateOrganizationResponse,
  CreateOrganizationResponseSchema,
  type CurrentRulesOfEngagementResponse,
  CurrentRulesOfEngagementResponseSchema,
  type Environment,
  type FindingDetailResponse,
  FindingDetailResponseSchema,
  type FindingResponse,
  FindingResponseSchema,
  type FindingSeverity,
  type FindingSource,
  type FindingStatus,
  type IgnoreFindingRequestInput,
  type IncidentDetailResponse,
  IncidentDetailResponseSchema,
  IncidentSchema,
  type IncidentStatus,
  LIMITS,
  type ListAlertChannelsResponse,
  ListAlertChannelsResponseSchema,
  type ListAllowlistResponse,
  ListAllowlistResponseSchema,
  type ListAppsResponse,
  ListAppsResponseSchema,
  type ListBuildsResponse,
  ListBuildsResponseSchema,
  type ListContainmentsResponse,
  ListContainmentsResponseSchema,
  type ListEventsResponse,
  ListEventsResponseSchema,
  type ListFindingsResponse,
  ListFindingsResponseSchema,
  type ListIncidentsResponse,
  ListIncidentsResponseSchema,
  type ListPatchesResponse,
  ListPatchesResponseSchema,
  type ListRulesOfEngagementResponse,
  ListRulesOfEngagementResponseSchema,
  type ListTargetsResponse,
  ListTargetsResponseSchema,
  type OrganizationResponse,
  OrganizationResponseSchema,
  type PolicyResponse,
  PolicyResponseSchema,
  type PolicyRuleInput,
  type PolicyVersionsResponse,
  PolicyVersionsResponseSchema,
  type ProblemError,
  ProblemSchema,
  type ResendConfirmationResponse,
  ResendConfirmationResponseSchema,
  type RollbackPolicyRequest,
  type RulesOfEngagementResponse,
  RulesOfEngagementResponseSchema,
  type SetPatchModeRequest,
  type SigningKeyResponse,
  SigningKeyResponseSchema,
  type SignRulesOfEngagementRequest,
  type SimulatePolicyRequestInput,
  type SimulatePolicyResponse,
  SimulatePolicyResponseSchema,
  type TargetResponse,
  TargetResponseSchema,
  type TestAlertChannelResponse,
  TestAlertChannelResponseSchema,
  type UpdateIncidentRequest,
  type VerifyTargetResponse,
  VerifyTargetResponseSchema,
} from "@antireverse/protocol";
import { z } from "zod";

// The Console's only way to the Airverse API. Server-only: the admin key never reaches the browser.
// Every response is validated against the protocol schemas. Error messages are built from the method, the
// path and the status — never from a header — and any text taken from the API is scrubbed of key-shaped,
// secret-shaped and URL-shaped substrings first (an alert channel URL can itself be a secret).

const DEFAULT_API_URL = "http://127.0.0.1:8787";

/** Anything that looks like an admin or Shield key or a webhook signing secret, whole or cut short. */
const KEY_LIKE = /\b(?:aro|ark|whsec)_[A-Za-z0-9_-]+/g;
/** Anything that looks like a URL: an alert channel URL must never travel in an error. */
const URL_LIKE = /\b[a-z][a-z0-9+.-]*:\/\/\S*/gi;
/** Anything that looks like a confirmation token of an alert recipient (43 base64url characters, slice 06b). */
const TOKEN_LIKE = /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g;
const scrub = (text: string): string =>
  text.replace(URL_LIKE, "[redacted]").replace(KEY_LIKE, "[redacted]").replace(TOKEN_LIKE, "[redacted]");

/** The API answered with a failure, answered with something the contract does not allow, or did not answer (status 0). */
export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** 401: the key is missing, malformed, unknown or revoked. */
export class UnauthorizedError extends ApiError {
  constructor(message: string) {
    super(message, 401);
    this.name = "UnauthorizedError";
  }
}

/** 404: the resource does not exist or belongs to another Organization. */
export class NotFoundError extends ApiError {
  constructor(message: string) {
    super(message, 404);
    this.name = "NotFoundError";
  }
}

/**
 * 409: the change conflicts with what the API holds — a Policy published by someone else since, an Incident
 * that is resolved, a block cap reached, a range that overlaps the never block list, a block already ended.
 * Nothing was stored. `reason` is the API's machine-readable kind of conflict (`CONFLICT_REASONS`), or
 * undefined when it sent none (or one the contract does not know).
 */
export class ConflictError extends ApiError {
  readonly reason: ConflictReason | undefined;
  constructor(message: string, reason?: ConflictReason) {
    super(message, 409);
    this.name = "ConflictError";
    this.reason = reason;
  }
}

/** 400: the API refused the input. `errors` says where. */
export class ValidationError extends ApiError {
  readonly errors: ProblemError[];
  constructor(message: string, errors: ProblemError[]) {
    super(message, 400);
    this.name = "ValidationError";
    this.errors = errors;
  }
}

/**
 * 429: too many requests of this kind. `retryAfter` is the whole seconds of the `Retry-After` header, or
 * undefined when the API named none (or anything but a plain number of seconds). It is a number and nothing else:
 * no text of a header travels in an error.
 */
export class RateLimitedError extends ApiError {
  readonly retryAfter: number | undefined;
  constructor(message: string, retryAfter: number | undefined) {
    super(message, 429);
    this.name = "RateLimitedError";
    this.retryAfter = retryAfter;
  }
}

/** Whole seconds, at most five digits: the only form of `Retry-After` that is read. */
const RETRY_AFTER = /^[0-9]{1,5}$/;

function retryAfterSeconds(response: Response): number | undefined {
  const value = response.headers.get("retry-after")?.trim();
  return value !== undefined && RETRY_AFTER.test(value) ? Number(value) : undefined;
}

/** Base URL of the API: `AR_API_URL`, or the local default. No trailing slash. */
export function apiBaseUrl(): string {
  const configured = process.env.AR_API_URL?.trim();
  return (configured ? configured : DEFAULT_API_URL).replace(/\/+$/, "");
}

interface Parser<T> {
  safeParse(value: unknown): { success: true; data: T } | { success: false };
}

interface CallOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  key?: string;
  body?: unknown;
}

async function send(path: string, options: CallOptions & { accept: string; signal?: AbortSignal }): Promise<Response> {
  const headers: Record<string, string> = { accept: options.accept };
  if (options.key !== undefined) headers.authorization = `Bearer ${options.key}`;
  if (options.body !== undefined) headers["content-type"] = "application/json";
  const init: RequestInit = { method: options.method ?? "GET", headers, cache: "no-store" };
  if (options.body !== undefined) init.body = JSON.stringify(options.body);
  if (options.signal !== undefined) init.signal = options.signal;
  return fetch(`${apiBaseUrl()}${path}`, init);
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

async function failure(what: string, response: Response): Promise<ApiError> {
  const parsed = ProblemSchema.safeParse(await readJson(response));
  const title = parsed.success ? `: ${scrub(parsed.data.title)}` : "";
  const message = `${what} failed with status ${response.status}${title}`;
  if (response.status === 401) return new UnauthorizedError(message);
  if (response.status === 404) return new NotFoundError(message);
  if (response.status === 409) return new ConflictError(message, parsed.success ? parsed.data.reason : undefined);
  if (response.status === 429) return new RateLimitedError(message, retryAfterSeconds(response));
  if (response.status === 400) {
    const errors = parsed.success ? (parsed.data.errors ?? []) : [];
    return new ValidationError(
      message,
      errors.map((error) => ({ path: scrub(error.path), message: scrub(error.message) })),
    );
  }
  return new ApiError(message, response.status);
}

async function call<T>(path: string, schema: Parser<T>, options: CallOptions = {}): Promise<T> {
  const what = `${options.method ?? "GET"} ${path}`;
  let response: Response;
  try {
    response = await send(path, { ...options, accept: "application/json" });
  } catch {
    // The cause is dropped on purpose: a transport error may quote the request it could not send.
    throw new ApiError(`${what} failed: the API could not be reached`, 0);
  }
  if (!response.ok) throw await failure(what, response);
  const parsed = schema.safeParse(await readJson(response));
  if (!parsed.success) throw new ApiError(`${what} returned a response that does not match the contract`, 502);
  return parsed.data;
}

/** Like `call`, for a request whose success is 204 No Content: any 2xx resolves, and its body is ignored. */
async function callNoContent(path: string, options: CallOptions): Promise<void> {
  const what = `${options.method ?? "GET"} ${path}`;
  let response: Response;
  try {
    response = await send(path, { ...options, accept: "application/json" });
  } catch {
    throw new ApiError(`${what} failed: the API could not be reached`, 0);
  }
  if (!response.ok) throw await failure(what, response);
}

/** `POST /v1/organizations` — needs no key; the response carries the first admin key, once. */
export function createOrganization(input: CreateOrganizationRequestInput): Promise<CreateOrganizationResponse> {
  return call("/v1/organizations", CreateOrganizationResponseSchema, { method: "POST", body: input });
}

/** `GET /v1/organization` — the Organization the admin key belongs to. */
export function getOrganization(key: string): Promise<OrganizationResponse> {
  return call("/v1/organization", OrganizationResponseSchema, { key });
}

/** `POST /v1/apps` — the response carries the App's Shield key, once. */
export function createApp(key: string, input: CreateAppRequestInput): Promise<CreateAppResponse> {
  return call("/v1/apps", CreateAppResponseSchema, { method: "POST", key, body: input });
}

/** `GET /v1/apps` — newest first. */
export function listApps(key: string): Promise<ListAppsResponse> {
  return call("/v1/apps", ListAppsResponseSchema, { key });
}

/** `GET /v1/apps/:appId` */
export function getApp(key: string, appId: string): Promise<AppResponse> {
  return call(`/v1/apps/${encodeURIComponent(appId)}`, AppResponseSchema, { key });
}

/** `GET /v1/apps/:appId/events?limit=` — newest first. */
export function listEvents(
  key: string,
  appId: string,
  limit: number = LIMITS.listDefault,
): Promise<ListEventsResponse> {
  return call(`/v1/apps/${encodeURIComponent(appId)}/events?limit=${limit}`, ListEventsResponseSchema, { key });
}

/** `GET /v1/apps/:appId/builds` — the App's Builds, newest first, at most `BUILD_LIMITS.listed`. */
export function listBuilds(key: string, appId: string): Promise<ListBuildsResponse> {
  return call(`/v1/apps/${encodeURIComponent(appId)}/builds`, ListBuildsResponseSchema, { key });
}

/** `GET /v1/apps/:appId/builds/:buildId` — one Build; 404 for an unknown Build or one of another Organization. */
export function getBuild(key: string, appId: string, buildId: string): Promise<BuildResponse> {
  return call(`/v1/apps/${encodeURIComponent(appId)}/builds/${encodeURIComponent(buildId)}`, BuildResponseSchema, {
    key,
  });
}

/** `GET /v1/signing-key` — needs no key and sends none: the public key Shield verifies a Policy with. */
export function getSigningKey(): Promise<SigningKeyResponse> {
  return call("/v1/signing-key", SigningKeyResponseSchema);
}

function policyPath(appId: string, environment: Environment): string {
  return `/v1/apps/${encodeURIComponent(appId)}/policies/${encodeURIComponent(environment)}`;
}

/** `GET /v1/apps/:appId/policies/:environment` — version 0 without Rules while nothing was published. */
export function getPolicy(key: string, appId: string, environment: Environment): Promise<PolicyResponse> {
  return call(policyPath(appId, environment), PolicyResponseSchema, { key });
}

/** `GET /v1/apps/:appId/policies/:environment/versions/:version` — one published version with its Rules. */
export function getPolicyVersion(
  key: string,
  appId: string,
  environment: Environment,
  version: number,
): Promise<PolicyResponse> {
  return call(
    `${policyPath(appId, environment)}/versions/${encodeURIComponent(String(version))}`,
    PolicyResponseSchema,
    {
      key,
    },
  );
}

/** `allowBroad`: the person confirmed enforcing a broad pattern (the stronger confirmation). Sent only when true. */
export interface BroadAcknowledgement {
  allowBroad?: boolean;
}

const acknowledged = (options: BroadAcknowledgement) => (options.allowBroad === true ? { allow_broad: true } : {});

/**
 * `PUT /v1/apps/:appId/policies/:environment` — publishes `rules`, in order, as the next version. A Rule
 * sent with its `id` keeps it; one without gets a new one. `expectedVersion` is the version the Rules were
 * read from: when another publish came first, the API stores nothing and this rejects with ConflictError.
 */
export function publishPolicy(
  key: string,
  appId: string,
  environment: Environment,
  rules: readonly PolicyRuleInput[],
  expectedVersion: number,
  options: BroadAcknowledgement = {},
): Promise<PolicyResponse> {
  return call(policyPath(appId, environment), PolicyResponseSchema, {
    method: "PUT",
    key,
    body: { rules, expected_version: expectedVersion, ...acknowledged(options) },
  });
}

/** `GET /v1/apps/:appId/policies/:environment/versions` — newest first, at most 20. */
export function listPolicyVersions(
  key: string,
  appId: string,
  environment: Environment,
): Promise<PolicyVersionsResponse> {
  return call(`${policyPath(appId, environment)}/versions`, PolicyVersionsResponseSchema, { key });
}

/**
 * `POST /v1/apps/:appId/policies/:environment/rollback` — publishes the Rules of `version` as the next version.
 * `expectedVersion` is the current version as last read; when it is no longer current this rejects with
 * ConflictError and nothing is stored.
 */
export function rollbackPolicy(
  key: string,
  appId: string,
  environment: Environment,
  version: number,
  expectedVersion: number,
  options: BroadAcknowledgement = {},
): Promise<PolicyResponse> {
  const body = {
    version,
    expected_version: expectedVersion,
    ...acknowledged(options),
  } satisfies RollbackPolicyRequest;
  return call(`${policyPath(appId, environment)}/rollback`, PolicyResponseSchema, { method: "POST", key, body });
}

/**
 * `POST /v1/apps/:appId/policy/simulate` — what `rules`, in order, would have done to the requests recorded for
 * `environment` in the last 24 hours (slice 11, D-066). Nothing is stored or published. Rejects with
 * ValidationError for Rules a publish would refuse and with RateLimitedError after too many simulations.
 */
export function simulatePolicy(
  key: string,
  appId: string,
  environment: Environment,
  rules: readonly PolicyRuleInput[],
): Promise<SimulatePolicyResponse> {
  const body = { environment, rules: [...rules] } satisfies SimulatePolicyRequestInput;
  return call(`/v1/apps/${encodeURIComponent(appId)}/policy/simulate`, SimulatePolicyResponseSchema, {
    method: "POST",
    key,
    body,
  });
}

/** `GET /v1/apps/:appId/events` — the raw upstream response for the list proxy, whatever its status. */
export function fetchEventList(key: string, appId: string, signal: AbortSignal): Promise<Response> {
  return send(`/v1/apps/${encodeURIComponent(appId)}/events`, { key, accept: "application/json", signal });
}

/**
 * `GET /v1/apps/:appId/events/stream` — the raw upstream response for the stream proxy, whatever its status.
 * `signal` must be the browser request's signal so that a client that leaves closes the upstream stream.
 */
export function openEventStream(key: string, appId: string, signal: AbortSignal): Promise<Response> {
  return send(`/v1/apps/${encodeURIComponent(appId)}/events/stream`, { key, accept: "text/event-stream", signal });
}

// ── Incidents and alert channels (contract P2 of slice 06) ─────────────────────────────────────────────

/** Narrows the Incident list. Both are optional; without them every Incident of the Organization is listed. */
export interface IncidentFilter {
  appId?: string | undefined;
  status?: IncidentStatus | undefined;
}

/** `GET /v1/incidents?app_id=&status=` — newest first by `last_seen`, at most `INCIDENT_LIMITS.listed`. */
export function listIncidents(key: string, filter: IncidentFilter = {}): Promise<ListIncidentsResponse> {
  const query = new URLSearchParams();
  if (filter.appId !== undefined) query.set("app_id", filter.appId);
  if (filter.status !== undefined) query.set("status", filter.status);
  const search = query.toString();
  return call(`/v1/incidents${search ? `?${search}` : ""}`, ListIncidentsResponseSchema, { key });
}

/** `GET /v1/incidents/:incidentId` — the Incident, its Detections and its evidence; 404 outside the Organization. */
export function getIncident(key: string, incidentId: string): Promise<IncidentDetailResponse> {
  return call(`/v1/incidents/${encodeURIComponent(incidentId)}`, IncidentDetailResponseSchema, { key });
}

const UpdateIncidentResponseSchema = z.object({ incident: IncidentSchema });
export type UpdateIncidentResponse = z.infer<typeof UpdateIncidentResponseSchema>;

/**
 * `PATCH /v1/incidents/:incidentId` — moves the Incident to `status`. A transition the API does not allow
 * from the Incident's current status (it changed since it was read) rejects with ConflictError.
 */
export function updateIncident(
  key: string,
  incidentId: string,
  status: UpdateIncidentRequest["status"],
): Promise<UpdateIncidentResponse> {
  const body = { status } satisfies UpdateIncidentRequest;
  return call(`/v1/incidents/${encodeURIComponent(incidentId)}`, UpdateIncidentResponseSchema, {
    method: "PATCH",
    key,
    body,
  });
}

/**
 * `GET /v1/alert-channels` — host and last 4 characters of each URL, never the URL; an email channel's recipients
 * with their status, never a token; and whether the service has SMTP settings.
 */
export function listAlertChannels(key: string): Promise<ListAlertChannelsResponse> {
  return call("/v1/alert-channels", ListAlertChannelsResponseSchema, { key });
}

/**
 * `POST /v1/alert-channels` — a webhook channel's response carries its signing secret, once. A URL the API
 * refuses rejects with ValidationError at path `url`; the 10-channel cap rejects with ConflictError.
 */
export function createAlertChannel(
  key: string,
  input: CreateAlertChannelRequestInput,
): Promise<CreateAlertChannelResponse> {
  return call("/v1/alert-channels", CreateAlertChannelResponseSchema, { method: "POST", key, body: input });
}

/** `DELETE /v1/alert-channels/:channelId` — 204; 404 for an unknown channel or one of another Organization. */
export function deleteAlertChannel(key: string, channelId: string): Promise<void> {
  return callNoContent(`/v1/alert-channels/${encodeURIComponent(channelId)}`, { method: "DELETE", key });
}

/**
 * `POST /v1/alert-channels/:channelId/recipients/:recipientId/resend` — 202: a new confirmation mail is on its way
 * and the previous link no longer works. 429 when the address got its mails of the day; 409 `recipient-confirmed`.
 */
export function resendConfirmation(
  key: string,
  channelId: string,
  recipientId: string,
): Promise<ResendConfirmationResponse> {
  const path = `/v1/alert-channels/${encodeURIComponent(channelId)}/recipients/${encodeURIComponent(recipientId)}/resend`;
  return call(path, ResendConfirmationResponseSchema, { method: "POST", key });
}

/**
 * Public `POST /v1/alert-recipients/confirm` — no key. The token of a confirmation link travels in the body only,
 * never in the address of the request, and no error built here can carry it (see `scrub`).
 */
export function confirmAlertRecipient(token: string): Promise<ConfirmAlertRecipientResponse> {
  return call("/v1/alert-recipients/confirm", ConfirmAlertRecipientResponseSchema, {
    method: "POST",
    body: { token },
  });
}

/** `POST /v1/alert-channels/:channelId/test` — sends one test alert synchronously and returns its delivery. */
export function testAlertChannel(key: string, channelId: string): Promise<TestAlertChannelResponse> {
  return call(`/v1/alert-channels/${encodeURIComponent(channelId)}/test`, TestAlertChannelResponseSchema, {
    method: "POST",
    key,
  });
}

// ── Containment and the never block list (contract P4 of slice 09) ────────────────────────────────────

/**
 * `POST /v1/incidents/:incidentId/containments` — blocks an Actor of the Incident, or its network (with the
 * prefix as typed in `confirm_prefix`). 201 for a new block, 200 when the same active block exists. A resolved
 * Incident, a network that overlaps the never block list and the 150-block cap reject with ConflictError.
 */
export function createContainment(
  key: string,
  incidentId: string,
  request: CreateContainmentRequest,
): Promise<ContainmentResponse> {
  return call(`/v1/incidents/${encodeURIComponent(incidentId)}/containments`, ContainmentResponseSchema, {
    method: "POST",
    key,
    body: request,
  });
}

/** `POST /v1/containments/:containmentId/lift` — ends an active block now; an ended one rejects with ConflictError. */
export function liftContainment(key: string, containmentId: string): Promise<ContainmentResponse> {
  return call(`/v1/containments/${encodeURIComponent(containmentId)}/lift`, ContainmentResponseSchema, {
    method: "POST",
    key,
  });
}

/** Narrows the block list. Every member is optional; without them every block of the Organization is listed. */
export interface ContainmentFilter {
  appId?: string | undefined;
  environment?: Environment | undefined;
  status?: ContainmentStatus | undefined;
}

/** `GET /v1/containments?app_id=&environment=&status=` — newest first. */
export function listContainments(key: string, filter: ContainmentFilter = {}): Promise<ListContainmentsResponse> {
  const query = new URLSearchParams();
  if (filter.appId !== undefined) query.set("app_id", filter.appId);
  if (filter.environment !== undefined) query.set("environment", filter.environment);
  if (filter.status !== undefined) query.set("status", filter.status);
  const search = query.toString();
  return call(`/v1/containments${search ? `?${search}` : ""}`, ListContainmentsResponseSchema, { key });
}

/** `GET /v1/allowlist` — the Organization's never block ranges. */
export function listAllowlist(key: string): Promise<ListAllowlistResponse> {
  return call("/v1/allowlist", ListAllowlistResponseSchema, { key });
}

/** `POST /v1/allowlist` — 201 with the entry; a full list or a listed range rejects with ConflictError. */
export function createAllowlistEntry(key: string, input: CreateAllowlistEntryRequest): Promise<AllowlistEntryResponse> {
  return call("/v1/allowlist", AllowlistEntryResponseSchema, { method: "POST", key, body: input });
}

/** `DELETE /v1/allowlist/:entryId` — 204; 404 for an unknown range or one of another Organization. */
export function deleteAllowlistEntry(key: string, entryId: string): Promise<void> {
  return callNoContent(`/v1/allowlist/${encodeURIComponent(entryId)}`, { method: "DELETE", key });
}

// ── Findings (slice 19) ───────────────────────────────────────────────────────────────────────────────

/** Narrows the Finding list. Every member is optional; without them every Finding of the Organization is listed. */
export interface FindingFilter {
  appId?: string | undefined;
  environment?: Environment | undefined;
  status?: FindingStatus | undefined;
  severity?: FindingSeverity | undefined;
  source?: FindingSource | undefined;
  /** An advisory id or any of its aliases (e.g. a CVE id). */
  advisoryId?: string | undefined;
  /** The build Findings of one Build. */
  buildId?: string | undefined;
}

/** `GET /v1/findings?app_id=&environment=&status=&severity=&source=&advisory_id=&build_id=` — newest first, at most 200. */
export function listFindings(key: string, filter: FindingFilter = {}): Promise<ListFindingsResponse> {
  const query = new URLSearchParams();
  if (filter.appId !== undefined) query.set("app_id", filter.appId);
  if (filter.environment !== undefined) query.set("environment", filter.environment);
  if (filter.status !== undefined) query.set("status", filter.status);
  if (filter.severity !== undefined) query.set("severity", filter.severity);
  if (filter.source !== undefined) query.set("source", filter.source);
  if (filter.advisoryId !== undefined) query.set("advisory_id", filter.advisoryId);
  if (filter.buildId !== undefined) query.set("build_id", filter.buildId);
  const search = query.toString();
  return call(`/v1/findings${search ? `?${search}` : ""}`, ListFindingsResponseSchema, { key });
}

/** `GET /v1/findings/:findingId` — the Finding and its advisory; 404 outside the Organization. */
export function getFinding(key: string, findingId: string): Promise<FindingDetailResponse> {
  return call(`/v1/findings/${encodeURIComponent(findingId)}`, FindingDetailResponseSchema, { key });
}

/**
 * `POST /v1/findings/:findingId/ignore` — ignores the Finding until `until` (at most 90 days ahead, the API's
 * check). A Finding that changed meanwhile rejects with ConflictError; a refused field with ValidationError.
 */
export function ignoreFinding(
  key: string,
  findingId: string,
  request: IgnoreFindingRequestInput,
): Promise<FindingResponse> {
  return call(`/v1/findings/${encodeURIComponent(findingId)}/ignore`, FindingResponseSchema, {
    method: "POST",
    key,
    body: request,
  });
}

/** `POST /v1/findings/:findingId/reopen` — ends an ignore now. */
export function reopenFinding(key: string, findingId: string): Promise<FindingResponse> {
  return call(`/v1/findings/${encodeURIComponent(findingId)}/reopen`, FindingResponseSchema, { method: "POST", key });
}

// ── Virtual patches (slice 20) ────────────────────────────────────────────────────────────────────────

/** `GET /v1/apps/:appId/patches?environment=` — every catalog patch with its mode, activity and hits there. */
export function listPatches(key: string, appId: string, environment: Environment): Promise<ListPatchesResponse> {
  const query = new URLSearchParams({ environment });
  return call(`/v1/apps/${encodeURIComponent(appId)}/patches?${query}`, ListPatchesResponseSchema, { key });
}

/** The body of a mode change: `confirm` is the patch id, required when going to enforce. */
export type PatchModeRequest = SetPatchModeRequest;

/**
 * `POST /v1/apps/:appId/patches/:patchId/mode` — stores the mode and re-issues the bundle. The response body is
 * not read: the page is rendered again from the list.
 */
export function setPatchMode(key: string, appId: string, patchId: string, request: PatchModeRequest): Promise<void> {
  return callNoContent(`/v1/apps/${encodeURIComponent(appId)}/patches/${encodeURIComponent(patchId)}/mode`, {
    method: "POST",
    key,
    body: request,
  });
}

// ── Prove (slice 14) ──────────────────────────────────────────────────────────────────────────────────
// The verification token is part of a target's instructions: it is shown to the admin on the target's page and
// never put into a URL, an error or a log line.

/** `GET /v1/targets` — the Organization's Verified Targets, without their tokens. */
export function listTargets(key: string): Promise<ListTargetsResponse> {
  return call("/v1/targets", ListTargetsResponseSchema, { key });
}

/** `POST /v1/targets` — 201 with the target and how to prove it; a refused host rejects with ValidationError. */
export function createTarget(key: string, input: { host: string }): Promise<TargetResponse> {
  return call("/v1/targets", TargetResponseSchema, { method: "POST", key, body: input });
}

/** `GET /v1/targets/:targetId` — the target and how to prove it; 404 outside the Organization. */
export function getTarget(key: string, targetId: string): Promise<TargetResponse> {
  return call(`/v1/targets/${encodeURIComponent(targetId)}`, TargetResponseSchema, { key });
}

/** `DELETE /v1/targets/:targetId` — 204; a target in the current scope rejects with ConflictError. */
export function deleteTarget(key: string, targetId: string): Promise<void> {
  return callNoContent(`/v1/targets/${encodeURIComponent(targetId)}`, { method: "DELETE", key });
}

/** `POST /v1/targets/:targetId/verify` — checks DNS, then the file; 429 after ten checks of the target in an hour. */
export function verifyTarget(key: string, targetId: string): Promise<VerifyTargetResponse> {
  return call(`/v1/targets/${encodeURIComponent(targetId)}/verify`, VerifyTargetResponseSchema, {
    method: "POST",
    key,
  });
}

/** `GET /v1/rules-of-engagement` — every signed version, newest first. */
export function listRulesOfEngagement(key: string): Promise<ListRulesOfEngagementResponse> {
  return call("/v1/rules-of-engagement", ListRulesOfEngagementResponseSchema, { key });
}

/** `GET /v1/rules-of-engagement/current` — the current version, or `{ version: null }` before the first. */
export function getCurrentRulesOfEngagement(key: string): Promise<CurrentRulesOfEngagementResponse> {
  return call("/v1/rules-of-engagement/current", CurrentRulesOfEngagementResponseSchema, { key });
}

/** `POST /v1/rules-of-engagement` — signs a new, immutable version with the typed phrase; 201 with the version. */
export function signRulesOfEngagement(
  key: string,
  request: SignRulesOfEngagementRequest,
): Promise<RulesOfEngagementResponse> {
  return call("/v1/rules-of-engagement", RulesOfEngagementResponseSchema, { method: "POST", key, body: request });
}

/** `POST /v1/prove/authorize` — a dry check of one test: allowed, or the rule that refuses it. Nothing is started. */
export function checkAuthorization(key: string, request: AuthorizeRequest): Promise<AuthorizeResult> {
  return call("/v1/prove/authorize", AuthorizeResultSchema, { method: "POST", key, body: request });
}
