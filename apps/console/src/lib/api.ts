import "server-only";
import {
  type AllowlistEntryResponse,
  AllowlistEntryResponseSchema,
  type AppResponse,
  AppResponseSchema,
  type AppSetupResponse,
  AppSetupResponseSchema,
  type AssessmentResponse,
  AssessmentResponseSchema,
  type AssessmentTier,
  AUDIT_EXPORT_CONTENT_TYPE,
  AUDIT_REASON_HEADER,
  type AuditAction,
  type AuditPublicKeyResponse,
  AuditPublicKeyResponseSchema,
  type AuditReasonErrorCode,
  type AuditVerifyResponse,
  AuditVerifyResponseSchema,
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
  type CreateAssessmentResponse,
  CreateAssessmentResponseSchema,
  type CreateContainmentRequest,
  type CreateOrganizationRequestInput,
  type CreateOrganizationResponse,
  CreateOrganizationResponseSchema,
  type CurrentRulesOfEngagementResponse,
  CurrentRulesOfEngagementResponseSchema,
  DATA_EXPORT_CONTENT_TYPE,
  type DeletionResponse,
  DeletionResponseSchema,
  type DeletionStatusResponse,
  DeletionStatusResponseSchema,
  type Environment,
  encodeAuditReason,
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
  type ListAssessmentsResponse,
  ListAssessmentsResponseSchema,
  type ListAuditResponse,
  ListAuditResponseSchema,
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
  type RetentionResponse,
  RetentionResponseSchema,
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
  type SubjectEraseResponse,
  SubjectEraseResponseSchema,
  type TargetResponse,
  TargetResponseSchema,
  type TestAlertChannelResponse,
  TestAlertChannelResponseSchema,
  type UpdateIncidentRequest,
  type UpdateRetentionRequest,
  type UpdateRetentionResponse,
  UpdateRetentionResponseSchema,
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

/**
 * 400: the API refused the input. `errors` says where; `code` is the kind of refusal of a reason header
 * (`AUDIT_REASON_ERROR_CODES`, slice 18a), when the API named one.
 */
export class ValidationError extends ApiError {
  readonly errors: ProblemError[];
  readonly code: AuditReasonErrorCode | undefined;
  constructor(message: string, errors: ProblemError[], code?: AuditReasonErrorCode) {
    super(message, 400);
    this.name = "ValidationError";
    this.errors = errors;
    this.code = code;
  }
}

/**
 * 400 `reason-required` (slice 18a): a sensitive change was sent without a reason. Nothing was stored. A
 * ValidationError, so that code that does not know it still treats it as a refusal.
 */
export class ReasonRequiredError extends ValidationError {
  constructor(message: string) {
    super(message, []);
    this.name = "ReasonRequiredError";
  }
}

/**
 * 403 `organization-deletion-pending` (slice 18b): the Organization is scheduled for deletion, and the API refuses
 * every route but the deletion status, its cancellation and the export until the deletion is cancelled.
 */
export class DeletionPendingError extends ApiError {
  constructor(message: string) {
    super(message, 403);
    this.name = "DeletionPendingError";
  }
}

/** The problem type of a pending deletion; matched on its last segment, whatever the API's base. */
const DELETION_PENDING_TYPE = /\/organization-deletion-pending$/;

/** The problem type of a missing reason; matched on its last segment, whatever the API's base. */
const REASON_REQUIRED_TYPE = /\/reason-required$/;

/**
 * The reason of a change (slice 18a), sent as the `X-Airverse-Reason` header, percent-encoded UTF-8. Optional on
 * every change; the API requires it on the sensitive ones.
 */
export interface ReasonOption {
  reason?: string | undefined;
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
  /** The reason of the change, as typed (trimmed). Sent encoded with `encodeAuditReason`. */
  reason?: string | undefined;
}

async function send(path: string, options: CallOptions & { accept: string; signal?: AbortSignal }): Promise<Response> {
  const headers: Record<string, string> = { accept: options.accept };
  if (options.key !== undefined) headers.authorization = `Bearer ${options.key}`;
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.reason !== undefined) headers[AUDIT_REASON_HEADER] = encodeAuditReason(options.reason);
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
  if (response.status === 403 && parsed.success && DELETION_PENDING_TYPE.test(parsed.data.type)) {
    return new DeletionPendingError(message);
  }
  if (response.status === 404) return new NotFoundError(message);
  if (response.status === 409) return new ConflictError(message, parsed.success ? parsed.data.reason : undefined);
  if (response.status === 429) return new RateLimitedError(message, retryAfterSeconds(response));
  if (response.status === 400) {
    if (parsed.success && REASON_REQUIRED_TYPE.test(parsed.data.type)) return new ReasonRequiredError(message);
    const errors = parsed.success ? (parsed.data.errors ?? []) : [];
    return new ValidationError(
      message,
      errors.map((error) => ({ path: scrub(error.path), message: scrub(error.message) })),
      parsed.success ? parsed.data.code : undefined,
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

function setupPath(appId: string, environment?: Environment): string {
  const query = environment === undefined ? "" : `?environment=${encodeURIComponent(environment)}`;
  return `/v1/apps/${encodeURIComponent(appId)}/setup${query}`;
}

/**
 * `GET /v1/apps/:appId/setup?environment=` (slice 16) — when each set-up step of the App Environment was first done;
 * without an Environment the API answers for the App's own.
 */
export function getAppSetup(key: string, appId: string, environment?: Environment): Promise<AppSetupResponse> {
  return call(setupPath(appId, environment), AppSetupResponseSchema, { key });
}

/** The raw upstream response of `GET /v1/apps/:appId/setup`, for the proxy the Set up page polls. */
export function fetchAppSetup(
  key: string,
  appId: string,
  environment: Environment | undefined,
  signal: AbortSignal,
): Promise<Response> {
  return send(setupPath(appId, environment), { key, accept: "application/json", signal });
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

/**
 * `GET /v1/apps/:appId/builds/:buildId/assessments` — the Build's Reverse Assessments (slice 12a), newest first, at
 * most `ASSESSMENT_LIMITS.listed`; 404 for an unknown Build or one of another Organization.
 */
export function listAssessments(key: string, appId: string, buildId: string): Promise<ListAssessmentsResponse> {
  return call(
    `/v1/apps/${encodeURIComponent(appId)}/builds/${encodeURIComponent(buildId)}/assessments`,
    ListAssessmentsResponseSchema,
    { key },
  );
}

/**
 * `POST /v1/apps/:appId/builds/:buildId/assessments` with the tier alone: the API assesses the Build's most recent
 * kept artifact again and answers 202 with the queued Assessment, or 409 `artifact-required` when none is kept. The
 * Console never uploads an artifact.
 */
export function createAssessment(
  key: string,
  appId: string,
  buildId: string,
  request: { tier: AssessmentTier },
): Promise<CreateAssessmentResponse> {
  return call(
    `/v1/apps/${encodeURIComponent(appId)}/builds/${encodeURIComponent(buildId)}/assessments`,
    CreateAssessmentResponseSchema,
    { method: "POST", key, body: { tier: request.tier } },
  );
}

/** `GET /v1/assessments/:id` — one Reverse Assessment; 404 for an unknown one or one of another Organization. */
export function getAssessment(key: string, assessmentId: string): Promise<AssessmentResponse> {
  return call(`/v1/assessments/${encodeURIComponent(assessmentId)}`, AssessmentResponseSchema, { key });
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
  options: BroadAcknowledgement & ReasonOption = {},
): Promise<PolicyResponse> {
  return call(policyPath(appId, environment), PolicyResponseSchema, {
    method: "PUT",
    key,
    body: { rules, expected_version: expectedVersion, ...acknowledged(options) },
    reason: options.reason,
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
  options: BroadAcknowledgement & ReasonOption = {},
): Promise<PolicyResponse> {
  const body = {
    version,
    expected_version: expectedVersion,
    ...acknowledged(options),
  } satisfies RollbackPolicyRequest;
  return call(`${policyPath(appId, environment)}/rollback`, PolicyResponseSchema, {
    method: "POST",
    key,
    body,
    reason: options.reason,
  });
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
  options: ReasonOption = {},
): Promise<ContainmentResponse> {
  return call(`/v1/incidents/${encodeURIComponent(incidentId)}/containments`, ContainmentResponseSchema, {
    method: "POST",
    key,
    body: request,
    reason: options.reason,
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
export function setPatchMode(
  key: string,
  appId: string,
  patchId: string,
  request: PatchModeRequest,
  options: ReasonOption = {},
): Promise<void> {
  return callNoContent(`/v1/apps/${encodeURIComponent(appId)}/patches/${encodeURIComponent(patchId)}/mode`, {
    method: "POST",
    key,
    body: request,
    reason: options.reason,
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
export function deleteTarget(key: string, targetId: string, options: ReasonOption = {}): Promise<void> {
  return callNoContent(`/v1/targets/${encodeURIComponent(targetId)}`, {
    method: "DELETE",
    key,
    reason: options.reason,
  });
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
  options: ReasonOption = {},
): Promise<RulesOfEngagementResponse> {
  return call("/v1/rules-of-engagement", RulesOfEngagementResponseSchema, {
    method: "POST",
    key,
    body: request,
    reason: options.reason,
  });
}

/** `POST /v1/prove/authorize` — a dry check of one test: allowed, or the rule that refuses it. Nothing is started. */
export function checkAuthorization(key: string, request: AuthorizeRequest): Promise<AuthorizeResult> {
  return call("/v1/prove/authorize", AuthorizeResultSchema, { method: "POST", key, body: request });
}

// ── Audit log (slice 18a) ─────────────────────────────────────────────────────────────────────────────

/** Narrows the audit log. Every member is optional; `from` is inclusive and `to` exclusive (ISO times). */
export interface AuditFilter {
  action?: AuditAction | undefined;
  appId?: string | undefined;
  targetId?: string | undefined;
  from?: string | undefined;
  to?: string | undefined;
  /** The `next_cursor` of the previous page. */
  cursor?: string | undefined;
  limit?: number | undefined;
}

/** `GET /v1/audit?action=&app_id=&target_id=&from=&to=&cursor=&limit=` — newest first, one page. */
export function listAudit(key: string, filter: AuditFilter = {}): Promise<ListAuditResponse> {
  const query = new URLSearchParams();
  if (filter.action !== undefined) query.set("action", filter.action);
  if (filter.appId !== undefined) query.set("app_id", filter.appId);
  if (filter.targetId !== undefined) query.set("target_id", filter.targetId);
  if (filter.from !== undefined) query.set("from", filter.from);
  if (filter.to !== undefined) query.set("to", filter.to);
  if (filter.cursor !== undefined) query.set("cursor", filter.cursor);
  if (filter.limit !== undefined) query.set("limit", String(filter.limit));
  const search = query.toString();
  return call(`/v1/audit${search ? `?${search}` : ""}`, ListAuditResponseSchema, { key });
}

/** `GET /v1/audit/public-key` — needs no key and sends none: the public half of the key that signs chain heads. */
export function getAuditPublicKey(): Promise<AuditPublicKeyResponse> {
  return call("/v1/audit/public-key", AuditPublicKeyResponseSchema);
}

/**
 * `GET /v1/audit/verify` — the chain recomputed from the first entry, and the head signed. Rejects with
 * RateLimitedError when checked too often.
 */
export function verifyAudit(key: string): Promise<AuditVerifyResponse> {
  return call("/v1/audit/verify", AuditVerifyResponseSchema, { key });
}

/** `GET /v1/audit/export` — the raw upstream NDJSON response for the export route, whatever its status. */
export function fetchAuditExport(key: string, signal: AbortSignal): Promise<Response> {
  return send("/v1/audit/export", { key, accept: AUDIT_EXPORT_CONTENT_TYPE, signal });
}

// ── Data controls (slice 18b) ─────────────────────────────────────────────────────────────────────────

/** `GET /v1/organization/deletion` — the pending deletion, or null. Answered while a deletion is pending. */
export function getDeletionStatus(key: string): Promise<DeletionStatusResponse> {
  return call("/v1/organization/deletion", DeletionStatusResponseSchema, { key });
}

/**
 * `POST /v1/organization/deletion` — the Organization's name typed exactly and a reason (required). 201 with the
 * pending deletion; 400 on `confirm_name` for another name; 409 when one is already pending.
 */
export function requestDeletion(
  key: string,
  request: { confirm_name: string },
  options: ReasonOption = {},
): Promise<DeletionResponse> {
  return call("/v1/organization/deletion", DeletionResponseSchema, {
    method: "POST",
    key,
    body: { confirm_name: request.confirm_name },
    reason: options.reason,
  });
}

/** `DELETE /v1/organization/deletion` — cancels the pending deletion (reason required); 404 when none is pending. */
export function cancelDeletion(key: string, options: ReasonOption = {}): Promise<DeletionResponse> {
  return call("/v1/organization/deletion", DeletionResponseSchema, { method: "DELETE", key, reason: options.reason });
}

/** `GET /v1/organization/export` — the raw upstream NDJSON response for the export route, whatever its status. */
export function fetchOrganizationExport(key: string, signal: AbortSignal): Promise<Response> {
  return send("/v1/organization/export", { key, accept: DATA_EXPORT_CONTENT_TYPE, signal });
}

/** `POST /v1/subjects/export` — the raw upstream NDJSON response of one actor hash, whatever its status. */
export function fetchSubjectExport(key: string, ipHash: string, signal: AbortSignal): Promise<Response> {
  return send("/v1/subjects/export", {
    method: "POST",
    key,
    body: { ip_hash: ipHash },
    accept: DATA_EXPORT_CONTENT_TYPE,
    signal,
  });
}

/**
 * `POST /v1/subjects/erase` — erases the Events and ended blocks of one actor hash (reason required); active blocks
 * are kept until they end and listed in the report.
 */
export function eraseSubject(key: string, ipHash: string, options: ReasonOption = {}): Promise<SubjectEraseResponse> {
  return call("/v1/subjects/erase", SubjectEraseResponseSchema, {
    method: "POST",
    key,
    body: { ip_hash: ipHash },
    reason: options.reason,
  });
}

// ── Retention (slice 18c) ─────────────────────────────────────────────────────────────────────────────

/** `GET /v1/organization/retention` — the Event retention, the fixed periods and the Organization's last run. */
export function getRetention(key: string): Promise<RetentionResponse> {
  return call("/v1/organization/retention", RetentionResponseSchema, { key });
}

/**
 * `PUT /v1/organization/retention` — sets the Event retention. A shortening needs a reason (400 `reason-required`
 * without one); the answer says before when received Events are removed at the next run.
 */
export function updateRetention(
  key: string,
  request: UpdateRetentionRequest,
  options: ReasonOption = {},
): Promise<UpdateRetentionResponse> {
  return call("/v1/organization/retention", UpdateRetentionResponseSchema, {
    method: "PUT",
    key,
    body: { event_retention_days: request.event_retention_days },
    reason: options.reason,
  });
}
