"use server";

import {
  ACTOR_HASH_PATTERN,
  ADMIN_KEY_PATTERN,
  ALERT_CHANNEL_KINDS,
  ALERT_EMAIL_LIMITS,
  type AlertChannel,
  type AlertChannelKind,
  type AlertDelivery,
  type AllowlistEntry,
  type App,
  type Assessment,
  type AssessmentTier,
  AUDIT_LIMITS,
  AUDIT_REASON_HEADER,
  type AuditEntry,
  type AuditReasonErrorCode,
  AuditReasonSchema,
  type AuthorizeResult,
  CAMPAIGN_INTENSITIES,
  CAMPAIGN_LIMITS,
  type CampaignIntensity,
  CONTAINMENT_LIMITS,
  CONTAINMENT_TTLS,
  type ContainmentTtl,
  CreateAlertChannelRequestSchema,
  type CreateContainmentRequest,
  confirmationPhrase,
  DECISION_MODES,
  type DecisionMode,
  ENVIRONMENTS,
  type Environment,
  EVENT_RETENTION_DAYS,
  type EventRetentionDays,
  EXPOSURE_LIMITS,
  holdsSecretShape,
  ID_PATTERNS,
  INCIDENT_LIMITS,
  INTENSITIES,
  type Intensity,
  IP_PREFIX_PATTERN,
  isBroadPattern,
  LIMIT_COUNTS,
  LIMIT_KEYS,
  LIMIT_LIMITS,
  LIMITS,
  type LimitCount,
  type LimitKey,
  normaliseHost,
  type Organization,
  PATCH_ID_PATTERN,
  PATH_PATTERN,
  POLICY_LIMITS,
  type PolicyRule,
  type PolicyRuleInput,
  parseCidr,
  ROE_LIMITS,
  type RuleLimit,
  RulesOfEngagementContentSchema,
  type SimulationResult,
  type SubjectEraseReport,
  TIER_IDS,
  VERIFICATION_FILE_PATH,
  type VerifyResult,
} from "@antireverse/protocol";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { confirmRecipientToken } from "@/features/alerts/confirm.ts";
import { auditFilterFrom, auditQueryFrom } from "@/features/audit/query.ts";
import { suggestCidr } from "@/features/containment/format.ts";
import { untilFromDate } from "@/features/findings/format.ts";
import { isBroadEnforce, newlyBroad, newlyEnforced } from "@/features/policy/broad.ts";
import { LIMIT_FIELDS, type LimitDraft, wholeNumber } from "@/features/policy/limit.ts";
import { RULE_METHODS } from "@/features/policy/methods.ts";
import { ruleFingerprint } from "@/features/policy/simulation.ts";
import {
  ApiError,
  type CampaignsUnavailable,
  CampaignsUnavailableError,
  ConflictError,
  cancelDeletion,
  checkAuthorization,
  createAlertChannel,
  createAllowlistEntry,
  createApp,
  createAssessment,
  createCampaign,
  createContainment,
  createOrganization,
  createTarget,
  DeletionPendingError,
  deleteAlertChannel,
  deleteAllowlistEntry,
  deleteTarget,
  eraseSubject,
  getOrganization,
  getPolicy,
  getPolicyVersion,
  ignoreFinding,
  liftContainment,
  listAudit,
  NotFoundError,
  type PatchModeRequest,
  publishPolicy,
  RateLimitedError,
  ReasonRequiredError,
  reopenFinding,
  requestDeletion,
  resendConfirmation,
  rollbackPolicy,
  setPatchMode,
  signRulesOfEngagement,
  simulatePolicy,
  stopCampaign,
  testAlertChannel,
  UnauthorizedError,
  updateIncident,
  updateRetention,
  ValidationError,
  verifyAudit,
  verifyTarget,
} from "@/lib/api.ts";
import { ROUTES } from "@/lib/routes.ts";
import { clearSession, readSession, writeSession } from "@/lib/session.ts";
import { type MessageKey, t } from "@/lib/t.ts";

// Server Actions of the Console. Each one is a public POST endpoint: it validates its input and checks
// the session itself. A result that contains a key goes back to the page through the action state and is
// rendered once — it is never put into a URL, a cookie other than the session, or a log line.

/** An error to show next to a field; `path: ""` is about the form as a whole. */
export interface FieldError {
  path: string;
  message: string;
}

export type CreateOrganizationState =
  | null
  | { ok: false; errors: FieldError[]; values: { name: string } }
  | { ok: true; organization: Organization; adminKey: string };

export type SignInState = null | { ok: false; message: string };

export type CreateAppState =
  | null
  | { ok: false; errors: FieldError[]; values: { name: string; environment: string } }
  | { ok: true; app: App; shieldKey: string; environment: Environment };

function text(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === "string" ? value.trim() : "";
}

function nameError(name: string): FieldError | null {
  if (name.length === 0) return { path: "name", message: t("error.name.required") };
  if (name.length > LIMITS.nameMax) return { path: "name", message: t("error.name.long") };
  return null;
}

const isLimitKey = (value: string): value is LimitKey => (LIMIT_KEYS as readonly string[]).includes(value);
const isLimitCount = (value: string): value is LimitCount => (LIMIT_COUNTS as readonly string[]).includes(value);

function isEnvironment(value: string): value is Environment {
  return (ENVIRONMENTS as readonly string[]).includes(value);
}

function isMode(value: string): value is DecisionMode {
  return (DECISION_MODES as readonly string[]).includes(value);
}

/**
 * Slice 18b: what to say when the API refused because the Organization's deletion is pending — a change that was not
 * saved, or a read that was not made — or null for any other error. Every failure branch of an action asks it first,
 * so that a tab opened before the deletion explains the refusal instead of reporting a generic failure.
 */
function deletionPending(error: unknown, kind: "change" | "read" = "change"): string | null {
  if (!(error instanceof DeletionPendingError)) return null;
  return t(kind === "change" ? "error.api.deletionPending" : "error.api.deletionPending.read");
}

/** What to tell the person when the API refused or failed. Anything that is not an ApiError is a defect and is rethrown. */
function apiErrors(error: unknown, fields: readonly string[]): FieldError[] {
  const pending = deletionPending(error);
  if (pending !== null) return [{ path: "", message: pending }];
  if (error instanceof ValidationError) {
    const known = error.errors.filter((entry) => fields.includes(entry.path));
    if (known.length === 0) return [{ path: "", message: t("error.api.failed") }];
    return known.map((entry) => ({ path: entry.path, message: t("error.field") }));
  }
  if (error instanceof ApiError) {
    return [{ path: "", message: error.status === 0 ? t("error.api") : t("error.api.failed") }];
  }
  throw error;
}

// ── The reason of a change (slice 18a) ────────────────────────────────────────────────────────────────
// A sensitive change (a Rule or a virtual patch promoted to enforce, a block, signing Rules of Engagement, removing a
// target) carries a reason, typed in its confirmation step as the field `reason`. It is checked here as the API checks
// it — trimmed, 1 to 500 characters, one line without control characters — before anything is sent, then forwarded
// to the API client, which sends it as the percent-encoded `X-Airverse-Reason` header. The API alone decides.

/** The path the API names when it refuses the reason header itself. */
const REASON_HEADER_PATH = `headers.${AUDIT_REASON_HEADER.toLowerCase()}`;

const reasonError = (key: MessageKey): { error: FieldError } => ({ error: { path: "reason", message: t(key) } });

/**
 * The reason of the form: `{ reason }` (undefined when none was typed and none is required), or the error to show
 * below the field.
 */
function reasonFrom(formData: FormData, required: boolean): { reason: string | undefined } | { error: FieldError } {
  const value = formData.get("reason");
  const reason = typeof value === "string" ? value.trim() : "";
  if (reason.length === 0) return required ? reasonError("error.reason.required") : { reason: undefined };
  if (reason.length > AUDIT_LIMITS.reasonMax) return reasonError("error.reason.long");
  if (!AuditReasonSchema.safeParse(reason).success) return reasonError("error.reason.invalid");
  // The protocol's check, the one the API applies: a reason is stored as given, so a secret in it is refused.
  if (holdsSecretShape(reason)) return reasonError("error.reason.secret");
  return { reason };
}

/**
 * The state of a refused sensitive change, with the reason as typed (trimmed) when there was one, so that the
 * confirmation step shows it again instead of an empty field.
 */
function keptReason<S extends { ok: false } | null>(state: S, formData: FormData): S {
  const reason = text(formData, "reason");
  return state !== null && reason.length > 0 ? { ...state, reason } : state;
}

/** The Console's words for each kind of refused reason the API names (`AUDIT_REASON_ERROR_CODES`). */
const REASON_REFUSAL: Readonly<Record<AuditReasonErrorCode, MessageKey>> = {
  "reason-not-ascii": "error.reason.refused",
  "reason-bad-encoding": "error.reason.refused",
  "reason-empty": "error.reason.required",
  "reason-too-long": "error.reason.long",
  "reason-unsafe-characters": "error.reason.invalid",
  "reason-holds-secret": "error.reason.secret",
};

/**
 * What to say when the API refused a change for its reason: missing (`reason-required`), or refused by its `code`
 * (the API's own words are never matched or shown). A refusal on the header without a code is a generic refusal.
 */
function reasonRefusal(error: unknown): FieldError[] | null {
  if (error instanceof ReasonRequiredError) return [{ path: "reason", message: t("error.reason.required") }];
  if (error instanceof ValidationError) {
    const aboutReason = error.code !== undefined || error.errors.some((entry) => entry.path === REASON_HEADER_PATH);
    if (!aboutReason) return null;
    return [
      { path: "reason", message: t(error.code === undefined ? "error.reason.refused" : REASON_REFUSAL[error.code]) },
    ];
  }
  return null;
}

/** The reason as the API client's option: nothing at all without one. */
const withReason = (reason: string | undefined): { reason?: string } => (reason === undefined ? {} : { reason });

/** Creates an Organization, signs its first admin key in, and returns that key to be shown once. */
export async function createOrganizationAction(
  _previous: CreateOrganizationState,
  formData: FormData,
): Promise<CreateOrganizationState> {
  const name = text(formData, "name");
  const invalid = nameError(name);
  if (invalid) return { ok: false, errors: [invalid], values: { name } };

  let created: Awaited<ReturnType<typeof createOrganization>>;
  try {
    created = await createOrganization({ name });
  } catch (error) {
    return { ok: false, errors: apiErrors(error, ["name"]), values: { name } };
  }
  await writeSession(created.admin_key.key);
  return { ok: true, organization: created.organization, adminKey: created.admin_key.key };
}

/** Signs in with a pasted admin key. The key is stored only when the API accepts it. */
export async function signInAction(_previous: SignInState, formData: FormData): Promise<SignInState> {
  const key = text(formData, "key");
  // A value that is not shaped like an admin key is never sent anywhere.
  if (!ADMIN_KEY_PATTERN.test(key)) return { ok: false, message: t("signin.invalid") };
  try {
    await getOrganization(key);
  } catch (error) {
    // Slice 18b: a valid key of an Organization pending deletion signs in to the one page still open to it.
    if (error instanceof DeletionPendingError) {
      await writeSession(key);
      redirect(ROUTES.dataControls({ blocked: true }));
    }
    if (error instanceof ApiError) {
      const refused = error instanceof UnauthorizedError || error.status === 403;
      return { ok: false, message: refused ? t("signin.invalid") : t("error.api.signin") };
    }
    throw error;
  }
  await writeSession(key);
  redirect(ROUTES.apps);
}

/** Creates an App and one Shield key for the chosen Environment, and returns that key to be shown once. */
export async function createAppAction(_previous: CreateAppState, formData: FormData): Promise<CreateAppState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const name = text(formData, "name");
  const environment = text(formData, "environment") || "development";
  const values = { name, environment };
  const invalid = nameError(name);
  if (invalid) return { ok: false, errors: [invalid], values };
  if (!isEnvironment(environment)) {
    return { ok: false, errors: [{ path: "environment", message: t("error.environment") }], values };
  }

  let created: Awaited<ReturnType<typeof createApp>>;
  try {
    created = await createApp(key, { name, environment });
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    return { ok: false, errors: apiErrors(error, ["name", "environment"]), values };
  }
  return {
    ok: true,
    app: created.app,
    shieldKey: created.shield_key.key,
    environment: created.shield_key.environment,
  };
}

// ── Policy ────────────────────────────────────────────────────────────────────────────────────────────
// Every Policy action publishes one new version: it reads the current Policy, changes it and sends the
// full Rule list back (existing Rules with their id, so that the API keeps them), together with the version
// the page showed (the form's `expectedVersion`). When the Policy moved on since then — found here or by the
// API (409) — the action says the Policy changed and publishes nothing; it never retries on its own.
// Enforcing a broad pattern needs the stronger confirmation: the Environment typed by the person
// (`typedEnvironment`), matched exactly here; only then is `allow_broad` sent. After a publish the action
// revalidates the Policy screen and redirects to its plain address, so that a reload never repeats the
// change and an open confirmation step closes.

export type PublishRuleState = null | {
  ok: false;
  errors: FieldError[];
  /**
   * What was typed, so the form can show it again; `requires` is true when Require a signed request was checked.
   * Slice 08: `action` is the chosen action and `limit` the limit fields as typed, when Throttle was chosen.
   */
  values: {
    name: string;
    path: string;
    methods: string[];
    requires?: boolean;
    action?: "block" | "throttle";
    limit?: LimitDraft;
  };
};

/** `reason`: the reason as typed, given back with a refusal of a sensitive change (slice 18a). */
export type PolicyChangeState = null | { ok: false; errors: FieldError[]; reason?: string };

interface PolicyTarget {
  appId: string;
  environment: Environment;
}

const failed = (path: string, message: string): { ok: false; errors: FieldError[] } => ({
  ok: false,
  errors: [{ path, message }],
});

/** The form no longer matches what the API holds — or it was not sent by this screen. */
const stale = () => failed("", t("error.policy.stale"));
const staleErrors = (): FieldError[] => [{ path: "", message: t("error.policy.stale") }];

/** The App and Environment a Policy form is about, or null when either is not what this screen sends. */
function policyTarget(formData: FormData): PolicyTarget | null {
  const appId = text(formData, "appId");
  const environment = text(formData, "environment");
  if (!ID_PATTERNS.app.test(appId) || !isEnvironment(environment)) return null;
  return { appId, environment };
}

const VERSION = /^[1-9][0-9]{0,8}$/;
const SHOWN_VERSION = /^(?:0|[1-9][0-9]{0,8})$/;

/** The version of the Policy the page showed when the form was rendered, or null when the form has none. */
function shownVersion(formData: FormData): number | null {
  const value = formData.get("expectedVersion");
  return typeof value === "string" && SHOWN_VERSION.test(value) ? Number(value) : null;
}

/** True when the form carries the confirmation step's answer: the Environment that was named in the question. */
function confirmed(formData: FormData, target: PolicyTarget): boolean {
  return text(formData, "confirm") === target.environment;
}

/**
 * The stronger confirmation: the Environment typed by the person, exactly — not trimmed, not folded.
 * Null when it matches; otherwise the error to show below the typed field.
 */
function typedError(formData: FormData, target: PolicyTarget): FieldError | null {
  if (formData.get("typedEnvironment") === target.environment) return null;
  return {
    path: "typedEnvironment",
    message: t("policy.confirm.typed.mismatch", { environment: target.environment }),
  };
}

/** Marks the Policy screen for a fresh render and goes to its plain address. Never returns. */
function published(target: PolicyTarget): never {
  revalidatePath(ROUTES.policy(target.appId));
  redirect(ROUTES.policy(target.appId, target.environment));
}

/**
 * Whether a publish of `rules` carries `allow_broad`: when it holds a broad Enforce Rule and every one of
 * them was either enforced already in `before` (acknowledged then) or confirmed by the person just now.
 * Otherwise nothing is acknowledged, and the API refuses a broad Enforce Rule.
 */
function acknowledgement(
  before: readonly PolicyRule[],
  rules: readonly PolicyRuleInput[],
  confirmedNow: boolean,
): { allowBroad: true } | undefined {
  if (!rules.some(isBroadEnforce)) return undefined;
  return confirmedNow || newlyBroad(before, rules).length === 0 ? { allowBroad: true } : undefined;
}

const RULE_ERROR_PATH = /^rules\.(\d+)\.([A-Za-z_]+)(?:\.|$)/;
/** A refusal of one number of a Rule's limit (slice 08), and the form field that holds it. */
const LIMIT_ERROR_PATH = /^rules\.(\d+)\.limit\.(requests|window_s)$/;
const LIMIT_ERROR_FIELD = { requests: LIMIT_FIELDS.requests, window_s: LIMIT_FIELDS.window } as const;

/**
 * What to tell the person when a publish was refused or failed. `own` is the position of the Rule this
 * action changed and the fields the form shows for it; a refusal about anything else is not blamed on a field.
 * `sent` is the Rule list that was sent: it tells a refused broad pattern from the guardrail.
 * The API's own words are never shown.
 */
function policyErrors(
  error: unknown,
  own?: { index: number; fields: readonly string[] },
  sent: readonly PolicyRuleInput[] = [],
): FieldError[] {
  if (error instanceof ValidationError) {
    const errors = new Map<string, FieldError>();
    for (const entry of error.errors) {
      const [, limitIndex, member] = LIMIT_ERROR_PATH.exec(entry.path) ?? [];
      if (member !== undefined) {
        const name = LIMIT_ERROR_FIELD[member as keyof typeof LIMIT_ERROR_FIELD];
        if (own && Number(limitIndex) === own.index && own.fields.includes(name)) {
          errors.set(name, { path: name, message: t("error.field") });
        }
        continue;
      }
      const [, index, field] = RULE_ERROR_PATH.exec(entry.path) ?? [];
      if (field === undefined) continue;
      // The API's guardrail and its refusal of an unacknowledged broad pattern speak through the mode of a Rule.
      if (field === "mode") {
        const rule = sent[Number(index)];
        const broad = rule !== undefined && rule.path !== BLOCKS_EVERYTHING && isBroadPattern(rule.path);
        errors.set("mode", { path: "mode", message: broad ? t("policy.broad.unconfirmed") : guardrail(rule) });
      } else if (own && Number(index) === own.index && own.fields.includes(field)) {
        errors.set(field, { path: field, message: t(field === "path" ? "error.path.invalid" : "error.field") });
      }
    }
    return errors.size > 0 ? [...errors.values()] : [{ path: "", message: t("error.api.failed") }];
  }
  // The App, the Environment's Policy or the version is not there (any more), or not the caller's; or
  // someone else published since the page showed the Policy.
  if (error instanceof NotFoundError || error instanceof ConflictError) return staleErrors();
  return apiErrors(error, []);
}

/** A Rule in Enforce mode on this pattern would block every request: the API refuses it, and so does the Console. */
const BLOCKS_EVERYTHING = "/**";

/** The guardrail in the words of the Rule it stopped: a limit Rule limits every request, any other blocks it. */
const guardrail = (rule: { limit?: unknown } | undefined): string =>
  t(rule?.limit === undefined ? "policy.guardrail" : "policy.guardrail.limit");

/** What a change makes of the Rules: the next list, the position of the Rule it changed, and whether the person confirmed a broad pattern. */
type Change = { rules: PolicyRuleInput[]; index?: number; broadConfirmed?: boolean } | "unchanged" | FieldError[];

/**
 * Reads the current Policy, lets `change` produce the next Rule list and publishes it as the successor of
 * `shown`, the version the page showed. When the current version is another one, nothing is published.
 * `change` returns the Rules to publish, `"unchanged"` when there is nothing to publish, or the errors to show.
 */
async function changePolicy(
  key: string,
  target: PolicyTarget,
  shown: number,
  change: (rules: PolicyRule[]) => Change,
  fields: readonly string[] = [],
  reason?: string,
): Promise<FieldError[] | null> {
  let index: number | undefined;
  let sent: readonly PolicyRuleInput[] = [];
  try {
    const { policy } = await getPolicy(key, target.appId, target.environment);
    if (policy.version !== shown) return staleErrors();
    const next = change(policy.rules);
    if (next === "unchanged") return null;
    if (Array.isArray(next)) return next;
    index = next.index;
    sent = next.rules;
    const options = {
      ...acknowledgement(policy.rules, next.rules, next.broadConfirmed === true),
      ...withReason(reason),
    };
    if (Object.keys(options).length > 0) {
      await publishPolicy(key, target.appId, target.environment, next.rules, shown, options);
    } else await publishPolicy(key, target.appId, target.environment, next.rules, shown);
    return null;
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    return reasonRefusal(error) ?? policyErrors(error, index === undefined ? undefined : { index, fields }, sent);
  }
}

/** What the add-Rule form holds, as it goes back to the form after a refusal or a simulation. */
type RuleFormValues = NonNullable<PublishRuleState>["values"];

/**
 * The Rule the add-Rule form describes. `values` is what was typed; `rule` is the Rule to send — always in Monitor
 * mode, whatever the form says — or `refused`: `"stale"` for a form this screen never sends, else the errors to show.
 * The publish and the simulation read the form the same way, so what is simulated is what would be added.
 */
function ruleFromForm(
  formData: FormData,
): { values: RuleFormValues } & ({ rule: PolicyRuleInput; refused?: never } | { refused: "stale" | FieldError[] }) {
  const name = text(formData, "name");
  const path = text(formData, "path");
  const chosen = formData.getAll("methods").filter((value): value is string => typeof value === "string");
  // In the order of the form, each once; a method the form does not offer stays visible in `values`.
  const methods = [
    ...RULE_METHODS.filter((method) => chosen.includes(method)),
    ...chosen.filter((method) => !(RULE_METHODS as readonly string[]).includes(method)),
  ];
  // The one requirement the form offers (slice 04). Any other value was not sent by this screen.
  const requirement = formData.get("requires");
  const requires = requirement === "signature";
  // Slice 08: Block (also when the form names no action) or Throttle, which comes with the four limit fields.
  const chosenAction = formData.get("action");
  const throttle = chosenAction === "throttle";
  const limitFields = Object.values(LIMIT_FIELDS);
  const draft: LimitDraft = {
    requests: text(formData, LIMIT_FIELDS.requests),
    window: text(formData, LIMIT_FIELDS.window),
    key: text(formData, LIMIT_FIELDS.key),
    count: text(formData, LIMIT_FIELDS.count),
  };
  const values: RuleFormValues = throttle
    ? { name, path, methods, requires, action: "throttle", limit: draft }
    : { name, path, methods, requires };

  if (requirement !== null && !requires) return { values, refused: "stale" };
  // What this screen never sends: another action, a limit without Throttle, Throttle without every limit
  // field or beside a requirement, and a key or a count it does not offer.
  if (chosenAction !== null && chosenAction !== "block" && !throttle) return { values, refused: "stale" };
  if (throttle) {
    if (requires || limitFields.some((field) => typeof formData.get(field) !== "string")) {
      return { values, refused: "stale" };
    }
    if (!isLimitKey(draft.key) || !isLimitCount(draft.count)) return { values, refused: "stale" };
  } else if (limitFields.some((field) => formData.has(field))) {
    return { values, refused: "stale" };
  }

  const invalid: FieldError[] = [];
  const badName = nameError(name);
  if (badName) invalid.push(badName);
  if (path.length === 0) invalid.push({ path: "path", message: t("error.path.required") });
  else if (!PATH_PATTERN.test(path)) invalid.push({ path: "path", message: t("error.path.invalid") });
  if (methods.some((method) => !(RULE_METHODS as readonly string[]).includes(method))) {
    invalid.push({ path: "methods", message: t("error.methods") });
  }
  // The limit mirrors the protocol: whole numbers, 1 to 100,000 requests per window of 1 to 3,600 seconds.
  let limit: RuleLimit | undefined;
  if (throttle && isLimitKey(draft.key) && isLimitCount(draft.count)) {
    const requests = wholeNumber(draft.requests, LIMIT_LIMITS.requestsMax);
    const window_s = wholeNumber(draft.window, LIMIT_LIMITS.windowSecondsMax);
    if (requests === null) invalid.push({ path: LIMIT_FIELDS.requests, message: t("error.limit.requests") });
    if (window_s === null) invalid.push({ path: LIMIT_FIELDS.window, message: t("error.limit.window") });
    if (requests !== null && window_s !== null) limit = { requests, window_s, key: draft.key, count: draft.count };
  }
  if (invalid.length > 0) return { values, refused: invalid };

  // The mode is not read from the form: a new Rule observes first, whatever its pattern.
  // A requirement keeps the action block: the Rule blocks only the requests that do not meet it.
  // A limit makes the action throttle; the two never go together with a requirement (checked above).
  const rule: PolicyRuleInput = limit
    ? { name, path, methods, action: "throttle", mode: "monitor", limit }
    : { name, path, methods, action: "block", mode: "monitor" };
  if (requires) rule.requires = "signature";
  return { values, rule };
}

/** The fields of the add-Rule form a refusal of the API can be shown below. */
const RULE_FORM_FIELDS = ["name", "path", "methods", LIMIT_FIELDS.requests, LIMIT_FIELDS.window] as const;

/** Adds one Rule to the end of the Policy — always in Monitor mode — and publishes. */
export async function publishRuleAction(_previous: PublishRuleState, formData: FormData): Promise<PublishRuleState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const typed = ruleFromForm(formData);
  const { values } = typed;
  const target = policyTarget(formData);
  const shown = shownVersion(formData);
  if (!target || shown === null || typed.refused === "stale") return { ...stale(), values };
  if (typed.refused) return { ok: false, errors: typed.refused, values };
  const { rule } = typed;

  const errors = await changePolicy(
    key,
    target,
    shown,
    (rules) => {
      if (rules.length >= POLICY_LIMITS.rulesMax) return [{ path: "", message: t("error.rules.max") }];
      return { rules: [...rules, rule], index: rules.length };
    },
    RULE_FORM_FIELDS,
  );
  if (errors) return { ok: false, errors, values };
  published(target);
}

// Policy simulation (slice 11, D-066): an estimate of what Rules would have done to the requests recorded in the
// last 24 hours. The action reads the Policy itself — the Rules are never taken from the form — and asks the API
// for the estimate. It publishes nothing, revalidates nothing and goes nowhere: the answer lives in the state of
// the page view that asked.

export type SimulationState =
  | null
  | {
      ok: true;
      /** True when the Rule being typed in the add-Rule form was simulated after the current Rules. */
      withDraft: boolean;
      simulation: SimulationResult;
      /** The mark (`ruleFingerprint`) of every Rule that was simulated, in order. */
      rules: string[];
      /** With a typed Rule: what was typed, so the form still holds it. */
      values?: RuleFormValues;
    }
  | { ok: false; withDraft: boolean; errors: FieldError[]; values?: RuleFormValues };

const simulationFailed = (key: MessageKey): FieldError[] => [{ path: "", message: t(key) }];

/** What to tell the person when a simulation was refused or failed. `own` and `sent` as for `policyErrors`. */
function simulationErrors(
  error: unknown,
  own: { index: number; fields: readonly string[] } | undefined,
  sent: readonly PolicyRuleInput[],
): FieldError[] {
  const pending = deletionPending(error);
  if (pending !== null) return [{ path: "", message: pending }];
  if (error instanceof RateLimitedError) {
    return [
      {
        path: "",
        message:
          error.retryAfter === undefined
            ? t("policy.simulate.limited.soon")
            : t("policy.simulate.limited", { seconds: Math.max(1, error.retryAfter) }),
      },
    ];
  }
  // The App or the Environment's Policy is not there (any more), or not the caller's.
  if (error instanceof NotFoundError || error instanceof ConflictError)
    return simulationFailed("policy.simulate.stale");
  if (error instanceof ValidationError) {
    // Only what is about a field of the typed Rule is shown below that field; the API's own words never are.
    const fields = policyErrors(error, own, sent).filter((entry) => own?.fields.includes(entry.path));
    return fields.length > 0 ? fields : simulationFailed("policy.simulate.failed");
  }
  if (error instanceof ApiError) {
    return simulationFailed(error.status === 0 ? "policy.simulate.unreachable" : "policy.simulate.failed");
  }
  throw error;
}

/**
 * Simulates the Rules of the Policy the page shows — with `simulate=draft`, followed by the Rule being typed in the
 * add-Rule form. Nothing is published.
 */
export async function simulatePolicyAction(_previous: SimulationState, formData: FormData): Promise<SimulationState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const which = formData.get("simulate");
  const withDraft = which === "draft";
  const typed = withDraft ? ruleFromForm(formData) : undefined;
  const answer = typed ? { withDraft, values: typed.values } : { withDraft };
  const refuse = (errors: FieldError[]): SimulationState => ({ ok: false, ...answer, errors });

  const target = policyTarget(formData);
  const shown = shownVersion(formData);
  if (!target || shown === null || (which !== null && !withDraft) || typed?.refused === "stale") {
    return refuse(simulationFailed("policy.simulate.stale"));
  }
  if (typed?.refused) return refuse(typed.refused);

  let sent: PolicyRuleInput[] = [];
  try {
    const { policy } = await getPolicy(key, target.appId, target.environment);
    if (policy.version !== shown) return refuse(simulationFailed("policy.simulate.stale"));
    if (typed && policy.rules.length >= POLICY_LIMITS.rulesMax) return refuse(simulationFailed("error.rules.max"));
    sent = typed ? [...policy.rules, typed.rule] : policy.rules;
    const { simulation } = await simulatePolicy(key, target.appId, target.environment, sent);
    return { ok: true, ...answer, simulation, rules: sent.map(ruleFingerprint) };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    return refuse(
      simulationErrors(error, typed ? { index: sent.length - 1, fields: RULE_FORM_FIELDS } : undefined, sent),
    );
  }
}

/**
 * Changes the mode of one Rule and publishes. Promoting to Enforce starts blocking requests, so it is
 * refused unless the form carries the confirmation — and, for a broad pattern, the typed Environment.
 * Going back to Monitor needs none.
 */
export async function setRuleModeAction(previous: PolicyChangeState, formData: FormData): Promise<PolicyChangeState> {
  return keptReason(await setRuleMode(previous, formData), formData);
}

async function setRuleMode(_previous: PolicyChangeState, formData: FormData): Promise<PolicyChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const target = policyTarget(formData);
  const shown = shownVersion(formData);
  const ruleId = text(formData, "ruleId");
  const mode = text(formData, "mode");
  if (!target || shown === null || !ID_PATTERNS.rul.test(ruleId) || !isMode(mode)) return stale();
  if (mode === "enforce" && !confirmed(formData, target)) return failed("confirm", t("policy.confirm.required"));
  // Promoting to Enforce is a sensitive change: it carries a reason. Back to Monitor needs none.
  const read = reasonFrom(formData, mode === "enforce");
  if ("error" in read) return { ok: false, errors: [read.error] };

  const errors = await changePolicy(
    key,
    target,
    shown,
    (rules) => {
      const index = rules.findIndex((rule) => rule.id === ruleId);
      const rule = rules[index];
      if (!rule) return staleErrors();
      if (rule.mode === mode) return "unchanged";
      let broadConfirmed = false;
      if (mode === "enforce") {
        if (rule.path === BLOCKS_EVERYTHING) return [{ path: "mode", message: guardrail(rule) }];
        if (isBroadPattern(rule.path)) {
          const typed = typedError(formData, target);
          if (typed) return [typed];
          broadConfirmed = true;
        }
      }
      return { rules: rules.map((other) => (other === rule ? { ...rule, mode } : other)), index, broadConfirmed };
    },
    [],
    read.reason,
  );
  if (errors) return { ok: false, errors };
  published(target);
}

/** Removes one Rule and publishes. A Rule that is already gone is not an error. */
export async function removeRuleAction(_previous: PolicyChangeState, formData: FormData): Promise<PolicyChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const target = policyTarget(formData);
  const shown = shownVersion(formData);
  const ruleId = text(formData, "ruleId");
  if (!target || shown === null || !ID_PATTERNS.rul.test(ruleId)) return stale();

  const errors = await changePolicy(key, target, shown, (rules) => {
    const rest = rules.filter((rule) => rule.id !== ruleId);
    return rest.length === rules.length ? "unchanged" : { rules: rest };
  });
  if (errors) return { ok: false, errors };
  published(target);
}

/**
 * Publishes the Rules of an earlier version as the next version. It can bring enforced Rules back, so it
 * is refused unless the form carries the confirmation — and, when it brings back a broad Enforce Rule that
 * is not enforced now, the typed Environment.
 */
export async function rollbackPolicyAction(
  previous: PolicyChangeState,
  formData: FormData,
): Promise<PolicyChangeState> {
  return keptReason(await rollbackPolicyChange(previous, formData), formData);
}

async function rollbackPolicyChange(_previous: PolicyChangeState, formData: FormData): Promise<PolicyChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const target = policyTarget(formData);
  const shown = shownVersion(formData);
  const version = text(formData, "version");
  if (!target || shown === null || !VERSION.test(version)) return stale();
  if (!confirmed(formData, target)) return failed("confirm", t("policy.confirm.required"));
  // A reason is always accepted; it is required once the earlier version is known to enforce a Rule anew.
  const read = reasonFrom(formData, false);
  if ("error" in read) return { ok: false, errors: [read.error] };

  let sent: readonly PolicyRule[] = [];
  try {
    const { policy: current } = await getPolicy(key, target.appId, target.environment);
    if (current.version !== shown) return stale();
    const { policy: earlier } = await getPolicyVersion(key, target.appId, target.environment, Number(version));
    sent = earlier.rules;
    const confirmedNow = newlyBroad(current.rules, earlier.rules).length > 0;
    if (confirmedNow) {
      const typed = typedError(formData, target);
      if (typed) return { ok: false, errors: [typed] };
    }
    if (read.reason === undefined && newlyEnforced(current.rules, earlier.rules).length > 0) {
      return { ok: false, errors: [reasonError("error.reason.required").error] };
    }
    const options = { ...acknowledgement(current.rules, earlier.rules, confirmedNow), ...withReason(read.reason) };
    if (Object.keys(options).length > 0) {
      await rollbackPolicy(key, target.appId, target.environment, Number(version), shown, options);
    } else await rollbackPolicy(key, target.appId, target.environment, Number(version), shown);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    return { ok: false, errors: reasonRefusal(error) ?? policyErrors(error, undefined, sent) };
  }
  published(target);
}

// ── Incidents ─────────────────────────────────────────────────────────────────────────────────────────
// Acknowledging an Incident is sent at once. Resolving is final (a resolved Incident is never reopened), so
// it is refused unless the form carries the confirmation step's answer: the id of the Incident named in the
// question. Which transition is allowed is the API's decision; when the Incident moved on since the page was
// read (409), or is gone (404), the action says so and saves nothing. After a change it revalidates the
// Incident screens and redirects to the Incident's plain address, which closes the confirmation step.

export type IncidentChangeState = null | { ok: false; errors: FieldError[] };

const INCIDENT_CHANGES = ["acknowledged", "resolved"] as const;
type IncidentChange = (typeof INCIDENT_CHANGES)[number];

const isIncidentChange = (value: string): value is IncidentChange =>
  (INCIDENT_CHANGES as readonly string[]).includes(value);

const incidentStale = (): { ok: false; errors: FieldError[] } => failed("", t("error.incident.stale"));

/** Moves an Incident to Acknowledged, or — with the confirmation — to Resolved. */
export async function updateIncidentAction(
  _previous: IncidentChangeState,
  formData: FormData,
): Promise<IncidentChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const incidentId = text(formData, "incidentId");
  const status = text(formData, "status");
  if (!ID_PATTERNS.inc.test(incidentId) || !isIncidentChange(status)) return incidentStale();
  if (status === "resolved" && text(formData, "confirm") !== incidentId) {
    return failed("confirm", t("incident.confirm.required"));
  }

  try {
    await updateIncident(key, incidentId, status);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ConflictError || error instanceof NotFoundError) return incidentStale();
    return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.incident(incidentId));
  revalidatePath(ROUTES.incidents());
  redirect(ROUTES.incident(incidentId));
}

// ── Alert channels ────────────────────────────────────────────────────────────────────────────────────
// A channel URL can itself be a secret (a Slack webhook URL): it is sent to the API once and never comes
// back — not in the action state, not in an error, not in a refilled field. A webhook's signing secret
// comes back once, in the action state of the form that created it, and is rendered once. An email channel
// (slice 06b) carries recipients instead, which are not secret; a confirmation token never reaches an action.

export type CreateAlertChannelState =
  | null
  | { ok: false; errors: FieldError[]; values: { kind: string; name: string; recipients?: string } }
  | { ok: true; channel: AlertChannel; signingSecret?: string };

export type AlertChannelChangeState = null | { ok: false; errors: FieldError[] };

export type ResendConfirmationState = null | { ok: false; message: string } | { ok: true };

export type TestAlertChannelState =
  | null
  | { ok: false; message: string }
  | { ok: true; outcome: AlertDelivery["outcome"]; statusCode: number | null };

const isChannelKind = (value: string): value is AlertChannelKind =>
  (ALERT_CHANNEL_KINDS as readonly string[]).includes(value);

/** The error for the URL field, or null. `http:` is allowed here: whether it may be used is the API's decision. */
function urlError(url: string): FieldError | null {
  if (url.length === 0) return { path: "url", message: t("error.alerts.url.required") };
  if (url.length > INCIDENT_LIMITS.urlMax) return { path: "url", message: t("error.alerts.url.long") };
  let protocol = "";
  try {
    protocol = new URL(url).protocol;
  } catch {
    // Not a URL: reported below.
  }
  if (protocol !== "https:" && protocol !== "http:") return { path: "url", message: t("error.alerts.url.invalid") };
  return null;
}

/**
 * The recipients of an email channel, typed one per line: checked with the protocol's own rules (trimmed,
 * lower-cased, 1 to 5 valid addresses, each once) and refused in the Console's words, naming the line. Blank
 * lines are dropped but still counted, so that a line number matches what the person sees.
 */
function parseRecipients(raw: string): { recipients: string[] } | { error: FieldError } {
  const lines = raw.split(/\r\n|\r|\n/);
  const given = lines.flatMap((line, index) => (line.trim().length > 0 ? [{ line: index + 1, address: line }] : []));
  if (given.length === 0) return { error: { path: "recipients", message: t("error.alerts.recipients.required") } };
  if (given.length > ALERT_EMAIL_LIMITS.recipientsMax) {
    const max = String(ALERT_EMAIL_LIMITS.recipientsMax);
    return { error: { path: "recipients", message: t("error.alerts.recipients.max", { max }) } };
  }
  // The name is checked apart (`nameError`): a fixed valid one here keeps its issues out of this answer.
  const parsed = CreateAlertChannelRequestSchema.safeParse({
    kind: "email",
    name: "Recipients",
    recipients: given.map((entry) => entry.address),
  });
  if (parsed.success) {
    return { recipients: parsed.data.kind === "email" ? parsed.data.recipients : [] };
  }
  const issue = parsed.error.issues.find((one) => one.path[0] === "recipients" && typeof one.path[1] === "number");
  if (!issue) return { error: { path: "recipients", message: t("error.alerts.recipients.refused") } };
  const line = String(given[issue.path[1] as number]?.line ?? 1);
  // The protocol marks a repeated address with a custom issue; anything else is an address it does not accept.
  const message =
    issue.code === "custom"
      ? t("error.alerts.recipients.duplicate", { line })
      : t("error.alerts.recipients.invalid", { line });
  return { error: { path: "recipients", message } };
}

/** What to say when the API refused a new channel: a 409 by its reason, a 400 by the fields it names. */
function createRefusal(error: unknown): FieldError[] | null {
  if (error instanceof ConflictError) {
    return error.reason === "smtp-not-configured"
      ? [{ path: "kind", message: t("alerts.add.smtp") }]
      : [{ path: "", message: t("error.alerts.max") }];
  }
  if (error instanceof ValidationError) {
    const errors: FieldError[] = [];
    const paths = new Set(error.errors.map((entry) => entry.path.split(".")[0]));
    // A refused URL (scheme, private address, …) is explained without repeating it.
    if (paths.has("url")) errors.push({ path: "url", message: t("error.alerts.url.refused") });
    if (paths.has("recipients")) errors.push({ path: "recipients", message: t("error.alerts.recipients.refused") });
    if (paths.has("name")) errors.push({ path: "name", message: t("error.field") });
    if (paths.has("kind")) errors.push({ path: "kind", message: t("error.alerts.kind") });
    return errors.length > 0 ? errors : [{ path: "", message: t("error.api.failed") }];
  }
  return null;
}

/**
 * Adds a webhook, Slack or email channel. A webhook's signing secret is returned to be shown once. An email
 * channel's recipients come back with the refusal, since they are not a secret; a URL never does.
 */
export async function createAlertChannelAction(
  _previous: CreateAlertChannelState,
  formData: FormData,
): Promise<CreateAlertChannelState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const kind = text(formData, "kind");
  const name = text(formData, "name");
  const email = kind === "email";
  const rawRecipients = (() => {
    const value = formData.get("recipients");
    return typeof value === "string" ? value : "";
  })();
  // The URL is deliberately not among the values sent back to the form.
  const values = email ? { kind, name, recipients: rawRecipients } : { kind, name };

  const invalid: FieldError[] = [];
  if (!isChannelKind(kind)) invalid.push({ path: "kind", message: t("error.alerts.kind") });
  const badName = nameError(name);
  if (badName) invalid.push(badName);
  let request: Parameters<typeof createAlertChannel>[1] | null = null;
  if (email) {
    const recipients = parseRecipients(rawRecipients);
    if ("error" in recipients) invalid.push(recipients.error);
    else request = { kind, name, recipients: recipients.recipients };
  } else {
    const url = text(formData, "url");
    const badUrl = urlError(url);
    if (badUrl) invalid.push(badUrl);
    else if (kind === "webhook" || kind === "slack") request = { kind, name, url };
  }
  if (invalid.length > 0 || request === null) return { ok: false, errors: invalid, values };

  let created: Awaited<ReturnType<typeof createAlertChannel>>;
  try {
    created = await createAlertChannel(key, request);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const refusal = createRefusal(error);
    return { ok: false, errors: refusal ?? apiErrors(error, []), values };
  }
  revalidatePath(ROUTES.alerts());
  return created.signing_secret === undefined
    ? { ok: true, channel: created.channel }
    : { ok: true, channel: created.channel, signingSecret: created.signing_secret };
}

/** Removes a channel. Refused unless the form carries the confirmation: the id of the channel named in the question. */
export async function deleteAlertChannelAction(
  _previous: AlertChannelChangeState,
  formData: FormData,
): Promise<AlertChannelChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const channelId = text(formData, "channelId");
  if (!ID_PATTERNS.chn.test(channelId)) return failed("", t("error.alerts.gone"));
  if (text(formData, "confirm") !== channelId) return failed("confirm", t("alerts.confirm.required"));

  try {
    await deleteAlertChannel(key, channelId);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    // A channel that is already gone is what was asked for.
    if (!(error instanceof NotFoundError)) return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.alerts());
  redirect(ROUTES.alerts());
}

/** Sends one test alert to a channel and returns how its delivery went. */
export async function testAlertChannelAction(
  _previous: TestAlertChannelState,
  formData: FormData,
): Promise<TestAlertChannelState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const channelId = text(formData, "channelId");
  if (!ID_PATTERNS.chn.test(channelId)) return { ok: false, message: t("error.alerts.gone") };

  try {
    const { delivery } = await testAlertChannel(key, channelId);
    return { ok: true, outcome: delivery.outcome, statusCode: delivery.status_code };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const pending = deletionPending(error);
    if (pending !== null) return { ok: false, message: pending };
    if (error instanceof NotFoundError) return { ok: false, message: t("error.alerts.gone") };
    if (error instanceof ConflictError && error.reason === "no-confirmed-recipients") {
      return { ok: false, message: t("error.alerts.unconfirmed") };
    }
    if (error instanceof ConflictError && error.reason === "smtp-not-configured") {
      return { ok: false, message: t("alerts.add.smtp") };
    }
    if (error instanceof ApiError) {
      return { ok: false, message: t(error.status === 0 ? "error.alerts.test.api" : "error.alerts.test") };
    }
    throw error;
  }
}

/**
 * Sends a pending recipient of an email channel a new confirmation email, by ids only: no address travels. The
 * API counts it toward the address's emails of the day and refuses a recipient that already confirmed.
 */
export async function resendConfirmationAction(
  _previous: ResendConfirmationState,
  formData: FormData,
): Promise<ResendConfirmationState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const channelId = text(formData, "channelId");
  const recipientId = text(formData, "recipientId");
  if (!ID_PATTERNS.chn.test(channelId) || !ID_PATTERNS.rcp.test(recipientId)) {
    return { ok: false, message: t("error.alerts.resend.gone") };
  }

  try {
    await resendConfirmation(key, channelId, recipientId);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const pending = deletionPending(error);
    if (pending !== null) return { ok: false, message: pending };
    if (error instanceof RateLimitedError) {
      const count = String(ALERT_EMAIL_LIMITS.confirmationMailsPerAddressPerDay);
      return { ok: false, message: t("error.alerts.resend.limit", { count }) };
    }
    if (error instanceof ConflictError && error.reason === "recipient-confirmed") {
      revalidatePath(ROUTES.alerts());
      return { ok: false, message: t("error.alerts.resend.confirmed") };
    }
    if (error instanceof ConflictError && error.reason === "smtp-not-configured") {
      return { ok: false, message: t("alerts.add.smtp") };
    }
    if (error instanceof NotFoundError) return { ok: false, message: t("error.alerts.resend.gone") };
    if (error instanceof ApiError) {
      return { ok: false, message: t(error.status === 0 ? "error.alerts.resend.api" : "error.alerts.resend") };
    }
    throw error;
  }
  revalidatePath(ROUTES.alerts());
  return { ok: true };
}

/**
 * "Confirm email" of a confirmation link (slice 06b). Public: whoever got the email clicks it, with no session.
 * The token comes in a hidden field of the POST and goes to the API server-side; the answer is a redirect to a page
 * that names the outcome only, so the token leaves the address bar and the history. Never logged.
 */
export async function confirmRecipientAction(formData: FormData): Promise<never> {
  const outcome = await confirmRecipientToken(formData.get("token"));
  redirect(ROUTES.alertConfirmDone(outcome));
}

// ── Containment (slice 09) ────────────────────────────────────────────────────────────────────────────
// A block is never one click. The containment bar only opens a confirmation step (a GET of the Incident's
// address); its form carries the target the question named (`confirm`). Blocking the network needs the
// stronger confirmation as well: the prefix typed by the person (`typedPrefix`), matched exactly here before
// anything is sent, and then sent as `confirm_prefix` so that the API checks it against the Incident again.
// A 409 carries the API's `reason`, which alone decides the message; nothing is read again to guess it. The
// form also carries the Environment the question named, for the cap message. Lifting is confirmed the same
// way, by the block's id.

export type ContainmentChangeState = null | { ok: false; errors: FieldError[]; reason?: string };

const containmentStale = (): { ok: false; errors: FieldError[] } => failed("", t("error.containment.stale"));
const containmentEnded = (): { ok: false; errors: FieldError[] } => failed("", t("error.containment.ended"));

const ttlFrom = (value: string): ContainmentTtl | undefined => CONTAINMENT_TTLS.find((ttl) => String(ttl) === value);

/** What to say when the API refused a block with 409: its `reason` alone decides; none means it changed. */
function containmentConflict(error: ConflictError, environment: Environment): string {
  switch (error.reason) {
    case "incident-resolved":
      return t("error.containment.resolved");
    case "prefix-allowlisted":
      return t("error.containment.overlap");
    case "containment-limit":
      return t("error.containment.cap", { environment });
    case "containment-ended":
      return t("error.containment.ended");
    case "containment-not-applicable":
      // A clone Incident, or any Incident without a network prefix (slice 10).
      return t("error.containment.notApplicable");
    default:
      // `actor-unknown`, another reason, or none: the Incident or its blocks moved on since the page was read.
      return t("error.containment.stale");
  }
}

/** Blocks one Actor of an Incident, or its network, for 15 minutes, 1 hour or 24 hours — with the confirmation. */
export async function createContainmentAction(
  previous: ContainmentChangeState,
  formData: FormData,
): Promise<ContainmentChangeState> {
  return keptReason(await createContainmentChange(previous, formData), formData);
}

async function createContainmentChange(
  _previous: ContainmentChangeState,
  formData: FormData,
): Promise<ContainmentChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const incidentId = text(formData, "incidentId");
  const environment = text(formData, "environment");
  const kind = text(formData, "kind");
  const ttl = ttlFrom(text(formData, "ttl"));
  const confirm = text(formData, "confirm");
  if (!ID_PATTERNS.inc.test(incidentId) || !isEnvironment(environment) || ttl === undefined) {
    return containmentStale();
  }

  let request: CreateContainmentRequest;
  if (kind === "actor") {
    const ipHash = text(formData, "ipHash");
    if (!ACTOR_HASH_PATTERN.test(ipHash)) return containmentStale();
    if (confirm !== ipHash) return failed("confirm", t("containment.confirm.required"));
    request = { target: { kind: "actor", ip_hash: ipHash }, ttl_s: ttl };
  } else if (kind === "prefix") {
    // `confirm` is the network the question named; the typed text must equal it exactly — not trimmed.
    if (!IP_PREFIX_PATTERN.test(confirm)) return containmentStale();
    if (formData.get("typedPrefix") !== confirm) {
      return failed("typedPrefix", t("containment.confirm.typed.mismatch", { network: confirm }));
    }
    request = { target: { kind: "prefix" }, ttl_s: ttl, confirm_prefix: confirm };
  } else {
    return containmentStale();
  }
  const read = reasonFrom(formData, true);
  if ("error" in read) return { ok: false, errors: [read.error] };

  let appId: string;
  try {
    ({
      containment: { app_id: appId },
    } = await createContainment(key, incidentId, request, withReason(read.reason)));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal };
    if (error instanceof ConflictError) return failed("", containmentConflict(error, environment));
    // The Incident is gone, or the Actor or the network is no longer the Incident's.
    if (error instanceof NotFoundError || error instanceof ValidationError) return containmentStale();
    return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.incident(incidentId));
  revalidatePath(ROUTES.incidents());
  revalidatePath(ROUTES.containment(appId));
  redirect(ROUTES.incident(incidentId));
}

/**
 * Lifts an active block — with the confirmation, the id of the block named in the question — and goes back
 * where the form came from: the Incident (`incidentId`) or the App's containment page (`appId`).
 */
export async function liftContainmentAction(
  _previous: ContainmentChangeState,
  formData: FormData,
): Promise<ContainmentChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const containmentId = text(formData, "containmentId");
  const incidentId = text(formData, "incidentId");
  const appId = text(formData, "appId");
  // The way back is built from a validated id, never taken from the form as an address.
  const back = ID_PATTERNS.inc.test(incidentId)
    ? ROUTES.incident(incidentId)
    : ID_PATTERNS.app.test(appId)
      ? ROUTES.containment(appId)
      : null;
  if (!ID_PATTERNS.cnt.test(containmentId) || back === null) return containmentEnded();
  if (text(formData, "confirm") !== containmentId) return failed("confirm", t("blocks.confirm.required"));

  let lifted: Awaited<ReturnType<typeof liftContainment>>["containment"];
  try {
    ({ containment: lifted } = await liftContainment(key, containmentId));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ConflictError || error instanceof NotFoundError) return containmentEnded();
    return { ok: false, errors: apiErrors(error, []) };
  }
  if (lifted.incident_id !== null) revalidatePath(ROUTES.incident(lifted.incident_id));
  revalidatePath(ROUTES.incidents());
  revalidatePath(ROUTES.containment(lifted.app_id));
  redirect(back);
}

// ── Findings (slice 19) ───────────────────────────────────────────────────────────────────────────────
// Ignoring is never one click: only the confirmation step holds the form, and it names the Finding in a
// hidden `confirm` field that the action checks. The reason and the date are checked here before anything is
// sent (reason 1–200 characters after trimming; a date from tomorrow up to 90 days ahead, as the start of that
// day in UTC); the API checks them again and alone decides. Reopening is sent at once.

export type IgnoreFindingState = null | { ok: false; errors: FieldError[]; values: { reason: string; until: string } };

export type FindingChangeState = null | { ok: false; errors: FieldError[] };

const findingStale = (): FieldError[] => [{ path: "", message: t("error.finding.stale") }];

/** Ignores a Finding until the chosen date, with a reason — only with the confirmation. */
export async function ignoreFindingAction(
  _previous: IgnoreFindingState,
  formData: FormData,
): Promise<IgnoreFindingState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const findingId = text(formData, "findingId");
  const reason = text(formData, "reason");
  const date = text(formData, "until");
  const values = { reason, until: date };
  if (!ID_PATTERNS.fnd.test(findingId)) return { ok: false, errors: findingStale(), values };
  if (text(formData, "confirm") !== findingId) {
    return { ok: false, errors: [{ path: "confirm", message: t("finding.confirm.required") }], values };
  }

  const errors: FieldError[] = [];
  if (reason.length === 0) errors.push({ path: "reason", message: t("error.finding.reason.required") });
  else if (reason.length > EXPOSURE_LIMITS.ignoreReasonMax) {
    errors.push({ path: "reason", message: t("error.finding.reason.long") });
  }
  const until = untilFromDate(date, Date.now());
  if (until === null) errors.push({ path: "until", message: t("error.finding.until") });
  if (errors.length > 0 || until === null) return { ok: false, errors, values };

  let appId: string;
  try {
    ({
      finding: { app_id: appId },
    } = await ignoreFinding(key, findingId, { reason, until }));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ConflictError || error instanceof NotFoundError) {
      return { ok: false, errors: findingStale(), values };
    }
    return { ok: false, errors: apiErrors(error, ["reason", "until"]), values };
  }
  revalidatePath(ROUTES.finding(findingId));
  revalidatePath(ROUTES.findings());
  revalidatePath(ROUTES.appFindings(appId));
  redirect(ROUTES.finding(findingId));
}

/** Reopens an ignored Finding now. */
export async function reopenFindingAction(
  _previous: FindingChangeState,
  formData: FormData,
): Promise<FindingChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const findingId = text(formData, "findingId");
  if (!ID_PATTERNS.fnd.test(findingId)) return { ok: false, errors: findingStale() };

  let appId: string;
  try {
    ({
      finding: { app_id: appId },
    } = await reopenFinding(key, findingId));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ConflictError || error instanceof NotFoundError) return { ok: false, errors: findingStale() };
    return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.finding(findingId));
  revalidatePath(ROUTES.findings());
  revalidatePath(ROUTES.appFindings(appId));
  redirect(ROUTES.finding(findingId));
}

// ── Virtual patches (slice 20) ────────────────────────────────────────────────────────────────────────
// Enforcing a patch is refused unless the form carries the patch id, typed by the person exactly as the
// question named it; the API checks it again. Going back to monitor reduces enforcement and needs none.

export type PatchModeState = null | { ok: false; errors: FieldError[]; reason?: string };

const patchStale = (): { ok: false; errors: FieldError[] } => failed("", t("error.patch.stale"));
const patchMismatch = (patchId: string): { ok: false; errors: FieldError[] } =>
  failed("confirm", t("patch.confirm.mismatch", { patch: patchId }));

/** Sets the mode of a virtual patch in one App and Environment, from the Finding page, then goes back to it. */
export async function setPatchModeAction(previous: PatchModeState, formData: FormData): Promise<PatchModeState> {
  return keptReason(await setPatchModeChange(previous, formData), formData);
}

async function setPatchModeChange(_previous: PatchModeState, formData: FormData): Promise<PatchModeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const appId = text(formData, "appId");
  const environment = text(formData, "environment");
  const patchId = text(formData, "patchId");
  const findingId = text(formData, "findingId");
  const mode = text(formData, "mode");
  if (
    !ID_PATTERNS.app.test(appId) ||
    !isEnvironment(environment) ||
    !PATCH_ID_PATTERN.test(patchId) ||
    !ID_PATTERNS.fnd.test(findingId) ||
    !isMode(mode)
  ) {
    return patchStale();
  }
  const request: PatchModeRequest = { environment, mode };
  if (mode === "enforce") {
    // Exactly as typed: not trimmed, not folded.
    if (formData.get("confirm") !== patchId) return patchMismatch(patchId);
    request.confirm = patchId;
  }
  // Enforcing is a sensitive change: it carries a reason. Back to monitor needs none.
  const read = reasonFrom(formData, mode === "enforce");
  if ("error" in read) return { ok: false, errors: [read.error] };

  try {
    if (read.reason === undefined) await setPatchMode(key, appId, patchId, request);
    else await setPatchMode(key, appId, patchId, request, { reason: read.reason });
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal };
    if (error instanceof ConflictError || error instanceof NotFoundError) return patchStale();
    if (error instanceof ValidationError && error.errors.some((entry) => entry.path === "confirm")) {
      return patchMismatch(patchId);
    }
    return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.finding(findingId));
  revalidatePath(ROUTES.policy(appId));
  redirect(ROUTES.finding(findingId));
}

// ── Never block list (slice 09) ───────────────────────────────────────────────────────────────────────
// A range is accepted only in canonical CIDR form, as the API stores it: nothing is rewritten silently.
// When the person wrote another spelling or set host bits, the error names the canonical form to use.

export type CreateAllowlistEntryState =
  | null
  | { ok: false; errors: FieldError[]; values: { cidr: string; note: string } }
  | { ok: true; entry: AllowlistEntry };

export type AllowlistChangeState = null | { ok: false; errors: FieldError[] };

/** The error for the range field, or null when it is a canonical CIDR. */
function cidrError(cidr: string): FieldError | null {
  if (cidr.length === 0) return { path: "cidr", message: t("error.allowlist.cidr.required") };
  if (parseCidr(cidr)?.cidr === cidr) return null;
  const canonical = suggestCidr(cidr);
  return canonical === null
    ? { path: "cidr", message: t("error.allowlist.cidr.invalid") }
    : { path: "cidr", message: t("error.allowlist.cidr.canonical", { cidr: canonical }) };
}

/** What to say when the API refused a range with 409: listed already, or the list is full — or it changed. */
function allowlistConflict(error: ConflictError): FieldError {
  if (error.reason === "allowlist-duplicate") return { path: "cidr", message: t("error.allowlist.duplicate") };
  if (error.reason === "allowlist-limit") return { path: "", message: t("error.allowlist.max") };
  return { path: "", message: t("error.allowlist.changed") };
}

/** Adds a range to the never block list and returns it, to be announced. */
export async function createAllowlistEntryAction(
  _previous: CreateAllowlistEntryState,
  formData: FormData,
): Promise<CreateAllowlistEntryState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const cidr = text(formData, "cidr");
  const note = text(formData, "note");
  const values = { cidr, note };
  const invalid: FieldError[] = [];
  const badCidr = cidrError(cidr);
  if (badCidr) invalid.push(badCidr);
  if (note.length > CONTAINMENT_LIMITS.noteMax) invalid.push({ path: "note", message: t("error.allowlist.note.long") });
  if (invalid.length > 0) return { ok: false, errors: invalid, values };

  let entry: AllowlistEntry;
  try {
    ({ entry } = await createAllowlistEntry(key, { cidr, note }));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ConflictError) return { ok: false, errors: [allowlistConflict(error)], values };
    if (error instanceof ValidationError) {
      const errors: FieldError[] = [];
      const paths = new Set(error.errors.map((entry) => entry.path));
      if (paths.has("cidr")) errors.push({ path: "cidr", message: t("error.allowlist.cidr.invalid") });
      if (paths.has("note")) errors.push({ path: "note", message: t("error.field") });
      return { ok: false, errors: errors.length > 0 ? errors : [{ path: "", message: t("error.api.failed") }], values };
    }
    return { ok: false, errors: apiErrors(error, []), values };
  }
  revalidatePath(ROUTES.allowlist());
  return { ok: true, entry };
}

/** Removes a range. Refused unless the form carries the confirmation: the id of the range named in the question. */
export async function deleteAllowlistEntryAction(
  _previous: AllowlistChangeState,
  formData: FormData,
): Promise<AllowlistChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const entryId = text(formData, "entryId");
  if (!ID_PATTERNS.alw.test(entryId)) return failed("", t("error.allowlist.gone"));
  if (text(formData, "confirm") !== entryId) return failed("confirm", t("allowlist.confirm.required"));

  try {
    await deleteAllowlistEntry(key, entryId);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    // A range that is already gone is what was asked for.
    if (!(error instanceof NotFoundError)) return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.allowlist());
  redirect(ROUTES.allowlist());
}

// ── Prove (slice 14) ──────────────────────────────────────────────────────────────────────────────────
// A host is checked here with the protocol's own rules before anything is sent; the API checks it again and
// alone decides. The API's own words are never shown: each refusal is explained in the Console's words. A
// verification token never travels in an action state — the target's page reads it from the API.

export type CreateTargetState = null | { ok: false; errors: FieldError[]; values: { host: string } };

export type VerifyTargetState = null | { ok: true; result: VerifyResult } | { ok: false; message: string };

export type TargetChangeState = null | { ok: false; errors: FieldError[]; reason?: string };

/** Adds a host and opens its page, which shows how to prove it. */
export async function createTargetAction(_previous: CreateTargetState, formData: FormData): Promise<CreateTargetState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const host = text(formData, "host");
  const values = { host };
  if (host.length === 0) return failedWith("host", t("error.target.host.required"), values);
  if (normaliseHost(host) === null) return failedWith("host", t("error.target.host.invalid"), values);

  let targetId: string;
  try {
    ({
      target: { id: targetId },
    } = await createTarget(key, { host }));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ConflictError) {
      if (error.reason === "target-limit") return failedWith("", t("error.target.max"), values);
      if (error.reason === "target-duplicate") return failedWith("host", t("error.target.duplicate"), values);
      return failedWith("", t("error.target.conflict"), values);
    }
    if (error instanceof ValidationError) {
      const aboutHost = error.errors.some((entry) => entry.path === "host");
      return aboutHost
        ? failedWith("host", t("error.target.host.refused"), values)
        : failedWith("", t("error.api.failed"), values);
    }
    return { ok: false, errors: apiErrors(error, []), values };
  }
  revalidatePath(ROUTES.targets);
  redirect(ROUTES.target(targetId));
}

function failedWith<V>(path: string, message: string, values: V): { ok: false; errors: FieldError[]; values: V } {
  return { ok: false, errors: [{ path, message }], values };
}

/** Checks the DNS record, then the file, of one target and returns the outcome. */
export async function verifyTargetAction(_previous: VerifyTargetState, formData: FormData): Promise<VerifyTargetState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const targetId = text(formData, "targetId");
  if (!ID_PATTERNS.tgt.test(targetId)) return { ok: false, message: t("error.target.gone") };

  let result: VerifyResult;
  try {
    ({ result } = await verifyTarget(key, targetId));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const pending = deletionPending(error);
    if (pending !== null) return { ok: false, message: pending };
    if (error instanceof NotFoundError) return { ok: false, message: t("error.target.gone") };
    if (error instanceof RateLimitedError) {
      return {
        ok: false,
        message:
          error.retryAfter === undefined
            ? t("target.verify.limited.soon")
            : t("target.verify.limited", { minutes: Math.max(1, Math.ceil(error.retryAfter / 60)) }),
      };
    }
    if (error instanceof ApiError) {
      return { ok: false, message: t(error.status === 0 ? "target.verify.unreachable" : "target.verify.error") };
    }
    throw error;
  }
  revalidatePath(ROUTES.target(targetId));
  revalidatePath(ROUTES.targets);
  return { ok: true, result };
}

/** Removes a target. Refused unless the form carries the confirmation: the id of the target named in the question. */
export async function deleteTargetAction(previous: TargetChangeState, formData: FormData): Promise<TargetChangeState> {
  return keptReason(await deleteTargetChange(previous, formData), formData);
}

async function deleteTargetChange(_previous: TargetChangeState, formData: FormData): Promise<TargetChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const targetId = text(formData, "targetId");
  if (!ID_PATTERNS.tgt.test(targetId)) return failed("", t("error.target.gone"));
  if (text(formData, "confirm") !== targetId) return failed("confirm", t("target.confirm.required"));
  const read = reasonFrom(formData, true);
  if ("error" in read) return { ok: false, errors: [read.error] };

  try {
    await deleteTarget(key, targetId, withReason(read.reason));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal };
    // The reason alone decides the message; without a known one it is never guessed.
    if (error instanceof ConflictError) {
      return failed("", t(error.reason === "target-in-scope" ? "error.target.inScope" : "error.target.conflict"));
    }
    // A target that is already gone is what was asked for.
    if (!(error instanceof NotFoundError)) return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.targets);
  redirect(ROUTES.targets);
}

/** What the form of a new Rules of Engagement version holds, sent back after a refusal. The phrase is not. */
export interface RulesOfEngagementFormValues {
  scope: string[];
  exclusions: string;
  intensity: string;
  days: string[];
  allDay: boolean;
  from: string;
  to: string;
  contacts: string;
}

export type SignRulesOfEngagementState = null | {
  ok: false;
  errors: FieldError[];
  values: RulesOfEngagementFormValues;
  /** The reason as typed (slice 18a); the phrase is never given back. */
  reason?: string;
};

/** The fields of the form, in the order their errors are listed. */
const ROE_FIELDS = ["scope", "exclusions", "intensity", "days", "from", "to", "contacts", "confirm", "reason"] as const;
type RoeField = (typeof ROE_FIELDS)[number];

const ROE_FIELD_ERROR: Record<RoeField, MessageKey> = {
  scope: "error.roe.scope.required",
  exclusions: "error.roe.exclusions.invalid",
  intensity: "error.roe.intensity",
  days: "error.roe.days",
  from: "error.roe.from",
  to: "error.roe.to",
  contacts: "error.roe.contacts",
  confirm: "error.roe.confirm",
  reason: "error.reason.required",
};

/** The form field a protocol path (`window.from`, `exclusions.2`, …) is about, or null. */
function roeField(path: readonly PropertyKey[]): RoeField | null {
  const [head, next] = path.map(String);
  if (head === "window") return next === "days" || next === "from" || next === "to" ? next : null;
  return (ROE_FIELDS as readonly string[]).includes(head ?? "") ? (head as RoeField) : null;
}

/** One error per field, in form order. */
function roeErrors(fields: Iterable<RoeField>, messages: Partial<Record<RoeField, string>> = {}): FieldError[] {
  const set = new Set(fields);
  return ROE_FIELDS.filter((field) => set.has(field)).map((field) => ({
    path: field,
    message: messages[field] ?? t(ROE_FIELD_ERROR[field]),
  }));
}

/** The non-empty, trimmed lines of a text area. */
const lines = (value: string): string[] =>
  value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

const all = (formData: FormData, name: string): string[] =>
  formData.getAll(name).filter((value): value is string => typeof value === "string");

/**
 * Signs a new Rules of Engagement version: the content is checked with the protocol's schema and the typed phrase
 * must be exactly `I authorise <intensity> testing` for the chosen intensity, before anything is sent. A signed
 * version is never changed; the new one becomes current.
 */
export async function signRulesOfEngagementAction(
  previous: SignRulesOfEngagementState,
  formData: FormData,
): Promise<SignRulesOfEngagementState> {
  return keptReason(await signRulesOfEngagementChange(previous, formData), formData);
}

async function signRulesOfEngagementChange(
  _previous: SignRulesOfEngagementState,
  formData: FormData,
): Promise<SignRulesOfEngagementState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const values: RulesOfEngagementFormValues = {
    scope: all(formData, "scope"),
    exclusions: String(formData.get("exclusions") ?? ""),
    intensity: text(formData, "intensity"),
    days: all(formData, "days"),
    allDay: formData.get("allDay") === "on",
    from: text(formData, "from"),
    to: text(formData, "to"),
    contacts: String(formData.get("contacts") ?? ""),
  };
  const exclusions = lines(values.exclusions);
  const content = {
    scope: values.scope,
    exclusions,
    intensity: values.intensity,
    window: {
      days: values.days,
      from: values.allDay ? "00:00" : values.from,
      to: values.allDay ? "24:00" : values.to,
    },
    contacts: lines(values.contacts),
  };
  const parsed = RulesOfEngagementContentSchema.safeParse(content);
  if (!parsed.success) {
    const fields = parsed.error.issues.map((issue) => roeField(issue.path)).filter((field) => field !== null);
    const messages = exclusions.length > ROE_LIMITS.exclusionsMax ? { exclusions: t("error.roe.exclusions.max") } : {};
    return { ok: false, errors: roeErrors(fields, messages), values };
  }
  const confirm = text(formData, "confirm");
  const read = reasonFrom(formData, true);
  const phraseWrong = confirm !== confirmationPhrase(parsed.data.intensity);
  if (phraseWrong || "error" in read) {
    const messages = "error" in read ? { reason: read.error.message } : {};
    return {
      ok: false,
      errors: roeErrors(
        [...(phraseWrong ? (["confirm"] as const) : []), ...("error" in read ? (["reason"] as const) : [])],
        messages,
      ),
      values,
    };
  }

  try {
    await signRulesOfEngagement(key, { ...parsed.data, confirm }, withReason(read.reason));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal, values };
    // A chosen target that lost its verification comes back as a 400 on `scope.N` (below); a 409 is not guessed at.
    if (error instanceof ConflictError) {
      return { ok: false, errors: [{ path: "", message: t("error.target.conflict") }], values };
    }
    if (error instanceof ValidationError) {
      const fields = error.errors.map((entry) => roeField(entry.path.split("."))).filter((field) => field !== null);
      if (fields.length === 0) return { ok: false, errors: [{ path: "", message: t("error.api.failed") }], values };
      return { ok: false, errors: roeErrors(fields, { scope: t("error.roe.scope.stale") }), values };
    }
    return { ok: false, errors: apiErrors(error, []), values };
  }
  revalidatePath(ROUTES.rulesOfEngagement);
  redirect(ROUTES.rulesOfEngagement);
}

export interface CheckTestValues {
  host: string;
  path: string;
  intensity: string;
  at: string;
}

export type CheckAuthorizationState =
  | null
  | { ok: true; result: AuthorizeResult; values: CheckTestValues }
  | { ok: false; errors: FieldError[]; values: CheckTestValues };

/** `YYYY-MM-DDTHH:MM` (or with seconds), read as UTC, as ISO text; null when it is not a real time. */
function utcFromLocalInput(value: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value)) return null;
  const iso = `${value.length === 16 ? `${value}:00` : value}.000Z`;
  const time = Date.parse(iso);
  return Number.isFinite(time) && new Date(time).toISOString() === iso ? iso : null;
}

const isIntensity = (value: string): value is Intensity => (INTENSITIES as readonly string[]).includes(value);

/** Asks the API whether a test would be allowed. A dry check: nothing is started. */
export async function checkAuthorizationAction(
  _previous: CheckAuthorizationState,
  formData: FormData,
): Promise<CheckAuthorizationState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const values: CheckTestValues = {
    host: text(formData, "host"),
    path: text(formData, "path"),
    intensity: text(formData, "intensity"),
    at: text(formData, "at"),
  };
  const errors: FieldError[] = [];
  if (normaliseHost(values.host) === null) errors.push({ path: "host", message: t("error.target.host.invalid") });
  if (!values.path.startsWith("/") || values.path.length > ROE_LIMITS.pathMax)
    errors.push({ path: "path", message: t("error.check.path") });
  if (!isIntensity(values.intensity)) errors.push({ path: "intensity", message: t("error.roe.intensity") });
  const at = utcFromLocalInput(values.at);
  if (at === null) errors.push({ path: "at", message: t("error.check.at") });
  if (errors.length > 0 || at === null || !isIntensity(values.intensity)) return { ok: false, errors, values };

  try {
    const result = await checkAuthorization(key, {
      host: values.host,
      path: values.path,
      intensity: values.intensity,
      at,
    });
    return { ok: true, result, values };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ValidationError) {
      const messages: Record<string, MessageKey> = {
        host: "error.target.host.invalid",
        path: "error.check.path",
        intensity: "error.roe.intensity",
        at: "error.check.at",
      };
      const known = error.errors.filter((entry) => Object.hasOwn(messages, entry.path));
      if (known.length > 0) {
        return {
          ok: false,
          errors: known.map((entry) => ({ path: entry.path, message: t(messages[entry.path] as MessageKey) })),
          values,
        };
      }
    }
    return { ok: false, errors: apiErrors(error, []), values };
  }
}

// ── Pentest Campaigns (slice 15a) ─────────────────────────────────────────────────────────────────────
// Launching a Campaign needs a target, an intensity, the typed phrase `I authorise a test of <host>`, the staging
// declaration and a reason; stopping one needs a reason. Each is checked here before anything is sent; the API checks
// everything again — the phrase against the target's host among it — and alone decides. The API's own words are
// never shown: each refusal is explained in the Console's words, at the field it is about.

/** What the new Campaign form holds, sent back after a refusal. The phrase and the declaration are not. */
export interface NewCampaignValues {
  target: string;
  intensity: string;
}

export type CreateCampaignState = null | {
  ok: false;
  errors: FieldError[];
  values: NewCampaignValues;
  /** The reason as typed; the phrase is never given back. */
  reason?: string;
};

export type StopCampaignState = null | { ok: false; errors: FieldError[]; reason?: string };

const isCampaignIntensity = (value: string): value is CampaignIntensity =>
  (CAMPAIGN_INTENSITIES as readonly string[]).includes(value);

/** The form field each field of the API's request is about, and what to say when the API refuses it. */
const CAMPAIGN_FIELD_REFUSAL: Readonly<Record<string, FieldError>> = {
  target_id: { path: "target", message: t("error.campaign.target.gone") },
  intensity: { path: "intensity", message: t("error.campaign.intensity") },
  confirm: { path: "confirm", message: t("error.campaign.confirm") },
  staging: { path: "staging", message: t("error.campaign.staging") },
};

const CAMPAIGNS_UNAVAILABLE: Readonly<Record<CampaignsUnavailable, MessageKey>> = {
  disabled: "error.campaign.disabled",
  stopped: "error.campaign.stopped",
  suspended: "error.campaign.suspended",
};

/** What to say for a 409 of a creation: the reason alone decides, and without a known one it is never guessed. */
function campaignConflict(error: ConflictError): FieldError {
  switch (error.reason) {
    case "campaign-active":
      return { path: "", message: t("error.campaign.active") };
    case "campaign-target-not-verified":
      return { path: "target", message: t("error.campaign.target.notVerified") };
    case "campaign-no-rules":
      return { path: "", message: t("error.campaign.noRules") };
    case "campaign-target-out-of-scope":
      return { path: "target", message: t("error.campaign.target.outOfScope") };
    case "campaign-rules-too-old":
      return { path: "", message: t("error.campaign.rulesTooOld", { days: CAMPAIGN_LIMITS.roeMaxAgeDays }) };
    case "campaign-intensity-exceeds":
      return { path: "intensity", message: t("error.campaign.intensity.exceeds") };
    case "campaign-verification-path-excluded":
      return { path: "", message: t("error.campaign.verificationPathExcluded", { path: VERIFICATION_FILE_PATH }) };
    default:
      return { path: "", message: t("error.campaign.conflict") };
  }
}

/** When to try again after too many Campaigns: whole hours from an hour and a half on, else minutes. */
function campaignLimited(retryAfter: number | undefined): string {
  const limits = {
    organization: CAMPAIGN_LIMITS.createdPerOrganizationPerDay,
    target: CAMPAIGN_LIMITS.createdPerTargetPerDay,
  };
  if (retryAfter === undefined) return t("error.campaign.limited.soon", limits);
  if (retryAfter >= 5400) return t("error.campaign.limited.hours", { ...limits, hours: Math.ceil(retryAfter / 3600) });
  return t("error.campaign.limited", { ...limits, minutes: Math.max(1, Math.ceil(retryAfter / 60)) });
}

/** Launches a Campaign and opens its page. A refusal keeps the target, the intensity and the reason. */
export async function createCampaignAction(
  previous: CreateCampaignState,
  formData: FormData,
): Promise<CreateCampaignState> {
  return keptReason(await createCampaignChange(previous, formData), formData);
}

async function createCampaignChange(_previous: CreateCampaignState, formData: FormData): Promise<CreateCampaignState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const values: NewCampaignValues = { target: text(formData, "target"), intensity: text(formData, "intensity") };
  const refused = (errors: FieldError[]): CreateCampaignState => ({ ok: false, errors, values });
  const confirm = text(formData, "confirm");
  const read = reasonFrom(formData, true);
  const errors: FieldError[] = [];
  if (!ID_PATTERNS.tgt.test(values.target))
    errors.push({ path: "target", message: t("error.campaign.target.required") });
  if (!isCampaignIntensity(values.intensity))
    errors.push({ path: "intensity", message: t("error.campaign.intensity") });
  if (confirm.length === 0 || confirm.length > 300)
    errors.push({ path: "confirm", message: t("error.campaign.confirm") });
  // The declaration is the checkbox itself, ticked for this attempt.
  if (formData.get("staging") !== "on") errors.push({ path: "staging", message: t("error.campaign.staging") });
  if ("error" in read) errors.push(read.error);
  if (errors.length > 0 || "error" in read || !isCampaignIntensity(values.intensity)) return refused(errors);

  let campaignId: string;
  try {
    ({
      campaign: { id: campaignId },
    } = await createCampaign(
      key,
      { target_id: values.target, intensity: values.intensity, confirm, staging: true },
      withReason(read.reason),
    ));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const refusal = reasonRefusal(error);
    if (refusal) return refused(refusal);
    if (error instanceof CampaignsUnavailableError) {
      return refused([{ path: "", message: t(CAMPAIGNS_UNAVAILABLE[error.kind]) }]);
    }
    if (error instanceof ConflictError) return refused([campaignConflict(error)]);
    if (error instanceof RateLimitedError) return refused([{ path: "", message: campaignLimited(error.retryAfter) }]);
    if (error instanceof ValidationError) {
      const known = error.errors.flatMap((entry) => {
        const field = CAMPAIGN_FIELD_REFUSAL[entry.path];
        return field === undefined ? [] : [field];
      });
      return refused(known.length > 0 ? known : [{ path: "", message: t("error.api.failed") }]);
    }
    return refused(apiErrors(error, []));
  }
  revalidatePath(ROUTES.campaigns);
  redirect(ROUTES.campaign(campaignId));
}

/**
 * Stops a Campaign for good. Refused unless the form carries the confirmation: the id of the Campaign named in the
 * question. A Campaign that had already ended is not an error: its page says so.
 */
export async function stopCampaignAction(previous: StopCampaignState, formData: FormData): Promise<StopCampaignState> {
  return keptReason(await stopCampaignChange(previous, formData), formData);
}

async function stopCampaignChange(_previous: StopCampaignState, formData: FormData): Promise<StopCampaignState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const campaignId = text(formData, "campaignId");
  if (!ID_PATTERNS.cmp.test(campaignId)) return failed("", t("campaign.gone"));
  if (text(formData, "confirm") !== campaignId) return failed("confirm", t("campaign.confirm.required"));
  const read = reasonFrom(formData, true);
  if ("error" in read) return { ok: false, errors: [read.error] };

  try {
    await stopCampaign(key, campaignId, withReason(read.reason));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal };
    if (error instanceof NotFoundError) return failed("", t("campaign.gone"));
    if (error instanceof ConflictError) {
      if (error.reason !== "campaign-ended") return failed("", t("error.target.conflict"));
      // It ended on its own, or another stop came first: what was asked for is true.
      revalidatePath(ROUTES.campaign(campaignId));
      redirect(ROUTES.campaign(campaignId, { notice: "ended" }));
    }
    return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.campaign(campaignId));
  revalidatePath(ROUTES.campaigns);
  redirect(ROUTES.campaign(campaignId));
}

// ── Reverse Assessment (slice 12a) ────────────────────────────────────────────────────────────────────
// "Assess again" sends the tier alone: the API assesses the Build's most recent kept artifact again. The Console
// never uploads an artifact; when none is kept any more, the person is told how to upload it again.

export type AssessAgainState = null | { ok: false; errors: FieldError[] } | { ok: true; assessment: Assessment };

const isTier = (value: string): value is AssessmentTier => (TIER_IDS as readonly string[]).includes(value);

/** Requests a new Assessment of a Build's kept artifact at the chosen tier, then refreshes the Build page. */
export async function assessAgainAction(_previous: AssessAgainState, formData: FormData): Promise<AssessAgainState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const appId = text(formData, "appId");
  const buildId = text(formData, "buildId");
  const tier = text(formData, "tier");
  if (!ID_PATTERNS.app.test(appId) || !ID_PATTERNS.bld.test(buildId)) {
    return failed("", t("error.assessment.stale"));
  }
  if (!isTier(tier)) return failed("tier", t("error.assessment.tier"));

  let assessment: Assessment;
  try {
    ({ assessment } = await createAssessment(key, appId, buildId, { tier }));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ConflictError && error.reason === "artifact-required") {
      // The page still offers the control: refresh it so that it reads the artifact as no longer kept.
      revalidatePath(ROUTES.build(appId, buildId));
      return failed("", t("error.assessment.notKept"));
    }
    if (error instanceof ConflictError || error instanceof NotFoundError) {
      return failed("", t("error.assessment.stale"));
    }
    if (error instanceof ValidationError && error.errors.some((entry) => entry.path === "tier")) {
      return failed("tier", t("error.assessment.tier"));
    }
    return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.build(appId, buildId));
  return { ok: true, assessment };
}

// ── Audit log (slice 18a) ─────────────────────────────────────────────────────────────────────────────
// "Load more" reads the next page of the list with the filters of the page's address and the cursor of the last
// page. It changes nothing; the answer lives in the state of the page view that asked.

export type LoadMoreAuditState =
  | { ok: true; entries: AuditEntry[]; nextCursor: string | null }
  | { ok: false; message: string };

const CURSOR = /^[1-9][0-9]{0,15}$/;

/** The next page of the audit log after `cursor`, narrowed by `query` (the page's address, read again here). */
export async function loadMoreAuditAction(
  query: { action?: string; app?: string; from?: string; to?: string },
  cursor: string,
): Promise<LoadMoreAuditState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);
  if (typeof cursor !== "string" || !CURSOR.test(cursor)) return { ok: false, message: t("audit.more.failed") };
  const known = typeof query === "object" && query !== null ? query : {};
  try {
    const page = await listAudit(key, { ...auditFilterFrom(auditQueryFrom(known)), cursor });
    return { ok: true, entries: page.entries, nextCursor: page.next_cursor };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const pending = deletionPending(error, "read");
    if (pending !== null) return { ok: false, message: pending };
    if (error instanceof ApiError) return { ok: false, message: t("audit.more.failed") };
    throw error;
  }
}

export type VerifyAuditChainState =
  | { ok: true; result: Awaited<ReturnType<typeof verifyAudit>> }
  | { ok: false; limited?: { retryAfter: number | undefined }; message?: string };

/** "Verify chain" of a filtered Audit log view: the chain checked now, a 429 with its wait, or a failure. */
export async function verifyAuditChainAction(): Promise<VerifyAuditChainState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);
  try {
    return { ok: true, result: await verifyAudit(key) };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const pending = deletionPending(error, "read");
    if (pending !== null) return { ok: false, message: pending };
    if (error instanceof RateLimitedError) return { ok: false, limited: { retryAfter: error.retryAfter } };
    if (error instanceof ApiError) return { ok: false };
    throw error;
  }
}

// ── Data controls (slice 18b) ─────────────────────────────────────────────────────────────────────────
// Deleting the Organization needs its name typed exactly and a reason; cancelling it and erasing an end user's records
// need a reason. Each is checked here before anything is sent; the API alone decides. After a request or a
// cancellation the page is opened afresh, so that a reload never repeats it and the banner follows the new state.

export type DeletionChangeState = null | { ok: false; errors: FieldError[]; reason?: string };

export type EraseSubjectState =
  | null
  | { ok: false; errors: FieldError[]; reason?: string }
  | { ok: true; report: SubjectEraseReport };

/** Asks for the Organization's deletion: its keys stop at once, its data is erased after the grace period. */
export async function requestDeletionAction(
  previous: DeletionChangeState,
  formData: FormData,
): Promise<DeletionChangeState> {
  return keptReason(await requestDeletionChange(previous, formData), formData);
}

async function requestDeletionChange(_previous: DeletionChangeState, formData: FormData): Promise<DeletionChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  // The name exactly as typed: the API compares it with the Organization's name character for character.
  const raw = formData.get("confirm_name");
  const confirmName = typeof raw === "string" ? raw : "";
  if (confirmName.trim().length === 0 || confirmName.length > 200) {
    return failed("confirm_name", t("data.delete.name.required"));
  }
  const read = reasonFrom(formData, true);
  if ("error" in read) return { ok: false, errors: [read.error] };

  try {
    await requestDeletion(key, { confirm_name: confirmName }, withReason(read.reason));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    // Already pending: the page shows it.
    if (error instanceof ConflictError || error instanceof DeletionPendingError) redirect(ROUTES.dataControls());
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal };
    if (error instanceof ValidationError && error.errors.some((entry) => entry.path === "confirm_name")) {
      return failed("confirm_name", t("data.delete.name.required"));
    }
    return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.dataControls());
  redirect(ROUTES.dataControls({ done: "requested" }));
}

/** Cancels the pending deletion: every key works again at once. */
export async function cancelDeletionAction(
  previous: DeletionChangeState,
  formData: FormData,
): Promise<DeletionChangeState> {
  return keptReason(await cancelDeletionChange(previous, formData), formData);
}

async function cancelDeletionChange(_previous: DeletionChangeState, formData: FormData): Promise<DeletionChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);
  const read = reasonFrom(formData, true);
  if ("error" in read) return { ok: false, errors: [read.error] };

  try {
    await cancelDeletion(key, withReason(read.reason));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    // Nothing pending any more: the page shows what there is.
    if (error instanceof NotFoundError) redirect(ROUTES.dataControls());
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal };
    return { ok: false, errors: apiErrors(error, []) };
  }
  revalidatePath(ROUTES.dataControls());
  redirect(ROUTES.dataControls({ done: "cancelled" }));
}

/**
 * Erases one end user's Events and ended blocks by actor hash. Refused unless the form carries the confirmation: the
 * actor hash named in the question. Active blocks are kept until they end; the report lists them.
 */
export async function eraseSubjectAction(previous: EraseSubjectState, formData: FormData): Promise<EraseSubjectState> {
  const state = await eraseSubjectChange(previous, formData);
  return state?.ok === true ? state : keptReason(state, formData);
}

async function eraseSubjectChange(_previous: EraseSubjectState, formData: FormData): Promise<EraseSubjectState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const ipHash = text(formData, "ip_hash");
  if (!ACTOR_HASH_PATTERN.test(ipHash)) return failed("ip_hash", t("data.subject.invalid"));
  if (text(formData, "confirm") !== ipHash) return failed("", t("data.subject.confirm.required"));
  const read = reasonFrom(formData, true);
  if ("error" in read) return { ok: false, errors: [read.error] };

  try {
    const { report } = await eraseSubject(key, ipHash, withReason(read.reason));
    return { ok: true, report };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal };
    return { ok: false, errors: apiErrors(error, []) };
  }
}

// ── Retention (slice 18c) ─────────────────────────────────────────────────────────────────────────────
// Lengthening (or keeping) the Event retention is sent at once, without a reason. Shortening removes Events at the next
// run: the page asks for it in its confirmation step, which sends `confirm=shorten` and a reason, forwarded as the
// reason header. The API alone decides what a shortening is: when it asks for a reason that was not sent (a tab that
// shows an older period), the state names the period so that the page opens the confirmation step for it.

export type RetentionChangeState =
  | null
  | { ok: false; errors: FieldError[]; reason?: string; confirm?: EventRetentionDays }
  | { ok: true; days: EventRetentionDays; eventsRemovedBefore: string };

const isRetentionDays = (value: number): value is EventRetentionDays =>
  (EVENT_RETENTION_DAYS as readonly number[]).includes(value);

/** Sets the Event retention; from the confirmation step (a shortening), with the reason it requires. */
export async function updateRetentionAction(
  previous: RetentionChangeState,
  formData: FormData,
): Promise<RetentionChangeState> {
  const state = await updateRetentionChange(previous, formData);
  return state?.ok === true ? state : keptReason(state, formData);
}

async function updateRetentionChange(
  _previous: RetentionChangeState,
  formData: FormData,
): Promise<RetentionChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const raw = text(formData, "event_retention_days");
  const days = /^[0-9]{1,3}$/.test(raw) ? Number(raw) : Number.NaN;
  if (!isRetentionDays(days)) return failed("event_retention_days", t("data.retention.invalid"));
  // The confirmation step stays open on every refusal it gets back.
  const fromStep = text(formData, "confirm") === "shorten";
  const step = fromStep ? { confirm: days } : {};
  const read = reasonFrom(formData, fromStep);
  if ("error" in read) return { ok: false, errors: [read.error], ...step };

  try {
    const answer = await updateRetention(key, { event_retention_days: days }, withReason(read.reason));
    revalidatePath(ROUTES.dataControls());
    return { ok: true, days, eventsRemovedBefore: answer.events_removed_before };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ReasonRequiredError && !fromStep) {
      // A shortening after all: the page shows the period the API holds, and the step for this one.
      revalidatePath(ROUTES.dataControls());
      return { ok: false, errors: [], confirm: days };
    }
    const refusal = reasonRefusal(error);
    if (refusal) return { ok: false, errors: refusal, ...step };
    if (error instanceof ValidationError && error.errors.some((entry) => entry.path === "event_retention_days")) {
      return { ...failed("event_retention_days", t("data.retention.invalid")), ...step };
    }
    return { ok: false, errors: apiErrors(error, []), ...step };
  }
}

/** Ends the session. */
export async function signOutAction(): Promise<void> {
  await clearSession();
  redirect(ROUTES.home);
}
