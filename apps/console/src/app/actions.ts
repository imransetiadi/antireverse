"use server";

import {
  ACTOR_HASH_PATTERN,
  ADMIN_KEY_PATTERN,
  ALERT_CHANNEL_KINDS,
  type AlertChannel,
  type AlertChannelKind,
  type AlertDelivery,
  type AllowlistEntry,
  type App,
  CONTAINMENT_LIMITS,
  CONTAINMENT_TTLS,
  type ContainmentTtl,
  type CreateContainmentRequest,
  DECISION_MODES,
  type DecisionMode,
  ENVIRONMENTS,
  type Environment,
  EXPOSURE_LIMITS,
  ID_PATTERNS,
  INCIDENT_LIMITS,
  IP_PREFIX_PATTERN,
  isBroadPattern,
  LIMITS,
  type Organization,
  PATCH_ID_PATTERN,
  PATH_PATTERN,
  POLICY_LIMITS,
  type PolicyRule,
  type PolicyRuleInput,
  parseCidr,
} from "@antireverse/protocol";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { suggestCidr } from "@/features/containment/format.ts";
import { untilFromDate } from "@/features/findings/format.ts";
import { isBroadEnforce, newlyBroad } from "@/features/policy/broad.ts";
import { RULE_METHODS } from "@/features/policy/methods.ts";
import {
  ApiError,
  ConflictError,
  createAlertChannel,
  createAllowlistEntry,
  createApp,
  createContainment,
  createOrganization,
  deleteAlertChannel,
  deleteAllowlistEntry,
  getOrganization,
  getPolicy,
  getPolicyVersion,
  ignoreFinding,
  liftContainment,
  NotFoundError,
  type PatchModeRequest,
  publishPolicy,
  reopenFinding,
  rollbackPolicy,
  setPatchMode,
  testAlertChannel,
  UnauthorizedError,
  updateIncident,
  ValidationError,
} from "@/lib/api.ts";
import { ROUTES } from "@/lib/routes.ts";
import { clearSession, readSession, writeSession } from "@/lib/session.ts";
import { t } from "@/lib/t.ts";

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

function isEnvironment(value: string): value is Environment {
  return (ENVIRONMENTS as readonly string[]).includes(value);
}

function isMode(value: string): value is DecisionMode {
  return (DECISION_MODES as readonly string[]).includes(value);
}

/** What to tell the person when the API refused or failed. Anything that is not an ApiError is a defect and is rethrown. */
function apiErrors(error: unknown, fields: readonly string[]): FieldError[] {
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
  /** What was typed, so the form can show it again; `requires` is true when Require a signed request was checked. */
  values: { name: string; path: string; methods: string[]; requires?: boolean };
};

export type PolicyChangeState = null | { ok: false; errors: FieldError[] };

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
      const [, index, field] = RULE_ERROR_PATH.exec(entry.path) ?? [];
      if (field === undefined) continue;
      // The API's guardrail and its refusal of an unacknowledged broad pattern speak through the mode of a Rule.
      if (field === "mode") {
        const rule = sent[Number(index)];
        const broad = rule !== undefined && rule.path !== BLOCKS_EVERYTHING && isBroadPattern(rule.path);
        errors.set("mode", { path: "mode", message: t(broad ? "policy.broad.unconfirmed" : "policy.guardrail") });
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
    const options = acknowledgement(policy.rules, next.rules, next.broadConfirmed === true);
    if (options) await publishPolicy(key, target.appId, target.environment, next.rules, shown, options);
    else await publishPolicy(key, target.appId, target.environment, next.rules, shown);
    return null;
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    return policyErrors(error, index === undefined ? undefined : { index, fields }, sent);
  }
}

/** Adds one Rule to the end of the Policy — always in Monitor mode — and publishes. */
export async function publishRuleAction(_previous: PublishRuleState, formData: FormData): Promise<PublishRuleState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

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
  const values = { name, path, methods, requires };

  const target = policyTarget(formData);
  const shown = shownVersion(formData);
  if (!target || shown === null) return { ...stale(), values };
  if (requirement !== null && !requires) return { ...stale(), values };

  const invalid: FieldError[] = [];
  const badName = nameError(name);
  if (badName) invalid.push(badName);
  if (path.length === 0) invalid.push({ path: "path", message: t("error.path.required") });
  else if (!PATH_PATTERN.test(path)) invalid.push({ path: "path", message: t("error.path.invalid") });
  if (methods.some((method) => !(RULE_METHODS as readonly string[]).includes(method))) {
    invalid.push({ path: "methods", message: t("error.methods") });
  }
  if (invalid.length > 0) return { ok: false, errors: invalid, values };

  const errors = await changePolicy(
    key,
    target,
    shown,
    (rules) => {
      if (rules.length >= POLICY_LIMITS.rulesMax) return [{ path: "", message: t("error.rules.max") }];
      // The mode is not read from the form: a new Rule observes first, whatever its pattern.
      // A requirement keeps the action block: the Rule blocks only the requests that do not meet it.
      const rule: PolicyRuleInput = { name, path, methods, action: "block", mode: "monitor" };
      if (requires) rule.requires = "signature";
      return { rules: [...rules, rule], index: rules.length };
    },
    ["name", "path", "methods"],
  );
  if (errors) return { ok: false, errors, values };
  published(target);
}

/**
 * Changes the mode of one Rule and publishes. Promoting to Enforce starts blocking requests, so it is
 * refused unless the form carries the confirmation — and, for a broad pattern, the typed Environment.
 * Going back to Monitor needs none.
 */
export async function setRuleModeAction(_previous: PolicyChangeState, formData: FormData): Promise<PolicyChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const target = policyTarget(formData);
  const shown = shownVersion(formData);
  const ruleId = text(formData, "ruleId");
  const mode = text(formData, "mode");
  if (!target || shown === null || !ID_PATTERNS.rul.test(ruleId) || !isMode(mode)) return stale();
  if (mode === "enforce" && !confirmed(formData, target)) return failed("confirm", t("policy.confirm.required"));

  const errors = await changePolicy(key, target, shown, (rules) => {
    const index = rules.findIndex((rule) => rule.id === ruleId);
    const rule = rules[index];
    if (!rule) return staleErrors();
    if (rule.mode === mode) return "unchanged";
    let broadConfirmed = false;
    if (mode === "enforce") {
      if (rule.path === BLOCKS_EVERYTHING) return [{ path: "mode", message: t("policy.guardrail") }];
      if (isBroadPattern(rule.path)) {
        const typed = typedError(formData, target);
        if (typed) return [typed];
        broadConfirmed = true;
      }
    }
    return { rules: rules.map((other) => (other === rule ? { ...rule, mode } : other)), index, broadConfirmed };
  });
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
  _previous: PolicyChangeState,
  formData: FormData,
): Promise<PolicyChangeState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const target = policyTarget(formData);
  const shown = shownVersion(formData);
  const version = text(formData, "version");
  if (!target || shown === null || !VERSION.test(version)) return stale();
  if (!confirmed(formData, target)) return failed("confirm", t("policy.confirm.required"));

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
    const options = acknowledgement(current.rules, earlier.rules, confirmedNow);
    if (options) await rollbackPolicy(key, target.appId, target.environment, Number(version), shown, options);
    else await rollbackPolicy(key, target.appId, target.environment, Number(version), shown);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    return { ok: false, errors: policyErrors(error, undefined, sent) };
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
// comes back once, in the action state of the form that created it, and is rendered once.

export type CreateAlertChannelState =
  | null
  | { ok: false; errors: FieldError[]; values: { kind: string; name: string } }
  | { ok: true; channel: AlertChannel; signingSecret?: string };

export type AlertChannelChangeState = null | { ok: false; errors: FieldError[] };

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

/** Adds a webhook or Slack channel. A webhook's signing secret is returned to be shown once. */
export async function createAlertChannelAction(
  _previous: CreateAlertChannelState,
  formData: FormData,
): Promise<CreateAlertChannelState> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);

  const kind = text(formData, "kind");
  const name = text(formData, "name");
  const url = text(formData, "url");
  // The URL is deliberately not among the values sent back to the form.
  const values = { kind, name };

  const invalid: FieldError[] = [];
  if (!isChannelKind(kind)) invalid.push({ path: "kind", message: t("error.alerts.kind") });
  const badName = nameError(name);
  if (badName) invalid.push(badName);
  const badUrl = urlError(url);
  if (badUrl) invalid.push(badUrl);
  if (invalid.length > 0 || !isChannelKind(kind)) return { ok: false, errors: invalid, values };

  let created: Awaited<ReturnType<typeof createAlertChannel>>;
  try {
    created = await createAlertChannel(key, { kind, name, url });
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof ConflictError)
      return { ok: false, errors: [{ path: "", message: t("error.alerts.max") }], values };
    if (error instanceof ValidationError) {
      const errors: FieldError[] = [];
      const paths = new Set(error.errors.map((entry) => entry.path));
      // A refused URL (scheme, private address, …) is explained without repeating it.
      if (paths.has("url")) errors.push({ path: "url", message: t("error.alerts.url.refused") });
      if (paths.has("name")) errors.push({ path: "name", message: t("error.field") });
      if (paths.has("kind")) errors.push({ path: "kind", message: t("error.alerts.kind") });
      return { ok: false, errors: errors.length > 0 ? errors : [{ path: "", message: t("error.api.failed") }], values };
    }
    return { ok: false, errors: apiErrors(error, []), values };
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
    if (error instanceof NotFoundError) return { ok: false, message: t("error.alerts.gone") };
    if (error instanceof ApiError) {
      return { ok: false, message: t(error.status === 0 ? "error.alerts.test.api" : "error.alerts.test") };
    }
    throw error;
  }
}

// ── Containment (slice 09) ────────────────────────────────────────────────────────────────────────────
// A block is never one click. The containment bar only opens a confirmation step (a GET of the Incident's
// address); its form carries the target the question named (`confirm`). Blocking the network needs the
// stronger confirmation as well: the prefix typed by the person (`typedPrefix`), matched exactly here before
// anything is sent, and then sent as `confirm_prefix` so that the API checks it against the Incident again.
// A 409 carries the API's `reason`, which alone decides the message; nothing is read again to guess it. The
// form also carries the Environment the question named, for the cap message. Lifting is confirmed the same
// way, by the block's id.

export type ContainmentChangeState = null | { ok: false; errors: FieldError[] };

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

  let appId: string;
  try {
    ({
      containment: { app_id: appId },
    } = await createContainment(key, incidentId, request));
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
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

export type PatchModeState = null | { ok: false; errors: FieldError[] };

const patchStale = (): { ok: false; errors: FieldError[] } => failed("", t("error.patch.stale"));
const patchMismatch = (patchId: string): { ok: false; errors: FieldError[] } =>
  failed("confirm", t("patch.confirm.mismatch", { patch: patchId }));

/** Sets the mode of a virtual patch in one App and Environment, from the Finding page, then goes back to it. */
export async function setPatchModeAction(_previous: PatchModeState, formData: FormData): Promise<PatchModeState> {
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

  try {
    await setPatchMode(key, appId, patchId, request);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
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

/** Ends the session. */
export async function signOutAction(): Promise<void> {
  await clearSession();
  redirect(ROUTES.home);
}
