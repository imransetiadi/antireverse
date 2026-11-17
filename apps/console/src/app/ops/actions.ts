"use server";

import {
  holdsSecretShape,
  ID_PATTERNS,
  ProveOperatorRequestSchema,
  type ProveOperatorState,
} from "@antireverse/protocol";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import {
  ApiError,
  enableCampaigns,
  getSloReport,
  killCampaigns,
  NotFoundError,
  resumeCampaigns,
  suspendCampaigns,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";
import {
  clearOpsSession,
  isCrossSiteForm,
  OPS_TOKEN_PATTERN,
  readOpsSession,
  writeOpsSession,
} from "@/lib/ops-session.ts";
import { type OpsProveDone, ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

// Slice 18d: the Server Actions of the operator dashboard. Each is a public POST endpoint: a form another site sent is
// refused before anything else. The operator token travels in the form body and the operator cookie only — never in a
// URL, the action state or a log line.

export type OpsSignInState = null | { ok: false; message: string };

/** Signs in with the operator token. It is checked by reading the SLO report with it and stored only when accepted. */
export async function opsSignInAction(_previous: OpsSignInState, formData: FormData): Promise<OpsSignInState> {
  if (isCrossSiteForm(await headers())) return { ok: false, message: t("ops.signin.crossSite") };
  const value = formData.get("token");
  const token = typeof value === "string" ? value.trim() : "";
  // A value that cannot be a token is never sent anywhere.
  if (!OPS_TOKEN_PATTERN.test(token)) return { ok: false, message: t("ops.signin.invalid") };
  try {
    await getSloReport(token);
  } catch (error) {
    if (error instanceof UnauthorizedError) return { ok: false, message: t("ops.signin.invalid") };
    if (error instanceof NotFoundError) return { ok: false, message: t("ops.signin.disabled") };
    // 502: the API client's verdict on an answer outside the contract.
    if (error instanceof ApiError) {
      return { ok: false, message: t(error.status === 502 ? "ops.signin.unexpected" : "ops.signin.failed") };
    }
    throw error;
  }
  await writeOpsSession(token);
  redirect(ROUTES.ops);
}

/** Ends the operator session. A sign-out another site sent changes nothing. */
export async function opsSignOutAction(): Promise<void> {
  if (isCrossSiteForm(await headers())) redirect(ROUTES.ops);
  await clearOpsSession();
  redirect(ROUTES.opsSignIn);
}

// ── The operator's Campaign switches (slice 15a) ──────────────────────────────────────────────────────
// Stop all Campaigns, enable them again, suspend or resume one Organization. Each needs the operator session and a
// reason, checked here before anything is sent; the API checks again and alone decides. After a change the page is
// opened afresh with what was done, so that a reload never repeats it.

export interface OpsProveValues {
  change: string;
  organization: string;
  reason: string;
}

export type OpsProveState = null | {
  ok: false;
  errors: Array<{ path: "" | "reason" | "organization"; message: string }>;
  /** What was typed, shown again. Never the token. */
  values: OpsProveValues;
};

const PROVE_CHANGES = ["kill", "enable", "suspend", "resume"] as const;
const isProveChange = (value: string): value is OpsProveDone => (PROVE_CHANGES as readonly string[]).includes(value);

const field = (formData: FormData, name: string): string => {
  const value = formData.get(name);
  return typeof value === "string" ? value.trim() : "";
};

export async function proveSwitchAction(_previous: OpsProveState, formData: FormData): Promise<OpsProveState> {
  const values: OpsProveValues = {
    change: field(formData, "change"),
    organization: field(formData, "organization"),
    reason: field(formData, "reason"),
  };
  const refused = (path: "" | "reason" | "organization", message: string): OpsProveState => ({
    ok: false,
    errors: [{ path, message }],
    values,
  });
  if (isCrossSiteForm(await headers())) return refused("", t("ops.prove.error.crossSite"));
  const token = await readOpsSession();
  if (token === undefined) redirect(ROUTES.opsSignIn);

  const { change, organization } = values;
  if (!isProveChange(change)) return refused("", t("ops.prove.error.change"));
  const parsed = ProveOperatorRequestSchema.safeParse({ reason: values.reason });
  if (!parsed.success) return refused("reason", t("ops.prove.error.reason"));
  const { reason } = parsed.data;
  // The reason is stored in the audit log of each Organization it affects: a secret in it is refused.
  if (holdsSecretShape(reason)) return refused("reason", t("error.reason.secret"));
  const perOrganization = change === "suspend" || change === "resume";
  if (perOrganization && !ID_PATTERNS.org.test(organization)) {
    return refused("organization", t("ops.prove.error.organization"));
  }

  let state: ProveOperatorState;
  try {
    if (change === "kill") state = await killCampaigns(token, reason);
    else if (change === "enable") state = await enableCampaigns(token, reason);
    else if (change === "suspend") state = await suspendCampaigns(token, organization, reason);
    else state = await resumeCampaigns(token, organization, reason);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.opsExpired);
    if (error instanceof NotFoundError) {
      return perOrganization
        ? refused("organization", t("ops.prove.error.unknownOrganization"))
        : refused("", t("ops.prove.error.disabled"));
    }
    if (error instanceof ValidationError) return refused("reason", t("ops.prove.error.reason"));
    if (error instanceof ApiError) return refused("", t("ops.prove.error.failed"));
    throw error;
  }
  redirect(
    ROUTES.opsProve(
      change === "kill" || change === "suspend" ? { done: change, stopped: state.stopped } : { done: change },
    ),
  );
}
