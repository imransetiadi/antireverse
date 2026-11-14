"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { ApiError, getSloReport, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { clearOpsSession, isCrossSiteForm, OPS_TOKEN_PATTERN, writeOpsSession } from "@/lib/ops-session.ts";
import { ROUTES } from "@/lib/routes.ts";
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
