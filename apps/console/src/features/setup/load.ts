import "server-only";
import { redirect } from "next/navigation";
import { getAppSetup, UnauthorizedError } from "@/lib/api.ts";
import { ROUTES } from "@/lib/routes.ts";
import { doneCount } from "./setup-state.ts";

/**
 * How many set-up steps of the App's own Environment are done, for "Set up: n of 3" (slice 16). Null when the API
 * could not say: the progress is a hint, so a failure never breaks the screen that shows it. A 401 goes to sign-in,
 * as every screen does for its own data.
 */
export async function loadSetupDone(key: string, appId: string): Promise<number | null> {
  try {
    return doneCount((await getAppSetup(key, appId)).setup);
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    return null;
  }
}
