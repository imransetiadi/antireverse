import "server-only";
import { cookies } from "next/headers";

/** The session cookie. Its value is the admin key, so it is httpOnly and never rendered. */
export const SESSION_COOKIE = "ar_admin";

/** Seven days. */
export const SESSION_MAX_AGE_SECONDS = 604_800;

/** The admin key of the current request, or undefined without a session. */
export async function readSession(): Promise<string | undefined> {
  const value = (await cookies()).get(SESSION_COOKIE)?.value;
  return value ? value : undefined;
}

/** Stores the admin key. Only a Server Action or a Route Handler may call this. */
export async function writeSession(adminKey: string): Promise<void> {
  (await cookies()).set(SESSION_COOKIE, adminKey, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_MAX_AGE_SECONDS,
  });
}

/** Ends the session. Only a Server Action or a Route Handler may call this. */
export async function clearSession(): Promise<void> {
  (await cookies()).delete(SESSION_COOKIE);
}
