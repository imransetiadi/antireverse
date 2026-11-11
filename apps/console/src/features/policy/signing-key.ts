import "server-only";
import { ApiError, getSigningKey } from "@/lib/api.ts";

/**
 * The policy public key for a set-up snippet, or null when the API could not give it. The key is not a
 * secret. A screen that only shows it must still load without it, and says that the key is missing.
 */
export async function policyPublicKey(): Promise<string | null> {
  try {
    return (await getSigningKey()).public_key;
  } catch (error) {
    if (error instanceof ApiError) return null;
    throw error;
  }
}
