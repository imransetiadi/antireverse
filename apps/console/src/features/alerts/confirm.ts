import "server-only";
import { ApiError, confirmAlertRecipient, RateLimitedError, ValidationError } from "@/lib/api.ts";
import { type ConfirmOutcome, isConfirmationToken } from "./confirm-result.ts";

/**
 * Confirms an alert recipient with the token of its confirmation link (slice 06b), server-side, after the person
 * clicked "Confirm email" (never on load: mail link scanners open links by themselves). The public API endpoint
 * gets it in a request body. A missing, repeated or malformed token is invalid without a call. The token
 * is never logged and never part of the answer; the API answers alike for an unknown, used and expired one.
 */
export async function confirmRecipientToken(token: unknown): Promise<ConfirmOutcome> {
  if (!isConfirmationToken(token)) return "invalid";
  try {
    const { confirmed } = await confirmAlertRecipient(token);
    return confirmed ? "confirmed" : "invalid";
  } catch (error) {
    if (error instanceof RateLimitedError) return "busy";
    if (error instanceof ValidationError) return "invalid";
    if (error instanceof ApiError) return "unavailable";
    throw error;
  }
}
