import { CONFIRMATION_TOKEN_PATTERN } from "@antireverse/protocol";

/** What a confirmation link came to: it worked, it did not, too many tries, or the API could not tell. */
export const CONFIRM_OUTCOMES = ["confirmed", "invalid", "busy", "unavailable"] as const;
export type ConfirmOutcome = (typeof CONFIRM_OUTCOMES)[number];

/** Whether a value of the address is a well-formed confirmation token (a single one). */
export const isConfirmationToken = (value: unknown): value is string =>
  typeof value === "string" && CONFIRMATION_TOKEN_PATTERN.test(value);

/** The outcome named by `?result=` of the done page; anything else (missing, repeated, unknown) is invalid. */
export const outcomeFrom = (value: unknown): ConfirmOutcome =>
  CONFIRM_OUTCOMES.find((outcome) => outcome === value) ?? "invalid";
