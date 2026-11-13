/**
 * A refused state without the reason the action gives back (slice 18a review F2), for the tests written before it
 * that are about the refusal itself. `audit-actions.test.ts` checks the reason that comes back.
 */
export function dropReason<S>(state: S): S {
  if (state === null || typeof state !== "object" || !("reason" in state)) return state;
  const { reason: _reason, ...rest } = state as S & { reason: unknown };
  return rest as S;
}
