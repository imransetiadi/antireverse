import "server-only";
import type { Environment, PatchSummary, StoredEvent } from "@antireverse/protocol";
import { listPatches, UnauthorizedError } from "@/lib/api.ts";

/**
 * The virtual patches of an App and Environment for a page that shows them beside other content: null when they
 * could not be read (an older API, a refusal, an outage), so the rest of the page still renders. A key the API no
 * longer accepts is passed on.
 */
export async function patchesOrNull(
  key: string,
  appId: string,
  environment: Environment,
): Promise<PatchSummary[] | null> {
  try {
    return (await listPatches(key, appId, environment)).patches;
  } catch (error) {
    if (error instanceof UnauthorizedError) throw error;
    return null;
  }
}

/** Patch titles by id, to name the patch of an Event; empty when they could not be read (ids are shown then). */
export function patchTitles(patches: readonly PatchSummary[] | null): Record<string, string> {
  return Object.fromEntries((patches ?? []).map((patch) => [patch.id, patch.title]));
}

/**
 * Patch titles for a feed: read for each Environment present in `events`, once each, and merged. An Environment
 * whose patches could not be read adds nothing (its patches are named by id); an Environment that first appears
 * later on the stream is named by id too.
 */
export async function feedPatchTitles(
  key: string,
  appId: string,
  events: readonly StoredEvent[],
): Promise<Record<string, string>> {
  const environments = [...new Set(events.map((event) => event.environment))];
  const lists = await Promise.all(environments.map((environment) => patchesOrNull(key, appId, environment)));
  return Object.assign({}, ...lists.map(patchTitles));
}
