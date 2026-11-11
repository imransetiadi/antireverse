import type { Finding, PatchSummary } from "@antireverse/protocol";

type QueryValue = string | string[] | undefined;

/** True when the address asks for the step that enforces the Finding's patch: exactly `?confirm=enforce`. */
export function confirmEnforceFrom(value: QueryValue): boolean {
  return value === "enforce";
}

/**
 * The virtual patch of a Finding: the one the API names it in, else one for its advisory (or an alias) in its
 * package — a patch that is not active there lists no Finding. Null when there is none.
 */
export function patchForFinding(patches: readonly PatchSummary[], finding: Finding): PatchSummary | null {
  const byId = patches.find((patch) => patch.findings.includes(finding.id));
  if (byId) return byId;
  const ids = new Set([finding.advisory_id, ...finding.aliases]);
  return (
    patches.find(
      (patch) => patch.package === finding.package && patch.advisories.some((advisory) => ids.has(advisory)),
    ) ?? null
  );
}
