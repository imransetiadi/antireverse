import type { OrganizationDeletion, SubjectEraseReport } from "@antireverse/protocol";

/** Slice 18b: a pending deletion, an actor hash and an erase report, shared by the data-controls tests. */
export const PENDING: OrganizationDeletion = {
  id: "del_0123456789abcdef01234567",
  organization_id: "org_0123456789abcdef01234567",
  status: "pending",
  requested_at: "2026-11-13T09:00:00.000Z",
  purge_after: "2026-11-20T09:00:00.000Z",
  cancelled_at: null,
  purged_at: null,
};

export const IP_HASH = "iph_0123456789abcdef0123456789abcdef";

export const ERASE_REPORT: SubjectEraseReport = {
  ip_hash: IP_HASH,
  events_erased: 12,
  containments_erased: 1,
  active_containments: [{ id: "cnt_0123456789abcdef01234567", expires_at: "2026-11-14T10:00:00.000Z" }],
};

export const PENDING_PROBLEM = {
  type: "https://antireverse.dev/problems/organization-deletion-pending",
  title: "Organization deletion pending",
  status: 403,
};
