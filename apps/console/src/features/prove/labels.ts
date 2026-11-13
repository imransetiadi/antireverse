import type {
  AuthorizeReason,
  DnsVerifyFailure,
  FileVerifyFailure,
  Intensity,
  RoeWindow,
  TargetStatus,
  VerificationMethod,
  Weekday,
} from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";

// The words of Prove (slice 14). Pure: the same on the server and in the browser.

export const TARGET_STATUS_LABEL: Record<TargetStatus, MessageKey> = {
  pending: "target.status.pending",
  verified: "target.status.verified",
  lapsed: "target.status.lapsed",
};

export const TARGET_STATUS_HELP: Record<TargetStatus, MessageKey> = {
  pending: "target.status.help.pending",
  verified: "target.status.help.verified",
  lapsed: "target.status.help.lapsed",
};

export const METHOD_LABEL: Record<VerificationMethod, MessageKey> = {
  dns: "target.method.dns",
  file: "target.method.file",
};

/** Why the DNS method failed, in a plain sentence. */
export const DNS_FAILURE_LABEL: Record<DnsVerifyFailure, MessageKey> = {
  no_record: "verify.dns.no_record",
  mismatch: "verify.dns.mismatch",
  lookup_failed: "verify.dns.lookup_failed",
};

/** Why the file method failed, in a plain sentence. */
export const FILE_FAILURE_LABEL: Record<FileVerifyFailure, MessageKey> = {
  not_reachable: "verify.file.not_reachable",
  connect_failed: "verify.file.connect_failed",
  tls_failed: "verify.file.tls_failed",
  redirect: "verify.file.redirect",
  status: "verify.file.status",
  timeout: "verify.file.timeout",
  too_large: "verify.file.too_large",
  mismatch: "verify.file.mismatch",
};

/** Why `authorize` refused a test, in a plain sentence. */
export const AUTHORIZE_REASON_LABEL: Record<AuthorizeReason, MessageKey> = {
  target_unknown: "authorize.target_unknown",
  target_not_verified: "authorize.target_not_verified",
  no_rules_of_engagement: "authorize.no_rules_of_engagement",
  out_of_scope: "authorize.out_of_scope",
  path_excluded: "authorize.path_excluded",
  intensity_exceeds: "authorize.intensity_exceeds",
  outside_window: "authorize.outside_window",
};

/** What each intensity allows. The intensity itself is shown as its value (`safe-active`), never translated. */
export const INTENSITY_HELP: Record<Intensity, MessageKey> = {
  passive: "intensity.help.passive",
  "safe-active": "intensity.help.safe-active",
  full: "intensity.help.full",
};

export const DAY_LABEL: Record<Weekday, MessageKey> = {
  mon: "day.mon",
  tue: "day.tue",
  wed: "day.wed",
  thu: "day.thu",
  fri: "day.fri",
  sat: "day.sat",
  sun: "day.sun",
};

/** The window in words: `Mon, Tue, 09:00 to 17:00 UTC`, `…, all day UTC` or `…, 22:00 to 06:00 the next day UTC`. */
export function windowText(window: RoeWindow): string {
  const days = window.days.map((day) => t(DAY_LABEL[day])).join(", ");
  if (window.from === "00:00" && window.to === "24:00") return t("roe.window.allDay", { days });
  const overnight = window.to !== "24:00" && window.to < window.from;
  return t(overnight ? "roe.window.overnight" : "roe.window.hours", { days, from: window.from, to: window.to });
}

/** A SHA-256 hex for display: its first 12 characters and an ellipsis. The full value goes in a title. */
export const shortHash = (hex: string): string => (hex.length > 12 ? `${hex.slice(0, 12)}…` : hex);
