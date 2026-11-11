import type { LimitCount, LimitKey, RuleLimit } from "@antireverse/protocol";
import { formatBytes } from "@/lib/format.ts";
import { type MessageKey, t } from "@/lib/t.ts";

// The limit of a Rule (slice 08, D-063) as the Console says and sends it. Isomorphic: the form, the Rule list
// and the Server Action share it — the action's check is the one that counts.

/** The names of the form's limit fields. The action reads them; an error is reported under the same name. */
export const LIMIT_FIELDS = {
  requests: "limitRequests",
  window: "limitWindow",
  key: "limitKey",
  count: "limitCount",
} as const;

/** The limit fields as typed: text, so that a refused value can be shown again exactly as it was entered. */
export interface LimitDraft {
  requests: string;
  window: string;
  key: string;
  count: string;
}

/** What the limit fields hold before anything is typed: per address, every request. */
export const EMPTY_LIMIT: LimitDraft = { requests: "", window: "", key: "ip", count: "requests" };

/**
 * The "Login protection" preset: what its button fills in. The admin still types the name and the path, and
 * the Rule starts in monitor mode like every new Rule.
 */
export const LOGIN_PROTECTION: { methods: readonly ["POST"]; action: "throttle"; limit: LimitDraft } = {
  methods: ["POST"],
  action: "throttle",
  limit: { requests: "10", window: "300", key: "ip", count: "failures" },
};

const WHOLE = /^[1-9][0-9]{0,8}$/;

/** A whole number from 1 to `max` written in plain digits, or null for anything else. Nothing is trimmed. */
export function wholeNumber(value: string, max: number): number | null {
  if (!WHOLE.test(value)) return null;
  const number = Number(value);
  return number <= max ? number : null;
}

/** A window in the largest units that fit: `45 s`, `5 min`, `1 min 30 s`, `1 h`. */
export function windowText(seconds: number): string {
  const parts: string[] = [];
  const hours = Math.floor(seconds / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const rest = seconds % 60;
  if (hours > 0) parts.push(`${hours} h`);
  if (minutes > 0) parts.push(`${minutes} min`);
  if (rest > 0 || parts.length === 0) parts.push(`${rest} s`);
  return parts.join(" ");
}

const COUNT: Record<LimitCount, { one: MessageKey; many: MessageKey }> = {
  requests: { one: "policy.limit.count.requests.one", many: "policy.limit.count.requests" },
  failures: { one: "policy.limit.count.failures.one", many: "policy.limit.count.failures" },
};
const KEY: Record<LimitKey, MessageKey> = { ip: "policy.limit.key.ip", device: "policy.limit.key.device" };

/**
 * The largest limit Shield counts exactly (plan amendment A7, F2); above it Shield counts approximately, and the
 * tag says so.
 */
export const EXACT_LIMIT_MAX = 1_000;

/**
 * A limit in words, e.g. `10 failed responses / 5 min per address` or `100 requests / 1 min per device`; above
 * `EXACT_LIMIT_MAX`, `About 5,000 requests / 1 min per address`.
 */
export function limitText(limit: RuleLimit): string {
  const words = COUNT[limit.count];
  return t(limit.requests > EXACT_LIMIT_MAX ? "policy.limit.tag.approx" : "policy.limit.tag", {
    count: limit.requests === 1 ? t(words.one) : t(words.many, { n: formatBytes(limit.requests) }),
    window: windowText(limit.window_s),
    key: t(KEY[limit.key]),
  });
}
