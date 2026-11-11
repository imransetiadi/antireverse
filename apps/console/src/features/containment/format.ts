import {
  CIDR_PREFIX_BOUNDS,
  type ContainmentTarget,
  type ContainmentTtl,
  parseAddress,
  parseCidr,
} from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";

// Pure formatting for containment: the same on the server and in the browser.

/** The words of each duration a block can have. */
export const TTL_LABEL: Record<ContainmentTtl, MessageKey> = {
  900: "containment.ttl.900",
  3600: "containment.ttl.3600",
  86400: "containment.ttl.86400",
};

/** The first 8 characters after an identifier's prefix and an ellipsis: `iph_2932b22c…`. The full value goes in a title. */
function shorten(value: string): string {
  const cut = value.indexOf("_") + 1 + 8;
  return value.length > cut ? `${value.slice(0, cut)}…` : value;
}

/** An actor hash for display; the full hash belongs in `title` and the accessible name. */
export const shortHash = (ipHash: string): string => shorten(ipHash);

/** A key id (or any `xxx_<hex>` id) for display. */
export const shortId = (id: string): string => shorten(id);

const two = (value: number): string => String(value).padStart(2, "0");

/**
 * When a block created now would end: `HH:MM UTC`, or `YYYY-MM-DD HH:MM UTC` when that is on another UTC day.
 * The API sets the real expiry when it stores the block; this is the statement of the confirmation.
 */
export function expiryText(nowMs: number, ttlS: number): string {
  const now = new Date(nowMs);
  const end = new Date(nowMs + ttlS * 1000);
  const clock = `${two(end.getUTCHours())}:${two(end.getUTCMinutes())}`;
  const sameDay =
    now.getUTCFullYear() === end.getUTCFullYear() &&
    now.getUTCMonth() === end.getUTCMonth() &&
    now.getUTCDate() === end.getUTCDate();
  const day = `${end.getUTCFullYear()}-${two(end.getUTCMonth() + 1)}-${two(end.getUTCDate())}`;
  return t("containment.until", { time: sameDay ? clock : `${day} ${clock}` });
}

/** What a block blocks, in words: `Actor iph_2932b22c…` or `Network 203.0.113.0/24`. */
export function targetText(target: ContainmentTarget): string {
  return target.kind === "actor"
    ? t("blocks.target.actor", { actor: shortHash(target.ip_hash) })
    : t("blocks.target.network", { network: target.ip_prefix });
}

/**
 * The canonical CIDR the person probably meant, or null when there is none or the text is canonical already.
 * Covers another spelling (`2001:DB8::/32`) and host bits that are set (`203.0.113.7/24` → `203.0.113.0/24`).
 */
export function suggestCidr(value: string): string | null {
  const parsed = parseCidr(value);
  if (parsed !== null) return parsed.cidr === value ? null : parsed.cidr;
  const slash = value.indexOf("/");
  if (slash <= 0 || !/^[1-9][0-9]{0,2}$/.test(value.slice(slash + 1))) return null;
  const address = value.slice(0, slash);
  const length = Number(value.slice(slash + 1));
  // An IPv4-mapped IPv6 address parses as IPv4; its IPv6 length would be out of the IPv4 bounds anyway.
  const parsedAddress = address.includes("%") ? null : parseAddress(address);
  if (parsedAddress === null) return null;
  const bounds = CIDR_PREFIX_BOUNDS[parsedAddress.version];
  if (length < bounds.min || length > bounds.max) return null;
  const words = parsedAddress.words.map((word, index) => {
    const bits = Math.min(16, Math.max(0, length - 16 * index));
    return word & ((0xffff << (16 - bits)) & 0xffff);
  });
  const [high = 0, low = 0] = words;
  const text =
    parsedAddress.version === 4
      ? `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`
      : words.map((word) => word.toString(16)).join(":");
  return parseCidr(`${text}/${length}`)?.cidr ?? null;
}
