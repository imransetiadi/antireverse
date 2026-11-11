import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ACTOR_HASH_PATTERN,
  ActorHashSchema,
  cidrContains,
  EXAMPLE_CONTAINMENT,
  EXAMPLE_INCIDENT,
} from "../src/index.ts";
import { actorHash } from "../src/server.ts";

// The synthetic Shield key of the documented examples (see EXAMPLE_BUNDLE_PAYLOAD): `ark_dev_` and 43 times `A`.
const KEY = `ark_dev_${"A".repeat(43)}`;
const OTHER_KEY = `ark_dev_${"B".repeat(43)}`;

// Known answers, computed outside this package with `node -e` and node:crypto alone:
//   "iph_" + HMAC-SHA256(KEY, "antireverse/actor/v1\n" + subject).hex.slice(0, 32)
const IPV4 = "iph_2932b22cf89905dbc929c64247ddad3e"; // subject "203.0.113.7"
const IPV4_NEIGHBOUR = "iph_c02ada6f2a7b8125dcb94f65cd8d67e9"; // subject "203.0.113.8"
const IPV6_SLASH_64 = "iph_d78c52b682710159027de8721a764da9"; // subject "2001:0db8:0000:0001"
const IPV6_NEXT_SLASH_64 = "iph_e0fd2652c21d56ffda9e22d5d4263e3a"; // subject "2001:0db8:0000:0002"
const IPV6_UNSPECIFIED = "iph_4876c3f8b0df60bcbb31cb5712087008"; // subject "0000:0000:0000:0000"
const IPV6_LINK_LOCAL = "iph_fa6b09791f24e222053ffd2b262b62e8"; // subject "fe80:0000:0000:0000"
const IPV4_OTHER_KEY = "iph_cf9133a5ee8b3b1274c425d7838b00e4"; // OTHER_KEY, subject "203.0.113.7"

const reference = (key: string, subject: string): string =>
  `iph_${createHmac("sha256", key).update(`antireverse/actor/v1\n${subject}`, "utf8").digest("hex").slice(0, 32)}`;

describe("actorHash", () => {
  it("matches the known answer for an IPv4 address: the whole address is the subject", () => {
    expect(actorHash(KEY, "203.0.113.7")).toBe(IPV4);
    expect(actorHash(KEY, "203.0.113.8")).toBe(IPV4_NEIGHBOUR);
    expect(IPV4).not.toBe(IPV4_NEIGHBOUR);
  });

  it("matches the known answer for an IPv6 address: its /64 is the subject", () => {
    expect(actorHash(KEY, "2001:db8:0:1::1")).toBe(IPV6_SLASH_64);
    expect(actorHash(KEY, "2001:db8:0:1:ffff:ffff:ffff:ffff")).toBe(IPV6_SLASH_64);
    expect(actorHash(KEY, "2001:0DB8:0000:0001:0000:0000:0000:0001")).toBe(IPV6_SLASH_64);
    expect(actorHash(KEY, "2001:db8:0:1::")).toBe(IPV6_SLASH_64);
  });

  it("gives another /64 another hash", () => {
    expect(actorHash(KEY, "2001:db8:0:2::1")).toBe(IPV6_NEXT_SLASH_64);
    expect(IPV6_NEXT_SLASH_64).not.toBe(IPV6_SLASH_64);
    expect(actorHash(KEY, "::1")).toBe(IPV6_UNSPECIFIED);
    expect(actorHash(KEY, "::")).toBe(IPV6_UNSPECIFIED);
  });

  it("hashes an IPv4-mapped IPv6 address as its IPv4 address", () => {
    expect(actorHash(KEY, "::ffff:203.0.113.7")).toBe(IPV4);
    expect(actorHash(KEY, "::FFFF:203.0.113.7")).toBe(IPV4);
    expect(actorHash(KEY, "::ffff:cb00:7107")).toBe(IPV4);
    expect(actorHash(KEY, "0:0:0:0:0:ffff:203.0.113.7")).toBe(IPV4);
  });

  it("strips a zone id", () => {
    expect(actorHash(KEY, "fe80::1%eth0")).toBe(IPV6_LINK_LOCAL);
    expect(actorHash(KEY, "fe80::2%en0")).toBe(IPV6_LINK_LOCAL);
    expect(actorHash(KEY, "::ffff:203.0.113.7%eth0")).toBe(IPV4);
  });

  it("is keyed with the Shield key: another key gives another hash", () => {
    expect(actorHash(OTHER_KEY, "203.0.113.7")).toBe(IPV4_OTHER_KEY);
    expect(IPV4_OTHER_KEY).not.toBe(IPV4);
  });

  it("follows the documented construction for other addresses", () => {
    expect(actorHash(KEY, "0.0.0.0")).toBe(reference(KEY, "0.0.0.0"));
    expect(actorHash(KEY, "255.255.255.255")).toBe(reference(KEY, "255.255.255.255"));
    expect(actorHash(KEY, "10.1.2.3")).toBe(reference(KEY, "10.1.2.3"));
    expect(actorHash(KEY, "ABCD:EF01:2345:6789::1")).toBe(reference(KEY, "abcd:ef01:2345:6789"));
    expect(actorHash(KEY, "1:2:3:4:5:6:7:8")).toBe(reference(KEY, "0001:0002:0003:0004"));
    expect(actorHash(KEY, "64:ff9b::192.0.2.33")).toBe(reference(KEY, "0064:ff9b:0000:0000"));
    expect(actorHash("k", "10.1.2.3")).toBe(reference("k", "10.1.2.3"));
  });

  it("returns a well-formed actor hash", () => {
    for (const address of ["203.0.113.7", "2001:db8::1", "::ffff:10.0.0.1", "fe80::1%eth0"]) {
      const hash = actorHash(KEY, address);
      expect(hash).toMatch(ACTOR_HASH_PATTERN);
      expect(ActorHashSchema.parse(hash)).toBe(hash);
    }
  });

  it.each([
    "",
    " ",
    "unknown",
    "203.0.113",
    "203.0.113.256",
    "203.0.113.07",
    " 203.0.113.7",
    "203.0.113.7:443",
    "203.0.113.7/32",
    "[::1]",
    "::1/128",
    "1::2::3",
    "fe80::1%",
  ])("returns null for the unparseable address %j", (address) => {
    expect(actorHash(KEY, address)).toBeNull();
  });

  it("returns null for an unknown address", () => {
    expect(actorHash(KEY, null)).toBeNull();
    expect(actorHash(KEY, undefined)).toBeNull();
    expect(actorHash(KEY, 3_405_803_783 as unknown as string)).toBeNull();
  });

  it("throws a TypeError for an empty or missing key, whatever the address", () => {
    expect(() => actorHash("", "203.0.113.7")).toThrow(TypeError);
    expect(() => actorHash("", null)).toThrow(TypeError);
    expect(() => actorHash(undefined as unknown as string, "203.0.113.7")).toThrow(TypeError);
    expect(() => actorHash(null as unknown as string, "203.0.113.7")).toThrow(TypeError);
    expect(() => actorHash(7 as unknown as string, "203.0.113.7")).toThrow(TypeError);
  });

  it("is the Actor of the documented Containment: 203.0.113.7, inside the documented Incident's network", () => {
    expect(EXAMPLE_CONTAINMENT.target).toEqual({ kind: "actor", ip_hash: actorHash(KEY, "203.0.113.7") });
    expect(cidrContains(EXAMPLE_INCIDENT.ip_prefix as string, "203.0.113.7")).toBe(true);
  });
});
