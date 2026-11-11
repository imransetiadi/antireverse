// Slice 09, contract P3: Shield parses client addresses and allowlist CIDRs and computes the actor hash by hand,
// because it imports nothing of the protocol at run time. Each mirror is pinned here against the protocol's own
// functions (`parseAddress`, `parseCidr`, `cidrContains`, `actorHash`) over one corpus, so a rule that changes there
// fails here. Review focus 1 and 2.
import {
  ACTOR_HASH_PATTERN,
  cidrContains as protocolCidrContains,
  parseAddress as protocolParseAddress,
  parseCidr as protocolParseCidr,
} from "@antireverse/protocol";
import { actorHash } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { inCidr, parseAddress, parseCidr, prefixOf } from "../src/address.ts";
import { ACTOR_HASH_DOMAIN, actorHashOf, containmentOf, describeClient } from "../src/containment.ts";
import { truncateIp } from "../src/ip.ts";
import { buildPolicy } from "../src/policy/store.ts";

const KEY = `ark_dev_${"A".repeat(43)}`;
const OTHER_KEY = `ark_dev_${"B".repeat(43)}`;

/** The known answers of the protocol (plan amendment A2 and the slice 09 briefing). */
const KNOWN: [string, string][] = [
  ["203.0.113.7", "iph_2932b22cf89905dbc929c64247ddad3e"],
  ["203.0.113.8", "iph_c02ada6f2a7b8125dcb94f65cd8d67e9"],
  ["2001:db8:0:1::1", "iph_d78c52b682710159027de8721a764da9"],
  ["2001:db8:0:1:ffff:ffff:ffff:ffff", "iph_d78c52b682710159027de8721a764da9"],
  ["2001:db8:0:2::1", "iph_e0fd2652c21d56ffda9e22d5d4263e3a"],
  ["::ffff:203.0.113.7", "iph_2932b22cf89905dbc929c64247ddad3e"],
  ["fe80::1%eth0", "iph_fa6b09791f24e222053ffd2b262b62e8"],
];

/** Addresses, valid and not, in every spelling the parsers have a rule for. */
const ADDRESSES: unknown[] = [
  "203.0.113.7",
  "203.0.113.8",
  "0.0.0.0",
  "255.255.255.255",
  "127.0.0.1",
  "10.0.0.1",
  "01.2.3.4",
  "1.2.3.04",
  "256.1.1.1",
  "1.2.3",
  "1.2.3.4.5",
  "1.2.3.4/24",
  " 1.2.3.4",
  "1.2.3.4 ",
  "1.2.3.4%eth0",
  "2001:db8:0:1::1",
  "2001:db8:0:1:ffff:ffff:ffff:ffff",
  "2001:0DB8:0000:0001:0000:0000:0000:0001",
  "2001:db8:0:1::",
  "2001:db8:0:2::1",
  "2001:db8:abcd:12::1",
  "::1",
  "::",
  ":::",
  "::ffff:203.0.113.7",
  "::FFFF:203.0.113.7",
  "::ffff:cb00:7107",
  "0:0:0:0:0:ffff:203.0.113.7",
  "0:0:0:0:0:ffff:cb00:7107",
  "::ffff:203.0.113.7%eth0",
  "::ffff:1.2.3",
  "64:ff9b::203.0.113.77",
  "64:ff9b::203.0.113.077",
  "1::2:3.4.5.6",
  "fe80::1%eth0",
  "fe80::2%en0",
  "fe80::1%",
  "fe80::1%%",
  "2001:db8:::1",
  "2001:db8::1::1",
  "12345::1",
  "gggg::1",
  "1:2:3:4:5:6:7:8",
  "1:2:3:4:5:6:7:8:9",
  "1:2:3:4:5:6:7::",
  "::1:2:3:4:5:6:7",
  "1:2:3:4:5:6:7::8",
  "1:2:3:4:5:6:1.2.3.4",
  "1:2:3:4:5:6:7:1.2.3.4",
  "[::1]",
  "::1:",
  ":1::",
  "",
  "x".repeat(10_000),
  `${"0:".repeat(60)}1`,
  "not-an-ip",
  null,
  undefined,
  42,
  {},
  ["203.0.113.7"],
];

/** CIDRs, canonical and not. */
const CIDRS: unknown[] = [
  "10.0.0.0/8",
  "10.0.0.1/8",
  "10.0.0.0/7",
  "0.0.0.0/0",
  "10.0.0.0/33",
  "10.0.0.0/08",
  "010.0.0.0/8",
  "10.0.0.0",
  " 10.0.0.0/8",
  "10.0.0.0/8\n",
  "10.32.0.0/11",
  "172.16.0.0/12",
  "192.168.128.0/17",
  "203.0.113.0/24",
  "203.0.113.7/24",
  "203.0.113.128/25",
  "203.0.113.6/31",
  "203.0.113.7/32",
  "198.51.100.0/24",
  "2001:db8::/32",
  "2001:DB8::/32",
  "2001:0db8::/32",
  "2001:db8:0:0:0:0:0:0/32",
  "2001:db8::1/64",
  "2001:db8::/16",
  "2001::/16",
  "::/15",
  "::/0",
  "::/129",
  "::/128",
  "::1/128",
  "1::/16",
  "0:0:1::/48",
  "2001:db8:0:1::/64",
  "2001:db8::1:1:1:1:1/128",
  "2001:db8:0:1:1:1:1:1/128",
  "2001::1:0:0:0:1/128",
  "2001:0:0:1::1/128",
  "2001:db8:0:0:1::1/128",
  "2001:db8::1:0:0:1/128",
  "64:ff9b::192.0.2.33/128",
  "64:ff9b::c000:221/128",
  "abcd:ef01:2345:6789:abcd:ef01:2345:6789/128",
  "ABCD:EF01:2345:6789:ABCD:EF01:2345:6789/128",
  "::ffff:10.0.0.0/104",
  "::ffff:0:0/96",
  "::fffe:0:0/96",
  "fe80::%eth0/64",
  "fe80::/10",
  "fe80::/16",
  "/24",
  "10.0.0.0/",
  "10.0.0.0/-8",
  "10.0.0.0/8/8",
  "",
  `${"1".repeat(200)}/8`,
  null,
  undefined,
  8,
  ["10.0.0.0/8"],
];

const plain = <T>(value: T): T => (value === null ? value : JSON.parse(JSON.stringify(value)));

describe("Shield's address parser is the protocol's", () => {
  it.each(ADDRESSES.map((value) => [value]))("parseAddress(%j) agrees", (value) => {
    expect(plain(parseAddress(value))).toEqual(plain(protocolParseAddress(value)));
  });

  it("never throws on anything", () => {
    for (const value of [...ADDRESSES, ...CIDRS, Symbol("x"), () => 1, 1n]) {
      expect(() => parseAddress(value)).not.toThrow();
      expect(() => parseCidr(value)).not.toThrow();
    }
  });
});

describe("Shield's CIDR parser is the protocol's", () => {
  it.each(CIDRS.map((value) => [value]))("parseCidr(%j) agrees, canonical text included", (value) => {
    expect(plain(parseCidr(value))).toEqual(plain(protocolParseCidr(value)));
  });

  it("containment agrees for every CIDR and address of the corpus, across versions", () => {
    let compared = 0;
    for (const cidr of CIDRS) {
      const range = parseCidr(cidr);
      if (range === null) continue;
      for (const address of [...ADDRESSES, "10.255.255.255", "203.0.113.77", "2001:db8:ffff::1", "fe80::abcd"]) {
        const parsed = parseAddress(address);
        if (parsed === null) continue;
        expect(inCidr(range, parsed), `${String(cidr)} ∋ ${String(address)}`).toBe(
          protocolCidrContains(cidr as string, address as string),
        );
        compared += 1;
      }
    }
    expect(compared).toBeGreaterThan(500);
  });
});

describe("the network prefix of a parsed address is the Event's prefix", () => {
  it.each(ADDRESSES.filter((value) => protocolParseAddress(value) !== null).map((value) => [value]))(
    "prefixOf(%j) equals truncateIp",
    (value) => {
      const parsed = parseAddress(value);
      expect(parsed).not.toBeNull();
      expect(prefixOf(parsed as NonNullable<typeof parsed>)).toBe(truncateIp(value));
    },
  );
});

describe("actor hash", () => {
  it("uses the protocol's domain separator", () => {
    expect(ACTOR_HASH_DOMAIN).toBe("antireverse/actor/v1\n");
  });

  it.each(KNOWN)("%s gives the known answer %s", (address, expected) => {
    expect(actorHashOf(KEY, parseAddress(address))).toBe(expected);
    expect(actorHash(KEY, address)).toBe(expected);
  });

  it("groups an IPv6 /64 and separates the next /64; an IPv4 neighbour is another Actor", () => {
    const slash64 = actorHashOf(KEY, parseAddress("2001:db8:0:1::1"));
    expect(actorHashOf(KEY, parseAddress("2001:db8:0:1:ffff:ffff:ffff:ffff"))).toBe(slash64);
    expect(actorHashOf(KEY, parseAddress("2001:db8:0:1:abcd::"))).toBe(slash64);
    expect(actorHashOf(KEY, parseAddress("2001:db8:0:2::1"))).not.toBe(slash64);
    expect(actorHashOf(KEY, parseAddress("203.0.113.7"))).not.toBe(actorHashOf(KEY, parseAddress("203.0.113.8")));
  });

  it("equals the protocol's actorHash for every address of the corpus and two keys", () => {
    for (const key of [KEY, OTHER_KEY]) {
      for (const address of ADDRESSES) {
        const expected = protocolParseAddress(address) === null ? null : actorHash(key, address as string);
        const got = actorHashOf(key, parseAddress(address));
        expect(got, String(address)).toBe(expected);
        if (got !== null) expect(got).toMatch(ACTOR_HASH_PATTERN);
      }
    }
    expect(actorHashOf(KEY, parseAddress("203.0.113.7"))).not.toBe(actorHashOf(OTHER_KEY, parseAddress("203.0.113.7")));
  });

  it("is null for an unknown address", () => {
    expect(actorHashOf(KEY, null)).toBeNull();
  });
});

/** Zone-id spellings (review F2): empty, long, odd characters, none; IPv4 with a zone; mapped with a zone. */
const ZONED: string[] = [
  "fe80::1",
  "fe80::1%eth0",
  "fe80::1%",
  "fe80::1%%",
  "fe80::1%%eth0",
  `fe80::1%${"z".repeat(60)}`,
  `fe80::1%${"z".repeat(119)}`,
  `fe80::1%${"z".repeat(120)}`,
  "fe80::1%eth0/64",
  "fe80::1%:1",
  "fe80::1% ",
  "fe80::1%\u0000",
  "fe80::1%ü",
  "fe80::1%25",
  "::ffff:203.0.113.7%eth0",
  "::ffff:203.0.113.7%",
  "203.0.113.7%eth0",
  "203.0.113.7%",
  "%eth0",
  "%",
];

describe("one address rule for the Event prefix, the actor hash and containment (review F2)", () => {
  const expires = Number.MAX_SAFE_INTEGER;
  const policy = buildPolicy({
    version: 1,
    issuedAt: 0,
    notAfter: Number.POSITIVE_INFINITY,
    rules: [],
    blocks: [
      { id: "cnt_000000000000000000000001", kind: "prefix", ipPrefix: "fe80:0:0::/48", expiresMs: expires },
      { id: "cnt_000000000000000000000002", kind: "prefix", ipPrefix: "203.0.113.0/24", expiresMs: expires },
    ],
  });

  it.each([...ZONED, ...ADDRESSES.filter((value): value is string => typeof value === "string")].map((v) => [v]))(
    "%j: ip_prefix, ip_hash and containment agree",
    (value) => {
      const prefix = truncateIp(value);
      const client = describeClient(KEY, value);
      const hit = containmentOf(policy, client, () => 0);
      const parsed = protocolParseAddress(value);
      // Each is null exactly when the protocol cannot parse the address.
      expect(prefix === null).toBe(parsed === null);
      expect(client.hash === null).toBe(parsed === null);
      if (parsed !== null) {
        expect(prefix).toBe(prefixOf(parseAddress(value) as NonNullable<ReturnType<typeof parseAddress>>));
        expect(client.hash).toBe(actorHash(KEY, value));
      }
      // Contained by a prefix block exactly when the Event's prefix is the blocked one.
      expect(hit !== null).toBe(prefix === "fe80:0:0::/48" || prefix === "203.0.113.0/24");
    },
  );
});
