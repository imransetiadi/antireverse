import { describe, expect, it } from "vitest";
import { truncateIp } from "../src/ip.ts";

describe("truncateIp", () => {
  it.each([
    ["203.0.113.77", "203.0.113.0/24"],
    ["127.0.0.1", "127.0.0.0/24"],
    ["255.255.255.255", "255.255.255.0/24"],
    ["0.0.0.0", "0.0.0.0/24"],
    // IPv4-mapped IPv6 is treated as IPv4, in dotted and in hex form
    ["::ffff:203.0.113.77", "203.0.113.0/24"],
    ["::FFFF:203.0.113.77", "203.0.113.0/24"],
    ["::ffff:cb00:714d", "203.0.113.0/24"],
    ["0:0:0:0:0:ffff:cb00:714d", "203.0.113.0/24"],
    // IPv6: the first three groups without leading zeros, then ::/48
    ["2001:db8:abcd:12::1", "2001:db8:abcd::/48"],
    ["2001:db8:abcd:1234:5678:9abc:def0:1", "2001:db8:abcd::/48"],
    ["2001:0DB8:00ab::1", "2001:db8:ab::/48"],
    ["2001:db8::1", "2001:db8:0::/48"],
    ["::1", "0:0:0::/48"],
    ["::", "0:0:0::/48"],
    ["fe80::1%lo0", "fe80:0:0::/48"],
    ["64:ff9b::203.0.113.77", "64:ff9b:0::/48"],
  ])("%s -> %s", (input, expected) => {
    expect(truncateIp(input)).toBe(expected);
  });

  it.each([
    [undefined],
    [null],
    [""],
    [42],
    ["not-an-ip"],
    ["1.2.3"],
    ["1.2.3.4.5"],
    ["256.1.1.1"],
    ["01.2.3.4"],
    ["1.2.3.4/24"],
    [" 1.2.3.4"],
    ["::ffff:1.2.3"],
    ["2001:db8:::1"],
    ["12345::1"],
    ["gggg::1"],
    ["1:2:3:4:5:6:7:8:9"],
    ["x".repeat(10_000)],
  ])("invalid input %j -> null, never throws", (input) => {
    expect(truncateIp(input)).toBeNull();
  });

  it("never returns the host part of an address", () => {
    expect(truncateIp("203.0.113.77")).not.toContain("77");
    expect(truncateIp("2001:db8:abcd:12::beef")).not.toContain("beef");
  });
});
