import { describe, expect, it } from "vitest";
import { isPublicAddress } from "../src/prove/address.ts";

// The SSRF classifier of the Prove file fetch (slice 14): only an address that is globally routable unicast may be
// contacted. Anything that does not parse, or names a private, local, shared, special-purpose or embedded
// non-public IPv4 space, is refused.

describe("Prove address classifier: isPublicAddress", () => {
  it.each([
    "93.184.216.34",
    "1.1.1.1",
    "8.8.8.8",
    "100.63.255.255", // just below CGNAT
    "100.128.0.0", // just above CGNAT
    "172.15.255.255", // just below 172.16/12
    "172.32.0.0", // just above 172.16/12
    "192.167.255.255",
    "192.169.0.0",
    "198.17.255.255",
    "198.20.0.0",
    "223.255.255.255", // last unicast before multicast
    "2606:2800:220:1:248:1893:25c8:1946",
    "2a00:1450:4001:82a::200e",
    "2001:4860:4860::8888", // 2001:4860::/32 is outside 2001::/23
    "2002:5db8:d822::1", // 6to4 of 93.184.216.34
    "64:ff9b::5db8:d822", // NAT64 of 93.184.216.34
    "::ffff:93.184.216.34", // IPv4-mapped public
    "::ffff:5db8:d822",
  ])("accepts the public address %s", (address) => {
    expect(isPublicAddress(address)).toBe(true);
  });

  it.each([
    // IPv4 special-purpose ranges
    ["this network 0/8", "0.0.0.0"],
    ["this network 0/8, not the first", "0.1.2.3"],
    ["private 10/8", "10.0.0.1"],
    ["private 10/8, last", "10.255.255.255"],
    ["CGNAT 100.64/10, first", "100.64.0.0"],
    ["CGNAT 100.64/10, last", "100.127.255.255"],
    ["loopback 127/8", "127.0.0.1"],
    ["loopback 127/8, other", "127.255.255.254"],
    ["link-local 169.254/16 (cloud metadata)", "169.254.169.254"],
    ["private 172.16/12, first", "172.16.0.0"],
    ["private 172.16/12, last", "172.31.255.255"],
    ["IETF protocol assignments 192.0.0/24", "192.0.0.170"],
    ["documentation TEST-NET-1", "192.0.2.10"],
    ["6to4 relay anycast", "192.88.99.1"],
    ["private 192.168/16", "192.168.1.1"],
    ["benchmarking 198.18/15", "198.19.255.255"],
    ["Azure WireServer (review F7)", "168.63.129.16"],
    ["documentation TEST-NET-2", "198.51.100.7"],
    ["documentation TEST-NET-3", "203.0.113.200"],
    ["multicast 224/4", "224.0.0.1"],
    ["multicast 224/4, last", "239.255.255.255"],
    ["reserved 240/4", "240.0.0.1"],
    ["broadcast", "255.255.255.255"],
    // IPv6
    ["unspecified ::", "::"],
    ["loopback ::1", "::1"],
    ["loopback, long form", "0:0:0:0:0:0:0:1"],
    ["IPv4-mapped loopback", "::ffff:127.0.0.1"],
    ["IPv4-mapped loopback, hex", "::ffff:7f00:1"],
    ["IPv4-mapped metadata", "::ffff:169.254.169.254"],
    ["IPv4-mapped private, hex", "::ffff:a00:5"],
    ["IPv4-mapped CGNAT", "::ffff:100.64.0.1"],
    ["IPv4-compatible private", "::10.0.0.1"],
    ["IPv4-compatible public (deprecated, never contacted)", "::93.184.216.34"],
    ["IPv4-translated loopback", "::ffff:0:7f00:1"],
    ["NAT64 of loopback", "64:ff9b::127.0.0.1"],
    ["NAT64 of private, hex", "64:ff9b::a00:1"],
    ["NAT64 of metadata", "64:ff9b::a9fe:a9fe"],
    ["local-use NAT64 64:ff9b:1::/48", "64:ff9b:1::5db8:d822"],
    ["6to4 of loopback", "2002:7f00:1::"],
    ["6to4 of private", "2002:c0a8:101::1"],
    ["6to4 of metadata", "2002:a9fe:a9fe::"],
    ["Teredo (2001::/32) embedding a private client", "2001:0:4136:e378:8000:63bf:f5ff:fffe"],
    ["Teredo with a public server", "2001:0:5db8:d822::1"],
    ["IETF protocol assignments 2001::/23", "2001:1ff:ffff::1"],
    ["ORCHIDv2 2001:20::/28", "2001:20::1"],
    ["documentation 2001:db8::/32", "2001:db8::1"],
    ["documentation 3fff::/20", "3fff:0fff::1"],
    ["discard-only 100::/64", "100::1"],
    ["unique-local fc00::/7 (fc)", "fc00::1"],
    ["unique-local fc00::/7 (fd)", "fd12:3456:789a::1"],
    ["link-local fe80::/10", "fe80::1"],
    ["link-local fe80::/10, upper end", "febf::1"],
    ["link-local with a zone", "fe80::1%en0"],
    ["site-local fec0::/10", "fec0::1"],
    ["multicast ff00::/8", "ff02::1"],
    ["outside 2000::/3", "4000::1"],
    ["a public address with a zone", "2606:2800:220:1:248:1893:25c8:1946%1"],
    // Not an address
    ["empty", ""],
    ["a name", "shop.acme-shop.io"],
    ["an IPv4 address with leading zeros", "010.0.0.1"],
    ["a shortened IPv4 address", "127.1"],
    ["a decimal IPv4 address", "2130706433"],
    ["a bracketed IPv6 address", "[::1]"],
    ["an IPv6 address with too many groups", "1:2:3:4:5:6:7:8:9"],
    ["an IPv6 address with two ::", "1::2::3"],
    ["an IPv4 address with a port", "93.184.216.34:443"],
    ["surrounding whitespace", " 93.184.216.34"],
  ])("refuses %s (%s)", (_name, address) => {
    expect(isPublicAddress(address)).toBe(false);
  });

  it("refuses anything that is not a string", () => {
    for (const value of [undefined, null, 1, {}, ["1.1.1.1"]]) {
      expect(isPublicAddress(value as unknown as string)).toBe(false);
    }
  });
});
