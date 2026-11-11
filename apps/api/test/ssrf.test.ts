import { describe, expect, it } from "vitest";
import { checkDestination, isForbiddenAddress, type Resolve } from "../src/notify/ssrf.ts";

const PUBLIC_V4 = "93.184.216.34";
const PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946";

/** A resolver that answers from a table and records what it was asked. */
function table(answers: Record<string, string[]>): Resolve & { asked: string[] } {
  const asked: string[] = [];
  const resolve = async (host: string) => {
    asked.push(host);
    const addresses = answers[host];
    if (addresses === undefined) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: "ENOTFOUND" });
    return addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
  };
  return Object.assign(resolve, { asked });
}

const resolve = table({
  "hooks.example.com": [PUBLIC_V4],
  "v6.example.com": [PUBLIC_V6],
  "internal.example.com": ["10.1.2.3"],
  "mixed.example.com": [PUBLIC_V4, "192.168.1.1"],
  "mixed-v6.example.com": [PUBLIC_V6, "fd00::1"],
  "localhost.example.com": ["127.0.0.1"],
  "empty.example.com": [],
});

describe("SSRF guard: checkDestination", () => {
  it("accepts an https URL whose host resolves only to public addresses, and returns the vetted address", async () => {
    expect(await checkDestination("https://hooks.example.com/ar", { resolve, allowPrivate: false })).toEqual({
      ok: true,
      address: PUBLIC_V4,
      family: 4,
    });
    expect(await checkDestination("https://v6.example.com/ar", { resolve, allowPrivate: false })).toEqual({
      ok: true,
      address: PUBLIC_V6,
      family: 6,
    });
    expect(await checkDestination(`https://${PUBLIC_V4}/ar`, { resolve, allowPrivate: false })).toEqual({
      ok: true,
      address: PUBLIC_V4,
      family: 4,
    });
  });

  it.each([
    ["http without the flag", "http://hooks.example.com/ar"],
    ["a scheme other than http(s)", "ftp://hooks.example.com/ar"],
    ["a URL that does not parse", "not a url"],
    ["loopback 127.0.0.1", "https://127.0.0.1/ar"],
    ["loopback anywhere in 127/8", "https://127.255.0.9/ar"],
    ["private 10.0.0.5", "https://10.0.0.5/ar"],
    ["private 172.16.0.1", "https://172.16.0.1/ar"],
    ["private 172.31.255.254", "https://172.31.255.254/ar"],
    ["private 192.168.0.10", "https://192.168.0.10/ar"],
    ["link-local metadata 169.254.169.254", "https://169.254.169.254/latest/meta-data"],
    ["CGNAT 100.64.0.1", "https://100.64.0.1/ar"],
    ["CGNAT 100.127.255.254", "https://100.127.255.254/ar"],
    ["unspecified 0.0.0.0", "https://0.0.0.0/ar"],
    ["IPv6 loopback [::1]", "https://[::1]/ar"],
    ["IPv6 unspecified [::]", "https://[::]/ar"],
    ["IPv4-mapped loopback [::ffff:127.0.0.1]", "https://[::ffff:127.0.0.1]/ar"],
    ["IPv4-mapped metadata [::ffff:169.254.169.254]", "https://[::ffff:169.254.169.254]/ar"],
    ["IPv4-mapped private, hex form", "https://[::ffff:a00:5]/ar"],
    ["unique-local fc00::/7", "https://[fd12:3456::1]/ar"],
    ["link-local fe80::/10", "https://[fe80::1]/ar"],
    ["a hostname resolving to a private address", "https://internal.example.com/ar"],
    ["a hostname resolving to loopback", "https://localhost.example.com/ar"],
    ["a mixed resolution, one public and one private", "https://mixed.example.com/ar"],
    ["a mixed IPv6 resolution, one public and one unique-local", "https://mixed-v6.example.com/ar"],
    ["a hostname that does not resolve", "https://nowhere.example.com/ar"],
    // F4: embedded IPv4 in other IPv6 forms, and special-purpose ranges.
    ["IPv4-translated loopback [::ffff:0:7f00:1]", "https://[::ffff:0:7f00:1]/ar"],
    ["IPv4-translated metadata [::ffff:0:a9fe:a9fe]", "https://[::ffff:0:a9fe:a9fe]/ar"],
    ["6to4 of loopback [2002:7f00:1::]", "https://[2002:7f00:1::]/ar"],
    ["6to4 of metadata [2002:a9fe:a9fe::]", "https://[2002:a9fe:a9fe::]/ar"],
    ["local-use NAT64 of loopback [64:ff9b:1::7f00:1]", "https://[64:ff9b:1::7f00:1]/ar"],
    ["benchmarking 198.18.0.1", "https://198.18.0.1/ar"],
    ["IETF protocol assignments 192.0.0.170", "https://192.0.0.170/ar"],
    ["TEST-NET-1 192.0.2.1", "https://192.0.2.1/ar"],
    ["TEST-NET-2 198.51.100.7", "https://198.51.100.7/ar"],
    ["TEST-NET-3 203.0.113.9", "https://203.0.113.9/ar"],
    ["discard-only [100::1]", "https://[100::1]/ar"],
    ["documentation [2001:db8::1]", "https://[2001:db8::1]/ar"],
    ["a hostname that resolves to nothing", "https://empty.example.com/ar"],
  ])("refuses %s", async (_, url) => {
    const result = await checkDestination(url, { resolve, allowPrivate: false });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // The reason is a fixed phrase: it never echoes the URL or the host.
    expect(result.reason).not.toContain("example.com");
    expect(result.reason).not.toContain("/ar");
  });

  it("with the flag on, allows http and loopback and private addresses (development and tests only)", async () => {
    expect(await checkDestination("http://127.0.0.1:8080/ar", { resolve, allowPrivate: true })).toEqual({
      ok: true,
      address: "127.0.0.1",
      family: 4,
    });
    expect(await checkDestination("http://[::1]:8080/ar", { resolve, allowPrivate: true })).toEqual({
      ok: true,
      address: "::1",
      family: 6,
    });
    expect(await checkDestination("https://internal.example.com/ar", { resolve, allowPrivate: true })).toEqual({
      ok: true,
      address: "10.1.2.3",
      family: 4,
    });
    // The flag never admits another scheme, nor a host that does not resolve.
    expect((await checkDestination("ftp://127.0.0.1/ar", { resolve, allowPrivate: true })).ok).toBe(false);
    expect((await checkDestination("https://nowhere.example.com/ar", { resolve, allowPrivate: true })).ok).toBe(false);
  });

  it("does not resolve an IP literal, and resolves a host name once", async () => {
    const counting = table({ "hooks.example.com": [PUBLIC_V4] });
    await checkDestination("https://10.0.0.5/ar", { resolve: counting, allowPrivate: false });
    await checkDestination("https://hooks.example.com/ar", { resolve: counting, allowPrivate: false });
    expect(counting.asked).toEqual(["hooks.example.com"]);
  });
});

describe("SSRF guard: isForbiddenAddress", () => {
  it.each([
    "127.0.0.1",
    "10.255.255.255",
    "172.16.0.0",
    "192.168.255.255",
    "169.254.0.1",
    "100.64.0.0",
    "0.0.0.0",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fc00::1",
    "fdff:ffff::1",
    "fe80::1",
    "febf::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
    "::ffff:a9fe:a9fe",
    "::ffff:0a00:0005",
    "64:ff9b::a9fe:a9fe",
    "ff02::1",
    "::ffff:0:7f00:1",
    "::ffff:0:a9fe:a9fe",
    "2002:7f00:1::",
    "2002:a9fe:a9fe::",
    "2002:0a00:0005::1",
    "64:ff9b:1::7f00:1",
    "64:ff9b:1::a00:5",
    "198.18.0.1",
    "198.19.255.255",
    "192.0.0.170",
    "192.0.2.1",
    "198.51.100.0",
    "203.0.113.255",
    "192.88.99.1",
    "100::1",
    "2001:db8::1",
    "2001:db8:ffff::1",
    "not-an-address",
  ])("forbids %s", (address) => {
    expect(isForbiddenAddress(address)).toBe(true);
  });

  it.each([
    "93.184.216.34",
    "8.8.8.8",
    "172.15.255.255",
    "172.32.0.0",
    "100.63.255.255",
    "100.128.0.0",
    "169.253.255.255",
    "2606:2800:220:1:248:1893:25c8:1946",
    "::ffff:5db8:d822",
    "::ffff:0:5db8:d822",
    "2002:5db8:d822::1",
    "64:ff9b:1::5db8:d822",
    "198.17.255.255",
    "198.20.0.0",
    "192.0.1.255",
    "101::1",
  ])("allows %s", (address) => {
    expect(isForbiddenAddress(address)).toBe(false);
  });
});
