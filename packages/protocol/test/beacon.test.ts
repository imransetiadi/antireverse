import { describe, expect, it } from "vitest";
import {
  BEACON_LIMITS,
  BEACON_TOKEN_PATTERN,
  type BeaconReport,
  BeaconReportSchema,
  BeaconTokenSchema,
  type BuildBeacon,
  BuildBeaconSchema,
  canonicalOrigin,
  isLocalOrigin,
  type ManifestBeacon,
  ManifestBeaconSchema,
  OriginSchema,
} from "../src/index.ts";

const ok = (schema: { safeParse: (value: unknown) => { success: boolean } }, value: unknown): boolean =>
  schema.safeParse(value).success;
const TOKEN = "bcn_0123456789abcdef01234567";
const APP = "app_0123456789abcdef01234567";
/** An https origin of exactly `length` characters ("https://" + host). */
const originOfLength = (length: number): string => {
  const head = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.`;
  return `https://${head}${"d".repeat(length - 8 - head.length)}`;
};

describe("beacon constants", () => {
  it("has the limits of contract P1", () => {
    expect(BEACON_LIMITS).toEqual({ originsMax: 20, bodyBytesMax: 1024, newOriginsPerHour: 20, reportsPerHour: 600 });
  });
});

describe("canonicalOrigin", () => {
  it.each([
    ["https://shop.example.com", "https://shop.example.com"],
    ["https://Shop.EXAMPLE.com", "https://shop.example.com"],
    ["HTTPS://shop.example.com", "https://shop.example.com"],
    ["https://shop.example.com/", "https://shop.example.com"],
    ["https://shop.example.com:443", "https://shop.example.com"],
    ["http://shop.example.com:80/", "http://shop.example.com"],
    ["http://shop.example.com:443", "http://shop.example.com:443"],
    ["https://shop.example.com:80", "https://shop.example.com:80"],
    ["https://shop.example.com:8443", "https://shop.example.com:8443"],
    ["https://shop.example.com:08443", "https://shop.example.com:8443"],
    ["http://127.0.0.1:3000", "http://127.0.0.1:3000"],
    ["https://Bücher.example", "https://xn--bcher-kva.example"],
    ["https://xn--bcher-kva.example", "https://xn--bcher-kva.example"],
    ["http://[2001:DB8:0:0:0:0:0:1]:8080", "http://[2001:db8::1]:8080"],
    ["http://[2001:db8:0:1:0:0:0:1]", "http://[2001:db8:0:1::1]"],
    ["https://[::1]:443/", "https://[::1]"],
    ["http://[::FFFF:127.0.0.1]", "http://[::ffff:7f00:1]"],
  ])("canonicalises %j to %j", (input, expected) => {
    expect(canonicalOrigin(input)).toBe(expected);
  });

  it.each([
    "ftp://shop.example.com",
    "file:///etc/passwd",
    "chrome-extension://abcdef",
    "null",
    "",
    "shop.example.com",
    "//shop.example.com",
    " https://shop.example.com",
    "https://shop.example.com ",
    "https://shop.exa\tmple.com",
    "https://shop.example.com\n",
    "https://exa mple.com",
    "https://shop.example.com/path",
    "https://shop.example.com//",
    "https://shop.example.com/?",
    "https://shop.example.com?q=1",
    "https://shop.example.com?",
    "https://shop.example.com#",
    "https://shop.example.com#top",
    "https://user@shop.example.com",
    "https://user:pw@shop.example.com",
    "https://@shop.example.com",
    "https:shop.example.com",
    "https:/shop.example.com",
    "https:///shop.example.com",
    "https:\\\\shop.example.com",
    "https://shop.example.com\\",
    "https://",
    "https://:443",
    "https://shop.example.com:99999",
    "https://shop.example.com:-1",
    "https://[::1",
    "https://[fe80::1%25eth0]",
    "https://[::1]x",
  ])("refuses %j", (input) => {
    expect(canonicalOrigin(input)).toBeNull();
  });

  it.each([null, undefined, 1, {}, ["https://shop.example.com"], new URL("https://shop.example.com")])(
    "refuses the non-string %j",
    (input) => {
      expect(canonicalOrigin(input)).toBeNull();
    },
  );

  it("allows at most 255 characters", () => {
    expect(originOfLength(255)).toHaveLength(255);
    expect(canonicalOrigin(originOfLength(255))).toBe(originOfLength(255));
    expect(canonicalOrigin(originOfLength(256))).toBeNull();
    expect(canonicalOrigin(`https://${"a".repeat(5000)}.example`)).toBeNull();
  });

  it("is idempotent: a canonical origin is its own canonical form", () => {
    for (const input of ["https://Shop.EXAMPLE.com:443/", "http://[2001:DB8::1]:80", "https://Bücher.example:8443"]) {
      const once = canonicalOrigin(input);
      expect(once).not.toBeNull();
      expect(canonicalOrigin(once)).toBe(once);
    }
  });
});

describe("OriginSchema", () => {
  it("accepts canonical origins unchanged", () => {
    for (const origin of ["https://shop.example.com", "http://[2001:db8::1]:8080", "https://xn--bcher-kva.example"]) {
      expect(OriginSchema.parse(origin)).toBe(origin);
    }
    expect(ok(OriginSchema, originOfLength(255))).toBe(true);
  });

  it("refuses a non-canonical spelling instead of rewriting it", () => {
    for (const origin of [
      "https://Shop.example.com",
      "https://shop.example.com:443",
      "https://shop.example.com/",
      "http://[2001:DB8::1]",
      "https://Bücher.example",
      "https://shop.example.com/path",
      "null",
      "",
      originOfLength(256),
      null,
      42,
    ]) {
      expect(ok(OriginSchema, origin)).toBe(false);
    }
  });
});

describe("isLocalOrigin", () => {
  it.each([
    "http://localhost",
    "http://localhost:3000",
    "http://LOCALHOST:3000",
    "http://localhost.",
    "https://app.localhost",
    "https://a.b.localhost:8443",
    "http://printer.local",
    "https://shop.test",
    "https://api.internal",
    "http://127.0.0.1",
    "http://127.255.255.254:8080",
    "http://10.0.0.1",
    "http://10.255.255.255",
    "http://172.16.0.1",
    "http://172.31.255.255",
    "http://192.168.1.10",
    "http://169.254.169.254",
    "http://[::1]",
    "http://[::1]:5173",
    "http://[fc00::1]",
    "http://[fdff:ffff::1]",
    "http://[fe80::1]",
    "http://[febf::1]",
    "http://[::ffff:127.0.0.1]",
    "http://[::ffff:192.168.0.1]",
    "http://0.0.0.0",
    "http://0.0.0.0:8080",
    "http://[::]",
    "http://[::]:3000",
    "http://[::ffff:0.0.0.0]",
    "null",
    "file://",
    "file:///index.html",
    "chrome-extension://abcdef",
    "ftp://shop.example.com",
    "",
    "not an origin",
  ])("treats %j as local (never reported)", (origin) => {
    expect(isLocalOrigin(origin)).toBe(true);
  });

  it.each([
    "https://shop.example.com",
    "https://clone.example",
    "https://localhost.example.com",
    "https://notlocalhost",
    "https://example.local.com",
    "https://test.example.com",
    "https://internal",
    "http://8.8.8.8",
    "http://11.0.0.1",
    "http://126.255.255.255",
    "http://128.0.0.1",
    "http://172.15.255.255",
    "http://172.32.0.1",
    "http://192.167.255.255",
    "http://192.169.0.1",
    "http://169.253.0.1",
    "http://169.255.0.1",
    "http://[2001:db8::1]",
    "http://[::2]",
    "http://[fbff::1]",
    "http://[fe00::1]",
    "http://[fec0::1]",
    "http://[::ffff:8.8.8.8]",
    "http://0.0.0.1",
    "http://[::ffff:0.0.0.1]",
  ])("treats %j as foreign", (origin) => {
    expect(isLocalOrigin(origin)).toBe(false);
  });
});

describe("BeaconTokenSchema", () => {
  it("uses the token pattern of beacon.ts: a derived value, so not one of ID_PATTERNS", () => {
    expect(BEACON_TOKEN_PATTERN.source).toBe("^bcn_[0-9a-f]{24}$");
  });

  it("accepts bcn_ followed by 24 lowercase hex characters only", () => {
    expect(BeaconTokenSchema.parse(TOKEN)).toBe(TOKEN);
    expect(ok(BeaconTokenSchema, "bcn_0123456789ABCDEF01234567")).toBe(false);
    expect(ok(BeaconTokenSchema, "bcn_0123456789abcdef0123456")).toBe(false);
    expect(ok(BeaconTokenSchema, "bcn_0123456789abcdef012345678")).toBe(false);
    expect(ok(BeaconTokenSchema, "cny_0123456789abcdef01234567")).toBe(false);
    expect(ok(BeaconTokenSchema, null)).toBe(false);
  });
});

describe("BeaconReportSchema", () => {
  it("parses { a, t, o } and strips anything else", () => {
    const report: BeaconReport = { a: APP, t: TOKEN, o: "https://clone.example" };
    const parsed = BeaconReportSchema.parse({ ...report, path: "/checkout", cookie: "a=b" });
    expect(parsed).toEqual(report);
    expect(parsed).not.toHaveProperty("path");
  });

  it("requires the App id a, as an App id", () => {
    expect(ok(BeaconReportSchema, { t: TOKEN, o: "https://clone.example" })).toBe(false);
    expect(ok(BeaconReportSchema, { a: "app_x", t: TOKEN, o: "https://clone.example" })).toBe(false);
    expect(ok(BeaconReportSchema, { a: "org_0123456789abcdef01234567", t: TOKEN, o: "https://clone.example" })).toBe(
      false,
    );
    expect(ok(BeaconReportSchema, { a: 1, t: TOKEN, o: "https://clone.example" })).toBe(false);
  });

  it("leaves canonical checking of o to the API but bounds it at 255 characters", () => {
    expect(ok(BeaconReportSchema, { a: APP, t: TOKEN, o: "HTTPS://Clone.Example:443" })).toBe(true);
    expect(ok(BeaconReportSchema, { a: APP, t: TOKEN, o: "x".repeat(255) })).toBe(true);
    expect(ok(BeaconReportSchema, { a: APP, t: TOKEN, o: "x".repeat(256) })).toBe(false);
    expect(ok(BeaconReportSchema, { a: APP, t: TOKEN, o: 1 })).toBe(false);
    expect(ok(BeaconReportSchema, { a: APP, t: "bcn_x", o: "https://clone.example" })).toBe(false);
    expect(ok(BeaconReportSchema, { a: APP, o: "https://clone.example" })).toBe(false);
    expect(ok(BeaconReportSchema, { a: APP, t: TOKEN })).toBe(false);
  });
});

describe("ManifestBeaconSchema and BuildBeaconSchema", () => {
  const origins = (count: number) => Array.from({ length: count }, (_, n) => `https://shop${n}.example.com`);

  it("round-trips a Manifest beacon", () => {
    const beacon: ManifestBeacon = { token: TOKEN, origins: ["https://shop.example.com", "http://[2001:db8::1]:8080"] };
    expect(ManifestBeaconSchema.parse(JSON.parse(JSON.stringify(beacon)))).toEqual(beacon);
  });

  it("requires 1..20 origins", () => {
    expect(ok(ManifestBeaconSchema, { token: TOKEN, origins: origins(1) })).toBe(true);
    expect(ok(ManifestBeaconSchema, { token: TOKEN, origins: origins(BEACON_LIMITS.originsMax) })).toBe(true);
    expect(ok(ManifestBeaconSchema, { token: TOKEN, origins: origins(0) })).toBe(false);
    expect(ok(ManifestBeaconSchema, { token: TOKEN, origins: origins(BEACON_LIMITS.originsMax + 1) })).toBe(false);
  });

  it("refuses a duplicate, a non-canonical and a local origin", () => {
    const shop = "https://shop.example.com";
    expect(ok(ManifestBeaconSchema, { token: TOKEN, origins: [shop, shop] })).toBe(false);
    expect(ok(ManifestBeaconSchema, { token: TOKEN, origins: ["https://Shop.example.com"] })).toBe(false);
    expect(ok(ManifestBeaconSchema, { token: TOKEN, origins: [shop, "http://localhost:3000"] })).toBe(false);
    expect(ok(ManifestBeaconSchema, { token: TOKEN, origins: [shop, "http://192.168.1.10"] })).toBe(false);
  });

  it("requires a well-formed token", () => {
    expect(ok(ManifestBeaconSchema, { origins: origins(1) })).toBe(false);
    expect(ok(ManifestBeaconSchema, { token: "bcn_x", origins: origins(1) })).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = ManifestBeaconSchema.parse({ token: TOKEN, origins: origins(1), endpoint: "https://api.example" });
    expect(parsed).toEqual({ token: TOKEN, origins: origins(1) });
  });

  it("shows a Build's beacon as its origins only: the token is stripped", () => {
    const parsed: BuildBeacon = BuildBeaconSchema.parse({ token: TOKEN, origins: origins(2) });
    expect(parsed).toEqual({ origins: origins(2) });
    expect(JSON.stringify(parsed)).not.toContain("bcn_");
    expect(ok(BuildBeaconSchema, { origins: [] })).toBe(false);
    expect(ok(BuildBeaconSchema, { origins: ["http://localhost"] })).toBe(false);
    expect(ok(BuildBeaconSchema, { origins: origins(BEACON_LIMITS.originsMax + 1) })).toBe(false);
  });
});
