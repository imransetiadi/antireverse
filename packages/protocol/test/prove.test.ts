import { describe, expect, it } from "vitest";
import {
  AUTHORIZE_REASONS,
  type AuthorizeRequest,
  AuthorizeRequestSchema,
  type AuthorizeResult,
  AuthorizeResultSchema,
  type AuthorizeState,
  authorizeTest,
  CHALLENGE_RECORD_PREFIX,
  CreateTargetRequestSchema,
  CurrentRulesOfEngagementResponseSchema,
  canonicalJson,
  challengeRecordName,
  confirmationPhrase,
  DNS_VALUE_PREFIX,
  dnsChallengeValue,
  EXAMPLE_RULES_OF_ENGAGEMENT,
  EXAMPLE_TARGET,
  FILE_VERIFY_FAILURES,
  HostSchema,
  ID_PATTERNS,
  INTENSITIES,
  type Intensity,
  intensityRank,
  isInsideWindow,
  isPathExcluded,
  ListRulesOfEngagementResponseSchema,
  ListTargetsResponseSchema,
  matchesDnsChallenge,
  matchesFileChallenge,
  normaliseHost,
  normaliseTestPath,
  PRIVATE_HOST_SUFFIXES,
  ROE_LIMITS,
  type RulesOfEngagementContent,
  RulesOfEngagementContentSchema,
  RulesOfEngagementResponseSchema,
  type RulesOfEngagementVersion,
  RulesOfEngagementVersionSchema,
  SignRulesOfEngagementRequestSchema,
  TARGET_LIMITS,
  TARGET_STATUSES,
  type Target,
  TargetResponseSchema,
  TargetSchema,
  VERIFICATION_FILE_PATH,
  VERIFICATION_METHODS,
  VERIFICATION_TOKEN_PATTERN,
  VerifyResultSchema,
  VerifyTargetResponseSchema,
  verificationFileUrl,
  verificationInstructions,
  WEEKDAYS,
} from "../src/index.ts";

const TOKEN = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE";

// --- Ids ------------------------------------------------------------------------------------------------

describe("identifiers", () => {
  it("has tgt_ and roe_ patterns", () => {
    expect(ID_PATTERNS.tgt.test("tgt_0123456789abcdef01234567")).toBe(true);
    expect(ID_PATTERNS.roe.test("roe_0123456789abcdef01234567")).toBe(true);
    expect(ID_PATTERNS.tgt.test("roe_0123456789abcdef01234567")).toBe(false);
  });
});

// --- Host -----------------------------------------------------------------------------------------------

describe("normaliseHost and HostSchema", () => {
  it.each([
    ["acme-shop.io", "acme-shop.io"],
    ["Shop.Acme-Shop.IO", "shop.acme-shop.io"],
    ["shop.acme-shop.io.", "shop.acme-shop.io"],
    ["  shop.acme-shop.io  ", "shop.acme-shop.io"],
    ["a.co", "a.co"],
    ["xn--bcher-kva.example", null],
    ["xn--bcher-kva.ch", "xn--bcher-kva.ch"],
    ["my-shop.acme-shop.org", "my-shop.acme-shop.org"],
    ["a1.b2.c3.dev", "a1.b2.c3.dev"],
    ["ab--cd.acme-shop.net", "ab--cd.acme-shop.net"],
    ["1.acme-shop.io", "1.acme-shop.io"],
    ["123.acme-shop.io", "123.acme-shop.io"],
    ["0x7f.acme-shop.io", "0x7f.acme-shop.io"],
  ])("normalises %j to %j", (input, expected) => {
    expect(normaliseHost(input)).toBe(expected);
    const parsed = HostSchema.safeParse(input);
    expect(parsed.success).toBe(expected !== null);
    if (parsed.success) expect(parsed.data).toBe(expected);
  });

  it.each([
    // IPv4 literals in every form a URL parser accepts.
    "127.0.0.1",
    "10.0.0.1",
    "203.0.113.7",
    "203.0.113.7.",
    "127.1",
    "2130706433",
    "0x7f000001",
    "0x7f.0.0.1",
    "0x7F.0x0.0x0.0x1",
    "0177.0.0.1",
    "1.2.3.0x4",
    "example.0x10",
    "example.123",
    "example.0x",
    // IPv6 literals.
    "::1",
    "[::1]",
    "fe80::1",
    "::ffff:127.0.0.1",
    "[::ffff:7f00:1]",
    "2001:db8::1",
  ])("refuses the IP literal %j", (value) => {
    expect(normaliseHost(value)).toBeNull();
    expect(HostSchema.safeParse(value).success).toBe(false);
  });

  it("lists the private suffixes of the plan", () => {
    expect([...PRIVATE_HOST_SUFFIXES]).toEqual([
      "localhost",
      "local",
      "internal",
      "intranet",
      "lan",
      "home.arpa",
      "example",
      "invalid",
      "test",
      "onion",
      "example.com",
      "example.net",
      "example.org",
      "corp",
      "home",
      "svc",
      "cluster.local",
      "default",
      "localdomain",
      "arpa",
    ]);
    expect(Object.isFrozen(PRIVATE_HOST_SUFFIXES)).toBe(true);
  });

  it.each([
    "x.corp",
    "printer.home",
    "kubernetes.default",
    "kubernetes.default.svc",
    "api.ns.svc.cluster.local",
    "localhost.localdomain",
    "foo.arpa",
    "1.0.0.127.in-addr.arpa",
    "8.b.d.0.1.0.0.2.ip6.arpa",
  ])("refuses the internal name %j (review F4)", (value) => {
    expect(normaliseHost(value)).toBeNull();
  });

  it.each(
    PRIVATE_HOST_SUFFIXES.flatMap((suffix) => [
      suffix,
      `app.${suffix}`,
      `a.b.${suffix}.`,
      `APP.${suffix.toUpperCase()}`,
    ]),
  )("refuses %j: equal to or under a private suffix", (value) => {
    expect(normaliseHost(value)).toBeNull();
  });

  it.each([
    "mylocalhost.com",
    "localhost.com",
    "local.acme-shop.io",
    "internal.acme-shop.org",
    "test.acme-shop.io",
    "onion.dev",
    "arpa.acme-shop.io",
    "notlan.io",
  ])("accepts %j: a private word that is not the suffix", (value) => {
    expect(normaliseHost(value)).toBe(value);
  });

  it.each([
    "",
    " ",
    ".",
    "com",
    "localhost",
    "example..com",
    ".acme-shop.io",
    "acme-shop.io..",
    "-shop.acme-shop.io",
    "shop-.acme-shop.io",
    "shop.-acme-shop.io",
    "sh_op.acme-shop.io",
    "shop acme-shop.io",
    "shop.acme-shop.io/",
    "https://shop.acme-shop.io",
    "shop.acme-shop.io:443",
    "user@shop.acme-shop.io",
    "*.acme-shop.io",
    "bücher.ch",
    "shop.exämple.com",
    "shop\u0000.acme-shop.io",
    "shop.acme-shop.io\n",
  ])("refuses the malformed host %j", (value) => {
    expect(normaliseHost(value)).toBeNull();
  });

  it("refuses non-strings", () => {
    for (const value of [undefined, null, 1, {}, ["a.com"]]) expect(normaliseHost(value)).toBeNull();
    expect(HostSchema.safeParse(42).success).toBe(false);
  });

  it("allows labels of 63 characters and refuses 64", () => {
    const label63 = "a".repeat(63);
    expect(normaliseHost(`${label63}.com`)).toBe(`${label63}.com`);
    expect(normaliseHost(`${"a".repeat(64)}.com`)).toBeNull();
    expect(normaliseHost(`shop.${"b".repeat(64)}`)).toBeNull();
  });

  it("allows 253 characters and refuses 254 (a trailing dot does not count)", () => {
    // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
    const host253 = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
    expect(host253.length).toBe(TARGET_LIMITS.hostMax);
    expect(normaliseHost(host253)).toBe(host253);
    expect(normaliseHost(`${host253}.`)).toBe(host253);
    const host254 = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62)].join(".");
    expect(normaliseHost(host254)).toBeNull();
  });

  it("refuses a huge input without work proportional to a regex backtrack", () => {
    expect(normaliseHost(`${"a.".repeat(100_000)}com`)).toBeNull();
  });
});

// --- Verification instructions --------------------------------------------------------------------------

describe("verification token and instructions", () => {
  it("defines the token as 43 base64url characters", () => {
    expect(VERIFICATION_TOKEN_PATTERN.test(TOKEN)).toBe(true);
    expect(VERIFICATION_TOKEN_PATTERN.test(TOKEN.slice(1))).toBe(false);
    expect(VERIFICATION_TOKEN_PATTERN.test(`${TOKEN.slice(1)}=`)).toBe(false);
    expect(VERIFICATION_TOKEN_PATTERN.test(`${TOKEN.slice(1)}+`)).toBe(false);
  });

  it("builds the DNS record name, the DNS value and the file URL", () => {
    expect(CHALLENGE_RECORD_PREFIX).toBe("_airverse-challenge");
    expect(DNS_VALUE_PREFIX).toBe("airverse-verification=");
    expect(VERIFICATION_FILE_PATH).toBe("/.well-known/airverse-verification.txt");
    expect(challengeRecordName("shop.acme-shop.io")).toBe("_airverse-challenge.shop.acme-shop.io");
    expect(dnsChallengeValue(TOKEN)).toBe(`airverse-verification=${TOKEN}`);
    expect(verificationFileUrl("shop.acme-shop.io")).toBe(
      "https://shop.acme-shop.io/.well-known/airverse-verification.txt",
    );
    expect(verificationInstructions("shop.acme-shop.io", TOKEN)).toEqual({
      dns_name: "_airverse-challenge.shop.acme-shop.io",
      dns_value: `airverse-verification=${TOKEN}`,
      file_url: "https://shop.acme-shop.io/.well-known/airverse-verification.txt",
      file_content: TOKEN,
    });
  });

  it("refuses to build instructions for an invalid host or token", () => {
    expect(() => challengeRecordName("127.0.0.1")).toThrow(TypeError);
    expect(() => challengeRecordName("Shop.Acme-Shop.io")).toThrow(TypeError);
    expect(() => verificationFileUrl("localhost")).toThrow(TypeError);
    expect(() => dnsChallengeValue("short")).toThrow(TypeError);
    expect(() => verificationInstructions("shop.acme-shop.io", "short")).toThrow(TypeError);
  });

  describe("matchesDnsChallenge", () => {
    const value = `airverse-verification=${TOKEN}`;
    it("matches any TXT record equal to the value", () => {
      expect(matchesDnsChallenge([["v=spf1 -all"], [value]], TOKEN)).toBe(true);
    });
    it("joins the chunks of one TXT record", () => {
      expect(matchesDnsChallenge([[value.slice(0, 10), value.slice(10, 30), value.slice(30)]], TOKEN)).toBe(true);
    });
    it("does not join chunks across records", () => {
      expect(matchesDnsChallenge([[value.slice(0, 10)], [value.slice(10)]], TOKEN)).toBe(false);
    });
    it.each([
      [[]],
      [[[]]],
      [[[TOKEN]]],
      [[[`${value} `]]],
      [[[` ${value}`]]],
      [[[value.toLowerCase()]]],
      [[[`airverse-verification=${TOKEN.slice(1)}X`]]],
      [[[`${value}extra`]]],
      [[[`AIRVERSE-VERIFICATION=${TOKEN}`]]],
    ])("refuses %j", (records) => {
      expect(matchesDnsChallenge(records as string[][], TOKEN)).toBe(false);
    });
    it("refuses everything for an invalid token and malformed records", () => {
      expect(matchesDnsChallenge([["airverse-verification="]], "")).toBe(false);
      expect(matchesDnsChallenge("nope" as never, TOKEN)).toBe(false);
      expect(matchesDnsChallenge([[1, 2]] as never, TOKEN)).toBe(false);
    });
  });

  describe("matchesFileChallenge", () => {
    it.each([TOKEN, `${TOKEN}\n`, `  ${TOKEN}\r\n`, `\t${TOKEN}\t`])(
      "accepts %j (surrounding whitespace ignored)",
      (body) => {
        expect(matchesFileChallenge(body, TOKEN)).toBe(true);
      },
    );
    it.each([
      "",
      `airverse-verification=${TOKEN}`,
      `${TOKEN}${TOKEN}`,
      `${TOKEN} x`,
      TOKEN.toLowerCase(),
      `<html>${TOKEN}</html>`,
    ])("refuses %j", (body) => {
      expect(matchesFileChallenge(body, TOKEN)).toBe(false);
    });
    it("refuses an invalid token even when the body equals it", () => {
      expect(matchesFileChallenge("", "")).toBe(false);
      expect(matchesFileChallenge("short", "short")).toBe(false);
    });
  });
});

// --- Targets --------------------------------------------------------------------------------------------

describe("Target schemas", () => {
  it("has the limits of the plan", () => {
    expect(TARGET_LIMITS.hostMax).toBe(253);
    expect(TARGET_LIMITS.labelMax).toBe(63);
    expect(TARGET_LIMITS.targetsPerOrganization).toBe(50);
    expect(TARGET_LIMITS.verifyAttemptsPerHour).toBe(10);
    expect(TARGET_LIMITS.verifyAttemptsPerOrganizationPerHour).toBe(60);
    expect(TARGET_LIMITS.recheckIntervalS).toBe(86_400);
    expect(TARGET_LIMITS.fetchTimeoutMs).toBe(5000);
    expect(TARGET_LIMITS.fetchBodyBytesMax).toBe(1024);
    expect(TARGET_LIMITS.authorizeFreshnessS).toBe(93_600);
    expect(TARGET_LIMITS.authorizeClockSkewS).toBe(300);
    expect(Object.isFrozen(TARGET_LIMITS)).toBe(true);
    expect([...TARGET_STATUSES]).toEqual(["pending", "verified", "lapsed"]);
    expect([...VERIFICATION_METHODS]).toEqual(["dns", "file"]);
  });

  it("accepts the example target, and it is frozen", () => {
    expect(TargetSchema.parse(EXAMPLE_TARGET)).toEqual(EXAMPLE_TARGET);
    expect(Object.isFrozen(EXAMPLE_TARGET)).toBe(true);
  });

  const pending: Target = {
    id: "tgt_0123456789abcdef01234567",
    host: "shop.acme-shop.io",
    status: "pending",
    method: null,
    verified_at: null,
    last_checked_at: null,
    lapsed_reason: null,
    created_at: "2026-11-12T08:00:00.000Z",
  };
  const verified: Target = {
    ...pending,
    status: "verified",
    method: "dns",
    verified_at: "2026-11-12T08:05:00.000Z",
    last_checked_at: "2026-11-12T08:05:00.000Z",
  };
  const lapsed: Target = {
    ...verified,
    status: "lapsed",
    last_checked_at: "2026-11-13T08:05:00.000Z",
    lapsed_reason: "dns: no_record; file: status",
  };

  it("accepts consistent pending, verified and lapsed targets", () => {
    for (const target of [pending, verified, lapsed, { ...pending, last_checked_at: "2026-11-12T08:01:00.000Z" }]) {
      expect(TargetSchema.safeParse(target).success).toBe(true);
    }
  });

  it.each([
    ["pending with a method", { ...pending, method: "dns" }],
    ["pending with verified_at", { ...pending, verified_at: "2026-11-12T08:05:00.000Z" }],
    ["pending with a lapse reason", { ...pending, lapsed_reason: "x" }],
    ["verified without method", { ...verified, method: null }],
    ["verified without verified_at", { ...verified, verified_at: null }],
    ["verified with a lapse reason", { ...verified, lapsed_reason: "x" }],
    ["lapsed without a reason", { ...lapsed, lapsed_reason: null }],
    ["lapsed with an empty reason", { ...lapsed, lapsed_reason: "" }],
    ["an unknown status", { ...pending, status: "revoked" }],
    ["an unknown method", { ...verified, method: "http" }],
    ["a non-canonical host", { ...pending, host: "Shop.Acme-Shop.io" }],
    ["a host with a trailing dot", { ...pending, host: "shop.acme-shop.io." }],
    ["an IP host", { ...pending, host: "203.0.113.7" }],
    ["a wrong id", { ...pending, id: "roe_0123456789abcdef01234567" }],
    ["a control character in the reason", { ...lapsed, lapsed_reason: "a\u0000b" }],
    ["a too long reason", { ...lapsed, lapsed_reason: "x".repeat(TARGET_LIMITS.lapsedReasonMax + 1) }],
  ])("refuses %s", (_name, target) => {
    expect(TargetSchema.safeParse(target).success).toBe(false);
  });

  it("CreateTargetRequest normalises the host", () => {
    expect(CreateTargetRequestSchema.parse({ host: " Shop.Acme-Shop.IO. " })).toEqual({ host: "shop.acme-shop.io" });
    expect(CreateTargetRequestSchema.safeParse({ host: "localhost" }).success).toBe(false);
    expect(CreateTargetRequestSchema.safeParse({ host: "10.0.0.1" }).success).toBe(false);
    expect(CreateTargetRequestSchema.safeParse({}).success).toBe(false);
  });

  it("TargetResponse carries the target and the instructions; the list carries targets only", () => {
    const response = { target: pending, verification: verificationInstructions(pending.host, TOKEN) };
    expect(TargetResponseSchema.parse(response)).toEqual(response);
    expect(
      TargetResponseSchema.safeParse({ ...response, verification: { ...response.verification, file_content: "short" } })
        .success,
    ).toBe(false);
    expect(
      TargetResponseSchema.safeParse({
        ...response,
        verification: verificationInstructions("other.acme-shop.io", TOKEN),
      }).success,
    ).toBe(false);
    expect(ListTargetsResponseSchema.parse({ targets: [pending, verified] })).toEqual({ targets: [pending, verified] });
    expect(
      ListTargetsResponseSchema.safeParse({
        targets: Array.from({ length: TARGET_LIMITS.targetsPerOrganization + 1 }, () => pending),
      }).success,
    ).toBe(false);
  });

  it("VerifyResult says which method passed, or why each failed", () => {
    expect(
      VerifyResultSchema.parse({ verified: true, method: "file", checked_at: "2026-11-12T08:05:00.000Z" }),
    ).toEqual({
      verified: true,
      method: "file",
      checked_at: "2026-11-12T08:05:00.000Z",
    });
    const failed = {
      verified: false,
      dns: "no_record",
      file: "not_reachable",
      checked_at: "2026-11-12T08:05:00.000Z",
    };
    expect(VerifyResultSchema.parse(failed)).toEqual(failed);
    // Review F4: one public reason for "not reached"; which internal check refused it is never told per target.
    expect(FILE_VERIFY_FAILURES).toEqual([
      "not_reachable",
      "connect_failed",
      "tls_failed",
      "redirect",
      "status",
      "timeout",
      "too_large",
      "mismatch",
    ]);
    for (const internal of ["address_not_public", "resolve_failed"]) {
      expect(VerifyResultSchema.safeParse({ ...failed, file: internal }).success).toBe(false);
    }
    expect(VerifyResultSchema.safeParse({ ...failed, dns: "nope" }).success).toBe(false);
    expect(VerifyResultSchema.safeParse({ verified: true, method: null, checked_at: failed.checked_at }).success).toBe(
      false,
    );
    expect(
      VerifyTargetResponseSchema.parse({
        target: verified,
        result: { verified: true, method: "dns", checked_at: verified.verified_at },
      }).target,
    ).toEqual(verified);
  });
});

// --- Rules of Engagement --------------------------------------------------------------------------------

const content: RulesOfEngagementContent = {
  scope: ["tgt_0123456789abcdef01234567"],
  exclusions: ["/admin"],
  intensity: "safe-active",
  window: { days: ["mon", "tue", "wed", "thu", "fri"], from: "09:00", to: "17:00" },
  contacts: ["security@example.com"],
};

describe("Rules of Engagement schemas", () => {
  it("orders the intensities and the weekdays", () => {
    expect([...INTENSITIES]).toEqual(["passive", "safe-active", "full"]);
    expect(INTENSITIES.map(intensityRank)).toEqual([0, 1, 2]);
    expect(() => intensityRank("extreme" as Intensity)).toThrow(TypeError);
    expect([...WEEKDAYS]).toEqual(["mon", "tue", "wed", "thu", "fri", "sat", "sun"]);
  });

  it("has the limits of the plan", () => {
    expect(ROE_LIMITS).toMatchObject({ scopeMax: 50, exclusionsMax: 50, exclusionMax: 256, contactsMax: 5 });
    expect(Object.isFrozen(ROE_LIMITS)).toBe(true);
  });

  it("accepts the content of the example", () => {
    expect(RulesOfEngagementContentSchema.parse(content)).toEqual(content);
  });

  it("accepts a window that ends at 24:00, the end of the day", () => {
    for (const from of ["00:00", "22:00"]) {
      const allDay = { ...content, window: { days: ["mon"], from, to: "24:00" } };
      expect(RulesOfEngagementContentSchema.safeParse(allDay).success).toBe(true);
    }
  });

  it("accepts a window that crosses midnight and empty exclusions", () => {
    const night = { ...content, exclusions: [], window: { days: ["sat"], from: "22:00", to: "02:00" } };
    expect(RulesOfEngagementContentSchema.safeParse(night).success).toBe(true);
  });

  it.each([
    ["an empty scope", { scope: [] }],
    ["51 targets", { scope: Array.from({ length: 51 }, (_, i) => `tgt_${i.toString(16).padStart(24, "0")}`) }],
    ["a duplicate target", { scope: ["tgt_0123456789abcdef01234567", "tgt_0123456789abcdef01234567"] }],
    ["a wrong scope id", { scope: ["roe_0123456789abcdef01234567"] }],
    ["an exclusion without /", { exclusions: ["admin"] }],
    ["an exclusion with a trailing /", { exclusions: ["/admin/"] }],
    ["an exclusion with a dot segment", { exclusions: ["/a/../admin"] }],
    ["an exclusion with a query", { exclusions: ["/admin?x=1"] }],
    ["an exclusion with a fragment", { exclusions: ["/admin#x"] }],
    ["an exclusion with an encoded character", { exclusions: ["/%61dmin"] }],
    ["an exclusion with a control character", { exclusions: ["/ad\u0000min"] }],
    ["a too long exclusion", { exclusions: [`/${"a".repeat(256)}`] }],
    ["51 exclusions", { exclusions: Array.from({ length: 51 }, (_, i) => `/p${i}`) }],
    ["a duplicate exclusion", { exclusions: ["/a", "/a"] }],
    ["an unknown intensity", { intensity: "aggressive" }],
    ["no days", { window: { days: [], from: "09:00", to: "17:00" } }],
    ["a duplicate day", { window: { days: ["mon", "mon"], from: "09:00", to: "17:00" } }],
    ["an unknown day", { window: { days: ["monday"], from: "09:00", to: "17:00" } }],
    ["a malformed time", { window: { days: ["mon"], from: "9:00", to: "17:00" } }],
    ["from 24:00", { window: { days: ["mon"], from: "24:00", to: "02:00" } }],
    ["to 24:01", { window: { days: ["mon"], from: "09:00", to: "24:01" } }],
    ["to 25:00", { window: { days: ["mon"], from: "09:00", to: "25:00" } }],
    ["minute 60", { window: { days: ["mon"], from: "09:60", to: "17:00" } }],
    ["an empty window", { window: { days: ["mon"], from: "09:00", to: "09:00" } }],
    ["no contact", { contacts: [] }],
    ["6 contacts", { contacts: ["a@x.io", "b@x.io", "c@x.io", "d@x.io", "e@x.io", "f@x.io"] }],
    ["a duplicate contact", { contacts: ["a@x.io", "a@x.io"] }],
    ["a malformed contact", { contacts: ["not-an-email"] }],
  ])("refuses %s", (_name, patch) => {
    expect(RulesOfEngagementContentSchema.safeParse({ ...content, ...patch }).success).toBe(false);
  });

  it("builds the confirmation phrase for each intensity", () => {
    expect(confirmationPhrase("passive")).toBe("I authorise passive testing");
    expect(confirmationPhrase("safe-active")).toBe("I authorise safe-active testing");
    expect(confirmationPhrase("full")).toBe("I authorise full testing");
    expect(() => confirmationPhrase("max" as Intensity)).toThrow(TypeError);
  });

  it("signing needs the exact phrase of the intensity", () => {
    const ok = { ...content, confirm: "I authorise safe-active testing" };
    expect(SignRulesOfEngagementRequestSchema.parse(ok)).toEqual(ok);
    for (const confirm of [
      "I authorise full testing",
      "I authorise passive testing",
      "i authorise safe-active testing",
      "I authorize safe-active testing",
      " I authorise safe-active testing",
      "I authorise safe-active testing.",
      "",
    ]) {
      expect(SignRulesOfEngagementRequestSchema.safeParse({ ...content, confirm }).success).toBe(false);
    }
    expect(SignRulesOfEngagementRequestSchema.safeParse(content).success).toBe(false);
  });

  it("accepts the example version, and it is frozen", () => {
    expect(RulesOfEngagementVersionSchema.parse(EXAMPLE_RULES_OF_ENGAGEMENT)).toEqual(EXAMPLE_RULES_OF_ENGAGEMENT);
    expect(Object.isFrozen(EXAMPLE_RULES_OF_ENGAGEMENT)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_RULES_OF_ENGAGEMENT.window.days)).toBe(true);
  });

  it.each([
    ["a wrong id", { id: "tgt_0123456789abcdef01234567" }],
    ["a signer that is not an admin key id", { signed_by: "aro_x" }],
    ["an upper-case hash", { content_sha256: "A".repeat(64) }],
    ["a short hash", { content_sha256: "a".repeat(63) }],
    ["a malformed time", { signed_at: "yesterday" }],
  ])("refuses a version with %s", (_name, patch) => {
    expect(RulesOfEngagementVersionSchema.safeParse({ ...EXAMPLE_RULES_OF_ENGAGEMENT, ...patch }).success).toBe(false);
  });

  it("wraps versions in responses", () => {
    expect(RulesOfEngagementResponseSchema.parse({ version: EXAMPLE_RULES_OF_ENGAGEMENT }).version.id).toBe(
      EXAMPLE_RULES_OF_ENGAGEMENT.id,
    );
    expect(
      ListRulesOfEngagementResponseSchema.parse({ versions: [EXAMPLE_RULES_OF_ENGAGEMENT] }).versions,
    ).toHaveLength(1);
    expect(CurrentRulesOfEngagementResponseSchema.parse({ version: null })).toEqual({ version: null });
  });
});

describe("canonicalJson", () => {
  it("sorts object keys at every depth and keeps array order", () => {
    expect(canonicalJson({ b: 1, a: { d: [3, 1, { z: 0, y: "x" }], c: null } })).toBe(
      '{"a":{"c":null,"d":[3,1,{"y":"x","z":0}]},"b":1}',
    );
  });
  it("is stable over key order", () => {
    const reordered = {
      window: { to: content.window.to, from: content.window.from, days: content.window.days },
      contacts: content.contacts,
      intensity: content.intensity,
      exclusions: content.exclusions,
      scope: content.scope,
    };
    expect(canonicalJson(reordered)).toBe(canonicalJson(content));
  });
  it("escapes strings as JSON does", () => {
    expect(canonicalJson({ 'k"': 'a"\n ' })).toBe(JSON.stringify({ 'k"': 'a"\n ' }));
  });
  it("sorts keys by code unit, not by locale", () => {
    expect(canonicalJson({ b: 1, B: 2, a: 3, é: 4 })).toBe('{"B":2,"a":3,"b":1,"é":4}');
  });
  it.each([
    [undefined],
    [Number.NaN],
    [Number.POSITIVE_INFINITY],
    [() => 1],
    [1n],
    [Symbol("x")],
    [{ a: undefined }],
    [new Date(0)],
  ])("refuses %s", (value) => {
    expect(() => canonicalJson(value)).toThrow(TypeError);
  });
});

// --- authorize ------------------------------------------------------------------------------------------

describe("normaliseTestPath", () => {
  it.each([
    ["/", "/"],
    ["/a/b", "/a/b"],
    ["/a/./b", "/a/b"],
    ["/a/../b", "/b"],
    ["/admin/../x", "/x"],
    ["/x/../admin", "/admin"],
    ["/../admin", "/admin"],
    ["/a/b/..", "/a/"],
    ["/a/b/.", "/a/b/"],
    ["/%2e%2e/admin", "/admin"],
    ["/x/%2e%2e/admin", "/admin"],
    ["/x/%2E%2E/admin", "/admin"],
    ["/x/.%2e/admin", "/admin"],
    ["/%61dmin", "/admin"],
    ["/admin%2fusers", "/admin/users"],
    ["/x/%252e%252e/admin", "/x/%2e%2e/admin"],
    ["/admin?next=/x", "/admin"],
    ["/admin#frag", "/admin"],
    ["/a%3fb", "/a?b"],
    ["/%zz", "/%zz"],
    ["/caf%C3%A9", "/café"],
  ])("normalises %j to %j", (input, expected) => {
    expect(normaliseTestPath(input)).toBe(expected);
  });
});

describe("isPathExcluded", () => {
  it.each([
    ["/admin", ["/admin"], true],
    ["/admin/", ["/admin"], true],
    ["/admin/users", ["/admin"], true],
    ["/administrator", ["/admin"], false],
    ["/admins/x", ["/admin"], false],
    ["/x", ["/admin"], false],
    ["/Admin", ["/admin"], true],
    ["/ADMIN/users", ["/admin"], true],
    ["/admin", ["/Admin"], true],
    ["\\admin", ["/admin"], true],
    ["/x\\..\\admin", ["/admin"], true],
    ["//admin", ["/admin"], true],
    ["/x//..//admin/", ["/admin"], true],
    ["/./admin", ["/admin"], true],
    ["/admin;jsessionid=1", ["/admin"], true],
    ["/admin;x=1/users", ["/admin"], true],
    ["/x/..;/admin", ["/admin"], true],
    ["/admin%3bx", ["/admin"], true],
    ["/x/%252e%252e/admin", ["/admin"], true],
    ["/%2561dmin", ["/admin"], true],
    ["/%25%36%31dmin", ["/admin"], true],
    ["/x%255c..%255cadmin", ["/admin"], true],
    ["/%252561dmin", ["/admin"], true],
    // Nested encodings: each pass removes one level; still changing after 5 passes counts as excluded.
    [`/x%${"25".repeat(3)}41`, ["/admin"], false],
    [`/x%${"25".repeat(5)}41`, ["/admin"], true],
    [`/x%${"25".repeat(10)}41`, ["/admin"], true],
    [`/x%${"25".repeat(10)}41`, [], false],
    // Review F1: every spelling a server may fold to /admin is excluded.
    ["/admin%2e", ["/admin"], true],
    ["/admin.", ["/admin"], true],
    ["/admin..", ["/admin"], true],
    ["/admin%252e", ["/admin"], true],
    ["/admin%20", ["/admin"], true],
    ["/admin%09", ["/admin"], true],
    ["/admin%00", ["/admin"], true],
    ["/admin%00/x", ["/admin"], true],
    ["/admin\u0000", ["/admin"], true],
    ["/admin\u0000.txt", ["/admin"], true],
    ["/admin%u0000", ["/admin"], true],
    ["/%u0061dmin", ["/admin"], true],
    ["/admin::$DATA", ["/admin"], true],
    ["/admin:$i30:$INDEX_ALLOCATION/x", ["/admin"], true],
    ["/admin%e2%80%8b", ["/admin"], true],
    ["/ad%e2%80%8cmin", ["/admin"], true],
    ["/admin%e2%81%a0", ["/admin"], true],
    ["/%ef%bb%bfadmin", ["/admin"], true],
    ["/ad%c2%admin", ["/admin"], true],
    ["/\uff41\uff44\uff4d\uff49\uff4e", ["/admin"], true],
    ["/x/..%c0%afadmin", ["/admin"], true],
    ["/admin%c0%af", ["/admin"], true],
    ["/adm%C4%B0n", ["/admin"], true],
    ["/adm\u0131n", ["/admin"], true],
    ["/caf%C3%A9", ["/admin"], true],
    ["/x/.../admin", ["/admin"], true],
    ["/admin. . /x", ["/admin"], true],
    // Still not excluded: other words, and ordinary paths.
    ["/admin-x", ["/admin"], false],
    ["/administrator.", ["/admin"], false],
    ["/admins%20", ["/admin"], false],
    ["/shop/items/42", ["/admin"], false],
    ["/a.b/c", ["/admin"], false],
    ["/caf%C3%A9", [], false],
    ["/x%e2%82%ac", ["/admin"], false],
    ["/api/v1;x/admin", ["/api/v1"], true],
    ["/admin/../x", ["/admin"], false],
    ["/admin\\..\\x", ["/admin"], false],
    ["/admin;x/../y", ["/admin"], false],
    ["/administrator;x", ["/admin"], false],
    ["/x/../admin", ["/admin"], true],
    ["/x/%2e%2e/admin/y", ["/admin"], true],
    ["/%61dmin", ["/admin"], true],
    ["/api/v1/admin", ["/api/v1"], true],
    ["/anything", ["/"], true],
    ["/", ["/"], true],
    ["/a/b", ["/x", "/a/b"], true],
    ["/a", [], false],
  ])("%j with %j → %s", (path, exclusions, expected) => {
    expect(isPathExcluded(path, exclusions)).toBe(expected);
  });
});

describe("isInsideWindow", () => {
  const weekday = { days: ["mon", "tue", "wed", "thu", "fri"] as const, from: "09:00", to: "17:00" };
  // 2026-11-09 is a Monday; 2026-11-14 a Saturday; 2026-11-15 a Sunday.
  it.each([
    ["2026-11-09T09:00:00.000Z", true],
    ["2026-11-09T08:59:59.999Z", false],
    ["2026-11-09T16:59:59.999Z", true],
    ["2026-11-09T17:00:00.000Z", false],
    ["2026-11-13T12:00:00.000Z", true],
    ["2026-11-14T12:00:00.000Z", false],
    ["2026-11-15T12:00:00.000Z", false],
    ["2026-11-09T12:00:00+02:00", true],
    ["2026-11-09T10:00:00+02:00", false],
  ])("a weekday 09:00–17:00 window at %s → %s", (at, expected) => {
    expect(isInsideWindow({ ...weekday, days: [...weekday.days] }, at)).toBe(expected);
  });

  // Friday 22:00 to 02:00: the hours after midnight belong to the day the window started.
  const night = { days: ["fri" as const], from: "22:00", to: "02:00" };
  it.each([
    ["2026-11-13T21:59:59.999Z", false],
    ["2026-11-13T22:00:00.000Z", true],
    ["2026-11-13T23:59:59.999Z", true],
    ["2026-11-14T00:00:00.000Z", true],
    ["2026-11-14T01:59:59.999Z", true],
    ["2026-11-14T02:00:00.000Z", false],
    ["2026-11-14T22:30:00.000Z", false],
    ["2026-11-13T01:00:00.000Z", false],
    ["2026-11-13T00:30:00.000Z", false],
  ])("a Friday 22:00–02:00 window at %s → %s", (at, expected) => {
    expect(isInsideWindow(night, at)).toBe(expected);
  });

  it("a Sunday night window continues into Monday", () => {
    const sunday = { days: ["sun" as const], from: "23:00", to: "01:00" };
    expect(isInsideWindow(sunday, "2026-11-15T23:30:00.000Z")).toBe(true);
    expect(isInsideWindow(sunday, "2026-11-16T00:30:00.000Z")).toBe(true);
    expect(isInsideWindow(sunday, "2026-11-09T00:30:00.000Z")).toBe(true);
    expect(isInsideWindow(sunday, "2026-11-16T01:00:00.000Z")).toBe(false);
    expect(isInsideWindow(sunday, "2026-11-14T23:30:00.000Z")).toBe(false);
  });

  it("covers a whole week with every day 00:00–24:00", () => {
    const always = { days: [...WEEKDAYS], from: "00:00", to: "24:00" };
    expect(isInsideWindow(always, "2026-11-09T00:00:00.000Z")).toBe(true);
    expect(isInsideWindow(always, "2026-11-12T12:34:56.789Z")).toBe(true);
    expect(isInsideWindow(always, "2026-11-15T23:59:59.999Z")).toBe(true);
  });

  it("an all-day window covers the listed day and nothing of the next", () => {
    const monday = { days: ["mon" as const], from: "00:00", to: "24:00" };
    expect(isInsideWindow(monday, "2026-11-09T00:00:00.000Z")).toBe(true);
    expect(isInsideWindow(monday, "2026-11-09T23:59:59.999Z")).toBe(true);
    expect(isInsideWindow(monday, "2026-11-10T00:00:00.000Z")).toBe(false);
    expect(isInsideWindow(monday, "2026-11-08T23:59:59.999Z")).toBe(false);
    const evening = { days: ["mon" as const], from: "22:00", to: "24:00" };
    expect(isInsideWindow(evening, "2026-11-09T21:59:59.999Z")).toBe(false);
    expect(isInsideWindow(evening, "2026-11-09T23:59:59.999Z")).toBe(true);
    expect(isInsideWindow(evening, "2026-11-10T00:00:00.000Z")).toBe(false);
  });

  it("is false for an unparseable time", () => {
    expect(isInsideWindow({ ...weekday, days: [...weekday.days] }, "not a time")).toBe(false);
    expect(isInsideWindow({ ...weekday, days: [...weekday.days] }, new Date(Number.NaN))).toBe(false);
  });

  it("accepts a Date", () => {
    expect(isInsideWindow({ ...weekday, days: [...weekday.days] }, new Date("2026-11-09T10:00:00.000Z"))).toBe(true);
  });
});

describe("authorizeTest", () => {
  const T1 = "tgt_000000000000000000000001";
  const T2 = "tgt_000000000000000000000002";
  const T3 = "tgt_000000000000000000000003";
  const T4 = "tgt_000000000000000000000004";
  const current: RulesOfEngagementVersion = {
    id: "roe_000000000000000000000001",
    scope: [T1, T3],
    exclusions: ["/admin", "/api/internal"],
    intensity: "safe-active",
    window: { days: ["mon", "tue", "wed", "thu", "fri"], from: "09:00", to: "17:00" },
    contacts: ["security@example.com"],
    signed_by: "key_0123456789abcdef01234567",
    signed_at: "2026-11-09T08:00:00.000Z",
    content_sha256: "0".repeat(64),
  };
  const state: AuthorizeState = {
    targets: [
      { id: T1, host: "shop.acme-shop.io", status: "verified", verified_at: "2026-11-09T08:00:00.000Z" },
      { id: T2, host: "pending.acme-shop.io", status: "pending", verified_at: null },
      { id: T3, host: "lapsed.acme-shop.io", status: "lapsed", verified_at: "2026-11-09T08:00:00.000Z" },
      { id: T4, host: "other.acme-shop.io", status: "verified", verified_at: "2026-11-09T08:00:00.000Z" },
    ],
    current,
  };
  const ok: AuthorizeRequest = {
    host: "shop.acme-shop.io",
    path: "/products",
    intensity: "passive",
    at: "2026-11-09T10:00:00.000Z",
  };
  const refused = (reason: string): AuthorizeResult => ({ allowed: false, reason }) as AuthorizeResult;

  it("judges freshness at `freshAt` when given (the API's clock), and the window at the request's time (review F6)", () => {
    // A test time in the past cannot make a stale target fresh again.
    expect(authorizeTest(state, ok, { freshAt: "2026-11-10T11:00:00.000Z" })).toEqual(refused("target_not_verified"));
    expect(authorizeTest(state, ok, { freshAt: "2026-11-10T09:59:59.999Z" })).toEqual({
      allowed: true,
      roe_id: current.id,
    });
    // The window still follows `at`: fresh now, but the asked-for time is outside it.
    expect(
      authorizeTest(state, { ...ok, at: "2026-11-09T18:00:00.000Z" }, { freshAt: "2026-11-09T10:00:00.000Z" }),
    ).toEqual(refused("outside_window"));
    // An unparseable clock fails closed.
    expect(authorizeTest(state, ok, { freshAt: "not a time" })).toEqual(refused("target_not_verified"));
  });

  it("lists the reasons in the order they are checked", () => {
    expect([...AUTHORIZE_REASONS]).toEqual([
      "target_unknown",
      "target_not_verified",
      "no_rules_of_engagement",
      "out_of_scope",
      "path_excluded",
      "intensity_exceeds",
      "outside_window",
    ]);
  });

  it("allows a test that passes every rule and names the version", () => {
    expect(authorizeTest(state, ok)).toEqual({ allowed: true, roe_id: current.id });
    expect(authorizeTest(state, { ...ok, intensity: "safe-active" })).toEqual({ allowed: true, roe_id: current.id });
    expect(AuthorizeResultSchema.parse(authorizeTest(state, ok))).toEqual({ allowed: true, roe_id: current.id });
  });

  it("matches the host after normalisation", () => {
    expect(authorizeTest(state, { ...ok, host: "SHOP.acme-shop.io." }).allowed).toBe(true);
  });

  it("target_unknown: a host the Organization does not have, or not a host at all", () => {
    expect(authorizeTest(state, { ...ok, host: "evil.acme-shop.io" })).toEqual(refused("target_unknown"));
    expect(authorizeTest(state, { ...ok, host: "acme-shop.io" })).toEqual(refused("target_unknown"));
    expect(authorizeTest(state, { ...ok, host: "sub.shop.acme-shop.io" })).toEqual(refused("target_unknown"));
    expect(authorizeTest(state, { ...ok, host: "127.0.0.1" })).toEqual(refused("target_unknown"));
    expect(authorizeTest(state, { ...ok, host: "" })).toEqual(refused("target_unknown"));
  });

  it("target_not_verified: pending or lapsed", () => {
    expect(authorizeTest(state, { ...ok, host: "pending.acme-shop.io" })).toEqual(refused("target_not_verified"));
    expect(authorizeTest(state, { ...ok, host: "lapsed.acme-shop.io" })).toEqual(refused("target_not_verified"));
  });

  it("target_not_verified: the last successful check is more than 26 hours from the test", () => {
    const at = (verifiedAt: string | null): AuthorizeState => ({
      ...state,
      targets: [{ id: T1, host: "shop.acme-shop.io", status: "verified", verified_at: verifiedAt }],
    });
    // ok.at is 2026-11-09T10:00:00.000Z; 26 hours earlier is 2026-11-08T08:00:00.000Z.
    expect(authorizeTest(at("2026-11-08T08:00:00.000Z"), ok)).toEqual({ allowed: true, roe_id: current.id });
    expect(authorizeTest(at("2026-11-08T07:59:59.999Z"), ok)).toEqual(refused("target_not_verified"));
    // Only checks before the test count, with 5 minutes of clock skew.
    expect(authorizeTest(at("2026-11-09T10:05:00.000Z"), ok)).toEqual({ allowed: true, roe_id: current.id });
    expect(authorizeTest(at("2026-11-09T10:05:00.001Z"), ok)).toEqual(refused("target_not_verified"));
    expect(authorizeTest(at("2026-11-10T12:00:00.000Z"), ok)).toEqual(refused("target_not_verified"));
    expect(authorizeTest(at(null), ok)).toEqual(refused("target_not_verified"));
    expect(authorizeTest(at("garbage"), ok)).toEqual(refused("target_not_verified"));
  });

  it("no_rules_of_engagement: nothing signed", () => {
    expect(authorizeTest({ ...state, current: null }, ok)).toEqual(refused("no_rules_of_engagement"));
  });

  it("out_of_scope: a verified host outside the current version", () => {
    expect(authorizeTest(state, { ...ok, host: "other.acme-shop.io" })).toEqual(refused("out_of_scope"));
  });

  it.each([
    "/admin",
    "/admin/",
    "/admin/users",
    "/x/../admin",
    "/%61dmin/x",
    "/x/%2e%2e/admin",
    "/api/internal/v2",
    "/admin?x=1",
    "/Admin",
    "//admin",
    "\\admin",
    "/admin;x=1",
    "/x/%252e%252e/admin",
  ])("path_excluded: %j", (path) => {
    expect(authorizeTest(state, { ...ok, path })).toEqual(refused("path_excluded"));
  });

  it.each(["/administrator", "/admin/../products", "/api/internals", "/Products"])("not excluded: %j", (path) => {
    expect(authorizeTest(state, { ...ok, path }).allowed).toBe(true);
  });

  it("intensity_exceeds: stronger than signed", () => {
    expect(authorizeTest(state, { ...ok, intensity: "full" })).toEqual(refused("intensity_exceeds"));
    expect(
      authorizeTest({ ...state, current: { ...current, intensity: "passive" } }, { ...ok, intensity: "safe-active" }),
    ).toEqual(refused("intensity_exceeds"));
  });

  it("outside_window: wrong hour or wrong day", () => {
    expect(authorizeTest(state, { ...ok, at: "2026-11-09T17:00:00.000Z" })).toEqual(refused("outside_window"));
    expect(authorizeTest(state, { ...ok, at: "2026-11-09T08:59:59.999Z" })).toEqual(refused("outside_window"));
    expect(authorizeTest(state, { ...ok, at: "2026-11-10T03:00:00.000Z" })).toEqual(refused("outside_window"));
    const saturday: AuthorizeState = {
      ...state,
      targets: [{ id: T1, host: "shop.acme-shop.io", status: "verified", verified_at: "2026-11-14T09:00:00.000Z" }],
    };
    expect(authorizeTest(saturday, { ...ok, at: "2026-11-14T10:00:00.000Z" })).toEqual(refused("outside_window"));
    // An unparseable time cannot be shown to be within 26 hours of the last ownership check.
    expect(authorizeTest(state, { ...ok, at: "not a time" })).toEqual(refused("target_not_verified"));
  });

  it("returns the first failing reason in the listed order", () => {
    const allBad: AuthorizeRequest = {
      host: "other.acme-shop.io",
      path: "/admin",
      intensity: "full",
      at: "2026-11-09T20:00:00.000Z",
    };
    expect(authorizeTest(state, allBad)).toEqual(refused("out_of_scope"));
    expect(authorizeTest({ ...state, current: null }, allBad)).toEqual(refused("no_rules_of_engagement"));
    expect(authorizeTest(state, { ...allBad, host: "pending.acme-shop.io" })).toEqual(refused("target_not_verified"));
    expect(authorizeTest(state, { ...allBad, host: "shop.acme-shop.io" })).toEqual(refused("path_excluded"));
    expect(authorizeTest(state, { ...allBad, host: "shop.acme-shop.io", path: "/x" })).toEqual(
      refused("intensity_exceeds"),
    );
    expect(authorizeTest(state, { ...allBad, host: "shop.acme-shop.io", path: "/x", intensity: "passive" })).toEqual(
      refused("outside_window"),
    );
  });

  it("does not mutate the state", () => {
    const frozen = structuredClone(state);
    authorizeTest(state, ok);
    expect(state).toEqual(frozen);
  });

  it("AuthorizeRequest validates the request and normalises the host", () => {
    expect(AuthorizeRequestSchema.parse({ ...ok, host: "Shop.Acme-Shop.io." })).toEqual(ok);
    for (const patch of [
      { host: "10.0.0.1" },
      { path: "products" },
      { path: "" },
      { path: `/${"a".repeat(ROE_LIMITS.pathMax)}` },
      { path: "/a\u0000" },
      { intensity: "max" },
      { at: "tomorrow" },
      { at: undefined },
    ]) {
      expect(AuthorizeRequestSchema.safeParse({ ...ok, ...patch }).success).toBe(false);
    }
  });

  it("AuthorizeResult accepts only the listed reasons", () => {
    for (const reason of AUTHORIZE_REASONS) {
      expect(AuthorizeResultSchema.safeParse({ allowed: false, reason }).success).toBe(true);
    }
    expect(AuthorizeResultSchema.safeParse({ allowed: false, reason: "nope" }).success).toBe(false);
    expect(AuthorizeResultSchema.safeParse({ allowed: true, roe_id: "tgt_000000000000000000000001" }).success).toBe(
      false,
    );
  });
});
