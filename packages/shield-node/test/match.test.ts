// Review focus 1: a block Rule must not be bypassed by spelling the path differently, and must not catch a
// different path. `matchPath` works on one form of the path as text; `canonicalPaths` gives the other forms
// (decoded, dot segments resolved) that `decide` matches as well. The tables of `matchPath` below are about the
// text form alone: a target listed there as "not decoded" is caught by a canonical form (test/decide.test.ts).
import { PATH_PATTERN, POLICY_LIMITS } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  canonicalPaths,
  compilePattern,
  matchMethod,
  matchPath,
  matchSplit,
  normalisePath,
  splitPath,
} from "../src/policy/match.ts";

/** Whether a request for `target` (path and, possibly, query string) matches `pattern`. */
function matches(pattern: string, target: string): boolean {
  const compiled = compilePattern(pattern);
  if (compiled === null) throw new Error(`not a path pattern: ${pattern}`);
  return matchPath(compiled, normalisePath(target));
}

describe("compilePattern: the grammar of the protocol", () => {
  const candidates = [
    "/",
    "/login",
    "/api/admin/**",
    "/api/users/*/export",
    "/a.b_c~d-e",
    "/**",
    "/*",
    "/*/*",
    "/a/*/**",
    "/A/B",
    "/.",
    "/..",
    "/a/../b",
    `/${"a".repeat(255)}`,
    "",
    "api",
    "*",
    "**",
    "/a//b",
    "//",
    "/a/",
    "/a/**/b",
    "/**/a",
    "/a/*x",
    "/a/x*",
    "/a/***",
    "/a/**/",
    "/a b",
    "/a?x",
    "/a#x",
    "/%61",
    "/a\\b",
    "/a\n",
    "/a\u0000",
    "/é",
    "/a(b)",
    "/a+",
    "/a$",
    "/[a]",
    "/a|b",
    `/${"a".repeat(256)}`,
    `/${"a/".repeat(200)}b`,
  ];

  it.each(candidates)("agrees with PATH_PATTERN of the protocol about %j", (candidate) => {
    expect(compilePattern(candidate) !== null).toBe(PATH_PATTERN.test(candidate));
  });

  it("accepts the documented examples and refuses the documented mistakes", () => {
    for (const good of ["/", "/login", "/api/admin/**", "/api/users/*/export", "/a.b_c~d-e"]) {
      expect(compilePattern(good), good).not.toBeNull();
    }
    for (const bad of ["api", "/a//b", "/a/**/b", "/a/*x", "/a b", "/a?x", "/a#x", "/%61", "/a\u0001"]) {
      expect(compilePattern(bad), bad).toBeNull();
    }
    expect(compilePattern(`/${"a".repeat(POLICY_LIMITS.pathMax - 1)}`)).not.toBeNull();
    expect(compilePattern(`/${"a".repeat(POLICY_LIMITS.pathMax)}`)).toBeNull(); // 257 characters
  });

  it.each([undefined, null, 42, {}, [], ["/a"], true])("refuses %j, which is not text, without throwing", (value) => {
    expect(compilePattern(value)).toBeNull();
  });
});

describe("bypass attempts on the block Rule /api/admin/**", () => {
  const pattern = "/api/admin/**";

  it.each([
    "/api/admin",
    "/api/admin/",
    "/api/admin/x",
    "/api/admin/x/y",
    "/api/admin/x/",
    "/API/Admin/x",
    "/Api/ADMIN/Reports",
    "/api/admin?x=1",
    "/api/admin/?x=1",
    "/api/admin?",
    "/api/admin/x?next=/api/public",
    "/api/admin#fragment",
    "/api/admin/reports#",
    "/api/admin//x",
    "/api/admin//",
    "/api/admin/x//y",
    "/api/admin/../public",
    "/api/admin/./x",
    "/api/admin/%2e%2e/public",
    "/api/admin/x%00",
    "/api/admin/x;jsessionid=1",
    `/api/admin/${"x".repeat(8_000)}`,
    "http://evil.test/api/admin/reports",
    "https://evil.test:8443/API/admin?x=1",
  ])("matches %s", (target) => {
    expect(matches(pattern, target)).toBe(true);
  });

  it.each([
    "/api/administrator",
    "/api/administrator/x",
    "/api/admin-old",
    "/api/admin.json",
    "/api/admin_x",
    "/api/admin~",
    "/api/adm",
    "/api",
    "/api/",
    "/",
    "/x/api/admin",
    "//api/admin",
    "/api//admin",
    "/api/admin%2Fx",
    "/api/%61dmin/x",
    "/api/admi%6e",
    "/api/public/../admin/x",
    "/api/./admin/x",
    "/api\\admin\\x",
    "/api/admin\\x",
    "api/admin/x",
    "",
    "?/api/admin",
    "/api?/admin",
    "/apiXadmin",
    "http://evil.test",
    "http://api/admin",
  ])("does not match %s: a different path, or text that is not decoded", (target) => {
    expect(matches(pattern, target)).toBe(false);
  });
});

describe("matchPath: an exact pattern", () => {
  it("matches the path whatever the letter case, with one trailing slash, and without the query string", () => {
    for (const target of ["/login", "/login/", "/LOGIN", "/Login?next=/account", "/login/?x", "/login#x"]) {
      expect(matches("/login", target), target).toBe(true);
    }
  });

  it("does not match a longer, a shorter or a merely similar path", () => {
    for (const target of ["/login/x", "/loginx", "/logi", "/login//", "/x/login", "/", "/login.php", "/%6cogin"]) {
      expect(matches("/login", target), target).toBe(false);
    }
  });

  it("the pattern / matches the root only", () => {
    expect(matches("/", "/")).toBe(true);
    expect(matches("/", "/?x=1")).toBe(true);
    expect(matches("/", "/x")).toBe(false);
    expect(matches("/", "")).toBe(false);
  });
});

describe("matchPath: * is exactly one segment that is not empty", () => {
  const pattern = "/api/users/*/export";

  it.each([
    "/api/users/42/export",
    "/api/users/42/export/",
    "/API/Users/a.b-c/Export?format=csv",
    "/api/users/../export", // a dot segment is text like any other
    "/api/users/%2F/export",
    "/api/users/*/export",
  ])("matches %s", (target) => {
    expect(matches(pattern, target)).toBe(true);
  });

  it.each([
    "/api/users/export",
    "/api/users//export",
    "/api/users/1/2/export",
    "/api/users/42/export/x",
    "/api/users/42",
    "/api/users/42/exports",
    "/api/users/42/",
  ])("does not match %s", (target) => {
    expect(matches(pattern, target)).toBe(false);
  });

  it("a star alone stands for one segment, never for none and never for two", () => {
    expect(matches("/*", "/x")).toBe(true);
    expect(matches("/*", "/x/")).toBe(true);
    expect(matches("/*", "/")).toBe(false);
    expect(matches("/*", "/x/y")).toBe(false);
    expect(matches("/*/*", "/x/y")).toBe(true);
    expect(matches("/*/*", "/x")).toBe(false);
  });
});

describe("matchPath: a final ** is zero or more segments", () => {
  it("matches the prefix itself and everything below it", () => {
    expect(matches("/files/**", "/files")).toBe(true);
    expect(matches("/files/**", "/files/")).toBe(true);
    expect(matches("/files/**", "/files/a")).toBe(true);
    expect(matches("/files/**", "/files/a/b/c.txt")).toBe(true);
    expect(matches("/files/**", "/filesystem")).toBe(false);
    expect(matches("/files/**", "/file")).toBe(false);
  });

  it("/** matches every path", () => {
    for (const target of ["/", "/x", "/x/y/z", "/?q", "//", "/%00"]) expect(matches("/**", target), target).toBe(true);
    expect(matches("/**", "")).toBe(false);
  });

  it("combines with a star: the star still needs its segment", () => {
    expect(matches("/orgs/*/admin/**", "/orgs/7/admin")).toBe(true);
    expect(matches("/orgs/*/admin/**", "/orgs/7/admin/keys/1")).toBe(true);
    expect(matches("/orgs/*/admin/**", "/orgs/admin")).toBe(false);
    expect(matches("/orgs/*/admin/**", "/orgs//admin/x")).toBe(false);
  });
});

describe("matchPath: literal text", () => {
  it("a dot, a tilde, an underscore and a hyphen stand for themselves", () => {
    expect(matches("/a.b_c~d-e", "/a.b_c~d-e")).toBe(true);
    expect(matches("/a.b_c~d-e", "/A.B_C~D-E")).toBe(true);
    expect(matches("/a.b", "/aXb")).toBe(false); // the dot is not "any character"
    expect(matches("/a.b", "/a/b")).toBe(false);
    expect(matches("/v1.2/*", "/v1.2/x")).toBe(true);
    expect(matches("/v1.2/*", "/v112/x")).toBe(false);
  });

  it("dot segments in a pattern are text, not navigation", () => {
    expect(matches("/a/../b", "/a/../b")).toBe(true);
    expect(matches("/a/../b", "/b")).toBe(false);
    expect(matches("/a/./b", "/a/b")).toBe(false);
  });

  it("only ASCII letters are folded: a look-alike character is a different character", () => {
    expect(matches("/api/k", "/api/K")).toBe(true);
    expect(matches("/api/k", "/api/K")).toBe(false); // KELVIN SIGN lower-cases to k in Unicode
    expect(matches("/api/i", "/api/İ")).toBe(false);
    expect(matches("/api/*", "/api/K")).toBe(true);
  });
});

describe("matchPath: cost", () => {
  it("is linear in the length of the path: 50 patterns against 16,000 characters take a few milliseconds at most", () => {
    const patterns = Array.from({ length: 50 }, (_, i) =>
      compilePattern(i % 2 === 0 ? `/${"*/".repeat(100)}x${i}` : `/${"a/".repeat(100)}**`),
    );
    const long = normalisePath(`/${"a/".repeat(8_000)}`);
    const started = performance.now();
    let matched = 0;
    for (let round = 0; round < 20; round++) {
      const split = splitPath(long); // once per Decision, as decide does
      if (split === null) throw new Error("not a path");
      for (const pattern of patterns) if (pattern !== null && matchSplit(pattern, split)) matched += 1;
    }
    const perDecision = (performance.now() - started) / 20;
    expect(matched).toBe(25 * 20);
    expect(perDecision).toBeLessThan(5);
  });
});

describe("matchMethod", () => {
  it("an empty list is every method", () => {
    for (const method of ["GET", "POST", "PURGE", "M-SEARCH", "UNKNOWN", ""])
      expect(matchMethod([], method)).toBe(true);
  });

  it("otherwise the method must be one of the list, exactly and in upper case", () => {
    expect(matchMethod(["GET", "POST"], "GET")).toBe(true);
    expect(matchMethod(["GET", "POST"], "POST")).toBe(true);
    expect(matchMethod(["GET", "POST"], "DELETE")).toBe(false);
    expect(matchMethod(["GET"], "get")).toBe(false);
    expect(matchMethod(["GET"], "GETX")).toBe(false);
    expect(matchMethod(["GET"], "")).toBe(false);
  });

  it("review F2: HEAD matches a list with GET (Express answers HEAD with the GET handler); nothing else is implied", () => {
    expect(matchMethod(["GET"], "HEAD")).toBe(true);
    expect(matchMethod(["POST", "GET"], "HEAD")).toBe(true);
    expect(matchMethod(["HEAD"], "HEAD")).toBe(true);
    expect(matchMethod(["POST"], "HEAD")).toBe(false);
    expect(matchMethod(["HEAD"], "GET")).toBe(false);
    expect(matchMethod(["GET"], "head")).toBe(false);
    expect(matchMethod(["GET"], "OPTIONS")).toBe(false);
  });
});

describe("normalisePath", () => {
  it.each([
    ["/api/admin", "/api/admin"],
    ["/api/admin/", "/api/admin"],
    ["/api/admin//", "/api/admin/"],
    ["/api/admin?x=1", "/api/admin"],
    ["/api/admin/?x=1&y=/z/", "/api/admin"],
    ["/api/admin#x?y", "/api/admin"],
    ["/api/admin?x#y", "/api/admin"],
    ["/", "/"],
    ["//", "/"],
    ["/?x", "/"],
    ["", ""],
    ["?x", ""],
    ["*", "*"],
    ["http://host.test/api/admin/?x", "/api/admin"],
    ["HTTPS://host.test:8443/a", "/a"],
    ["http://host.test", "/"],
    ["http://host.test?x", "/"],
    ["http://user:pw@host.test/a/b/", "/a/b"],
    ["host.test:443", "host.test:443"],
  ])("%j gives %j", (target, expected) => {
    expect(normalisePath(target)).toBe(expected);
  });
});

describe("canonicalPaths: the forms a later middleware may read", () => {
  it.each([
    ["/a/b", []],
    ["/", []],
    ["/a/b/c.txt", []],
    ["/a//b", ["/a/b"]],
    ["/a/./b", ["/a/b"]],
    ["/a/x/../b", ["/a/b"]],
    ["/a/b/", ["/a/b"]],
    ["/a/%62", ["/a/b"]],
    ["/a/%2E%2e/b", ["/b"]], // hex digits in either case
    ["/a/%2e%2E/b", ["/b"]],
    ["/a%2fb", ["/a/b"]],
    ["/a%2Fb", ["/a/b"]],
    ["/a%5cb", ["/a\\b", "/a/b"]], // a backslash is kept as text in one form and is a separator in the other
    ["/a\\b", ["/a/b"]],
    ["/x/%252e%252e/b", ["/x/%2e%2e/b", "/b"]], // double encoding: each decoding depth is a form of its own
    ["/%25252e%25252e/b", ["/%252e%252e/b", "/%2e%2e/b", "/b"]], // three rounds at most
    ["/%2525252e%2525252e/b", ["/%25252e%25252e/b", "/%252e%252e/b", "/%2e%2e/b"]], // a fourth is not decoded
    ["/../../a", ["/a"]], // never above the root
    ["/a/../../..", ["/"]],
    ["/%2e%2e/%2e%2e/a", ["/a"]],
    ["/a/%zz/b", []], // a malformed sequence is kept as it is
    ["/a/%zz%62", ["/a/%zzb"]],
    ["/a/%", []],
    ["/a/%6", []],
    ["/a/%%62", ["/a/%b"]],
    ["/a/%3f/b", ["/a/?/b"]], // an encoded ? is a character of the path, not a query string
  ])("%j gives %j", (path, expected) => {
    expect(canonicalPaths(path)).toEqual(expected);
  });

  it("gives nothing for text that is not a path, and never throws", () => {
    for (const text of ["", "*", "host.test:443", "%2fa", "a/b"]) expect(canonicalPaths(text), text).toEqual([]);
    expect(() => canonicalPaths("/%ff%fe/%c0%ae%c0%ae/\u0000")).not.toThrow();
  });

  it("decodes byte by byte: a non-ASCII character never becomes a separator or a dot", () => {
    // %c0%ae is an overlong `.`: a decoder that accepts it would see `..`. Shield reads two characters that are not.
    expect(canonicalPaths("/a/%c0%ae%c0%ae/b")).toEqual(["/a/\u00c0\u00ae\u00c0\u00ae/b"]);
  });
});
