import { STAND_IN_CATALOG } from "@antireverse/prove";
import { describe, expect, it } from "vitest";
import { BODY_WITHHELD, evidenceWindow, redactBody, redactText } from "../src/campaign/redact.ts";

// Slice 15a, second independent safety review: secrets that must not survive redaction (M1 nested assignments, M2
// escaped quotes, L1 further shapes), digits that must survive it (L8), and its cost on hostile 64 KB bodies. Each
// case: [label, input, secret substrings].
const CASES: [string, string, string[]][] = [
  ["swallowed: URL with a scheme", "Reset link: https://shop.test/reset?token=abc123def", ["abc123def"]],
  ["swallowed: href attribute", `<a href="/reset?token=abc123def&u=7">reset</a>`, ["abc123def"]],
  ["swallowed: JSON url member", `{"next":"https://shop.test/cb?access_token=abc123def"}`, ["abc123def"]],
  ["swallowed: JSON string of k=v", `{"config":"db_password=hunter2;user=app"}`, ["hunter2"]],
  ["swallowed: Location-like line", "Location: /login?session=abc123def", ["abc123def"]],
  ["swallowed: log line", "msg=login password=hunter2", ["hunter2"]],
  ["swallowed: chained", "debug:password=hunter2", ["hunter2"]],
  ["swallowed: form action", `<form action="/pay?api_key=abc123def">`, ["abc123def"]],
  ["swallowed: time prefix", "12:00:01 password=hunter2", ["hunter2"]],
  ["JSON escaped quote", String.raw`{"password":"a\"b c-hunter2"}`, ["hunter2"]],
  ["JSON escaped quote 2", String.raw`{"api_key":"abc\"DEFGHIJ-topsecret"}`, ["topsecret"]],
  ["single-quoted with escape", String.raw`password = 'it\'s-hunter2'`, ["hunter2"]],
  ["single quoted", `password='hunter2 x'`, ["hunter2"]],
  ["YAML bare", "password: hunter2", ["hunter2"]],
  ["YAML bare with spaces", "password: correct horse battery", ["horse", "battery"]],
  ["URL query", "https://x.test/cb?token=abc123def&next=1", ["abc123def"]],
  ["URL query access_token last", "GET /cb?access_token=abc123def", ["abc123def"]],
  ["Basic", "Authorization: Basic dXNlcjpwYXNzd29yZA==", ["dXNlcjpwYXNzd29yZA"]],
  ["Basic short", "Authorization: Basic YTpi", ["YTpi"]],
  ["Authorization Token scheme", "Authorization: Token 9944b09199c62bcf", ["9944b09199c62bcf"]],
  ["Authorization Digest", 'Authorization: Digest username="bob", response="6629fae49393a053"', ["6629fae49393a053"]],
  ["Proxy-Authorization ApiKey", "Authorization: ApiKey hunter2hunter2", ["hunter2hunter2"]],
  ["PEM", "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\ndef\n-----END RSA PRIVATE KEY-----", ["MIIEabc", "def"]],
  [
    "PEM in JSON",
    String.raw`{"k":"-----BEGIN PRIVATE KEY-----\nMIIEabc\ndefg\n-----END PRIVATE KEY-----\n"}`,
    ["MIIEabc", "defg"],
  ],
  [
    "PGP block",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\nabcd=\n-----END PGP PRIVATE KEY BLOCK-----",
    ["lQOYBF"],
  ],
  ["AWS id", "aws_access_key_id AKIAIOSFODNN7EXAMPLE", ["AKIAIOSFODNN7EXAMPLE"]],
  ["AWS id glued", "idAKIAIOSFODNN7EXAMPLE", ["AKIAIOSFODNN7EXAMPLE"]],
  ["GitHub", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", ["ghp_abcdefghij"]],
  [
    "GitHub fine-grained",
    "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij",
    ["mnopqrstuvwxyz"],
  ],
  ["Slack", "xoxb-1234567890-abcdefghij", ["1234567890-abcdefghij"]],
  ["Stripe", "sk_live_abcdefgh12345678", ["abcdefgh12345678"]],
  [
    "JWT",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ["eyJzdWIiOiIx", "dozjgNryP4J3"],
  ],
  [
    "JWT split by line breaks",
    "eyJhbGciOiJIUzI1NiJ9.\neyJzdWIiOiIxMjM0NTY3ODkwIn0.\ndozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ["eyJzdWIiOiIx", "dozjgNryP4J3"],
  ],
  ["JWT short payload", "eyJhbGciOiJIUzI1NiJ9.e30.abcdefghijklmnop", ["abcdefghijklmnop"]],
  ["conn string", "DATABASE_URL=postgres://app:hunter2@db.internal.example.com:5432/app", ["hunter2"]],
  ["conn string localhost", "postgres://app:hunter2@localhost:5432/app", ["hunter2"]],
  ["conn string in JSON", `{"dsn":"mysql://root:hunter2@db/app"}`, ["hunter2"]],
  ["card mixed separators", "4111 1111-1111.1111", ["1111-1111"]],
  ["card double space", "4111  1111  1111  1111", ["1111  1111  1111"]],
  ["card slash", "4111/1111/1111/1111", ["1111/1111/1111"]],
  ["card nbsp", "4111 1111 1111 1111", ["1111 1111"]],
  ["card tabs", "4111\t1111\t1111\t1111", ["1111\t1111"]],
  ["card JSON number", `{"card":4111111111111111}`, ["4111111111111111"]],
  ["card JSON digits array", `[4,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]`, ["1,1,1,1,1,1,1,1,1,1,1,1"]],
  ["card with underscore", "4111_1111_1111_1111", ["1111_1111_1111"]],
  ["email plus", "bob+tag@example.com", ["bob", "example.com"]],
  ["email unicode local", "josé@example.com", ["example.com"]],
  ["email unicode local 2", "müller@example.com", ["mü", "example.com"]],
  ["email idn", "bob@exämple.com", ["bob@"]],
  ["email entity", "bob&#64;example.com", ["bob&#64;example.com"]],
  ["email in text", "bob@example.com", ["example.com"]],
  ["PHP arrow", `'password' => 'hunter2'`, ["hunter2"]],
  ["XML element", "<password>hunter2</password>", ["hunter2"]],
  ["HTML input", `<input type="hidden" name="csrf_token" value="hunter2hunter2">`, ["hunter2hunter2"]],
  ["env DB_PASS", "DB_PASS=hunter2", ["hunter2"]],
  ["env SMTP_PASS json", `{"smtp_pass":"hunter2"}`, ["hunter2"]],
  ["cookie in body", "Cookie: sid=hunter2hunter2; theme=dark", ["hunter2hunter2"]],
  ["set-cookie in body", "Set-Cookie: connect.sid=hunter2hunter2; Path=/", ["hunter2hunter2"]],
  ["name/value JSON", `{"name":"password","value":"hunter2"}`, ["hunter2"]],
  ["password then newline value", `"password":\n  "hunter2"`, ["hunter2"]],
  ["password spaced wide", `password          =          hunter2`, ["hunter2"]],
  ["python repr", `{'secret': b'hunter2'}`, ["hunter2"]],
  ["url-encoded form", "user=a&password=hunter2&x=1", ["hunter2"]],
  ["key=", "encryption_key=hunter2hunter2", ["hunter2hunter2"]],
  [
    "Authorization in JSON keeps the rest",
    `{"authorization":"Token 9944b09199c62bcf","ok":true}`,
    ["9944b09199c62bcf"],
  ],
  ["XML with attributes", `<db:password type="x">hunter2</db:password>`, ["hunter2"]],
  ["name/value single quotes", `<input name='session_token' value='hunter2hunter2'>`, ["hunter2hunter2"]],
  ["python bytes double", `{"secret": b"hunter2"}`, ["hunter2"]],
  ["passwd", "passwd=hunter2", ["hunter2"]],
  ["pwd json", `{"pwd":"hunter2"}`, ["hunter2"]],
  ["private_key", "private_key: hunter2hunter2", ["hunter2hunter2"]],
  ["xsrf", "XSRF-TOKEN=hunter2hunter2", ["hunter2hunter2"]],
  ["sid", "sid=hunter2hunter2&x=1", ["hunter2hunter2"]],
  ["auth", `{"auth":"hunter2"}`, ["hunter2"]],
  ["card comma separated", "4111,1111,1111,1111", ["1111,1111,1111"]],
  ["email hex entity", "bob&#x40;example.com", ["bob&#x40;example.com"]],
];

describe("review2 15a: redaction leaks", () => {
  for (const [label, input, secrets] of CASES) {
    it(label, () => {
      const out = redactText(input);
      for (const secret of secrets)
        expect(out, `${JSON.stringify(input)} -> ${JSON.stringify(out)}`).not.toContain(secret);
      expect(redactText(out), "stable").toBe(out);
    });
  }
});

describe("review2 15a: redaction cost on hostile 64 KB bodies", () => {
  const N = 65_536;
  const fill = (unit: string) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const BODIES: [string, string][] = [
    ["a", fill("a")],
    ["@", fill("@")],
    ["a@", fill("a@")],
    ["%40", fill("%40")],
    ["eyJ", fill("eyJ")],
    ["eyJ dotted", fill("eyJaaaaa.")],
    ["eyJ 2k", fill(`eyJ${"a".repeat(2048)}!`)],
    ["eyJ a.b no third", fill(`eyJ${"a".repeat(2000)}.${"b".repeat(4096)}!`)],
    ["pem begin", fill("-----BEGIN PRIVATE KEY-----")],
    ["pem begin partial", fill("-----BEGIN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
    [
      "pem end partial",
      `-----BEGIN PRIVATE KEY-----${fill("-----END AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA PRIVATE KEY----")}`,
    ],
    ["assign dq open", fill(`a="${";".repeat(511)}\n`)],
    ["assign dq many", fill(`a=";`)],
    ["assign sq/dq", fill(`a="b='`)],
    ["assign ws", fill(`a        `)],
    ["assign ws2", fill(`a"        :        `)],
    ["assign names", fill(`${"a".repeat(64)}-`)],
    ["assign secret names", fill(`token=`)],
    ["assign colon", fill(`a:`)],
    ["assign =", fill(`=`)],
    ["bearer", fill("Bearer ")],
    ["bearer ws", fill("Bearer        ")],
    ["basic x", fill("Basic aaaaaaa ")],
    ["digits", fill("4")],
    ["digits sep", fill("4 ")],
    ["digits luhn0", fill("0")],
    ["digits mix", fill("4111-1111.1111 1111")],
    ["candidate", fill("aB3/")],
    ["hex", fill("0123456789abcdef")],
    ["AKIA", fill("AKIA")],
    ["sk_live_", fill("sk_live_")],
    ["xox", fill("xoxb-")],
    ["aro_", fill("aro_")],
    ["newlines", fill("\n")],
    ["quotes", fill(`"`)],
    ["sq", fill(`'`)],
    ["mixed", fill(`"a":"`)],
    ["a=' long", fill(`a='${"x".repeat(520)}`)],
    ['a=" long', fill(`;a="${" ".repeat(520)}`)],
  ];
  for (const [label, body] of BODIES) {
    it(`${label}: under 250 ms`, () => {
      const started = performance.now();
      redactBody(Buffer.from(body));
      expect(performance.now() - started).toBeLessThan(250);
    });
  }
});

describe("review2 15a: bodies that are not text", () => {
  it("withholds UTF-16 and UTF-32 without a BOM, and a body with one NUL", () => {
    for (const body of [
      Buffer.from("password=hunter2", "utf16le"),
      Buffer.from("password=hunter2", "utf16le").swap16(),
      Buffer.from("p\0\0\0a\0\0\0s\0\0\0s\0\0\0", "latin1"),
      Buffer.from("fine text\0"),
    ])
      expect(redactBody(body)).toBe(BODY_WITHHELD);
    expect(evidenceWindow(BODY_WITHHELD)).toBe(BODY_WITHHELD);
  });
  it("an excerpt never holds a lone surrogate or a control character, wherever it is cut", () => {
    const body = `${"a".repeat(255)}${"\u{1F600}".repeat(3000)}\u0001\u0085`;
    // Third review (D-107): the excerpt is the evidence window, at most 200 characters, cut by a check anywhere.
    for (let at = 0; at < 600; at++) {
      const excerpt = evidenceWindow(body.slice(at, at + 200));
      expect(excerpt.length).toBeLessThanOrEqual(200);
      expect(excerpt.isWellFormed()).toBe(true);
    }
    const tail = evidenceWindow(body.slice(-150));
    expect(tail.isWellFormed()).toBe(true);
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the absence of control characters is the point.
    expect(tail).not.toMatch(/[\u0001\u0085]/);
  });
  it("L8: few random 16-digit numbers that are not cards are replaced (the Luhn chance, one in ten)", () => {
    let seed = 42;
    const next = () => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed / 2147483648;
    };
    let replaced = 0;
    for (let i = 0; i < 2000; i++) {
      const digits = Array.from({ length: 16 }, () => Math.floor(next() * 10)).join("");
      if (redactText(`order ${digits}`) !== `order ${digits}`) replaced++;
    }
    expect(replaced).toBeLessThan(400);
  });

  it("L8: a log line with a date, a time, an address and sizes survives, and so do timestamps and versions", () => {
    for (const line of [
      "2026-11-16 10:00:01.123 203.0.113.10 200 1532",
      "2026-11-16T10:00:01.123Z GET /api/orders/1001 200 1532 12ms",
      "[16/Nov/2026:10:00:01 +0000] 203.0.113.10 - - 200 1532 0.012",
      "v1.2.3 build 20261116.1 rows 52, 8, 30 at 1763287201",
      "1763287201123 1763287201124 1763287201125",
      "Content-Length: 1532; max-age=63072000",
    ]) {
      expect(redactText(line)).toBe(line);
    }
  });

  it("L8: card numbers are still caught, alone or inside a longer run of digits", () => {
    for (const [text, card] of [
      ["card 4111 1111 1111 1111", "4111 1111 1111 1111"],
      ["order 1001 4111 1111 1111 1111 paid", "4111 1111 1111 1111"],
      ["2026-11-15 4111-1111-1111-1111", "4111-1111-1111-1111"],
      ["card 4111.1111.1111.1111", "4111.1111.1111.1111"],
      ["amex 378282246310005", "378282246310005"],
      ["2026-11-16 10 5500 0000 0000 0004 ok", "5500 0000 0000 0004"],
      ["id 77 6011000990139424 x", "6011000990139424"],
    ] as const) {
      expect(redactText(text)).not.toContain(card);
      expect(redactText(text)).toContain("[redacted-number]");
    }
  });
});

describe("review2 15a: the stand-in's detectors on hostile bodies", () => {
  const N = 65_536;
  const fill = (unit: string) => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const BODIES = [
    fill("\n at "),
    fill("\n    at a ("),
    fill(`\n at ${"a".repeat(200)} (${"a:1".repeat(133)}`),
    fill("\n \t \t at x (a:1:"),
    fill(`\n at x (${":1".repeat(200)}`),
    fill("\n at x (a:1:1"),
    fill('"reports'),
    fill('"><airverse-probe-marke'),
  ];
  it("each detector answers within 250 ms", () => {
    let worst = 0;
    for (const body of BODIES) {
      for (const check of STAND_IN_CATALOG) {
        for (const status of [200, 302, 500]) {
          const started = performance.now();
          check.detect({
            ok: true,
            seq: 1,
            status,
            headers: {},
            body,
            truncated: false,
            location: "other-host",
            withheld: false,
          });
          worst = Math.max(worst, performance.now() - started);
        }
      }
    }
    expect(worst).toBeLessThan(250);
  });
});
