import { CAMPAIGN_LIMITS } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { BODY_WITHHELD, evidenceWindow, HEADER_PRESENT, redactHeaders, redactText } from "../src/campaign/redact.ts";

// Slice 15a, third independent safety review, F5 (D-107). The pattern catalogue is not grown: what is kept of a body
// is a window of at most 200 characters, and the redactor that still runs over it is idempotent — redacting what was
// redacted changes nothing, whatever the input. The property is run over the review's samples (shapes the redactor
// misses included: idempotence holds for them too), fixtures of the earlier reviews, their combinations, and every
// window cut from them.

/** The review's samples: secret shapes that passed redaction, and its second-pass repro. */
const REVIEW3: string[] = [
  "define('DB_PASSWORD', 'hunter2');",
  "user[password]=hunter2",
  '<add key="Password" value="hunter2" />',
  '<input type="password" id="pw" value="hunter2">',
  String.raw`{"body":"{\"password\":\"hunter2\"}"}`,
  "%7B%22password%22%3A%22hunter2%22%7D",
  '"secret": {\n "value": "hunter2"\n}',
  '"passwords": ["hunter2","hunter3"]',
  '"passwords": [redacted-secret], "hunter3"]',
  '"passwords": [redacted-secret]], "hunter3"]',
];

/** Fixtures of the first and second reviews (copied: a test file is not imported). */
const EARLIER: string[] = [
  "Reset link: https://shop.test/reset?token=abc123def",
  `<a href="/reset?token=abc123def&u=7">reset</a>`,
  `{"next":"https://shop.test/cb?access_token=abc123def"}`,
  `{"config":"db_password=hunter2;user=app"}`,
  "Location: /login?session=abc123def",
  "msg=login password=hunter2",
  "debug:password=hunter2",
  "12:00:01 password=hunter2",
  String.raw`{"password":"a\"b c-hunter2"}`,
  String.raw`password = 'it\'s-hunter2'`,
  "password: correct horse battery",
  "https://x.test/cb?token=abc123def&next=1",
  "Authorization: Basic dXNlcjpwYXNzd29yZA==",
  "Authorization: Token 9944b09199c62bcf",
  'Authorization: Digest username="bob", response="6629fae49393a053"',
  "Cookie: sid=abc123; theme=dark; token=xyz",
  "Set-Cookie: session=abcdef0123456789; HttpOnly",
  "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\ndef\n-----END RSA PRIVATE KEY-----",
  "-----BEGIN PRIVATE KEY-----\nMIIEabc never ends",
  "aws_access_key_id AKIAIOSFODNN7EXAMPLE",
  "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
  "xoxb-1234567890-abcdefghij",
  "sk_live_abcdefgh12345678",
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  "postgres://app:s3cretpw@db.internal:5432/shop",
  "mail jane.doe@acme-shop.io or bob%40acme-shop.io",
  "card 4242 4242 4242 4242 exp 12/29, order 20261116100000123",
  "id 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  '<input name="csrf_token" type="hidden" value="abcDEF123456">',
  "<password>hunter2</password><api:token x='1'>abc</api:token>",
  'api_key => "abc123def456", secret=>bare-value',
  "password=b'hunter2 bytes'",
  "Bearer abcdefgh.ijklmnop",
  "token=[redacted-secret]",
  "token: [redacted-token] and key=[redacted-key]",
  "password=[redacted",
  "[redacted-secret]=[redacted-secret]",
  "secret=[[redacted-secret]]",
  'x "password": [redacted-secret]}',
  "[binary or non-UTF-8 body withheld]",
];

const JOINERS = [" ", "\n", ", ", "&", ";", '"', "'", "]", "[", "=", ": ", "}{"];

function* inputs(): Generator<string> {
  const all = [...REVIEW3, ...EARLIER];
  yield* all;
  // Each sample after and before each other one, through every joiner: values that run into the next shape.
  for (const [index, sample] of all.entries()) {
    const other = all[(index * 7 + 3) % all.length] as string;
    for (const joiner of JOINERS) {
      yield `${sample}${joiner}${other}`;
      yield `${joiner}${sample}${joiner}`;
    }
  }
  // Every window of at most 200 characters cut from the samples in a row, as a check may cut it.
  const page = all.join("\n");
  for (let start = 0; start < page.length; start += 7) yield page.slice(start, start + 200);
  for (let start = 0; start < page.length; start += 13) yield page.slice(start, start + 61);
}

describe("review3 F5: redaction is idempotent", () => {
  it("redact(redact(x)) === redact(x), for every sample, combination and window", () => {
    const unstable: string[] = [];
    let count = 0;
    for (const input of inputs()) {
      count++;
      const once = redactText(input);
      const twice = redactText(once);
      if (twice !== once)
        unstable.push(`${JSON.stringify(input)}\n  once:  ${JSON.stringify(once)}\n  twice: ${JSON.stringify(twice)}`);
    }
    expect(count).toBeGreaterThan(1500);
    expect(unstable.slice(0, 10)).toEqual([]);
  });

  it("holds for texts assembled at random from the pieces the patterns are made of", () => {
    const PIECES = [
      "password",
      "token",
      "secret",
      "api_key",
      "Authorization",
      "Cookie",
      "name",
      "value",
      "sid",
      "user",
      "Bearer",
      "Basic",
      "=",
      ":",
      "=>",
      " ",
      " ",
      "\n",
      '"',
      "'",
      "\\",
      "[",
      "]",
      "{",
      "}",
      "<",
      ">",
      "</",
      ",",
      ";",
      "&",
      "@",
      "%40",
      ".",
      "/",
      "://",
      "-----BEGIN PRIVATE KEY-----",
      "-----END PRIVATE KEY-----",
      "eyJhbGciOiJIUzI1NiJ9",
      "hunter2",
      "abc123def456ghi789jkl012mno345",
      "4242 4242 4242 4242",
      "acme-shop.io",
      "jane",
      "b",
      "x",
      "[redacted-secret]",
      "[redacted-token]",
      "[redacted-key]",
      "[redacted-email]",
      "[redacted-number]",
      "[redacted",
      "sk_live_abcdefgh12345678",
      "AKIAIOSFODNN7EXAMPLE",
    ];
    let state = 0x15a3;
    const next = (): number => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state;
    };
    const unstable: string[] = [];
    let withheld = 0;
    for (let i = 0; i < 20_000; i++) {
      let text = "";
      for (let n = 2 + (next() % 12); n > 0; n--) text += PIECES[next() % PIECES.length];
      const once = redactText(text);
      const twice = redactText(once);
      if (twice !== once)
        unstable.push(`${JSON.stringify(text)} -> ${JSON.stringify(once)} -> ${JSON.stringify(twice)}`);
      // None needed the last resort (a text that never settles is withheld whole).
      if (once === BODY_WITHHELD) withheld++;
    }
    expect(unstable.slice(0, 15)).toEqual([]);
    expect(withheld).toBe(0);
  });

  it("the review's repro: a marker's own `]` does not end a value a second time", () => {
    const once = redactText('"passwords": ["hunter2","hunter3"]');
    expect(redactText(once)).toBe(once);
    expect(redactText('"passwords": [redacted-secret], "hunter3"]')).toBe('"passwords": [redacted-secret], "hunter3"]');
    expect(redactText("token=[redacted-secret]&next=1")).toBe("token=[redacted-secret]&next=1");
    expect(redactText("password: [redacted-secret]")).toBe("password: [redacted-secret]");
    // A value that merely starts like a marker is still a value.
    expect(redactText("password=[redacted-hunter2")).toBe("password=[redacted-secret]");
    expect(redactText("password=[hunter2]")).toBe("password=[redacted-secret]");
  });

  it("a third and a fourth pass change nothing either", () => {
    for (const input of [...REVIEW3, ...EARLIER]) {
      const once = redactText(input);
      expect(redactText(redactText(redactText(once)))).toBe(once);
    }
  });

  it("what redaction removed before still goes: the earlier fixtures' secrets do not come back", () => {
    const out = EARLIER.map(redactText).join("\n");
    for (const secret of ["abc123def", "dXNlcjpwYXNzd29yZA", "s3cretpw", "jane.doe", "4242 4242", "MIIEabc"]) {
      expect(out).not.toContain(secret);
    }
  });
});

describe("review3 F5: the evidence window as stored", () => {
  it("is at most 200 characters, redacted, and stable when stored again", () => {
    const unstable: string[] = [];
    for (const input of inputs()) {
      const window = evidenceWindow(input);
      expect(window.length).toBeLessThanOrEqual(CAMPAIGN_LIMITS.evidenceWindowMax);
      if (redactText(input.slice(0, 200)) === input.slice(0, 200) && evidenceWindow(window) !== window) {
        unstable.push(input);
      }
    }
    expect(unstable).toEqual([]);
  });

  it("holds 200 characters when redaction lengthens the text", () => {
    const window = evidenceWindow("a@b.cd ".repeat(28));
    expect(window.length).toBe(200);
    expect(window).not.toContain("a@b.cd");
  });

  it("keeps no control character but a line break and a tab, and no half of a surrogate pair", () => {
    expect(evidenceWindow("a\u0001b\u001fc\u007fd\ne\tf\u0085g")).toBe("a b c d\ne\tf g");
    const cut = evidenceWindow(`${"x".repeat(199)}😀`);
    expect(cut).toBe("x".repeat(199));
    expect(evidenceWindow("\udc00ok\ud83d")).toBe("ok");
    expect(evidenceWindow("😀")).toBe("😀");
  });
});

describe("review3 F5: no header value that can carry a secret is kept", () => {
  it("keeps of a Content-Security-Policy only that it was sent", () => {
    const kept = redactHeaders(
      {
        "content-security-policy":
          "default-src 'self'; script-src 'nonce-4AEemGb0xJptoIGFP3Nd'; report-uri /csp?key=hunter2",
        "content-type": "text/html; charset=utf-8",
      },
      "shop.acme-shop.io",
    );
    expect(kept).toEqual({ "content-security-policy": HEADER_PRESENT, "content-type": "text/html; charset=utf-8" });
    expect(redactHeaders({ "content-security-policy": ["a", "b"] }, "shop.acme-shop.io")).toEqual({
      "content-security-policy": HEADER_PRESENT,
    });
    expect(redactHeaders({}, "shop.acme-shop.io")).toEqual({});
  });

  it("redacts what the other kept headers hold, and keeps each short", () => {
    const kept = redactHeaders(
      {
        server: "nginx token=hunter2hunter2",
        "x-powered-by": "PHP/8.3 sk_live_abcdefgh12345678",
        "cache-control": `private, ${"x".repeat(400)}`,
        "x-request-secret": "never kept",
      },
      "shop.acme-shop.io",
    );
    expect(JSON.stringify(kept)).not.toMatch(/hunter2|abcdefgh12345678|never kept/);
    expect(Object.keys(kept).sort()).toEqual(["cache-control", "server", "x-powered-by"]);
    expect(kept["cache-control"]?.length).toBe(256);
  });
});
