import { describe, expect, it } from "vitest";
import { BODY_WITHHELD, evidenceWindow, redactBody, redactHeaders, redactText } from "../src/campaign/redact.ts";

// Slice 15a, fifth independent safety review, 2: characters that are not text — a soft hyphen, a zero-width space, a
// word joiner, a C1 control — were turned into spaces AFTER the patterns had run, so they hid a secret from the
// patterns and then vanished from what was stored. They are taken out first now: the engine never sees the hidden
// form, and what is stored is a fixed point of the whole cleaning.

const SHY = "\u00ad";
const ZWSP = "\u200b";
const WJ = "\u2060";
const NEL = "\u0085";
// Sixth review (D-114): a control (NEL, ESC, DEL, a C1) separates and becomes a line feed or a space; it is no longer
// in this list of characters that are deleted from inside a word.
const HIDERS = [SHY, ZWSP, WJ, "\u200d", "\ufeff", "\u202e", "\u034f", "\ufe0f"];

/** Secret fixtures of the earlier reviews: [text, what must not survive]. */
const SECRETS: [string, string[]][] = [
  ['{"card":"4111 1111 1111 1111"}', ["4111 1111 1111 1111", "4111111111111111"]],
  ["Authorization: Bearer AbCdEfGh.IjKlMnOp-12345678", ["AbCdEfGh.IjKlMnOp-12345678", "IjKlMnOp"]],
  ["db_password = hunter2-is-the-root-password", ["hunter2"]],
  ["token=abc123def456ghi789", ["abc123def456ghi789"]],
  ["mail jane.doe@acme-shop.io now", ["jane.doe@acme-shop.io", "jane.doe"]],
  ["key sk_live_abcdefgh12345678 end", ["abcdefgh12345678"]],
  ['{"password":"correct horse battery"}', ["horse", "battery"]],
  ["postgres://app:s3cretpw@db.internal:5432/shop", ["s3cretpw"]],
  ["id eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", ["dozjgNryP4J3"]],
];

const strip = (text: string) => text.replace(/[\p{Cc}\p{Cf}\u2028\u2029 ]/gu, "");

describe("review5 2: characters that are not text are taken out before the patterns run", () => {
  it("the review's three: a hidden card number, bearer token and password are not stored", () => {
    const hidden = [
      `{"card":"4111${SHY}1111${ZWSP}1111${WJ}1111"}`,
      `Authorization: Bea${SHY}rer AbCdEfGh.IjKlMnOp-12345678`,
      `db_pass${WJ}word = hunter2-is-the-root-password`,
      `db_pass${ZWSP}word = hunter2-is-the-root-password`,
    ];
    for (const text of hidden) {
      for (const stored of [evidenceWindow(text), redactBody(Buffer.from(text)), redactText(text)]) {
        expect(stored, JSON.stringify(text)).not.toMatch(/4111|AbCdEfGh|hunter2/);
        expect(strip(stored)).not.toMatch(/4111111111111111|hunter2/);
      }
    }
  });

  it("a kept header: a C1 control or a soft hyphen (single bytes of a header value) hides nothing", () => {
    const kept = redactHeaders(
      {
        server: `nginx to${SHY}ken=hunter2hunter2`,
        "x-powered-by": `PHP sk_${WJ}live_abcdefgh12345678`,
        "cache-control": `private, pass${WJ}word=hunter2`,
      },
      "shop.acme-shop.io",
    );
    expect(strip(JSON.stringify(kept))).not.toMatch(/hunter2|abcdefgh12345678/);
  });

  it("property: one of these characters at any position of a secret fixture never lets the secret through", () => {
    const leaks: string[] = [];
    let cases = 0;
    for (const [text, secrets] of SECRETS) {
      for (const hider of HIDERS) {
        for (let at = 1; at < text.length; at++) {
          cases++;
          const hidden = `${text.slice(0, at)}${hider}${text.slice(at)}`;
          for (const stored of [evidenceWindow(hidden), redactBody(Buffer.from(hidden))]) {
            const bare = strip(stored);
            for (const secret of secrets) {
              if (bare.includes(strip(secret))) leaks.push(`${JSON.stringify(hidden)} -> ${JSON.stringify(stored)}`);
            }
          }
        }
      }
    }
    expect(cases).toBeGreaterThan(2500);
    expect(leaks.slice(0, 10)).toEqual([]);
  });

  it("the engine sees the cleaned body: what it cuts a window from is what the gate holds", () => {
    const body = redactBody(Buffer.from(`Error: bo${SHY}om\r\n    at handler (/srv/app.js:1:1)${NEL}next\u001b[31m`));
    // CR LF is one line break; the soft hyphen is gone.
    // Sixth review (D-114): a control that separates is one space, NEL a line break; only what has no width goes.
    expect(body).toBe("Error: boom\n    at handler (/srv/app.js:1:1)\nnext [31m");
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the absence of control characters is the point.
    expect(body).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
    expect(evidenceWindow(body)).toBe(body);
  });
});

describe("review5 2: what is stored is a fixed point", () => {
  const inputs = function* (): Generator<string> {
    let state = 0x5eed;
    const next = (): number => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state;
    };
    const PIECES = [
      ...SECRETS.map(([text]) => text),
      ...HIDERS,
      "\r\n",
      "\r",
      "\n",
      "\t",
      " ",
      "=",
      ":",
      '"',
      "'",
      "[",
      "]",
      "{",
      "}",
      ";",
      "&",
      "@",
      "\u2028",
      "\u2029",
      "[redacted-secret]",
      "[redacted-number]",
      "[redacted",
      "password",
      "token",
      "x".repeat(60),
      "😀",
      "é",
    ];
    for (let i = 0; i < 6000; i++) {
      let text = "";
      for (let n = 1 + (next() % 10); n > 0; n--) text += PIECES[next() % PIECES.length];
      yield text;
    }
    for (const [text] of SECRETS) for (const hider of HIDERS) yield `${text}${hider}`.repeat(4);
  };

  it("evidenceWindow(evidenceWindow(x)) === evidenceWindow(x), and it is at most 200 characters", () => {
    const unstable: string[] = [];
    for (const input of inputs()) {
      const once = evidenceWindow(input);
      expect(once.length).toBeLessThanOrEqual(200);
      expect(once.isWellFormed()).toBe(true);
      if (evidenceWindow(once) !== once) unstable.push(`${JSON.stringify(input)} -> ${JSON.stringify(once)}`);
    }
    expect(unstable.slice(0, 10)).toEqual([]);
  });

  it("a kept header is a fixed point too: keeping it again changes nothing", () => {
    const unstable: string[] = [];
    for (const input of inputs()) {
      const once = redactHeaders({ server: input }, "shop.acme-shop.io").server ?? "";
      expect(once.length).toBeLessThanOrEqual(256);
      const twice = redactHeaders({ server: once }, "shop.acme-shop.io").server ?? "";
      if (twice !== once)
        unstable.push(`${JSON.stringify(input)} -> ${JSON.stringify(once)} -> ${JSON.stringify(twice)}`);
    }
    expect(unstable.slice(0, 10)).toEqual([]);
  });

  it("redactText is still idempotent, with these characters in the text", () => {
    const unstable: string[] = [];
    for (const input of inputs()) {
      const once = redactText(input);
      if (redactText(once) !== once) unstable.push(JSON.stringify(input));
    }
    expect(unstable.slice(0, 10)).toEqual([]);
  });
});

describe("review5: a Content-Type with empty parameters is read", () => {
  const read = (contentType: string) => redactBody(Buffer.from("plain text"), { contentType });
  it("a trailing semicolon and empty parameters are allowed by the grammar (RFC 9110)", () => {
    for (const type of [
      "text/html; charset=utf-8;",
      "text/html;charset=utf-8; ",
      "text/html;; charset=utf-8",
      "text/html; ; charset=UTF-8 ;;",
      "text/html;",
    ]) {
      expect(read(type), type).toBe("plain text");
    }
    // Still withheld: anything that is not a parameter, and any other charset.
    for (const type of [
      "text/html; charset=utf-7;",
      "text/html; charset=utf-8; charset",
      "text/html; charset=utf-8;x",
    ]) {
      expect(read(type), type).toBe(BODY_WITHHELD);
    }
  });
});
