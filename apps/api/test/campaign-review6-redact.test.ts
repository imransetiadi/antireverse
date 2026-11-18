import { describe, expect, it } from "vitest";
import { BODY_WITHHELD, evidenceWindow, redactBody, redactHeaders, redactText } from "../src/campaign/redact.ts";

// Slice 15a, sixth independent safety review, F4 and F5 (D-114): characters are classified, and the text is put into
// one form. A control that separates (NEL, VT, FF, FS to US, any other C0 or C1) becomes a line feed or one space — it
// used to be deleted, which glued a secret to the word before it and out of a pattern's reach. Only what has no width
// is deleted: format characters and the default-ignorable code points. Then the whole text is NFKC-normalised, so that
// the engine, the patterns and what is stored read the same characters (fullwidth digits are digits).

const cp = (...codes: number[]) => String.fromCodePoint(...codes);
const NEL = cp(0x85);
const US = cp(0x1f);
const VT = cp(0x0b);
const FF = cp(0x0c);

/** Zero-width and default-ignorable code points: hidden inside a secret, each must be taken out. */
const IGNORABLE: [string, string][] = [
  ["soft hyphen", cp(0xad)],
  ["zero width space", cp(0x200b)],
  ["word joiner", cp(0x2060)],
  ["combining grapheme joiner", cp(0x34f)],
  ["variation selector 16", cp(0xfe0f)],
  ["variation selector 17", cp(0xe0100)],
  ["Mongolian free variation selector", cp(0x180b)],
  ["Khmer vowel inherent AQ", cp(0x17b4)],
  ["Hangul filler", cp(0x3164)],
  ["Hangul choseong filler", cp(0x115f)],
  ["Hangul jungseong filler", cp(0x1160)],
  ["halfwidth Hangul filler", cp(0xffa0)],
  ["tag character", cp(0xe0041)],
  ["byte order mark", cp(0xfeff)],
];
const SECRETS: [string, string[]][] = [
  ["card 4111 1111 1111 1111 end", ["4111 1111 1111 1111", "4111111111111111"]],
  ["db password=hunter2hunter2 end", ["hunter2hunter2"]],
  ["key sk_live_abcdefgh12345678 end", ["abcdefgh12345678"]],
  ["mail jane.doe@acme-shop.io end", ["jane.doe@acme-shop.io"]],
];
const bare = (text: string) => text.replace(/[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point} ]/gu, "");

describe("review6 F4 (D-114): a control that separates stays a separator", () => {
  it("the review's four: a secret after NEL, US or VT is still found by its pattern", () => {
    const cases: [string, string][] = [
      [`token${NEL}Bearer abcdefgh.ijkl~mnop`, "abcdefgh.ijkl~mnop"],
      [`report${US}sk_live_abcdefgh1234`, "sk_live_abcdefgh1234"],
      [`id${VT}ghp_abcdefghijklmnopqrstuvwx`, "ghp_abcdefghijklmnopqrstuvwx"],
      [`n${NEL}bcn_aaaaaaaaaaaaaaaaaaaaaaaa`, "bcn_aaaaaaaaaaaaaaaaaaaaaaaa"],
    ];
    for (const [text, secret] of cases) {
      for (const stored of [redactText(text), evidenceWindow(text), redactBody(Buffer.from(text))]) {
        expect(stored, JSON.stringify(text)).not.toContain(secret);
      }
    }
  });

  it("NEL is a line break; every other control but tab and line feed is one space", () => {
    expect(redactText(`a${NEL}b`)).toBe("a\nb");
    expect(redactText(`a${VT}b${FF}c${US}d${cp(0x1c)}e${cp(0x1b)}f${cp(0x7f)}g${cp(0x9f)}h${cp(0x01)}i`)).toBe(
      "a b c d e f g h i",
    );
    expect(redactText("a\tb\r\nc\rd")).toBe("a\tb\nc\nd");
    expect(redactText(`a${cp(0x2028)}b${cp(0x2029)}c`)).toBe("a\nb\nc");
  });

  it("kept headers: such a control is one space there too, and hides nothing", () => {
    const kept = redactHeaders(
      { server: `nginx${US}sk_live_abcdefgh1234`, "x-powered-by": `PHP${NEL}Bearer abcdefgh.ijkl~mnop` },
      "shop.acme-shop.io",
    );
    expect(JSON.stringify(kept)).not.toMatch(/abcdefgh1234|ijkl~mnop/);
    expect(kept.server?.startsWith("nginx ")).toBe(true);
  });
});

describe("review6 F5 (D-114): what has no width is deleted, and the text has one form", () => {
  it("each default-ignorable code point hidden inside a card number, a password, a key and an address", () => {
    const leaks: string[] = [];
    let cases = 0;
    for (const [label, hider] of IGNORABLE) {
      for (const [text, secrets] of SECRETS) {
        for (let at = 6; at < text.length - 4; at++) {
          cases++;
          const hidden = `${text.slice(0, at)}${hider}${text.slice(at)}`;
          for (const stored of [evidenceWindow(hidden), redactBody(Buffer.from(hidden))]) {
            for (const secret of secrets) {
              if (bare(stored).includes(bare(secret))) leaks.push(`${label} at ${at}: ${JSON.stringify(stored)}`);
            }
          }
        }
      }
    }
    expect(cases).toBeGreaterThan(1000);
    expect(leaks.slice(0, 10)).toEqual([]);
  });

  it("fullwidth digits, letters and signs are their ASCII forms before the patterns run", () => {
    const fullwidth = (text: string) =>
      [...text].map((c) => (c >= "!" && c <= "~" ? cp((c.codePointAt(0) as number) + 0xfee0) : c)).join("");
    expect(redactText(`card ${fullwidth("4111 1111 1111 1111")} end`)).toBe("card [redacted-number] end");
    expect(redactText(`key ${fullwidth("sk_live_abcdefgh12345678")}`)).not.toContain("abcdefgh12345678");
    expect(redactText(fullwidth("password=hunter2hunter2"))).not.toContain("hunter2");
    expect(redactText(`mail jane.doe${cp(0xff20)}acme-shop.io`)).toBe("mail [redacted-email]");
    // One form for all three readers: the engine's body is the normalised text.
    expect(redactBody(Buffer.from(fullwidth("plain words")))).toBe("plain words");
    expect(redactBody(Buffer.from(`e${cp(0x301)} ${cp(0xfb01)}`))).toBe(`${cp(0xe9)} fi`);
  });

  it("is a fixed point: cleaning what was cleaned, storing what was stored, changes nothing", () => {
    let state = 0x6e;
    const next = (): number => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state;
    };
    const PIECES = [
      ...SECRETS.map(([text]) => text),
      ...IGNORABLE.map(([, hider]) => hider),
      NEL,
      US,
      VT,
      FF,
      cp(0x1b),
      cp(0x7f),
      cp(0x9f),
      cp(0x2028),
      "\r\n",
      "\r",
      "\n",
      "\t",
      " ",
      cp(0xff14),
      cp(0xff11),
      cp(0xff20),
      cp(0xfb01),
      cp(0x2460),
      cp(0x1e9b, 0x323),
      cp(0x3a9),
      cp(0x212b),
      cp(0xfdfa),
      cp(0x33a8),
      "=",
      ":",
      '"',
      "[",
      "]",
      "password",
      "token",
      "Bearer ",
      "sk_live_",
      "x".repeat(50),
    ];
    const unstable: string[] = [];
    for (let i = 0; i < 6000; i++) {
      let text = "";
      for (let n = 1 + (next() % 10); n > 0; n--) text += PIECES[next() % PIECES.length];
      const once = redactText(text);
      if (redactText(once) !== once) unstable.push(`text ${JSON.stringify(text)}`);
      const window = evidenceWindow(text);
      if (evidenceWindow(window) !== window) unstable.push(`window ${JSON.stringify(text)}`);
      if (window !== window.normalize("NFKC")) unstable.push(`not NFKC ${JSON.stringify(window)}`);
      const header = redactHeaders({ server: text }, "h.io").server ?? "";
      if ((redactHeaders({ server: header }, "h.io").server ?? "") !== header)
        unstable.push(`header ${JSON.stringify(text)}`);
    }
    expect(unstable.slice(0, 10)).toEqual([]);
  });

  it("documented limit: a Braille blank and an ordinary combining mark are text, and still split a pattern", () => {
    // U+2800 shows as nothing and is neither a control, a format character nor default-ignorable; a combining mark
    // is part of a letter. Taking either out would be a guess about what a text means (15b).
    expect(redactText(`sk_live_abcd${cp(0x2800)}efgh12345678`)).toContain("efgh12345678");
    expect(redactText(`sk_live_abcd${cp(0x301)}efgh12345678`)).toContain("efgh12345678");
  });
});

describe("review6 I1: the six-pass cap is reachable, and fails closed", () => {
  it("texts that keep changing for six passes are withheld whole, not handed on half-redacted", () => {
    const first = `${`bcn_${"a".repeat(64)}pwd=${"x".repeat(1024)}`}`.repeat(5);
    const second = "cookie: a=b;".repeat(Math.floor(65_536 / 12));
    for (const text of [first, second]) {
      const out = redactText(text);
      // Either it settled, or it is withheld: never a text that a further pass would still change.
      expect(redactText(out)).toBe(out);
    }
    expect([redactText(first), redactText(second)]).toContain(BODY_WITHHELD);
    // And the body of a response that does not settle is withheld like any body that cannot be read.
    expect([redactBody(Buffer.from(first)), redactBody(Buffer.from(second))]).toContain(BODY_WITHHELD);
  });
});
