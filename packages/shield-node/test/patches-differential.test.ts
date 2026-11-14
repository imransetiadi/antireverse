// Slice 18f: the body side of the patch matcher was made cheaper (the JSON-escape form is built and scanned only for
// a condition it can change; a long text is first probed for a needle's characters). Nothing it decides may differ.
// The matcher as it was before the slice is kept in test/reference/patches-before-18f.ts; here both run on the same
// requests — hand-written hostile bodies and many generated ones — and must give the same result for every patch,
// with a view shared by the patches of a request (the caches) and with a fresh one. A growth test then checks that
// the changed paths stay linear in the body.
import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import {
  type Condition,
  createPatchChecker,
  matchBody,
  matchPatch,
  type PatchState,
  preparePatch,
  RequestView,
} from "../src/patches.ts";
import type { AppliedPatch, AppliedPolicy } from "../src/policy/store.ts";
import * as before from "./reference/patches-before-18f.ts";

/** A small deterministic PRNG (mulberry32). */
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const body = (op: Condition["op"], value?: string): Condition =>
  value === undefined ? { target: "body", op } : { target: "body", op, value };

/** Needles chosen to meet what an escape can decode to, what a probe can miss, and the edges of each operator. */
const NEEDLES = [
  "__proto__",
  "[__proto__]",
  "__proto__.",
  "<__proto__",
  "constructor",
  "prototype",
  "constructor[prototype]",
  "constructor.prototype",
  "a",
  "A",
  "_",
  ":",
  " ",
  '"',
  "\\",
  "\\u",
  "\\u0041",
  "u0041",
  "0041",
  "%41",
  "%5f",
  "+",
  "é",
  "É",
  "\u00e9x",
  "\ud83d\ude00",
  "\ud83d",
  "\ufffd",
  "\u0000",
  "ab",
  "aa",
  "a:b",
  'a" :',
  "key",
  "k y",
  "abcdefghij", // more distinct characters than are probed
  "zqxjkvbpyg",
  "the quick brown fox",
  "a".repeat(256),
  `${"a".repeat(255)}b`,
  "{",
  "}",
  '{"',
  "]]",
  "x",
];

const CONDITION_SETS: Condition[][] = [
  ...NEEDLES.flatMap((needle) => [
    [body("contains", needle)],
    [body("json_key", needle)],
    [body("equals", needle)],
    [body("starts_with", needle)],
    [body("ends_with", needle)],
  ]),
  [body("present")],
  [body("length_over", "0")],
  [body("length_over", "10")],
  [body("length_over", "4096")],
  // Several conditions on one patch: all must hold.
  [body("json_key", "constructor"), body("json_key", "prototype")],
  [body("contains", "a"), body("contains", "_"), body("json_key", "a")],
  [body("present"), body("contains", "__proto__"), body("length_over", "3")],
  // A condition outside the body in front of the body's.
  [{ target: "header", name: "content-type", op: "contains", value: "json" }, body("json_key", "__proto__")],
  [{ target: "method", op: "equals", value: "POST" }, body("contains", "é")],
  [{ target: "path", op: "starts_with", value: "/api" }, body("ends_with", "}")],
  [{ target: "header", name: "x-absent", op: "present" }, body("contains", "a")],
];

const PATCHES = CONDITION_SETS.map((conditions) => ({
  ours: preparePatch({ conditions }),
  theirs: before.preparePatch({ conditions }),
}));

const CONTENT_TYPES: (string | undefined)[] = [
  undefined,
  "application/json",
  "application/json; charset=utf-8",
  "application/json; charset=",
  "application/x-www-form-urlencoded",
  "text/plain; charset=utf-16le",
  "text/plain; charset=utf-16be",
  "text/plain; charset=utf-16",
  "text/plain; charset=utf-32le",
  "text/plain; charset=utf-32be",
  "text/plain; charset=utf-32",
  "text/plain; charset=latin1",
  "text/plain; charset=iso-8859-1",
  'text/plain; charset="windows-1252"',
  "text/plain; charset=shift_jis", // not understood: every body condition holds (D-062)
  "text/plain; charset=utf-7",
];

function utf16(text: string, big: boolean, mark: boolean): Uint8Array {
  const out = new Uint8Array((text.length + (mark ? 1 : 0)) * 2);
  let at = 0;
  const put = (unit: number): void => {
    out[at++] = big ? unit >> 8 : unit & 0xff;
    out[at++] = big ? unit & 0xff : unit >> 8;
  };
  if (mark) put(0xfeff);
  for (let i = 0; i < text.length; i++) put(text.charCodeAt(i));
  return out;
}

function utf32(text: string, big: boolean, mark: boolean): Uint8Array {
  const points = [...(mark ? "\ufeff" : ""), ...text].map((char) => char.codePointAt(0) as number);
  const out = new Uint8Array(points.length * 4);
  const view = new DataView(out.buffer);
  points.forEach((point, i) => {
    view.setUint32(i * 4, point, !big);
  });
  return out;
}

/** The byte forms a text is sent in: every encoding the matcher reads, with and without a mark, and cut short. */
function bytesOf(text: string): Uint8Array[] {
  const utf8 = new Uint8Array(Buffer.from(text, "utf8"));
  const marked = new Uint8Array(utf8.length + 3);
  marked.set([0xef, 0xbb, 0xbf]);
  marked.set(utf8, 3);
  const forms = [
    utf8,
    marked,
    new Uint8Array(Buffer.from(text, "latin1")),
    utf16(text, false, false),
    utf16(text, false, true),
    utf16(text, true, false),
    utf16(text, true, true),
    utf32(text, false, true),
    utf32(text, true, false),
  ];
  // One byte short: an odd UTF-16 tail, a cut UTF-8 sequence, 1–3 UTF-32 bytes left over.
  if (utf8.length > 1) forms.push(utf8.subarray(0, utf8.length - 1), utf16(text, false, false).subarray(1));
  return forms;
}

/** Long enough that the matcher probes for a needle's characters before it scans (1,024 characters and more). */
const FILLER = "the quick brown fox 0123456789 ".repeat(40);
/** As long, with none of the letters of most needles: probes miss, scans are skipped. */
const BLAND = "0101 2323 4545 ".repeat(90);

const HOSTILE_TEXTS: string[] = [
  "",
  "{}",
  "[]",
  "a",
  "A",
  "_",
  "__proto__",
  '{"__proto__":{"x":1}}',
  '{"__proto__" \t\r\n:{"x":1}}',
  '{"__proto__"x:1}',
  '{"constructor":{"prototype":{"x":1}}}',
  '{"CONSTRUCTOR":{"Prototype":{}}}',
  // The key written with escapes: whole, in part, in either hex case, with the escape's letter in upper case.
  '{"\\u005f\\u005fproto\\u005f\\u005f":1}',
  '{"\\u005F_proto_\\u005F":1}',
  '{"__pr\\u006fto__":1}',
  '{"__PR\\u004FTO__":1}',
  '{"\\U005f_proto__":1}',
  '{"c\\u006fnstructor":{"pr\\u006ftotype":1}}',
  // The quote, the colon and the whitespace of `json_key` written as escapes.
  "{\\u0022__proto__\\u0022:1}",
  '{"__proto__"\\u003a1}',
  '{"__proto__"\\u0020\\u0009\\u000a\\u000d:1}',
  '{"__proto__"\\u0020\\u003a1}',
  '{"__proto__" \\u003a 1}',
  '{"a"\\u003a1,"k y"\\u0020:2}',
  // Escapes that are not escapes, and escapes of escapes.
  "\\u",
  "\\u0",
  "\\u00",
  "\\u004",
  "\\u0041",
  "x\\u0041",
  "\\u0041x",
  "\\u004g",
  "\\u00 41",
  "\\uu0041",
  "\\u\\u0041",
  "\\\\u0041",
  "\\u005cu0041",
  "\\u005c\\u0075\\u0030\\u0030\\u0034\\u0031",
  "\\u0025\\u0034\\u0031",
  "%5cu0041",
  "%5Cu005f%5Cu005fproto__",
  "%5f%5fproto%5f%5f",
  "%5F_proto_%5f=1&a=b",
  "%u005f",
  "%",
  "%4",
  "%zz",
  "a+b",
  "a%2bb",
  // Surrogates: a pair, each half alone, in the wrong order, written raw and as escapes.
  "\\ud83d\\ude00",
  "\\uD83D\\uDE00",
  "\\ud83d",
  "\\ude00\\ud83d",
  "\\ud83dx\\ude00",
  "\ud83d\ude00",
  "\ud83d",
  "x\ude00",
  "\\u0000",
  "\u0000",
  "\\ufffd",
  "\\ufeff__proto__",
  "é",
  "\\u00e9",
  "\\u00E9",
  "\\u00c9",
  "É",
  "\\u00e9x",
  "a\\u00e9\\u00e9\\u00e9a",
  // More distinct decoded characters than the matcher keeps a set of.
  Array.from({ length: 40 }, (_, i) => `\\u00${(0x30 + i).toString(16)}`).join(""),
  Array.from({ length: 40 }, (_, i) => `\\u00${(0x41 + i).toString(16)}`).join("-"),
  `${Array.from({ length: 30 }, (_, i) => `\\u01${(0x10 + i).toString(16)}`).join("")}\\u005f\\u005fproto__`,
  // Equality, prefixes and suffixes around an escape.
  "\\u0061",
  "\\u0061b",
  "a\\u0062",
  '\\u007b"',
  '{"\\u007d',
  "]\\u005d",
  "\\u0061\\u0061",
  `${"a".repeat(255)}\\u0062`,
  `${"a".repeat(255)}b`,
  `${"a".repeat(300)}`,
  // Invalid JSON, duplicate keys, deep nesting.
  '{"a":1,"a":2,"__proto__":3,"__proto__":4',
  '{"a":1,,}',
  '{"a" "b"}',
  "{'__proto__':1}",
  '"__proto__":',
  '"__proto__"',
  '"__proto__" ',
  '"a":"a":"a"',
  `${"[".repeat(5_000)}"__proto__"${"]".repeat(5_000)}`,
  `${'{"a":'.repeat(2_000)}1${"}".repeat(2_000)}`,
  `${'{"\\u0061":'.repeat(2_000)}1${"}".repeat(2_000)}`,
  // Long texts (probed before they are scanned), the needle at the start, in the middle, at the end, absent.
  FILLER,
  BLAND,
  `__proto__${FILLER}`,
  `${FILLER}__proto__`,
  `${FILLER}{"__proto__":1}${FILLER}`,
  `${BLAND}{"__proto__":1}`,
  `${BLAND}{"\\u005f_proto__":1}${BLAND}`,
  `${BLAND}"__proto__"${" ".repeat(2_000)}:`,
  `${BLAND}"__proto__"${" ".repeat(2_000)}\\u003a`,
  `${BLAND}"__proto__"${"\\u0020".repeat(300)}:`,
  `${BLAND}\\u00e9${BLAND}`,
  `${BLAND}\\u0061${BLAND}`,
  `${FILLER}\\u0041`,
  `\\u0041${FILLER}`,
  `${BLAND}%5f%5fproto%5f%5f${BLAND}`,
  `${BLAND}%5cu005f_proto__`,
  `${BLAND}constructor[prototype]`,
  `${BLAND}constructor\\u005bprototype\\u005d`,
  `${BLAND}CONSTRUCTOR.PROTOTYPE${BLAND}`,
  `${BLAND}abcdefghi`, // nine of the ten characters of a needle
  `${BLAND}abcdefghij`,
  `${BLAND}jihgfedcba`,
  `${"a".repeat(4_000)}b`,
  `${"a".repeat(4_000)}\\u0062`,
  `${"\\u0061".repeat(700)}b`,
  `${"é".repeat(2_000)}`,
  `${"\\u".repeat(2_000)}0041`,
  `${"\\".repeat(3_000)}u0041`,
  // Huge strings.
  `{"k":"${"x".repeat(300_000)}"}`,
  `{"k":"${"x".repeat(150_000)}\\u005f\\u005fproto\\u005f\\u005f${"x".repeat(150_000)}"}`,
  `{"k":"${"\\u00e9".repeat(50_000)}","__proto__":1}`,
];

/** Bodies that are not text in any encoding. */
const HOSTILE_BYTES: Uint8Array[] = [
  new Uint8Array([0xff]),
  new Uint8Array([0xff, 0xfe]),
  new Uint8Array([0xfe, 0xff]),
  new Uint8Array([0xff, 0xfe, 0, 0]),
  new Uint8Array([0, 0, 0xfe, 0xff]),
  new Uint8Array([0xef, 0xbb, 0xbf]),
  new Uint8Array([0xc3]),
  new Uint8Array([0xc3, 0x28, 0xa0, 0xa1, 0xe2, 0x28, 0xa1, 0xf0, 0x28, 0x8c, 0xbc]),
  new Uint8Array([0xed, 0xa0, 0x80]), // a surrogate written as UTF-8
  new Uint8Array([0xc0, 0xaf, 0xe0, 0x80, 0xaf]), // overlong forms
  Uint8Array.from({ length: 256 }, (_, i) => i),
  Uint8Array.from({ length: 4_096 }, (_, i) => (i * 131 + 7) & 0xff),
  // `__proto__` with one byte that is not UTF-8 inside and around it.
  new Uint8Array([...Buffer.from('{"__pro'), 0xff, ...Buffer.from('to__":1}')]),
  new Uint8Array([0x80, ...Buffer.from('{"__proto__":1}'), 0xfe]),
  new Uint8Array([...Buffer.from("\\u00"), 0xe9, ...Buffer.from("41\\u0041")]),
];

interface Sample {
  readonly bytes: Uint8Array;
  readonly contentType: string | undefined;
}

const requestOf = (sample: Sample) => ({
  method: "POST",
  path: "/api/items",
  rawPath: "/api/items",
  query: "",
  headers: sample.contentType === undefined ? {} : { "content-type": sample.contentType },
});

let compared = 0;

/**
 * Compares both matchers on one request: every patch through a view shared by all of them (as a request has, with
 * its caches), and a rotating share of the patches through a view of their own (nothing may depend on what an
 * earlier patch asked) — every fourth on a small body, fewer on a large one, which each fresh view decodes again.
 * Returns how many patches matched, for the test's own check of its corpus.
 */
function compare(sample: Sample, label: string): number {
  const request = requestOf(sample);
  const sharedOurs = new RequestView(request);
  const sharedTheirs = new before.RequestView(request);
  const stride = sample.bytes.length < 4_096 ? 4 : sample.bytes.length < 100_000 ? 16 : 64;
  const offset = compared++ % stride;
  let matched = 0;
  for (let i = 0; i < PATCHES.length; i++) {
    const { ours, theirs } = PATCHES[i] as (typeof PATCHES)[number];
    const expected = before.matchPatch(theirs, sharedTheirs, sample.bytes);
    const shared = matchPatch(ours, sharedOurs, sample.bytes);
    const alone = i % stride === offset;
    const fresh = alone ? matchPatch(ours, new RequestView(request), sample.bytes) : shared;
    if (
      shared.matched !== expected.matched ||
      shared.bodyPending !== expected.bodyPending ||
      shared.undecodable !== expected.undecodable ||
      fresh.matched !== expected.matched ||
      fresh.undecodable !== expected.undecodable ||
      (alone &&
        matchBody(ours, new RequestView(request), sample.bytes) !==
          before.matchBody(theirs, new before.RequestView(request), sample.bytes))
    ) {
      // Reported with the input, never with `toEqual` on megabytes.
      throw new Error(
        `${label}: patch ${JSON.stringify(CONDITION_SETS[i])} on ${sample.bytes.length} bytes (${JSON.stringify(
          Buffer.from(sample.bytes.subarray(0, 120)).toString("latin1"),
        )}…, content-type ${sample.contentType}): before ${JSON.stringify(expected)}, now ${JSON.stringify(shared)} (shared view), ${JSON.stringify(fresh)} (fresh view)`,
      );
    }
    if (expected.matched) matched += 1;
  }
  return matched;
}

describe("the body matcher against the matcher before slice 18f", () => {
  it("decides the same on hostile bodies, in every encoding and under every content type", () => {
    let samples = 0;
    let matches = 0;
    for (const text of HOSTILE_TEXTS) {
      // Megabyte texts in the encodings a client can realistically send; the small ones in all of them.
      const forms =
        text.length > 20_000 ? [new Uint8Array(Buffer.from(text, "utf8")), utf16(text, false, true)] : bytesOf(text);
      const types =
        text.length > 20_000 ? [undefined, "application/json", "text/plain; charset=latin1"] : CONTENT_TYPES;
      for (const bytes of forms) {
        for (const contentType of types) {
          matches += compare({ bytes, contentType }, "hostile text");
          samples += 1;
        }
      }
    }
    for (const bytes of HOSTILE_BYTES) {
      for (const contentType of CONTENT_TYPES) {
        matches += compare({ bytes, contentType }, "hostile bytes");
        samples += 1;
      }
    }
    // The corpus must exercise both answers, or agreeing on it proves nothing.
    expect(samples).toBeGreaterThan(15_000);
    expect(matches).toBeGreaterThan(50_000);
    expect(matches).toBeLessThan(samples * PATCHES.length - 50_000);
  }, 120_000);

  it("decides the same on generated bodies built from escapes, near misses and filler", () => {
    const rand = random(20_261_114);
    const pick = <T>(list: readonly T[]): T => list[Math.floor(rand() * list.length)] as T;
    const hex4 = (unit: number): string => {
      const digits = unit.toString(16).padStart(4, "0");
      return rand() < 0.3 ? digits.toUpperCase() : digits;
    };
    /** Characters the needles are made of, and the ones `json_key` looks for. */
    const UNITS = [...'_protcnsuaAbkey :"\\[].<{}%+é\t\n\r0u4x'].map((char) => char.charCodeAt(0));
    const fragment = (): string => {
      const kind = rand();
      if (kind < 0.22) return `\\u${hex4(pick(UNITS))}`;
      if (kind < 0.27) return `\\u${hex4(Math.floor(rand() * 0x10000))}`;
      if (kind < 0.32) return pick(["\\u", "\\u00", "\\u004", "\\uu", "\\\\u", "\\U0041", "\\u00zz", "\\"]);
      if (kind < 0.4) return `%${pick(UNITS).toString(16).padStart(2, "0")}`;
      if (kind < 0.62) return String.fromCharCode(pick(UNITS));
      if (kind < 0.86) return pick(NEEDLES);
      if (kind < 0.9) return pick(['"__proto__":', '"a" :', '{"constructor":{"prototype":', '"k y"\t:', '","']);
      if (kind < 0.94) return String.fromCharCode(Math.floor(rand() * 0x10000));
      if (kind < 0.97) return pick([FILLER, BLAND]);
      return " ".repeat(Math.floor(rand() * 40));
    };
    const KEYS = ["__proto__", "constructor", "prototype", "a", "key", "k y", "x", "ab"];
    /**
     * A quoted key whose tail — the whitespace and the colon `json_key` reads behind it — comes as escapes, in either
     * hex case, the quotes and the name raw: no escape decodes to a character of the needle, only to its tail.
     */
    const escapedTail = (): string => {
      const space = (): string =>
        rand() < 0.75 ? `\\u${hex4(pick([0x20, 0x09, 0x0a, 0x0d]))}` : pick([" ", "\t", "\n", "\r"]);
      let tail = "";
      for (let k = Math.floor(rand() * 4); k > 0; k--) tail += space();
      // At least one escape in the tail: the colon, or else some whitespace before a raw colon.
      const colon = tail.includes("\\u") && rand() < 0.4 ? ":" : `\\u${hex4(0x3a)}`;
      return `{"${pick(KEYS)}"${tail}${colon}1}`;
    };
    /**
     * 14 to 19 distinct escapes of characters no needle has, then a needle with one character written as an escape:
     * around the number of distinct decoded characters the matcher keeps, the needle's own decoded last.
     */
    const aroundTheCap = (): string => {
      const count = 14 + Math.floor(rand() * 6);
      const first = 0x0100 + Math.floor(rand() * 0x400);
      let block = "";
      for (let k = 0; k < count; k++) block += `\\u${hex4(first + k)}`;
      const needle = pick(["__proto__", "constructor", "prototype", "ab", "key", "x", '"a":', "a:b"]);
      const at = Math.floor(rand() * needle.length);
      const written = `${needle.slice(0, at)}\\u${hex4(needle.charCodeAt(at))}${needle.slice(at + 1)}`;
      return rand() < 0.5 ? `${block}${written}` : `${block}{"${written}":1}`;
    };
    let samples = 0;
    let matches = 0;
    for (let n = 0; n < 6_000; n++) {
      const parts: string[] = [];
      // Most bodies short; one in five long enough to be probed (a bland run in front, behind or both).
      const long = rand() < 0.2;
      if (long && rand() < 0.7) parts.push(BLAND);
      const count = 1 + Math.floor(rand() * (rand() < 0.5 ? 4 : 24));
      for (let k = 0; k < count; k++) parts.push(fragment());
      if (long && rand() < 0.7) parts.push(BLAND);
      // One body in eight is one of the two shapes alone, so that no other fragment's escape hides what it tests.
      const shape = rand();
      const text = shape < 0.06 ? escapedTail() : shape < 0.12 ? aroundTheCap() : parts.join("");
      const encoding = rand();
      const bytes =
        encoding < 0.7
          ? new Uint8Array(Buffer.from(text, "utf8"))
          : encoding < 0.78
            ? new Uint8Array(Buffer.from(text, "latin1"))
            : encoding < 0.9
              ? utf16(text, rand() < 0.5, rand() < 0.5)
              : encoding < 0.96
                ? utf32(text, rand() < 0.5, rand() < 0.5)
                : (pick(bytesOf(text)) as Uint8Array);
      // Sometimes a byte changed or the end cut off: not text any more.
      if (bytes.length > 0 && rand() < 0.08) bytes[Math.floor(rand() * bytes.length)] = Math.floor(rand() * 256);
      const cut = rand() < 0.05 ? bytes.subarray(0, Math.floor(rand() * bytes.length)) : bytes;
      matches += compare(
        { bytes: cut, contentType: rand() < 0.6 ? pick(CONTENT_TYPES.slice(0, 5)) : pick(CONTENT_TYPES) },
        `generated #${n}`,
      );
      samples += 1;
    }
    expect(samples).toBe(6_000);
    expect(matches).toBeGreaterThan(20_000);
    expect(matches).toBeLessThan(samples * PATCHES.length - 20_000);
  }, 120_000);

  it("refuses, monitors and records the same through the checker's body hook", () => {
    const policyOf = (prepare: typeof preparePatch | typeof before.preparePatch): AppliedPolicy =>
      ({
        patches: CONDITION_SETS.map(
          (conditions, i) =>
            ({
              ...prepare({ conditions }),
              id: `vp_generated_${i}`,
              mode: i % 3 === 0 ? "enforce" : "monitor",
            }) as unknown as AppliedPatch,
        ),
      }) as unknown as AppliedPolicy;
    const ours = policyOf(preparePatch);
    const theirs = policyOf(before.preparePatch);
    const summary = (state: PatchState | before.PatchState | null, refused: boolean) => ({
      refused,
      blocked: state?.blocked?.id ?? null,
      blockedBody: state?.blockedBody,
      monitor: state?.monitor?.id ?? null,
      monitorBody: state?.monitorBody,
      bodyChecked: state?.bodyChecked,
    });
    let refusals = 0;
    for (const text of HOSTILE_TEXTS.filter((candidate) => candidate.length < 20_000)) {
      for (const contentType of [
        undefined,
        "application/json",
        "text/plain; charset=utf-16le",
        "text/plain; charset=shift_jis",
      ]) {
        const bytes = Buffer.from(text, "utf8");
        const run = (checker: ReturnType<typeof createPatchChecker>, policy: AppliedPolicy, recordMonitor: boolean) => {
          const request = {
            url: "/api/items",
            headers: contentType === undefined ? {} : { "content-type": contentType },
          } as unknown as IncomingMessage;
          const state = checker.evaluate(policy, request, "POST", true, recordMonitor);
          const refused = checker.verifyBody(request, bytes);
          return summary(state, refused);
        };
        for (const recordMonitor of [true, false]) {
          const expected = run(
            before.createPatchChecker() as unknown as ReturnType<typeof createPatchChecker>,
            theirs,
            recordMonitor,
          );
          const actual = run(createPatchChecker(), ours, recordMonitor);
          expect(actual, `${JSON.stringify(text.slice(0, 120))} as ${contentType}`).toEqual(expected);
          if (expected.refused) refusals += 1;
        }
      }
    }
    expect(refusals).toBeGreaterThan(100);
  }, 120_000);
});

describe("the body matcher's cost", () => {
  /** Every body condition of every patch on `text`, with one view as the checker has; the fastest of a few runs. */
  function cost(conditionSets: Condition[][], text: string): number {
    const patches = conditionSets.map((conditions) => preparePatch({ conditions }));
    const bytes = new Uint8Array(Buffer.from(text, "utf8"));
    const request = { method: "POST", path: "/", rawPath: "/", query: "", headers: {} };
    let best = Number.POSITIVE_INFINITY;
    for (let run = 0; run < 5; run++) {
      const started = performance.now();
      const view = new RequestView(request);
      for (const patch of patches) matchBody(patch, view, bytes);
      best = Math.min(best, performance.now() - started);
    }
    return best;
  }

  /** Bodies built to make each changed path as expensive as it gets, at `n` characters or a small multiple of it. */
  const SHAPES: readonly (readonly [string, Condition[][], (n: number) => string])[] = [
    [
      "escapes that decode to a needle's characters (the escape form is built and scanned)",
      [[body("contains", `${"a".repeat(255)}b`)], [body("json_key", "aaaaaaaa")], [body("ends_with", "ab")]],
      (n) => "\\u0061".repeat(n / 6),
    ],
    [
      "escapes of many distinct characters (more than the matcher keeps a set of)",
      [[body("contains", "__proto__")], [body("json_key", "constructor")], [body("equals", "x")]],
      (n) =>
        Array.from({ length: n / 6 }, (_, i) => `\\u${(0x100 + (i % 4_000)).toString(16).padStart(4, "0")}`).join(""),
    ],
    [
      "backslashes and cut escapes (every `\\u` is looked at, none decodes)",
      [[body("contains", "\\u0041")], [body("json_key", "\\u")], [body("contains", "u00")]],
      (n) => `${"\\u\\u0\\u00\\u004".repeat(n / 16)}`,
    ],
    [
      "near misses of a 256-character needle whose probed characters are all present",
      [[body("contains", `${"a".repeat(255)}b`)], [body("contains", `${"ab".repeat(127)}bb`)]],
      (n) => `${"a".repeat(n)}b`,
    ],
    [
      "probed characters present only at the very end (each probe reads the whole body)",
      [
        [body("contains", "zqxjkvbpyg")],
        [body("contains", "ZQXJ kvbp")],
        [body("json_key", "zqxjkvbp")],
        [body("starts_with", "qzxjkvbp")],
      ],
      (n) => `${"0".repeat(n)}zqxjkvbp "`,
    ],
    [
      "a quoted key followed by whitespace and no colon, raw and as escapes",
      [[body("json_key", "k")], [body("json_key", "a")]],
      (n) => `${'"k"   \\u0020  '.repeat(n / 28)}${'"a"\\u0020\\u0009 '.repeat(n / 30)}`,
    ],
    [
      "the release gate's benign JSON body",
      [
        [body("contains", "[__proto__]")],
        [body("json_key", "constructor"), body("json_key", "prototype")],
        [body("contains", "constructor[prototype]")],
        [body("json_key", "__proto__")],
        [body("contains", "__proto__.")],
        [body("contains", "constructor.prototype")],
        [body("contains", "<__proto__")],
      ],
      (n) => `{"items":[${'{"id":1,"name":"item\\u00e9 1","tags":["a","b"],"price":3},'.repeat(n / 62)}{}]}`,
    ],
  ];

  it.each(SHAPES)("grows linearly with the body: %s", (_name, conditionSets, shape) => {
    // Growth, not a wall-clock budget, so a loaded machine cannot fail it: linear matching makes 4× the body cost
    // about 4× the time, a quadratic path about 16×. A generous absolute cap still catches a catastrophic one.
    cost(conditionSets, shape(40_000)); // warm-up
    const small = Math.max(cost(conditionSets, shape(240_000)), 0.05);
    const large = cost(conditionSets, shape(960_000));
    expect(large / small).toBeLessThan(10);
    expect(large).toBeLessThan(2_000);
  });
});
