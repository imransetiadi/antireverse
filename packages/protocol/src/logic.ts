// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { deepFreeze, text, utf8Bytes } from "./shared.ts";

// The logic inventory (slice 12b, W3 Logic): the protected functions a tenant designates with `harden --logic
// <file>`. Each has a public part the Assessment's agent sees (id, description, up to 2 examples) and a hidden part
// it never sees (10–200 test vectors). The Manifest carries the file's digest and function count only
// (`logicDigest`, server entry); the file goes beside the Manifest at registration, and the API stores it with the
// Build and never returns the vectors. Every object schema is a plain `z.object`, which strips unknown keys.

export const LOGIC_LIMITS = deepFreeze({
  /** Functions of one logic file. */
  functionsMin: 1,
  functionsMax: 5,
  /** Characters of a function id. */
  idMax: 32,
  /** Characters of a function's description. */
  descriptionMax: 500,
  /** Public examples of one function, shown to the agent. */
  examplesMax: 2,
  /** Hidden test vectors of one function, never shown to the agent. */
  vectorsMin: 10,
  vectorsMax: 200,
  /** Bytes of the whole logic file as UTF-8 JSON (1 MB). */
  fileBytesMax: 1_048_576,
  /** Bytes of a W3 submission's function body as UTF-8 (64 KB). */
  bodyBytesMax: 65_536,
  /** W3 submissions per run. Enforced by prove. */
  submissionsMax: 3,
  /** Milliseconds one vector may run in the sandbox. Enforced by prove. */
  vectorTimeoutMs: 1000,
  /** Milliseconds all vectors of one submission may run together. Enforced by prove. */
  batchTimeoutMs: 20_000,
} as const);

const FUNCTION_ID = /^[a-z][a-z0-9-]{0,31}$/;

/** A protected function's id: a lower-case letter, then up to 31 lower-case letters, digits or hyphens. */
export const LogicFunctionIdSchema = z.string().regex(FUNCTION_ID);

/**
 * One call of a protected function and its expected result: `input` is the JSON array of arguments, `output` any
 * JSON value (finite numbers only). The W3 verifier compares outputs by canonical JSON (`canonicalJson`).
 */
export const LogicVectorSchema = z.object({ input: z.array(z.json()), output: z.json() });
export type LogicVector = z.infer<typeof LogicVectorSchema>;

const examples = z.array(LogicVectorSchema).max(LOGIC_LIMITS.examplesMax);
const vectors = z.array(LogicVectorSchema).min(LOGIC_LIMITS.vectorsMin).max(LOGIC_LIMITS.vectorsMax);
const description = text(LOGIC_LIMITS.descriptionMax).min(1);

/** One designated protected function: id, description, public examples (0–2) and hidden vectors (10–200). */
export const LogicFunctionSchema = z.object({ id: LogicFunctionIdSchema, description, examples, vectors });
export type LogicFunction = z.infer<typeof LogicFunctionSchema>;

/** What the Assessment's agent sees of a function: id, description and examples. Parsing strips the vectors. */
export const LogicPublicSchema = z.object({ id: LogicFunctionIdSchema, description, examples });
export type LogicPublic = z.infer<typeof LogicPublicSchema>;

/** The hidden part of a function, which never reaches the agent or an API response: its id and its vectors. */
export const LogicHiddenSchema = z.object({ id: LogicFunctionIdSchema, vectors });
export type LogicHidden = z.infer<typeof LogicHiddenSchema>;

/**
 * The whole logic file a tenant passes to `harden --logic` and the CLI sends beside the Manifest (`logic`): 1–5
 * functions, each id once, at most 1 MB as UTF-8 JSON.
 */
export const LogicFileSchema = z
  .object({
    functions: z.array(LogicFunctionSchema).min(LOGIC_LIMITS.functionsMin).max(LOGIC_LIMITS.functionsMax),
  })
  .refine((file) => new Set(file.functions.map((entry) => entry.id)).size === file.functions.length, {
    message: "Must not list a function id twice.",
    path: ["functions"],
  })
  .refine((file) => utf8Bytes(JSON.stringify(file), LOGIC_LIMITS.fileBytesMax) <= LOGIC_LIMITS.fileBytesMax, {
    message: "The logic file must be at most 1 MB as UTF-8 JSON.",
  });
export type LogicFile = z.infer<typeof LogicFileSchema>;

// Documented example, reused by the tests of every workspace. It is synthetic and deeply frozen.

/** A logic file of a small shop: one function, a price in cents with a tax rate in percent, rounded. */
export const EXAMPLE_LOGIC: LogicFile = deepFreeze({
  functions: [
    {
      id: "price-with-tax",
      description: "The price in cents including tax: price in cents and tax rate in percent, rounded to a cent.",
      examples: [
        { input: [1000, 10], output: 1100 },
        { input: [2500, 20], output: 3000 },
      ],
      vectors: [
        { input: [0, 10], output: 0 },
        { input: [1, 10], output: 1 },
        { input: [999, 7], output: 1069 },
        { input: [12345, 19], output: 14691 },
        { input: [500, 0], output: 500 },
        { input: [100, 25], output: 125 },
        { input: [7777, 8], output: 8399 },
        { input: [42, 50], output: 63 },
        { input: [19999, 21], output: 24199 },
        { input: [300, 5], output: 315 },
      ],
    },
  ],
});
