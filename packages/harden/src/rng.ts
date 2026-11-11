// Deterministic randomness for the engine: a seeded PRNG and a collision-free name generator. Given one
// seed, every call sequence is identical, which is what makes `harden` byte-reproducible.

/** A scope-like object the namer can consult to avoid shadowing a name already live in a Babel scope. */
export interface ScopeLike {
  hasBinding(name: string): boolean;
  hasGlobal(name: string): boolean;
  hasReference(name: string): boolean;
}

/**
 * mulberry32: a tiny, fast PRNG seeded by one 32-bit integer. Returns a function yielding numbers in [0, 1).
 * Exactly the form the spike proved deterministic across runs on this machine.
 */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Names a mangled identifier must never take: ECMAScript reserved words, plus the contextually-reserved and
// special names that are illegal or unsafe as a binding in strict/module code. A generated name that landed on
// one of these would be a SyntaxError (review finding F2).
export const RESERVED_WORDS: ReadonlySet<string> = new Set([
  "break",
  "case",
  "catch",
  "class",
  "const",
  "continue",
  "debugger",
  "default",
  "delete",
  "do",
  "else",
  "enum",
  "export",
  "extends",
  "false",
  "finally",
  "for",
  "function",
  "if",
  "import",
  "in",
  "instanceof",
  "new",
  "null",
  "return",
  "super",
  "switch",
  "this",
  "throw",
  "true",
  "try",
  "typeof",
  "var",
  "void",
  "while",
  "with",
  "let",
  "static",
  "yield",
  "await",
  "async",
  "arguments",
  "eval",
  "implements",
  "interface",
  "package",
  "private",
  "protected",
  "public",
  "undefined",
]);

// A mangled identifier starts with a non-digit and continues with any identifier character.
const HEAD = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$";
const TAIL = `${HEAD}0123456789`;

/**
 * A seeded generator of fresh identifier names. Each name is unique within this generator (a `used` set),
 * is not in `reserved`, and — when a scope is passed — does not clash with a binding, global or reference in
 * that scope. Deterministic for a given seeded `rng`.
 */
export function makeNamer(rng: () => number, reserved?: ReadonlySet<string>): (scope?: ScopeLike) => string {
  const used = new Set<string>([...RESERVED_WORDS, ...(reserved ?? [])]);
  return (scope?: ScopeLike): string => {
    for (let tries = 0; tries < 100_000; tries++) {
      const len = 2 + Math.floor(rng() * 4); // 2..5 characters
      let name = HEAD[Math.floor(rng() * HEAD.length)] as string;
      for (let i = 1; i < len; i++) name += TAIL[Math.floor(rng() * TAIL.length)] as string;
      if (used.has(name)) continue;
      if (scope && (scope.hasBinding(name) || scope.hasGlobal(name) || scope.hasReference(name))) continue;
      used.add(name);
      return name;
    }
    throw new Error("harden: identifier name space exhausted");
  };
}
