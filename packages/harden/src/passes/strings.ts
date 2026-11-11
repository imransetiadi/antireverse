// Pass 2 — scoped string encryption. Plain `StringLiteral`s are replaced by a reference to a module-local
// that holds the DECODED value, decoded exactly ONCE at module load. There is deliberately NO per-access
// decode call (`__ar_d(i)` at every use): the spike measured that pattern at ~+92% runtime on hot paths.
//
// The decoder prelude binds each unique string to a `const` right after the imports:
//     const __ar_k = <key bytes>;
//     const __ar_d = (s) => <xor-decode base64 with __ar_k>;
//     const __ar_s0 = __ar_d("<b64>"), __ar_s1 = __ar_d("<b64>");
// and each `"foo"` becomes the bare identifier `__ar_s0`. The decoder names are 6+ characters, which the
// mangler (max 5) can never produce, so running mangle first keeps them collision-free.
//
// NOT transformed: template literals, import/export source strings, and non-computed object/class property
// keys. Computed keys and string *values* ARE encrypted (a decoded string is byte-identical, so access and
// comparison behave the same).

import type { NodePath } from "@babel/traverse";
import _traverse from "@babel/traverse";
import type { File, StringLiteral } from "@babel/types";
import * as t from "@babel/types";
import { parseSource } from "../babel.ts";
import type { Pass, PassContext } from "../types.ts";

const traverse = _traverse as unknown as typeof import("@babel/traverse").default;

const PREFIX = "__ar_s"; // per-string locals: __ar_s0, __ar_s1, ...
const KEY_ID = "__ar_k";
const DEC_ID = "__ar_d";

/** The 4-byte XOR key derived from the seed (never the seed itself leaves the build). */
function keyFromSeed(seed: number): Buffer {
  const n = (seed ^ 0x9e3779b9) >>> 0;
  return Buffer.from([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

function xorBase64(value: string, key: Buffer): string {
  const buf = Buffer.from(value, "utf8");
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = (buf[i] as number) ^ (key[i % key.length] as number);
  return out.toString("base64");
}

/** True when this string literal must keep its plaintext form (keys, import/export sources, type positions). */
function mustKeep(path: NodePath<StringLiteral>): boolean {
  const parent = path.parent;
  if (t.isImportDeclaration(parent) || t.isExportNamedDeclaration(parent) || t.isExportAllDeclaration(parent)) {
    return true; // module source specifiers
  }
  if ((t.isObjectProperty(parent) || t.isObjectMethod(parent)) && parent.key === path.node && !parent.computed) {
    return true; // plain object key
  }
  if ((t.isClassProperty(parent) || t.isClassMethod(parent)) && parent.key === path.node && !parent.computed) {
    return true; // plain class member key
  }
  if (t.isTSLiteralType(parent) || t.isTSEnumMember(parent)) return true; // a TS type-level string
  if (t.isJSXAttribute(parent)) return true; // a JSX attribute value needs to stay a literal
  return false;
}

export function createStringsPass(): Pass {
  return {
    name: "strings",
    run(ast: File, ctx: PassContext): { count: number } {
      const key = keyFromSeed(ctx.seed);
      const table: string[] = [];
      const index = new Map<string, number>();

      const intern = (value: string): number => {
        const existing = index.get(value);
        if (existing !== undefined) return existing;
        const i = table.length;
        index.set(value, i);
        table.push(xorBase64(value, key));
        return i;
      };

      traverse(ast, {
        StringLiteral(path) {
          if (mustKeep(path)) return;
          const idx = intern(path.node.value);
          path.replaceWith(t.identifier(`${PREFIX}${idx}`));
          path.skip();
        },
      });

      if (table.length === 0) return { count: 0 };

      // Build the decoder prelude as source and splice it in after the last import declaration.
      const keyB64 = key.toString("base64");
      const decls = table.map((b64, i) => `${PREFIX}${i} = ${DEC_ID}(${JSON.stringify(b64)})`).join(", ");
      const prelude = `const ${KEY_ID} = Uint8Array.from(atob(${JSON.stringify(keyB64)}), (c) => c.charCodeAt(0));
const ${DEC_ID} = (s) => { const b = Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); const o = new Uint8Array(b.length); for (let j = 0; j < b.length; j++) o[j] = b[j] ^ ${KEY_ID}[j % ${KEY_ID}.length]; return new TextDecoder().decode(o); };
const ${decls};`;

      const preludeBody = parseSource(prelude, "prelude.mjs").program.body;
      const body = ast.program.body;
      let at = 0;
      while (at < body.length && t.isImportDeclaration(body[at])) at++;
      body.splice(at, 0, ...preludeBody);

      return { count: table.length };
    },
  };
}
