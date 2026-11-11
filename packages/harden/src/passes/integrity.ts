// Pass 3 — the opt-in integrity self-check (`--integrity`, never in a default profile).
//
// It wraps ALREADY-BUNDLED, non-ESM output: the protected code is embedded as a string, a hash of it is
// computed at build time, and the wrapper recomputes that hash at run time and refuses to run the payload if
// it no longer matches. A one-byte change to the embedded region trips it. It works by `eval`-ing the
// payload, which CANNOT execute `import`/`export`, so ESM input is refused with a clear error — bundle first.
//
// Honest limits (documented so no one over-trusts it): this is a tamper *signal*, not tamper-proofing. An
// attacker who controls the runtime can delete the check, stub the hash, or run the payload directly; the
// embedded hash is not a signature. It roughly doubles the file's size. It belongs after bundling, as the
// last step, guarded behind `--integrity`.
import { parse } from "@babel/parser";

/** FNV-1a (32-bit) over UTF-16 code units, as hex. Pure, dependency-free — the same function runs at runtime. */
function tinyHash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
    h >>>= 0;
  }
  return (h >>> 0).toString(16);
}

/** True when `code` uses static `import`/`export`, i.e. it is an ES module and cannot be run via `eval`. */
export function containsEsm(code: string): boolean {
  let ast: ReturnType<typeof parse>;
  try {
    ast = parse(code, { sourceType: "unambiguous", plugins: [] });
  } catch {
    // If it will not parse as a script or module, fall back to a conservative textual check.
    return /(^|[\s;}])(import|export)\b/.test(code);
  }
  if (ast.program.sourceType === "module") {
    return ast.program.body.some(
      (node) =>
        node.type === "ImportDeclaration" ||
        node.type === "ExportNamedDeclaration" ||
        node.type === "ExportDefaultDeclaration" ||
        node.type === "ExportAllDeclaration",
    );
  }
  return false;
}

/**
 * Wraps bundled, non-ESM `code` in the integrity self-check. Throws on ESM input (the CLI turns this into a
 * message). The output is deterministic for a given input.
 */
export function applyIntegrity(code: string): string {
  if (containsEsm(code)) {
    throw new Error(
      "harden: --integrity needs already-bundled, non-ESM code (no import/export). Bundle the output first, then apply integrity.",
    );
  }
  const expected = tinyHash(code);
  const payload = JSON.stringify(code);
  return `(function(){
function __h(s){let h=0x811c9dc5;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,0x01000193);h>>>=0;}return (h>>>0).toString(16);}
var __payload=${payload};
if(__h(__payload)!==${JSON.stringify(expected)}){throw new Error("[antireverse] integrity check failed: the protected code was modified after build");}
(0,eval)(__payload);
})();
`;
}

export { tinyHash };
