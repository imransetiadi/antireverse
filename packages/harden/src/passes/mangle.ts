// Pass 1 — identifier mangling. Renames LOCAL bindings only, via `path.scope.rename`, which rewrites every
// reference bound to that binding and nothing else. It never touches:
//   - import bindings (`binding.kind === "module"`),
//   - exported names (the public API: Babel re-emits `export { renamed as Name }`, so the name survives),
//   - global references (Math, console — they are not bindings),
//   - object/class property keys (keys are not identifier bindings).
//
// Two correctness guards (review findings F1, F4):
//   - A class name is a binding in TWO scopes (the enclosing scope and the class's own scope), sharing one
//     identifier node. We assign one new name per identifier node and rename every scope that owns that binding
//     to the SAME name, so the declaration and all inner/outer references stay in sync.
//   - If the file calls `eval` directly, `eval("localName")` can read a local by name, so renaming locals would
//     break it. We detect a direct eval and skip mangling the whole file (reported by the engine).

import type { NodePath, Scope } from "@babel/traverse";
import _traverse from "@babel/traverse";
import type { File, Node } from "@babel/types";
import { makeNamer } from "../rng.ts";
import type { Pass, PassContext } from "../types.ts";

// In Babel 8 the default export of @babel/traverse IS the traverse function (no `.default`).
const traverse = _traverse as unknown as typeof import("@babel/traverse").default;

/** True when this binding must keep its name: an import, or a binding that is part of an export. */
function isProtectedBinding(path: NodePath): boolean {
  if (path.isExportSpecifier() || path.isExportDefaultSpecifier() || path.isExportNamespaceSpecifier()) return true;
  const parent = path.parentPath;
  if (parent?.isExportNamedDeclaration() || parent?.isExportDefaultDeclaration() || parent?.isExportAllDeclaration()) {
    return true;
  }
  return false;
}

/** True when the file contains a direct call to the global `eval`. */
function usesDirectEval(ast: File): boolean {
  let found = false;
  traverse(ast, {
    CallExpression(path) {
      // A direct call written as `eval(...)`. We do not use scope.hasBinding("eval") — Babel counts `eval` as a
      // global binding, so that check is always true. Over-skipping a file that shadows eval is harmless.
      const callee = path.node.callee;
      if (callee.type === "Identifier" && callee.name === "eval") {
        found = true;
        path.stop();
      }
    },
  });
  return found;
}

export function createManglePass(reserved?: ReadonlySet<string>): Pass {
  return {
    name: "mangle",
    run(ast: File, ctx: PassContext): { count: number; note?: "eval" } {
      if (usesDirectEval(ast)) return { count: 0, note: "eval" };

      const namer = makeNamer(ctx.rng, reserved);
      // One new name per binding identifier node. A class is bound in two scopes that share one id node, so both
      // must be renamed to the same name; without this they would get two names and desync (review finding F1).
      const assigned = new Map<Node, string>();
      let count = 0;
      traverse(ast, {
        Scopable(path) {
          const scope: Scope = path.scope;
          for (const name of Object.keys(scope.bindings)) {
            const binding = scope.bindings[name];
            if (!binding) continue;
            if (binding.kind === "module") continue; // import bindings
            if (isProtectedBinding(binding.path)) continue; // exported names stay public
            const idNode: Node = binding.identifier;
            let next = assigned.get(idNode);
            if (next === undefined) {
              next = namer(scope);
              assigned.set(idNode, next);
              count++;
            }
            if (name !== next) scope.rename(name, next);
          }
        },
      });
      return { count };
    },
  };
}
