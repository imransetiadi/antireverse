// The Babel 8 bridge: parse source to an AST and generate code back. Babel lives only in this package, and
// only these two functions touch the parser and generator; the passes work on the AST. Import forms are the
// ones the spike verified for Babel 8.1.0.
import { generate } from "@babel/generator";
import type { ParserPlugin } from "@babel/parser";
import { parse } from "@babel/parser";
import type { File } from "@babel/types";

/** Babel parser plugins to enable for a path, chosen by its extension. */
function pluginsFor(path: string): ParserPlugin[] {
  const lower = path.toLowerCase();
  if (lower.endsWith(".tsx")) return ["typescript", "jsx"];
  if (lower.endsWith(".ts") || lower.endsWith(".mts") || lower.endsWith(".cts")) return ["typescript"];
  if (lower.endsWith(".jsx")) return ["jsx"];
  return [];
}

/**
 * Parses `code` as an ES module. The extension of `path` selects the TypeScript/JSX plugins. Throws a
 * `SyntaxError` on invalid input; the engine catches it and reports the file rather than failing the run.
 */
export function parseSource(code: string, path: string): File {
  return parse(code, { sourceType: "module", plugins: pluginsFor(path) });
}

/** Generates code from an AST. Comments are dropped so the output carries no original identifiers or notes. */
export function generateCode(ast: File): string {
  return generate(ast, { comments: false }).code;
}
