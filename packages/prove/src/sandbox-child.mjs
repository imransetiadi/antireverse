// The sandbox child process (review 12b F1, N1, N2). Every sandbox — the Toolbelt's `run`, the W3 logic vectors and
// the W4 tamper runs — executes here, in a fresh `node` process started by child.ts with the permission model (no
// file reads beyond this script and Babel's parser, no writes, child processes, workers or addons), code generation
// from strings disabled in this process's own realm, an empty environment, a heap limit and a kill timer.
//
// The untrusted code runs in a vm context and must never reach an object of this process's realm: such an object's
// prototype chain leads to this realm's Object.prototype, where the code could plant `toJSON` or accessors and
// forge a result. The one way it could get one was the promise of `import()`, so any source with a dynamic
// `import(...)` or `import.meta` is refused before it compiles: statically (a conservative scanner, refined by a
// Babel parse when the file parses) and, in W4 where eval is allowed, at run time by the context's own eval and
// Function-constructor guards. Everything handed to the context is created in the context's realm (stubs,
// recorder, guards), and this realm's prototypes are snapshotted before and checked after the untrusted code.
// Result lines are built by concatenation from primitives this script checks itself; the request's token stays in
// this module's scope and is never a property of any object.
// Plain JavaScript (no TypeScript): this file is loaded by `node` itself under the permission model.
import { pathToFileURL } from "node:url";
import vm from "node:vm";

// --- This realm's intrinsics, captured before any untrusted code runs ---------------------------------------

const ReflectApply = Reflect.apply;
const ReflectOwnKeys = Reflect.ownKeys;
const ReflectDeleteProperty = Reflect.deleteProperty;
const ObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const ObjectDefineProperty = Object.defineProperty;
const ObjectHasOwn = Object.hasOwn;
const JsonStringify = JSON.stringify;
const JsonParse = JSON.parse;
const StringIncludes = String.prototype.includes;
const StringIndexOf = String.prototype.indexOf;
const StringSlice = String.prototype.slice;
const StringCharCodeAt = String.prototype.charCodeAt;

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const request = JsonParse(Buffer.concat(chunks).toString("utf8"));
const token = String(request.token);
delete request.token;
const stdoutWrite = process.stdout.write.bind(process.stdout);

// --- Prototype snapshot (belt and braces, review N1) ---------------------------------------------------------

const WATCHED = [
  Object.prototype,
  Array.prototype,
  Function.prototype,
  Promise.prototype,
  String.prototype,
  Error.prototype,
  EvalError.prototype,
  RangeError.prototype,
  ReferenceError.prototype,
  SyntaxError.prototype,
  TypeError.prototype,
  URIError.prototype,
  AggregateError.prototype,
  Map.prototype,
  Set.prototype,
  WeakMap.prototype,
  WeakSet.prototype,
  Symbol,
  Symbol.prototype,
  JSON,
  Object,
  Reflect,
];
const MapCtor = Map;
const MapSet = Map.prototype.set;
const MapHas = Map.prototype.has;
function snapshotOf(target) {
  const keys = ReflectOwnKeys(target);
  const entries = [];
  for (let i = 0; i < keys.length; i++) {
    entries[entries.length] = [keys[i], ObjectGetOwnPropertyDescriptor(target, keys[i])];
  }
  return entries;
}
const SNAPSHOT = WATCHED.map(snapshotOf);
function sameDescriptor(a, b) {
  return (
    a !== undefined &&
    b !== undefined &&
    a.value === b.value &&
    a.get === b.get &&
    a.set === b.set &&
    a.writable === b.writable &&
    a.enumerable === b.enumerable &&
    a.configurable === b.configurable
  );
}
/** Restores every watched object to its snapshot; true when anything had changed. */
function restorePrototypes() {
  let changed = false;
  for (let w = 0; w < WATCHED.length; w++) {
    const target = WATCHED[w];
    const before = SNAPSHOT[w];
    // Map.prototype is watched too: use the captured methods, never the (possibly changed) prototype's.
    const known = new MapCtor();
    for (let i = 0; i < before.length; i++) ReflectApply(MapSet, known, [before[i][0], before[i][1]]);
    const now = ReflectOwnKeys(target);
    for (let i = 0; i < now.length; i++) {
      if (!ReflectApply(MapHas, known, [now[i]])) {
        changed = true;
        try {
          ReflectDeleteProperty(target, now[i]);
        } catch {}
      }
    }
    for (let i = 0; i < before.length; i++) {
      const [key, descriptor] = before[i];
      if (!sameDescriptor(ObjectGetOwnPropertyDescriptor(target, key), descriptor)) {
        changed = true;
        try {
          ObjectDefineProperty(target, key, descriptor);
        } catch {}
      }
    }
  }
  return changed;
}

// --- Result lines, built from checked primitives -------------------------------------------------------------

const enc = {
  str: (value) => (typeof value === "string" ? JsonStringify(value) : "null"),
  num: (value) => (typeof value === "number" && Number.isFinite(value) ? JsonStringify(value) : "0"),
  bool: (value) => (value === true ? "true" : "false"),
  strs: (values) => {
    let out = "[";
    for (let i = 0; i < values.length; i++) {
      if (i > 0) out += ",";
      out += typeof values[i] === "string" ? JsonStringify(values[i]) : '""';
    }
    return `${out}]`;
  },
};
/** Writes one line: pairs of a field name (a literal of this script) and an encoded value. */
function sendLine(fields) {
  // A modified realm means the code reached it: restore it and report that instead of any result.
  if (restorePrototypes()) {
    stdoutWrite(`{"token":${JsonStringify(token)},"polluted":true}\n`);
    return;
  }
  let out = `{"token":${JsonStringify(token)}`;
  for (let i = 0; i < fields.length; i += 2) out += `,${JsonStringify(fields[i])}:${fields[i + 1]}`;
  stdoutWrite(`${out}}\n`);
}

function text(value, max = 300) {
  return typeof value === "string" ? ReflectApply(StringSlice, value, [0, max]) : "unreadable error";
}

/** The error's name and message by own data properties only (no getter of the sandboxed code runs). */
function describeError(error, max = 300) {
  try {
    if (error !== null && typeof error === "object") {
      const nameDescriptor = ObjectGetOwnPropertyDescriptor(error, "name");
      const messageDescriptor = ObjectGetOwnPropertyDescriptor(error, "message");
      const name = nameDescriptor && ObjectHasOwn(nameDescriptor, "value") ? nameDescriptor.value : undefined;
      const message =
        messageDescriptor && ObjectHasOwn(messageDescriptor, "value") ? messageDescriptor.value : undefined;
      const label = typeof name === "string" ? name : errorKind(error);
      return text(`${label}: ${typeof message === "string" ? message : ""}`, max);
    }
    if (typeof error === "string") return text(error, max);
    return "a non-error value was thrown";
  } catch {
    return "unreadable error";
  }
}
function errorKind(error) {
  // V8's own errors (SyntaxError, TypeError…) keep their name on the prototype; read it by descriptor only.
  try {
    let proto = Object.getPrototypeOf(error);
    for (let depth = 0; proto !== null && depth < 4; depth++) {
      const descriptor = ObjectGetOwnPropertyDescriptor(proto, "name");
      if (descriptor && ObjectHasOwn(descriptor, "value") && typeof descriptor.value === "string")
        return descriptor.value;
      proto = Object.getPrototypeOf(proto);
    }
  } catch {}
  return "Error";
}

function isTimeout(error) {
  try {
    const descriptor =
      error !== null && typeof error === "object" ? ObjectGetOwnPropertyDescriptor(error, "code") : null;
    return descriptor?.value === "ERR_SCRIPT_EXECUTION_TIMEOUT";
  } catch {
    return false;
  }
}

// --- Refusing import() and import.meta ----------------------------------------------------------------------

const IMPORT_REFUSED = "import() and import.meta are not available in the sandbox.";

/**
 * Conservative: true when `import` (not a member name) is followed, after whitespace or comments, by `(` or `.` —
 * a dynamic import or import.meta wherever it occurs, and also inside strings or comments (a false positive the
 * Babel parse clears for static sources). Any non-ASCII character counts as whitespace, so nothing slips through.
 * Its source is also compiled into the W4 context, so it uses only `charCodeAt` passed in.
 */
function scanForImport(source, codeAt) {
  const length = source.length;
  const identifier = (c) =>
    (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 36 || c === 95;
  for (let i = 0; i + 6 <= length; i++) {
    if (
      codeAt(source, i) !== 105 ||
      codeAt(source, i + 1) !== 109 ||
      codeAt(source, i + 2) !== 112 ||
      codeAt(source, i + 3) !== 111 ||
      codeAt(source, i + 4) !== 114 ||
      codeAt(source, i + 5) !== 116
    ) {
      continue;
    }
    if (i > 0) {
      const before = codeAt(source, i - 1);
      if (identifier(before) || before === 46) continue;
    }
    let j = i + 6;
    if (j < length && identifier(codeAt(source, j))) continue;
    for (;;) {
      if (j >= length) break;
      const c = codeAt(source, j);
      if (c <= 32 || c >= 127) {
        j++;
        continue;
      }
      if (c === 47 && j + 1 < length && codeAt(source, j + 1) === 42) {
        j += 2;
        while (j + 1 < length && !(codeAt(source, j) === 42 && codeAt(source, j + 1) === 47)) j++;
        j += 2;
        continue;
      }
      const lineComment =
        (c === 47 && j + 1 < length && codeAt(source, j + 1) === 47) ||
        (c === 60 &&
          j + 3 < length &&
          codeAt(source, j + 1) === 33 &&
          codeAt(source, j + 2) === 45 &&
          codeAt(source, j + 3) === 45) ||
        (c === 45 && j + 2 < length && codeAt(source, j + 1) === 45 && codeAt(source, j + 2) === 62);
      if (lineComment) {
        while (j < length && codeAt(source, j) !== 10 && codeAt(source, j) !== 13) j++;
        continue;
      }
      break;
    }
    if (j < length) {
      const next = codeAt(source, j);
      if (next === 40 || next === 46) return true;
    }
  }
  return false;
}
const codeAtHere = (source, index) => ReflectApply(StringCharCodeAt, source, [index]);

const BABEL_BYTES_MAX = 1_048_576;
let parseFn = null;
async function babelParse(source, options) {
  if (typeof request.parserPath !== "string") return null;
  if (parseFn === null) parseFn = (await import(pathToFileURL(request.parserPath).href)).parse;
  return parseFn(source, options);
}

function astHasImport(program) {
  const stack = [program];
  while (stack.length > 0) {
    const node = stack.pop();
    if (node === null || typeof node !== "object") continue;
    if (Array.isArray(node)) {
      for (const child of node) stack.push(child);
      continue;
    }
    if (node.type === "ImportExpression" || node.type === "Import") return true;
    if (node.type === "MetaProperty" && node.meta?.name === "import") return true;
    for (const [key, value] of Object.entries(node)) {
      if (key !== "loc" && key !== "extra" && value !== null && typeof value === "object") stack.push(value);
    }
  }
  return false;
}

/** For `run` and W3 bodies: refused when the scanner flags it and a Babel parse confirms it (or cannot clear it). */
async function bodyRefusesImport(source) {
  if (!scanForImport(source, codeAtHere)) return false;
  if (source.length > BABEL_BYTES_MAX) return true;
  try {
    const ast = await babelParse(source, {
      sourceType: "script",
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
    });
    return ast === null ? true : astHasImport(ast.program);
  } catch {
    return true;
  }
}

// --- run: the Toolbelt's code runner ----------------------------------------------------------------------

async function runMode() {
  const { code, input, timeoutMs } = request;
  if (await bodyRefusesImport(code)) {
    sendLine(["ok", "false", "kind", enc.str("error"), "error", enc.str(`Error: ${IMPORT_REFUSED}`)]);
    return;
  }
  let output;
  try {
    const context = vm.createContext(Object.create(null), {
      name: "prove-run",
      codeGeneration: { strings: false, wasm: false },
      microtaskMode: "afterEvaluate",
    });
    context.__input = input;
    context.__fn = vm.compileFunction(`"use strict";\n${code}`, ["input"], {
      parsingContext: context,
      filename: "run.js",
    });
    const source =
      '"use strict";(function () {' +
      "const __parse = JSON.parse; const __stringify = JSON.stringify; const __fn = globalThis.__fn;" +
      "delete globalThis.__fn;" +
      "const __result = __fn.call(undefined, __parse(__input));" +
      'if (__result !== null && (typeof __result === "object" || typeof __result === "function") && typeof __result.then === "function") {' +
      'throw new TypeError("The code must return a value, not a Promise.");}' +
      "return __stringify(__result === undefined ? null : __result);" +
      "})()";
    output = new vm.Script(source, { filename: "wrapper.js" }).runInContext(context, {
      timeout: timeoutMs,
      breakOnSigint: false,
    });
  } catch (error) {
    if (isTimeout(error)) {
      sendLine(["ok", "false", "kind", enc.str("timeout"), "error", enc.str("The code ran over the time limit.")]);
    } else {
      sendLine(["ok", "false", "kind", enc.str("error"), "error", enc.str(describeError(error))]);
    }
    return;
  }
  let isJson = output === undefined;
  if (typeof output === "string") {
    try {
      JsonParse(output);
      isJson = true;
    } catch {}
  }
  if (!isJson) sendLine(["ok", "false", "kind", enc.str("error"), "error", enc.str("The result is not JSON data.")]);
  else sendLine(["ok", "true", "output", enc.str(output === undefined ? "null" : output)]);
}

// --- logic: W3 vectors ------------------------------------------------------------------------------------

async function logicMode() {
  const { body, inputs, params, timeoutMs, outputCharsMax } = request;
  if (await bodyRefusesImport(body)) {
    sendLine(["compileError", enc.str(`Error: ${IMPORT_REFUSED}`)]);
    return;
  }
  const context = vm.createContext(Object.create(null), {
    name: "prove-logic",
    codeGeneration: { strings: false, wasm: false },
    microtaskMode: "afterEvaluate",
  });
  try {
    context.__fn = vm.compileFunction(`"use strict";\n${body}`, params, {
      parsingContext: context,
      filename: "logic.js",
    });
    new vm.Script(
      '(function () { "use strict"; const fn = globalThis.__fn; delete globalThis.__fn;' +
        "const parse = JSON.parse, stringify = JSON.stringify;" +
        "globalThis.__run = function (input, count) { const args = parse(input); const call = [];" +
        "for (let i = 0; i < count; i++) call.push(args[i]); call.push(args);" +
        "const result = fn.apply(undefined, call);" +
        'if (result !== null && (typeof result === "object" || typeof result === "function") && typeof result.then === "function") {' +
        'throw new TypeError("The body must return a value, not a Promise."); }' +
        "return stringify(result === undefined ? null : result); }; })()",
    ).runInContext(context, { timeout: 1000 });
  } catch (error) {
    sendLine(["compileError", enc.str(describeError(error))]);
    return;
  }
  const script = new vm.Script("__run(__input, __count)", { filename: "vector.js" });
  for (let index = 0; index < inputs.length; index++) {
    let output;
    try {
      context.__input = inputs[index];
      context.__count = params.length - 1;
      output = script.runInContext(context, { timeout: timeoutMs, breakOnSigint: false });
    } catch (error) {
      if (isTimeout(error)) {
        // A body that loops on one vector is judged on that: the rest are not run (review 12b F4).
        sendLine([
          "index",
          enc.num(index),
          "ok",
          "false",
          "kind",
          enc.str("timeout"),
          "error",
          enc.str("The vector ran over its time limit."),
          "stop",
          "true",
        ]);
        return;
      }
      sendLine([
        "index",
        enc.num(index),
        "ok",
        "false",
        "kind",
        enc.str("error"),
        "error",
        enc.str(describeError(error)),
      ]);
      continue;
    }
    let valid = typeof output === "string" && output.length <= outputCharsMax;
    if (valid) {
      try {
        JsonParse(output);
      } catch {
        valid = false;
      }
    }
    if (valid) sendLine(["index", enc.num(index), "ok", "true", "output", enc.str(output)]);
    else {
      sendLine([
        "index",
        enc.num(index),
        "ok",
        "false",
        "kind",
        enc.str("error"),
        "error",
        enc.str("The result is not JSON data."),
      ]);
    }
  }
}

// --- tamper: W4 ------------------------------------------------------------------------------------------

const STUB_NAMES_MAX = 5_000;
const ESM_FALLBACK = /(^|[\s;}])(import|export)\b/;
const MODULE_DECLARATIONS = new Set([
  "ImportDeclaration",
  "ExportNamedDeclaration",
  "ExportDefaultDeclaration",
  "ExportAllDeclaration",
]);
const SKIPPED_KEYS = new Set([
  "loc",
  "start",
  "end",
  "extra",
  "range",
  "leadingComments",
  "trailingComments",
  "innerComments",
  "comments",
  "errors",
  "tokens",
]);

function nameOf(node) {
  if (node?.type === "Identifier" && typeof node.name === "string") return node.name;
  if (node?.type === "StringLiteral" && typeof node.value === "string") return node.value;
  return null;
}

/** The textual analysis for files too large to parse: Harden's fallback test and bounded name patterns. */
function textualAnalysis(code) {
  const importFound = scanForImport(code, codeAtHere);
  if (!ESM_FALLBACK.test(code)) return { module: false, names: [], importFound };
  const names = new Set();
  for (const match of code.matchAll(/\b(?:import|export)[ \t]{0,8}\{([^}]{0,4096})\}/g)) {
    for (const part of (match[1] ?? "").split(",")) {
      const name = /^\s*([A-Za-z_$][\w$]{0,63})/.exec(part)?.[1];
      if (name) names.add(name);
      if (names.size >= STUB_NAMES_MAX) break;
    }
  }
  for (const match of code.matchAll(/\.[ \t]{0,8}([A-Za-z_$][\w$]{0,63})/g)) {
    if (names.size >= STUB_NAMES_MAX) break;
    names.add(match[1]);
  }
  names.delete("default");
  names.delete("then");
  return { module: true, names: [...names], importFound };
}

/**
 * Whether the code is an ES module, as Harden's containsEsm decides (Babel, sourceType unambiguous, a static
 * import or export; if it does not parse, Harden's textual test); the names its stub imports export; and whether
 * it uses a dynamic import or import.meta. Files over 1 MB use the textual analysis (review 12b F3).
 */
async function analyse(code) {
  if (Buffer.byteLength(code, "utf8") > BABEL_BYTES_MAX) return textualAnalysis(code);
  let program;
  try {
    const ast = await babelParse(code, { sourceType: "unambiguous", plugins: [] });
    if (ast === null) return textualAnalysis(code);
    program = ast.program;
  } catch {
    return { module: ESM_FALLBACK.test(code), names: [], importFound: scanForImport(code, codeAtHere) };
  }
  const importFound = scanForImport(code, codeAtHere) && astHasImport(program);
  const body = program.body ?? [];
  const module = program.sourceType === "module" && body.some((node) => MODULE_DECLARATIONS.has(node.type));
  if (!module) return { module: false, names: [], importFound };
  const names = new Set();
  const stack = [program];
  while (stack.length > 0 && names.size < STUB_NAMES_MAX) {
    const node = stack.pop();
    if (node === null || typeof node !== "object") continue;
    if (Array.isArray(node)) {
      for (const child of node) stack.push(child);
      continue;
    }
    if (node.type === "ImportSpecifier") {
      const name = nameOf(node.imported);
      if (name !== null) names.add(name);
    } else if (node.type === "ExportSpecifier") {
      const name = nameOf(node.local);
      if (name !== null) names.add(name);
    } else if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
      const name = node.computed === true ? null : nameOf(node.property);
      if (name !== null) names.add(name);
    }
    for (const [key, value] of Object.entries(node)) {
      if (!SKIPPED_KEYS.has(key) && value !== null && typeof value === "object") stack.push(value);
    }
  }
  names.delete("default");
  names.delete("then");
  return { module: true, names: [...names], importFound };
}

function similarity(original, candidate) {
  if (original.length === 0) return 0;
  const shorter = Math.min(original.length, candidate.length);
  let prefix = 0;
  while (prefix < shorter && original.charCodeAt(prefix) === candidate.charCodeAt(prefix)) prefix++;
  let suffix = 0;
  const room = shorter - prefix;
  while (
    suffix < room &&
    original.charCodeAt(original.length - 1 - suffix) === candidate.charCodeAt(candidate.length - 1 - suffix)
  ) {
    suffix++;
  }
  return Math.min(1, (prefix + suffix) / original.length);
}

/** The longest common subsequence of two lists of strings, as a count (two typed rows). */
function lcsLength(a, b) {
  if (a.length === 0 || b.length === 0) return 0;
  let previous = new Int32Array(b.length + 1);
  let current = new Int32Array(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      current[j] = a[i - 1] === b[j - 1] ? previous[j - 1] + 1 : Math.max(previous[j], current[j - 1]);
    }
    const swap = previous;
    previous = current;
    current = swap;
    current.fill(0);
  }
  return previous[b.length];
}

function removeFirst(source, part) {
  const at = ReflectApply(StringIndexOf, source, [part]);
  if (at === -1) return source;
  return ReflectApply(StringSlice, source, [0, at]) + ReflectApply(StringSlice, source, [at + part.length]);
}

const TRACE_BASELINE_MAX = 2_000;
const TRACE_RUN_MAX = 4_000;

/**
 * The context's boot script, run before the untrusted code. Everything here is of the context's own realm. It
 * captures the context's intrinsics, defines the six stub globals (non-writable, non-configurable proxies that
 * record a trace of names: get, set, call, new — never values), replaces eval with a recorder (refusing sources with
 * import(), recording source, the marker before and after, and whether the evaluation completed normally) and
 * guards every Function-family constructor the same way. It returns accessors for the records, for this script.
 */
function contextBoot(scannerSource, traceMax, recordCharsMax, refusal) {
  return `(function () {
  "use strict";
  const ReflectApply = Reflect.apply, ReflectConstruct = Reflect.construct;
  const defineProperty = Object.defineProperty, getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const hasOwn = Object.hasOwn, getPrototypeOf = Object.getPrototypeOf;
  const MapCtor = Map, MapGet = Map.prototype.get, MapSet = Map.prototype.set, MapHas = Map.prototype.has;
  const charCodeAt = String.prototype.charCodeAt, StringSlice = String.prototype.slice;
  const IntrinsicEval = globalThis.eval;
  const TypeErrorCtor = TypeError;
  const scan = (${scannerSource});
  const codeAt = (s, i) => ReflectApply(charCodeAt, s, [i]);
  const hasImport = (s) => scan(s, codeAt);
  const refuse = () => { throw new TypeErrorCtor(${JsonStringify(refusal)}); };

  // The trace of the stub globals: names only.
  const trace = new MapCtor();
  let traceCount = 0;
  const note = (entry) => { if (traceCount < ${traceMax}) { ReflectApply(MapSet, trace, [traceCount, entry]); traceCount += 1; } };
  const keyName = (key) => typeof key === "string" ? ReflectApply(StringSlice, key, [0, 64]) : "[symbol]";
  const proxies = new MapCtor();
  let proxyCount = 0;
  let generic;
  const genericHandler = {
    get(target, key) { if (key === Symbol.toPrimitive) return function () { return ""; };
      if (key === "then" || key === Symbol.iterator || key === Symbol.asyncIterator) return undefined; return generic; },
    set() { return true; }, has() { return true; }, deleteProperty() { return true; },
    apply() { return generic; }, construct() { return generic; } };
  generic = new Proxy(function () {}, genericHandler);
  const stubFor = (path, depth) => {
    if (depth > 6 || proxyCount >= 2000) return generic;
    if (ReflectApply(MapHas, proxies, [path])) return ReflectApply(MapGet, proxies, [path]);
    proxyCount += 1;
    const handler = {
      get(target, key) {
        if (key === Symbol.toPrimitive) return function () { return ""; };
        if (key === "then" || key === Symbol.iterator || key === Symbol.asyncIterator) return undefined;
        const name = keyName(key);
        note("get " + path + "." + name);
        return stubFor(path + "." + name, depth + 1);
      },
      set(target, key) { note("set " + path + "." + keyName(key)); return true; },
      has() { return true; }, deleteProperty() { return true; },
      apply() { note("call " + path); return stubFor(path + "()", depth + 1); },
      construct() { note("new " + path); return stubFor("new " + path, depth + 1); },
    };
    const proxy = new Proxy(function () {}, handler);
    ReflectApply(MapSet, proxies, [path, proxy]);
    return proxy;
  };
  for (const name of ["window", "document", "self", "navigator", "location", "localStorage"]) {
    defineProperty(globalThis, name, { value: stubFor(name, 0), writable: false, enumerable: false, configurable: false });
  }

  // The browser utilities Harden's own string decoder needs (atob, TextDecoder), with their inverses: plain
  // JavaScript of this realm, not traced (they are not the page's globals).
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const fromCharCode = String.fromCharCode;
  const Uint8ArrayCtor = Uint8Array;
  const invalid = (what) => { const e = new Error(what); defineProperty(e, "name", { value: "InvalidCharacterError" }); throw e; };
  const b64Index = (c) => (c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 71 : c >= 48 && c <= 57 ? c + 4 : c === 43 ? 62 : c === 47 ? 63 : -1);
  const atobImpl = function atob(input) {
    const s = "" + input;
    let clean = "";
    for (let i = 0; i < s.length; i++) {
      const c = codeAt(s, i);
      if (c === 9 || c === 10 || c === 12 || c === 13 || c === 32) continue;
      clean += fromCharCode(c);
    }
    if (clean.length % 4 === 0 && codeAt(clean, clean.length - 1) === 61) {
      clean = ReflectApply(StringSlice, clean, [0, codeAt(clean, clean.length - 2) === 61 ? -2 : -1]);
    }
    if (clean.length % 4 === 1) invalid("The string to be decoded is not correctly encoded.");
    let out = "";
    let buffer = 0;
    let bits = 0;
    for (let i = 0; i < clean.length; i++) {
      const v = b64Index(codeAt(clean, i));
      if (v < 0) invalid("The string to be decoded is not correctly encoded.");
      buffer = (buffer << 6) | v;
      bits += 6;
      if (bits >= 8) { bits -= 8; out += fromCharCode((buffer >> bits) & 255); }
    }
    return out;
  };
  const btoaImpl = function btoa(input) {
    const s = "" + input;
    let out = "";
    for (let i = 0; i < s.length; i += 3) {
      const a = codeAt(s, i), b = i + 1 < s.length ? codeAt(s, i + 1) : -1, c = i + 2 < s.length ? codeAt(s, i + 2) : -1;
      if (a > 255 || b > 255 || c > 255) invalid("The string to be encoded contains characters outside of the Latin1 range.");
      const n = (a << 16) | ((b < 0 ? 0 : b) << 8) | (c < 0 ? 0 : c);
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (b < 0 ? "=" : B64[(n >> 6) & 63]) + (c < 0 ? "=" : B64[n & 63]);
    }
    return out;
  };
  class TextDecoderImpl {
    get encoding() { return "utf-8"; }
    decode(input) {
      if (input === undefined) return "";
      const bytes = input instanceof Uint8ArrayCtor ? input : new Uint8ArrayCtor(input.buffer !== undefined ? input.buffer : input);
      let out = "";
      for (let i = 0; i < bytes.length; ) {
        const b0 = bytes[i];
        let code = 0xfffd, size = 1;
        if (b0 < 0x80) { code = b0; }
        else if (b0 >= 0xc2 && b0 <= 0xdf && i + 1 < bytes.length && (bytes[i + 1] & 0xc0) === 0x80) { code = ((b0 & 0x1f) << 6) | (bytes[i + 1] & 0x3f); size = 2; }
        else if (b0 >= 0xe0 && b0 <= 0xef && i + 2 < bytes.length && (bytes[i + 1] & 0xc0) === 0x80 && (bytes[i + 2] & 0xc0) === 0x80) {
          const c = ((b0 & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f);
          if (c >= 0x800 && (c < 0xd800 || c > 0xdfff)) { code = c; size = 3; }
        } else if (b0 >= 0xf0 && b0 <= 0xf4 && i + 3 < bytes.length && (bytes[i + 1] & 0xc0) === 0x80 && (bytes[i + 2] & 0xc0) === 0x80 && (bytes[i + 3] & 0xc0) === 0x80) {
          const c = ((b0 & 0x07) << 18) | ((bytes[i + 1] & 0x3f) << 12) | ((bytes[i + 2] & 0x3f) << 6) | (bytes[i + 3] & 0x3f);
          if (c >= 0x10000 && c <= 0x10ffff) { code = c; size = 4; }
        }
        if (code > 0xffff) { const v = code - 0x10000; out += fromCharCode(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff)); }
        else out += fromCharCode(code);
        i += size;
      }
      return out;
    }
  }
  class TextEncoderImpl {
    get encoding() { return "utf-8"; }
    encode(input) {
      const s = input === undefined ? "" : "" + input;
      const out = [];
      for (let i = 0; i < s.length; i++) {
        let c = codeAt(s, i);
        if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
          const d = codeAt(s, i + 1);
          if (d >= 0xdc00 && d <= 0xdfff) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++; }
          else c = 0xfffd;
        } else if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
        if (c < 0x80) out[out.length] = c;
        else if (c < 0x800) { out[out.length] = 0xc0 | (c >> 6); out[out.length] = 0x80 | (c & 63); }
        else if (c < 0x10000) { out[out.length] = 0xe0 | (c >> 12); out[out.length] = 0x80 | ((c >> 6) & 63); out[out.length] = 0x80 | (c & 63); }
        else { out[out.length] = 0xf0 | (c >> 18); out[out.length] = 0x80 | ((c >> 12) & 63); out[out.length] = 0x80 | ((c >> 6) & 63); out[out.length] = 0x80 | (c & 63); }
      }
      return new Uint8ArrayCtor(out);
    }
  }
  for (const [name, value] of [["atob", atobImpl], ["btoa", btoaImpl], ["TextDecoder", TextDecoderImpl], ["TextEncoder", TextEncoderImpl]]) {
    defineProperty(globalThis, name, { value, writable: true, enumerable: false, configurable: true });
  }

  // The marker, read by descriptor (no getter of the sandboxed code runs).
  const markerNow = () => {
    const d = getOwnPropertyDescriptor(globalThis, "__airverse_tamper");
    if (d === undefined || !hasOwn(d, "value")) return null;
    return typeof d.value === "string" ? d.value : null;
  };

  // The eval recorder.
  const records = new MapCtor();
  let recordCount = 0;
  let recordChars = 0;
  // How an evaluation ended, as "Name: message" read by own data properties only (the name may sit on the
  // prototype of V8's own errors). Compared with how the original's evaluation ended (review N2, real bundles).
  const errorText = (error) => {
    if (error === null || (typeof error !== "object" && typeof error !== "function")) return "non-error " + typeof error;
    let name = "Error";
    let proto = error;
    for (let depth = 0; proto !== null && depth < 5; depth++) {
      const d = getOwnPropertyDescriptor(proto, "name");
      if (d !== undefined && hasOwn(d, "value") && typeof d.value === "string") { name = d.value; break; }
      proto = getPrototypeOf(proto);
    }
    const m = getOwnPropertyDescriptor(error, "message");
    const message = m !== undefined && hasOwn(m, "value") && typeof m.value === "string" ? m.value : "";
    return ReflectApply(StringSlice, name + ": " + message, [0, 1000]);
  };
  const STRIDE = 5;
  const record = (source, before, after, normal, ended) => {
    if (recordCount >= 1000) return;
    const keep = recordChars + source.length <= ${recordCharsMax};
    if (keep) recordChars += source.length;
    ReflectApply(MapSet, records, [recordCount * STRIDE, keep ? source : ""]);
    ReflectApply(MapSet, records, [recordCount * STRIDE + 1, before]);
    ReflectApply(MapSet, records, [recordCount * STRIDE + 2, after]);
    ReflectApply(MapSet, records, [recordCount * STRIDE + 3, normal && keep]);
    ReflectApply(MapSet, records, [recordCount * STRIDE + 4, ended]);
    recordCount += 1;
  };
  const recorder = { eval(source) {
    if (typeof source !== "string") return IntrinsicEval(source);
    if (hasImport(source)) refuse();
    const before = markerNow();
    let normal = false;
    let ended = null;
    try {
      const result = IntrinsicEval(source);
      normal = true;
      return result;
    } catch (error) {
      ended = errorText(error);
      throw error;
    } finally {
      record(source, before, markerNow(), normal, ended);
    }
  } }.eval;
  defineProperty(globalThis, "eval", { value: recorder, writable: false, enumerable: false, configurable: false });

  // The Function-family constructors refuse sources with import() as well.
  const guard = (Intrinsic) => {
    // A plain function: callable and constructible, as the intrinsic is.
    const guarded = function (...args) {
      for (let i = 0; i < args.length; i++) if (typeof args[i] === "string" && hasImport(args[i])) refuse();
      return ReflectConstruct(Intrinsic, args, Intrinsic);
    };
    // So that instanceof and Function.prototype keep meaning what they mean.
    defineProperty(guarded, "prototype", { value: Intrinsic.prototype, writable: false, enumerable: false, configurable: false });
    defineProperty(Intrinsic.prototype, "constructor", { value: guarded, writable: false, enumerable: false, configurable: false });
    return guarded;
  };
  const guardedFunction = guard(Function);
  guard(getPrototypeOf(async function () {}).constructor);
  guard(getPrototypeOf(function* () {}).constructor);
  guard(getPrototypeOf(async function* () {}).constructor);
  defineProperty(globalThis, "Function", { value: guardedFunction, writable: false, enumerable: false, configurable: false });

  return {
    stub: generic,
    traceCount: () => traceCount,
    traceAt: (i) => ReflectApply(MapGet, trace, [i]),
    recordCount: () => recordCount,
    recordAt: (i) => ReflectApply(MapGet, records, [i]),
  };
})()`;
}

async function tamperMode() {
  const {
    code,
    nonce,
    reference,
    baseline,
    baselineTrace,
    baselineError,
    payloadError,
    timeoutMs,
    errorsMax,
    errorCharsMax,
  } = request;
  const markerStatement = typeof nonce === "string" ? `globalThis.__airverse_tamper=${JsonStringify(nonce)};` : null;
  const analysis = await analyse(code);
  const errors = [];
  let timedOut = false;
  let completedNormally = false;
  /** How the file's own run ended when it threw ("Name: message"), else null. */
  let endError = null;
  const noteError = (error) => {
    if (isTimeout(error)) {
      timedOut = true;
      return;
    }
    endError = describeError(error, 1000);
    if (errors.length < errorsMax) errors[errors.length] = describeError(error, errorCharsMax);
  };

  const context = vm.createContext(Object.create(null), {
    name: "prove-tamper",
    codeGeneration: { strings: true, wasm: false },
    // A module's evaluation promise must settle through the normal microtask queue; the parent's kill bounds it.
    ...(analysis.module ? {} : { microtaskMode: "afterEvaluate" }),
  });
  const traceMax = baseline ? TRACE_BASELINE_MAX : TRACE_RUN_MAX;
  const boot = new vm.Script(
    contextBoot(scanForImport.toString(), traceMax, code.length * 4 + 1_048_576, `${IMPORT_REFUSED}`),
  ).runInContext(context, { timeout: 2000 });
  // Read once, now, while only our code has run: the accessors are of the context's realm and touch only its
  // captured intrinsics and private Maps.
  const accessor = (name) => ObjectGetOwnPropertyDescriptor(boot, name).value;
  const stub = accessor("stub");
  const traceCount = accessor("traceCount");
  const traceAt = accessor("traceAt");
  const recordCount = accessor("recordCount");
  const recordAt = accessor("recordAt");

  if (analysis.importFound) {
    errors[errors.length] = `Error: ${IMPORT_REFUSED}`;
  } else if (analysis.module) {
    let stubCount = 0;
    const stubModule = () => {
      stubCount += 1;
      return new vm.SyntheticModule(
        ["default", ...analysis.names],
        function () {
          this.setExport("default", stub);
          for (const name of analysis.names) this.setExport(name, stub);
        },
        { context, identifier: `stub:${stubCount}` },
      );
    };
    try {
      const module = new vm.SourceTextModule(code, { context, identifier: "submitted.mjs" });
      await module.link(() => stubModule());
      let failed = false;
      const evaluation = module.evaluate({ timeout: timeoutMs, breakOnSigint: false }).then(
        () => {},
        (error) => {
          failed = true;
          noteError(error);
        },
      );
      let timer;
      let finished = false;
      await Promise.race([
        evaluation.then(() => {
          finished = true;
        }),
        new Promise((resolve) => {
          timer = setTimeout(() => {
            timedOut = true;
            resolve();
          }, timeoutMs);
        }),
      ]);
      clearTimeout(timer);
      completedNormally = finished && !failed && !timedOut;
    } catch (error) {
      noteError(error);
    }
  } else {
    try {
      new vm.Script(code, { filename: "submitted.js" }).runInContext(context, {
        timeout: timeoutMs,
        breakOnSigint: false,
      });
      completedNormally = true;
    } catch (error) {
      noteError(error);
    }
  }

  // Facts, from the context's private records and this script's own reads.
  const trace = [];
  const traced = traceCount();
  for (let i = 0; i < traced; i++) {
    const entry = traceAt(i);
    if (typeof entry === "string") trace[trace.length] = entry;
  }
  const evaluations = [];
  const recorded = recordCount();
  for (let i = 0; i < recorded; i++) {
    const source = recordAt(i * 5);
    const before = recordAt(i * 5 + 1);
    const after = recordAt(i * 5 + 2);
    const normal = recordAt(i * 5 + 3) === true;
    const ended = recordAt(i * 5 + 4);
    if (typeof source !== "string" || source.length === 0) continue;
    try {
      new vm.Script(source, { filename: "eval-check.js" });
    } catch {
      continue; // a SyntaxError never counts
    }
    evaluations[evaluations.length] = {
      source,
      before,
      after,
      normal,
      ended: typeof ended === "string" ? ended : null,
    };
  }

  if (baseline) {
    // The payload: the longest evaluated string that compiled, and how its evaluation ended.
    let chosen = null;
    for (let i = 0; i < evaluations.length; i++) {
      if (chosen === null || evaluations[i].source.length > chosen.source.length) chosen = evaluations[i];
    }
    sendLine([
      "payload",
      enc.str(chosen === null ? null : chosen.source),
      "payloadError",
      enc.str(chosen === null || chosen.normal ? null : chosen.ended),
      "endError",
      enc.str(completedNormally ? null : endError),
      "trace",
      enc.strs(trace),
      "timedOut",
      enc.bool(timedOut),
    ]);
    return;
  }
  // A run counts when it completes normally, or ends exactly as the original's did (review N2, real bundles).
  const completedLikeBaseline =
    !timedOut &&
    (completedNormally || (endError !== null && typeof baselineError === "string" && endError === baselineError));

  let bestSetInside = 0;
  if (typeof reference === "string" && markerStatement !== null) {
    for (let i = 0; i < evaluations.length; i++) {
      const { source, before, after, normal, ended } = evaluations[i];
      const counts = normal || (ended !== null && typeof payloadError === "string" && ended === payloadError);
      if (!counts) continue;
      if (before === nonce || after !== nonce) continue;
      if (!ReflectApply(StringIncludes, source, [markerStatement])) continue;
      const share = similarity(reference, removeFirst(source, markerStatement));
      if (share > bestSetInside) bestSetInside = share;
    }
  }
  let traceRatio = -1;
  const expected = Array.isArray(baselineTrace) ? baselineTrace.filter((entry) => typeof entry === "string") : [];
  if (expected.length > 0) traceRatio = lcsLength(expected, trace) / expected.length;
  const markerValue = (() => {
    const descriptor = ObjectGetOwnPropertyDescriptor(context, "__airverse_tamper");
    return descriptor !== undefined && ObjectHasOwn(descriptor, "value") && typeof descriptor.value === "string"
      ? descriptor.value
      : null;
  })();
  let integrityFailed = false;
  for (let i = 0; i < errors.length; i++) {
    if (ReflectApply(StringIncludes, errors[i], ["integrity check failed"])) integrityFailed = true;
  }
  sendLine([
    "module",
    enc.bool(analysis.module),
    "errors",
    enc.strs(errors),
    "integrityFailed",
    enc.bool(integrityFailed),
    "marker",
    enc.str(markerValue),
    "completedNormally",
    enc.bool(completedNormally),
    "completedLikeBaseline",
    enc.bool(completedLikeBaseline),
    "evalCount",
    enc.num(evaluations.filter((e) => e.normal).length),
    "bestSetInside",
    enc.num(bestSetInside),
    "traceRatio",
    enc.num(traceRatio),
    "traceLength",
    enc.num(trace.length),
    "timedOut",
    enc.bool(timedOut),
  ]);
}

// --- probe: what the permission model allows (tests) ---------------------------------------------------------

async function probeMode() {
  const outcome = (fn) => {
    try {
      fn();
      return "allowed";
    } catch (error) {
      return ObjectGetOwnPropertyDescriptor(error, "code")?.value ?? error?.name ?? "error";
    }
  };
  const fs = process.getBuiltinModule("node:fs");
  sendLine([
    "read",
    enc.str(outcome(() => fs.readFileSync(request.path))),
    "write",
    enc.str(outcome(() => fs.writeFileSync(`${request.path}.probe`, "x"))),
    "spawn",
    enc.str(outcome(() => process.getBuiltinModule("node:child_process").execFileSync("/bin/echo", ["x"]))),
    "worker",
    enc.str(outcome(() => new (process.getBuiltinModule("node:worker_threads").Worker)("1", { eval: true }))),
    "codegen",
    enc.str(outcome(() => Function("return 1")())),
    "env",
    enc.strs(Object.keys(process.env).filter((key) => key !== "__CF_USER_TEXT_ENCODING")),
  ]);
}

// --- pollute: a test of the snapshot (the parent asks this realm to change one watched object) -----------------

function polluteMode() {
  const targets = {
    "Object.prototype": Object.prototype,
    "Array.prototype": Array.prototype,
    "Function.prototype": Function.prototype,
    "Promise.prototype": Promise.prototype,
    "String.prototype": String.prototype,
    "Error.prototype": Error.prototype,
    "TypeError.prototype": TypeError.prototype,
    "RangeError.prototype": RangeError.prototype,
    "ReferenceError.prototype": ReferenceError.prototype,
    "SyntaxError.prototype": SyntaxError.prototype,
    "Map.prototype": Map.prototype,
    "Set.prototype": Set.prototype,
    "WeakMap.prototype": WeakMap.prototype,
    Symbol,
    "Symbol.prototype": Symbol.prototype,
    JSON,
  };
  const target = ObjectHasOwn(targets, request.target) ? targets[request.target] : null;
  if (target !== null) ObjectDefineProperty(target, "__probe", { value: 1, configurable: true, writable: true });
  sendLine(["ok", "true"]);
}

try {
  if (request.mode === "pollute") polluteMode();
  else if (request.mode === "run") await runMode();
  else if (request.mode === "logic") await logicMode();
  else if (request.mode === "tamper") await tamperMode();
  else if (request.mode === "probe") await probeMode();
} catch {
  sendLine(["sandboxFailure", "true"]);
}
stdoutWrite("", () => process.exit(0));
