// Slice 12b — `harden --logic <file>`: the designated protected functions for W3 Logic. The file is read and
// validated (`LogicFileSchema`, at most 1 MB) before any work; an invalid or oversized file exits 2 with a clear
// message. With --register it goes beside the Manifest (`logic`) and the Manifest carries `logic_count` and
// `logic_digest`; without --register it is read and validated, and the report says it was not sent. The file —
// above all its hidden vectors — never appears in the protected output, the report, the JSON report or an error.
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Assessment,
  EXAMPLE_ASSESSMENT,
  EXAMPLE_BUILD,
  EXAMPLE_ROUTE_INVENTORY,
  LOGIC_LIMITS,
  type LogicFile,
  RegisterBuildRequestSchema,
} from "@antireverse/protocol";
import { logicDigest } from "@antireverse/protocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.ts";
import { beaconHostModule } from "./helpers.ts";

const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const ENDPOINT = "https://api.example.test";
const MODULE = beaconHostModule();

const temps: string[] = [];
afterEach(() => {
  vi.unstubAllGlobals();
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
});

function tempDir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  temps.push(d);
  return d;
}

function bundle(): string {
  const d = tempDir("harden-cli12b-");
  writeFileSync(join(d, "a.mjs"), MODULE);
  return d;
}

// Distinctive values: none may appear in the output, the output bundle, the report or an error message.
const SECRET_ARG = "zqv-hidden-arg";
const SECRET_OUT = 918273645;
const vectors = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ input: [`${SECRET_ARG}-${i}`, i], output: SECRET_OUT + i }));

const LOGIC: LogicFile = {
  functions: [
    {
      id: "zqv-score",
      description: "zqv-description of the scoring rule",
      examples: [{ input: ["zqv-example", 1], output: 777111 }],
      vectors: vectors(10),
    },
    { id: "zqv-other", description: "zqv-second function", examples: [], vectors: vectors(12) },
  ],
};

function noLogic(text: string): void {
  expect(text).not.toContain("zqv-");
  expect(text).not.toContain(String(SECRET_OUT));
  expect(text).not.toContain("777111");
}

function writeLogic(dir: string, content: unknown = LOGIC, name = "logic.json"): string {
  const file = join(dir, name);
  writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content));
  return file;
}

async function run(argv: string[], cwd: string, env: Record<string, string> = { AR_ADMIN_KEY: KEY }) {
  let out = "";
  let err = "";
  const code = await main(argv, {
    env,
    cwd,
    stdout: (s) => {
      out += s;
    },
    stderr: (s) => {
      err += s;
    },
  });
  return { code, out, err };
}

const QUEUED: Assessment = {
  ...EXAMPLE_ASSESSMENT,
  build_id: EXAMPLE_BUILD.build_id,
  app_id: EXAMPLE_BUILD.app_id,
  status: "queued",
  results: [],
  rrs: null,
  inconclusive_reason: null,
  inconclusive_code: null,
  renormalised: false,
  started_at: null,
  finished_at: null,
  failure_reason: null,
};

type Call = { url: string; body: string };

function stubApi(): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    calls.push({ url, body: String(init.body) });
    const isAssess = url.endsWith("/assessments");
    return new Response(JSON.stringify(isAssess ? { assessment: QUEUED } : { build: EXAMPLE_BUILD }), {
      status: isAssess ? 202 : 201,
      headers: { "content-type": "application/json" },
    });
  });
  return calls;
}

const register = [
  "--register",
  "--endpoint",
  ENDPOINT,
  "--key-env",
  "AR_ADMIN_KEY",
  "--app",
  EXAMPLE_BUILD.app_id,
  "--environment",
  "development",
  "--build-version",
  "1.0.0",
];

describe("--logic <file>", () => {
  it("sends the logic file beside the Manifest, with logic_count and logic_digest, and prints a count only", async () => {
    const d = bundle();
    writeLogic(d);
    const out = join(tempDir("harden-cli12b-out-"), "out");
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--logic", "logic.json", "--out", out, ...register], d);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    expect(calls.length).toBe(1);
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(Object.keys(body).sort()).toEqual(["logic", "manifest"]);
    expect(body.logic).toEqual(LOGIC);
    expect(body.manifest.logic_count).toBe(2);
    expect(body.manifest.logic_digest).toBe(logicDigest(LOGIC));
    expect(RegisterBuildRequestSchema.safeParse(body).success).toBe(true);
    expect(r.out).toContain("✓ 2 protected functions designated");
    noLogic(r.out + r.err);
    // Never written into the output bundle (the logic file sits inside the bundle dir here).
    expect(readdirSync(out)).toEqual(["a.mjs"]);
    noLogic(readFileSync(join(out, "a.mjs"), "utf8"));
  });

  it("sends logic beside routes when both are given", async () => {
    const d = bundle();
    writeLogic(d);
    writeFileSync(join(d, "routes.json"), JSON.stringify(EXAMPLE_ROUTE_INVENTORY));
    const calls = stubApi();
    const r = await run(
      ["harden", d, "--seed", "1", "--logic", "logic.json", "--routes", "routes.json", ...register],
      d,
    );
    expect(r.code).toBe(0);
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(Object.keys(body).sort()).toEqual(["logic", "manifest", "routes"]);
    expect(RegisterBuildRequestSchema.safeParse(body).success).toBe(true);
  });

  it("strips unknown keys before sending (the schema's parse is what goes out)", async () => {
    const d = bundle();
    writeLogic(d, { ...LOGIC, extra: "zqv-unknown" });
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--logic", "logic.json", ...register], d);
    expect(r.code).toBe(0);
    expect(JSON.parse(calls[0]?.body ?? "{}").logic).toEqual(LOGIC);
  });

  it("never uploads the logic file with --assess", async () => {
    const d = bundle();
    writeLogic(d);
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--logic", "logic.json", "--assess", "T1", ...register], d);
    expect(r.code).toBe(0);
    expect(calls.length).toBe(2);
    noLogic(calls[1]?.body ?? "");
    noLogic(r.out + r.err);
  });

  it("without --register reads and validates the file, says it was not sent, and exits 0", async () => {
    const d = bundle();
    const file = writeLogic(d);
    const out = join(tempDir("harden-cli12b-out-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--logic", file, "--out", out], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain("2 protected functions read (not sent: pass --register)");
    noLogic(r.out + r.err);
    expect(readdirSync(out)).toEqual(["a.mjs"]);
    noLogic(readFileSync(join(out, "a.mjs"), "utf8"));
  });

  it("--json carries logic { count } and never the file", async () => {
    const d = bundle();
    writeLogic(d);
    stubApi();
    const r = await run(["harden", d, "--seed", "1", "--logic", "logic.json", "--json", ...register], d);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).logic).toEqual({ count: 2 });
    noLogic(r.out + r.err);
  });

  it("--json without --register carries logic { count } and never the file", async () => {
    const d = bundle();
    writeLogic(d);
    const r = await run(["harden", d, "--seed", "1", "--logic", "logic.json", "--json"], d);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).logic).toEqual({ count: 2 });
    noLogic(r.out + r.err);
  });

  it("--json without --logic carries logic null and the body has no logic fields", async () => {
    const d = bundle();
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--json", ...register], d);
    expect(JSON.parse(r.out).logic).toBeNull();
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(Object.keys(body)).toEqual(["manifest"]);
    expect("logic_count" in body.manifest).toBe(false);
    expect("logic_digest" in body.manifest).toBe(false);
  });

  const fn = LOGIC.functions[0] as LogicFile["functions"][number];
  const oversized = JSON.stringify(LOGIC) + " ".repeat(LOGIC_LIMITS.fileBytesMax);

  it.each([
    ["a missing file", null, /--logic .*cannot be read/],
    ["a file that is not JSON", '{"functions": [{"id": "zqv-x"', /--logic .*not JSON/],
    ["a JSON array", [fn], /--logic .*not a valid logic file/],
    ["no functions", { functions: [] }, /--logic .*not a valid logic file.*functions/],
    ["six functions", { functions: Array.from({ length: 6 }, (_, i) => ({ ...fn, id: `f${i}` })) }, /functions/],
    ["a bad id", { functions: [{ ...fn, id: "Zqv-Upper" }] }, /functions\[0\]\.id/],
    ["9 vectors", { functions: [{ ...fn, vectors: vectors(9) }] }, /functions\[0\]\.vectors/],
    ["201 vectors", { functions: [{ ...fn, vectors: vectors(201) }] }, /functions\[0\]\.vectors/],
    ["3 examples", { functions: [{ ...fn, examples: vectors(3) }] }, /functions\[0\]\.examples/],
    ["an empty description", { functions: [{ ...fn, description: "" }] }, /functions\[0\]\.description/],
    [
      "a vector input that is not an array",
      { functions: [{ ...fn, vectors: [...vectors(9), { input: "zqv-s", output: 1 }] }] },
      /functions\[0\]\.vectors\[9\]\.input/,
    ],
    ["a function id listed twice", { functions: [fn, { ...fn }] }, /twice/],
    ["a file over 1 MB", oversized, /--logic .*larger than 1 MB/],
  ])("%s exits 2 before any work, without echoing the file", async (_name, content, message) => {
    const d = bundle();
    if (content !== null) writeLogic(d, content);
    const calls = stubApi();
    const out = join(tempDir("harden-cli12b-out-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--logic", "logic.json", "--out", out, ...register], d);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(message);
    expect(calls.length).toBe(0);
    expect(existsSync(out)).toBe(false);
    // The file name is printed as given; nothing of its content is.
    noLogic(r.out + r.err.replaceAll("logic.json", ""));
  });

  it("--logic with no value exits 2", async () => {
    const d = bundle();
    const r = await run(["harden", d, "--seed", "1", "--logic"], d);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--logic needs a path");
  });

  it("the usage text documents --logic", async () => {
    const r = await run(["harden", "--help"], tempDir("harden-cli12b-help-"));
    expect(r.out + r.err).toContain("--logic <file>");
  });
});
