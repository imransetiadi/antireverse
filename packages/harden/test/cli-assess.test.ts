// Slice 12a — the CLI around the Reverse Assessment: `--routes <file>` (a route inventory, validated before any
// work, sent beside the Manifest with --register; only its count and digest are in the Manifest and only its count
// is printed), and `--assess <T1|T2|T3>` (needs --register; uploads the protected files after a successful
// registration and prints the Assessment id and the Console link; a failed upload exits 1 but the Build stays
// registered; the 25 MB / 1,000-file limits are checked before anything is sent).
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type Assessment,
  CreateAssessmentRequestSchema,
  EXAMPLE_ASSESSMENT,
  EXAMPLE_BUILD,
  RegisterBuildRequestSchema,
} from "@antireverse/protocol";
import { routesDigest } from "@antireverse/protocol/server";
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
  const d = tempDir("harden-cli12a-");
  writeFileSync(join(d, "a.mjs"), MODULE);
  return d;
}

// Distinctive paths: none may appear in the output, the output bundle or an error message.
const ROUTES = [
  "GET /zq-internal/admin/users",
  "post /zq-internal/admin/users/:userId/impersonate",
  "GET /api/zq-orders/:orderId",
];

function noRoutes(text: string): void {
  expect(text).not.toContain("zq-internal");
  expect(text).not.toContain("zq-orders");
  expect(text).not.toContain("impersonate");
}

function writeRoutes(dir: string, content: unknown = ROUTES, name = "routes.json"): string {
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

/** Stubs the API: registration answers 201 with EXAMPLE_BUILD; the assessment request answers `assess`. */
function stubApi(assess: { status: number; body: unknown } = { status: 202, body: { assessment: QUEUED } }): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    calls.push({ url, body: String(init.body) });
    const isAssess = url.endsWith("/assessments");
    return new Response(JSON.stringify(isAssess ? assess.body : { build: EXAMPLE_BUILD }), {
      status: isAssess ? assess.status : 201,
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

describe("--routes <file>", () => {
  it("sends the routes beside the Manifest, with route_count and routes_digest, and prints a count only", async () => {
    const d = bundle();
    writeRoutes(d);
    const out = join(tempDir("harden-cli12a-out-"), "out");
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--routes", "routes.json", "--out", out, ...register], d);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    expect(calls.length).toBe(1);
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(Object.keys(body).sort()).toEqual(["manifest", "routes"]);
    expect(body.routes).toEqual(ROUTES);
    expect(body.manifest.route_count).toBe(3);
    expect(body.manifest.routes_digest).toBe(routesDigest(ROUTES));
    expect(RegisterBuildRequestSchema.safeParse(body).success).toBe(true);
    expect(r.out).toContain("✓ 3 routes in inventory");
    noRoutes(r.out + r.err);
    // Never written into the output bundle.
    expect(readdirSync(out)).toEqual(["a.mjs"]);
    noRoutes(readFileSync(join(out, "a.mjs"), "utf8"));
  });

  it("without --register reads and validates the file, says it was not sent, and exits 0", async () => {
    const d = bundle();
    const file = writeRoutes(d);
    const r = await run(["harden", d, "--seed", "1", "--routes", file], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain("3 routes read (not sent: pass --register)");
    noRoutes(r.out + r.err);
  });

  it("--json carries routes { count } and never the routes", async () => {
    const d = bundle();
    writeRoutes(d);
    stubApi();
    const r = await run(["harden", d, "--seed", "1", "--routes", "routes.json", "--json", ...register], d);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).routes).toEqual({ count: 3 });
    noRoutes(r.out);
  });

  it("--json without --routes carries routes null and the body has no route fields", async () => {
    const d = bundle();
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--json", ...register], d);
    expect(JSON.parse(r.out).routes).toBeNull();
    const body = JSON.parse(calls[0]?.body ?? "{}");
    expect(Object.keys(body)).toEqual(["manifest"]);
    expect("route_count" in body.manifest).toBe(false);
    expect("routes_digest" in body.manifest).toBe(false);
  });

  it.each([
    ["a missing file", null, /--routes .*cannot be read/],
    ["a file that is not JSON", '["GET /zq-internal/x"', /--routes .*not JSON/],
    ["a JSON object", { routes: ["GET /zq-internal/x"] }, /--routes .*JSON array/],
    ["an entry that is not METHOD /path", ["GET /zq-internal/ok", "/zq-internal/no-method"], /entry 2 .*METHOD \/path/],
    ["a non-string entry", ["GET /zq-internal/ok", 7], /entry 2 .*METHOD \/path/],
    ["a route listed twice", ["GET /zq-internal/x", "get /zq-internal/x"], /lists a route twice/],
    [
      "over 2,000 routes",
      Array.from({ length: 2001 }, (_, i) => `GET /zq-internal/r${i}`),
      /2,001 routes.*at most 2,000/,
    ],
  ])("%s exits 2 before any work, without echoing a route", async (_name, content, message) => {
    const d = bundle();
    if (content !== null) writeRoutes(d, content);
    const calls = stubApi();
    const out = join(tempDir("harden-cli12a-out-"), "out");
    const r = await run(["harden", d, "--seed", "1", "--routes", "routes.json", "--out", out, ...register], d);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(message);
    expect(calls.length).toBe(0);
    expect(existsSync(out)).toBe(false);
    noRoutes(r.out + r.err);
  });

  it("--routes with no value exits 2", async () => {
    const d = bundle();
    const r = await run(["harden", d, "--seed", "1", "--routes"], d);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--routes needs a path");
  });
});

describe("--assess <tier>", () => {
  it("needs --register: exit 2 before any work", async () => {
    const d = bundle();
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--assess", "T1"], d);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--assess needs --register");
    expect(calls.length).toBe(0);
  });

  it.each([["T4"], ["t1"], [undefined]])("rejects tier %s with exit 2 before register", async (tier) => {
    const d = bundle();
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", ...register, "--assess", ...(tier ? [tier] : [])], d);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--assess must be one of T1, T2, T3");
    expect(calls.length).toBe(0);
  });

  it("after registration uploads the protected files (the Manifest's hashes) and prints the id and Console link", async () => {
    const d = bundle();
    const out = join(tempDir("harden-cli12a-out-"), "out");
    const queuedT2: Assessment = { ...QUEUED, tier: "T2", scope: { ...QUEUED.scope, tier: "T2" } };
    const calls = stubApi({ status: 202, body: { assessment: queuedT2 } });
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...register, "--assess", "T2"], d, {
      AR_ADMIN_KEY: KEY,
      AR_CONSOLE_URL: "https://console.example.test/",
    });
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    expect(calls.length).toBe(2);
    expect(calls[1]?.url).toBe(
      `${ENDPOINT}/v1/apps/${EXAMPLE_BUILD.app_id}/builds/${EXAMPLE_BUILD.build_id}/assessments`,
    );
    const manifest = JSON.parse(calls[0]?.body ?? "{}").manifest;
    const request = JSON.parse(calls[1]?.body ?? "{}");
    expect(CreateAssessmentRequestSchema.safeParse(request).success).toBe(true);
    expect(request.tier).toBe("T2");
    // Proof of Ownership: the uploaded files are exactly the Manifest's artifacts, byte for byte.
    const uploaded = request.files.map((f: { path: string; base64: string }) => {
      const bytes = Buffer.from(f.base64, "base64");
      return { path: f.path, sha256: createHash("sha256").update(bytes).digest("hex"), bytes: bytes.length };
    });
    expect(uploaded).toEqual(manifest.artifacts);
    expect(Buffer.from(request.files[0].base64, "base64").toString("utf8")).toBe(
      readFileSync(join(out, "a.mjs"), "utf8"),
    );
    expect(r.out).toContain(`✓ assessment ${QUEUED.id} queued (T2)`);
    expect(r.out).toContain(
      `https://console.example.test/apps/${EXAMPLE_BUILD.app_id}/builds/${EXAMPLE_BUILD.build_id}`,
    );
    expect(r.out + r.err).not.toContain(KEY);
  });

  it("links to the local Console when AR_CONSOLE_URL is not set", async () => {
    const d = bundle();
    stubApi();
    const r = await run(["harden", d, "--seed", "1", ...register, "--assess", "T1"], d);
    expect(r.code).toBe(0);
    expect(r.out).toContain(`http://127.0.0.1:3000/apps/${EXAMPLE_BUILD.app_id}/builds/${EXAMPLE_BUILD.build_id}`);
  });

  it("--json carries assessment { id, status }", async () => {
    const d = bundle();
    stubApi();
    const r = await run(["harden", d, "--seed", "1", "--json", ...register, "--assess", "T1"], d);
    expect(r.code).toBe(0);
    const report = JSON.parse(r.out);
    expect(report.assessment).toEqual({ id: QUEUED.id, status: "queued" });
    expect(report.registered).toEqual({ build_id: EXAMPLE_BUILD.build_id });
  });

  it("--json without --assess carries no assessment", async () => {
    const d = bundle();
    stubApi();
    const r = await run(["harden", d, "--seed", "1", "--json", ...register], d);
    expect("assessment" in JSON.parse(r.out)).toBe(false);
  });

  it("a refused upload exits 1 with the reason; the Build stays registered and --out is written", async () => {
    const d = bundle();
    const out = join(tempDir("harden-cli12a-out-"), "out");
    const calls = stubApi({
      status: 400,
      body: {
        type: "about:blank",
        title: "Bad Request",
        status: 400,
        detail: "The artifact does not match the Manifest.",
      },
    });
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...register, "--assess", "T1"], d);
    expect(r.code).toBe(1);
    expect(calls.length).toBe(2);
    expect(r.err).toContain("harden: assessment request failed: The artifact does not match the Manifest.");
    expect(r.err).toContain(`the Build stays registered (${EXAMPLE_BUILD.build_id})`);
    expect(r.out).toContain(`registered: ${EXAMPLE_BUILD.build_id}`);
    expect(existsSync(join(out, "a.mjs"))).toBe(true);
  });

  it("--json on a refused upload carries assessment { error } and exits 1", async () => {
    const d = bundle();
    stubApi({ status: 503, body: {} });
    const r = await run(["harden", d, "--seed", "1", "--json", ...register, "--assess", "T1"], d);
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).assessment).toEqual({ error: "the API responded 503" });
  });

  it("over 1,000 files registers and writes as usual, then skips the upload with the reason and exits 1", async () => {
    const d = bundle();
    for (let i = 0; i < 1000; i++) writeFileSync(join(d, `m${i}.mjs`), `export const v${i} = ${i};\n`);
    const out = join(tempDir("harden-cli12a-out-"), "out");
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--out", out, ...register, "--assess", "T1"], d);
    expect(r.code).toBe(1);
    // Registered, never uploaded.
    expect(calls.length).toBe(1);
    expect(calls[0]?.url.endsWith("/builds")).toBe(true);
    expect(existsSync(join(out, "a.mjs"))).toBe(true);
    expect(existsSync(join(out, "m999.mjs"))).toBe(true);
    expect(r.err).toMatch(
      new RegExp(
        `harden: assessment skipped: .*1,001 files.*at most 1,000; the Build stays registered \\(${EXAMPLE_BUILD.build_id}\\)`,
      ),
    );
    expect(r.out).toContain(`registered: ${EXAMPLE_BUILD.build_id}`);
  }, 60_000);

  it("--json over the limits carries assessment { error } and exits 1", async () => {
    const d = bundle();
    for (let i = 0; i < 1000; i++) writeFileSync(join(d, `m${i}.mjs`), `export const v${i} = ${i};\n`);
    const calls = stubApi();
    const r = await run(["harden", d, "--seed", "1", "--json", ...register, "--assess", "T1"], d);
    expect(r.code).toBe(1);
    expect(calls.length).toBe(1);
    const report = JSON.parse(r.out);
    expect(report.registered).toEqual({ build_id: EXAMPLE_BUILD.build_id });
    expect(report.assessment.error).toMatch(/1,001 files.*at most 1,000/);
  }, 60_000);
});
