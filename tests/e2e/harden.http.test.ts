// Slice 05 over HTTP/CLI: harden the reference web bundle (deterministic, behaviour unchanged), register the
// Build with the API, read it back, and prove tenancy and that only the Manifest leaves the machine.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import { buildManifest, checkEquivalence, harden, registerBuild } from "@antireverse/harden";
import {
  BuildResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  ListBuildsResponseSchema,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const webDir = fileURLToPath(new URL("../../apps/range/web", import.meta.url));
const read = (rel: string) => readFileSync(`${webDir}/${rel}`, "utf8");
const SOURCES = { "src/index.ts": read("src/index.ts"), "src/pricing.ts": read("src/pricing.ts") };
const EQUIV_COMMAND = "node --experimental-strip-types check.ts";

function protectedFiles(seed: number): Record<string, string> {
  const result = harden(SOURCES, { profile: "balanced", seed });
  return Object.fromEntries(result.files.map((f) => [f.path, f.code]));
}

let api: RunningApi;
let adminKey: string;
let appId: string;

async function post(path: string, body: unknown, key?: string): Promise<Response> {
  return fetch(`${api.url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(key ? { authorization: `Bearer ${key}` } : {}) },
    body: JSON.stringify(body),
  });
}

beforeAll(async () => {
  api = await startApi({ logger: { info() {}, warn() {} } });
  const org = CreateOrganizationResponseSchema.parse(await (await post("/v1/organizations", { name: "Acme" })).json());
  adminKey = org.admin_key.key;
  const app = CreateAppResponseSchema.parse(await (await post("/v1/apps", { name: "shop-web" }, adminKey)).json());
  appId = app.app.id;
});

afterAll(async () => {
  await api?.close();
});

describe("slice 05 harden path over HTTP", () => {
  it("is deterministic: the same seed is byte-identical, a different seed differs", () => {
    expect(protectedFiles(1)).toEqual(protectedFiles(1));
    expect(protectedFiles(1)).not.toEqual(protectedFiles(2));
  });

  it("keeps the bundle's behaviour: the original and the protected bundle both pass the bundle's own check", async () => {
    const original = await checkEquivalence({ dir: webDir, testCommand: EQUIV_COMMAND, protectedFiles: {} });
    expect(original.passed, original.output).toBe(true);
    const prot = await checkEquivalence({ dir: webDir, testCommand: EQUIV_COMMAND, protectedFiles: protectedFiles(1) });
    expect(prot.passed, prot.output).toBe(true);
  });

  it("registers a Build and reads it back; only the Manifest leaves the machine", async () => {
    const seed = 7;
    const result = harden(SOURCES, { profile: "balanced", seed });
    const equivalence = (
      await checkEquivalence({
        dir: webDir,
        testCommand: EQUIV_COMMAND,
        protectedFiles: Object.fromEntries(result.files.map((f) => [f.path, f.code])),
      })
    ).passed
      ? "passed"
      : "skipped";
    expect(equivalence).toBe("passed");

    const manifest = buildManifest({
      buildId: newId("bld"),
      appId,
      environment: "development",
      version: "1.0.0",
      profile: "balanced",
      seed,
      artifacts: result.files.map((f) => ({ path: f.path, code: f.code })),
      originals: SOURCES,
      transform: result.transform,
      equivalence,
    });

    // Capture exactly what registerBuild sends, so we can prove no source leaves.
    const sent: { url: string; body: string }[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      sent.push({ url: String(input), body: String(init?.body ?? "") });
      return realFetch(input, init);
    }) as typeof fetch;
    try {
      const registered = await registerBuild({ endpoint: api.url, key: adminKey, appId, manifest });
      expect("build" in registered && registered.build.build_id).toBe(manifest.build_id);
    } finally {
      globalThis.fetch = realFetch;
    }

    // Exactly one request, to the builds route, carrying only { manifest } — no source, no key in the body.
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe(`${api.url}/v1/apps/${appId}/builds`);
    const body = JSON.parse(sent[0]?.body ?? "{}");
    expect(Object.keys(body)).toEqual(["manifest"]);
    const bodyText = sent[0]?.body ?? "";
    for (const leak of ["TIERS", "priceOf", "enterprise-eu", "function", adminKey]) {
      expect(bodyText).not.toContain(leak);
    }

    // The Console-facing reads return it.
    const detail = await fetch(`${api.url}/v1/apps/${appId}/builds/${manifest.build_id}`, {
      headers: { authorization: `Bearer ${adminKey}` },
    });
    expect(detail.status).toBe(200);
    expect(BuildResponseSchema.parse(await detail.json()).build.version).toBe("1.0.0");

    const list = await fetch(`${api.url}/v1/apps/${appId}/builds`, {
      headers: { authorization: `Bearer ${adminKey}` },
    });
    const { builds } = ListBuildsResponseSchema.parse(await list.json());
    expect(builds.some((b) => b.build_id === manifest.build_id)).toBe(true);
  });

  it("keeps a Build away from a second Organization", async () => {
    const other = CreateOrganizationResponseSchema.parse(
      await (await post("/v1/organizations", { name: "Other" })).json(),
    );
    const key = other.admin_key.key;
    expect(
      (await fetch(`${api.url}/v1/apps/${appId}/builds`, { headers: { authorization: `Bearer ${key}` } })).status,
    ).toBe(404);
  });
});
