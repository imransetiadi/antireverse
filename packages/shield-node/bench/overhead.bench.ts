// PB-02: Shield adds p99 <= 0.5 ms per request.
//
// Calls the middleware directly, with minimal request and response doubles, and measures everything Shield does
// for one request: the middleware itself, the accessors the router triggers while it matches, and the 'close'
// listener that builds and buffers the Event. No sockets and no Express: only Shield's own time is measured.
// Prints p50 and p99 in microseconds and exits non-zero when a p99 exceeds the budget.
//
// Every scenario runs twice: under the built-in Policy (no Rules), and with a Policy of 50 Rules applied of which
// none matches the request — the most work `decide` can have, since every Rule is compared and none ends the search.
// A third run adds 100 Canaries (50 decoy keys, 50 decoy routes) to that Policy, and every request carries a bearer
// token, an `x-api-key` header and (in two scenarios) a query string that match none of them: every lookup is made.
// A fourth run adds 150 Containment blocks (75 actor, 75 prefix) and 100 allowlist CIDRs (PB-15). The requests match
// no block, so each pays for the actor hash and both lookups; one more scenario comes from a client inside a blocked
// /24 that only the last allowlist CIDR exempts: the whole allowlist is read and the request still proceeds.
// A fifth run (slice 03) adds three attestation keys to the fourth run's bundle, and every request carries an
// `ar-attestation` header: a valid token seen before (warm, from the cache), a valid token never seen (cold: decode,
// Ed25519 verify, claims, cache insert with LRU eviction), and an invalid token (a forged signature: verified and
// refused every time). These are measured against PB-01 (p99 <= 1.5 ms), the budget of an attested route.
// The same run (slice 04) then measures signed requests against PB-01: `ar-attestation` with a token carrying
// `cnf.jwk`, `ar-signature` and `ar-content-sha256` over a fresh nonce — warm (token and session key cached:
// signature verify and nonce check), cold (token and key never seen: token verify, key import, signature verify,
// nonce insert), and a replay (the same signed headers every time: verify, then the nonce is found). Signed runs make
// fewer iterations so that the fresh nonces of one run stay below the 100,000-entry nonce store.
// A sixth run (slice 20) adds Virtual patches to the fifth run's bundle: 50 patches, as many conditions each as the
// bundle's 16,384-byte `patches` budget allows, measured against PB-01. The conditions are built so that every one
// but the last holds for the benchmark request, and the last fails: every condition of every patch is evaluated and
// no patch decides. 50 patches × 8 such conditions do not fit in the budget, so a last run applies exactly that
// (built in the process, beyond what a bundle can carry) behind the middleware, with the 50 Rules, as the bound of
// the cost (`PATCH_LIMITS`: at most 50 patches × 8 conditions per request).
// A last run (amendment A6, F8) measures the body side: the nine patches of the first catalog (qs, lodash, xml2js;
// copied here, the bench imports nothing of the API) in a bundle, and a benign 100 KB JSON body with `\u00e9`
// escapes (so the JSON-escape form is a second form to scan) through the middleware and `shield.verifyBody`. Each
// distinct form of the body is lower-cased once and every body condition searches it with the native `indexOf`.
// Held to PB-01 (p99 <= 1.5 ms; Jev native_indexof_latin1).
// The limit run (slice 08) applies a bundle of 50 limit Rules, every one of which matches the benchmark request and
// counts it: half count requests (when the request is decided), half count failures (looked at when it is decided,
// counted when its 401 closes); half per address, half per attested device (every request carries a valid, cached
// token); half enforce, half monitor; plus 100 never-block CIDRs, none of which holds the client, so the whole list
// is read. A device Rule counts the device and the address (5 times the limit), so a request updates 75 counters;
// their keys carry a keyed hash of the client, made twice per request (address, device), not once per Rule.
// Measured twice against PB-01: with 1,000 clients (75,000 counters: every hit updates one) and with 4,000 clients
// (300,000 counters wanted in a table of 100,000: every hit inserts a key and drops the idlest one).
import { createHash, createHmac, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { setImmediate as tick } from "node:timers/promises";
import { decide } from "../src/decide.ts";
import { createExpressMiddleware } from "../src/express.ts";
import { createShield, type Shield, type ShieldMiddleware } from "../src/index.ts";
import { createPatchChecker, type PatchInput, readPatch } from "../src/patches.ts";
import { compilePattern } from "../src/policy/match.ts";
import { buildPolicy, routeOfDecision } from "../src/policy/store.ts";

const ITERATIONS = 200_000;
const WARMUP = 20_000;
const BUDGET_P99_US = 500;
/** PB-01: an attested route, Shield's whole overhead. */
const ATTESTED_BUDGET_P99_US = 1_500;
/** Signed runs: their fresh nonces (iterations + warm-up) stay below the nonce store's 100,000 entries. */
const SIGNED_ITERATIONS = 40_000;
const SIGNED_WARMUP = 4_000;

type Routed = IncomingMessage & { baseUrl?: string; params?: Record<string, string>; route?: { path: string } };

class ResponseDouble {
  statusCode = 200;
  headersSent = false;
  close: (() => void) | undefined;
  setHeader(): this {
    return this;
  }
  end(): this {
    this.headersSent = true;
    return this;
  }
  once(event: string, listener: () => void): this {
    if (event === "close") this.close = listener;
    return this;
  }
}

/** Headers of every request of the Canary run: a bearer token and an API key that are no Canary. */
const CANARY_RUN_HEADERS = {
  authorization: `Bearer ak_live_${"N".repeat(32)}`,
  "x-api-key": `ak_live_${"M".repeat(32)}`,
};
const NO_HEADERS = {};

/** The client of every scenario that names none: in no blocked network and no allowlist range. */
const CLIENT = "203.0.113.77";

const requestDouble = (url: string, headers: Record<string, string>, address = CLIENT): Routed =>
  ({ method: "GET", url, headers, socket: { remoteAddress: address } }) as unknown as Routed;

interface Scenario {
  name: string;
  url: string;
  /** The client address. Default: `CLIENT`. */
  address?: string;
  /** What router 2.2.0 assigns on the request while it matches, in its order. */
  route(req: Routed): void;
}

const productRoute = { path: "/api/products/:id" };
const appRoute = { path: "/apps/:appId" };
const noParams = {};

const scenarios: Scenario[] = [
  {
    name: "GET /api/products/:id (route on the application)",
    url: "/api/products/42?token=secret",
    route(req) {
      req.baseUrl = "";
      req.params = noParams; // a middleware layer in front of the route
      req.route = productRoute; // Router.handle
      req.params = { id: "42" };
      req.route = productRoute; // Route.dispatch assigns it again
    },
  },
  {
    name: "GET /orgs/:orgId/apps/:appId (router on a parameterised mount)",
    url: "/orgs/org_0123456789abcdef01234567/apps/app_89abcdef0123456789abcdef",
    route(req) {
      req.baseUrl = "";
      req.params = noParams;
      req.params = { orgId: "org_0123456789abcdef01234567" }; // the mount layer
      req.baseUrl = "/orgs/org_0123456789abcdef01234567";
      req.params = noParams; // the router's own middleware
      req.route = appRoute;
      req.params = { appId: "app_89abcdef0123456789abcdef" };
      req.route = appRoute;
      req.baseUrl = "";
      req.params = undefined as unknown as Record<string, string>; // routing leaves the router
    },
  },
  {
    // Not canonical: every decoding depth and the resolved dot segments are matched as well.
    name: "GET /api/./products/%34%32 (a path with canonical forms)",
    url: "/api/./products/%34%32?token=secret",
    route(req) {
      req.baseUrl = "";
      req.params = noParams;
      req.route = productRoute;
      req.params = { id: "42" };
      req.route = productRoute;
    },
  },
  {
    name: "GET /nothing/here (no route: 404)",
    url: "/nothing/here",
    route(req) {
      req.baseUrl = "";
      req.params = noParams;
    },
  },
];

/** Only in the Containment run: a client in a blocked /24, exempted by the last allowlist CIDR. */
const allowlisted: Scenario = {
  name: "GET /api/products/:id from a blocked /24, exempted by the 100th allowlist CIDR",
  url: "/api/products/42?token=secret",
  address: "198.18.7.9",
  route: scenarios[0]?.route ?? (() => {}),
};

const KEY = `ark_dev_${"A".repeat(43)}`; // synthetic, well-formed
/** The customer-held actor key: every request is hashed with it. Synthetic. */
const ACTOR_KEY = `ck_bench_${"7".repeat(32)}`;
const RULES = 50;
const CANARIES = 100;
const BLOCKS = 150;
const ALLOWLIST = 100;
/** A client one of the actor blocks names: it must be answered 403, to check that the blocks were applied. */
const BLOCKED_CLIENT = "192.0.2.17";

/** The actor hash of an address, as Shield computes it (the bench imports nothing of the protocol). */
function benchActorHash(address: string): string {
  return `iph_${createHmac("sha256", ACTOR_KEY).update(`antireverse/actor/v1\n${address}`, "utf8").digest("hex").slice(0, 32)}`;
}

/**
 * 150 blocks expiring in an hour: 75 actor blocks (192.0.2.0 to 192.0.2.74) and 75 prefix blocks (10.0.0.0/24 to
 * 10.0.74.0/24, and 198.18.7.0/24 for the allowlisted scenario). None names `CLIENT` or its /24.
 */
function hundredFiftyBlocks(): unknown[] {
  const expires = new Date(Date.now() + 3_600_000).toISOString();
  return Array.from({ length: BLOCKS }, (_, i) => {
    const id = `cnt_${i.toString(16).padStart(24, "0")}`;
    if (i < BLOCKS / 2) return { id, kind: "actor", ip_hash: benchActorHash(`192.0.2.${i}`), expires_at: expires };
    const n = i - BLOCKS / 2;
    const ip_prefix = n === 0 ? "198.18.7.0/24" : `10.0.${n}.0/24`;
    return { id, kind: "prefix", ip_prefix, expires_at: expires };
  });
}

/** 100 canonical CIDRs, IPv6 and IPv4 mixed; only the last one contains the allowlisted scenario's client. */
function hundredCidrs(): string[] {
  return Array.from({ length: ALLOWLIST }, (_, i) =>
    i === ALLOWLIST - 1 ? "198.18.7.0/28" : i % 2 === 0 ? `2001:db8:${(i + 1).toString(16)}::/48` : `172.16.${i}.0/24`,
  );
}

/** 100 well-formed Canaries, half decoy keys and half decoy routes, none of which a benchmark request uses. */
function hundredCanaries(): unknown[] {
  return Array.from({ length: CANARIES }, (_, i) => {
    const id = `cny_${i.toString(16).padStart(24, "0")}`;
    return i % 2 === 0
      ? { id, kind: "key", value: `ak_live_${i.toString(36).padStart(32, "Z")}` }
      : { id, kind: "route", value: `/api/internal/${i.toString(36).padStart(8, "q")}/export` };
  });
}

/** A request that uses one of the Canaries, to check that they were applied. */
const DECOY_KEY = `ak_live_${(0).toString(36).padStart(32, "Z")}`;

/**
 * 50 Rules that share their first segments with the benchmark's paths, so that a comparison does not end at the
 * first character, and of which none matches: a star and a literal tail, a `**` below a sibling, method lists.
 */
function fiftyRules(): unknown[] {
  return Array.from({ length: RULES }, (_, i) => {
    const n = String(i).padStart(2, "0");
    const path =
      i % 5 === 0
        ? `/api/products/*/reviews-${n}`
        : i % 5 === 1
          ? `/api/products-${n}/**`
          : i % 5 === 2
            ? `/orgs/*/apps/*/keys-${n}/**`
            : i % 5 === 3
              ? `/nothing/here/${n}`
              : `/api/admin/section-${n}/**`;
    return {
      id: `rul_${i.toString(16).padStart(24, "0")}`,
      path,
      methods: i % 7 === 0 ? ["POST", "PUT", "DELETE"] : [],
      action: "block",
      mode: i % 2 === 0 ? "enforce" : "monitor",
    };
  });
}

/** Three attestation keys (previous, current, next); tokens are signed with the middle one. Synthetic. */
const attestationKeys = [0, 1, 2].map(() => {
  const pair = generateKeyPairSync("ed25519");
  const raw = pair.publicKey.export({ format: "jwk" }).x as string;
  const kid = createHash("sha256").update(Buffer.from(raw, "base64url")).digest("hex").slice(0, 16);
  return { kid, raw, privateKey: pair.privateKey };
});
const TOKEN_KEY = attestationKeys[1] as (typeof attestationKeys)[number];
const APP_ID = "app_89abcdef0123456789abcdef";
const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
const TOKEN_HEADER = b64({ alg: "EdDSA", typ: "JWT", kid: TOKEN_KEY.kid });

/** An Attestation Token as the API signs it: `n` gives a distinct jti. Synthetic claims. */
function attestationToken(n: number): string {
  const iat = Math.floor(Date.now() / 1000);
  const input = `${TOKEN_HEADER}.${b64({
    iss: "antireverse",
    aud: APP_ID,
    sub: "dev_06c43c0cbc18cb7048ab26a1",
    iat,
    exp: iat + 300,
    jti: n.toString(16).padStart(32, "0"),
    cnf: { jkt: "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s" },
    verdict: "suspect",
    risk: 70,
    sig: ["automation.webdriver"],
    pv: 1,
  })}`;
  return `${input}.${sign(null, Buffer.from(input, "ascii"), TOKEN_KEY.privateKey).toString("base64url")}`;
}

/** A P-256 session key as Guard holds one, with its public jwk and RFC 7638 thumbprint. Synthetic. */
function sessionKey(): { privateKey: KeyObject; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; jkt: string } {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const exported = pair.publicKey.export({ format: "jwk" });
  const jwk = { kty: "EC" as const, crv: "P-256" as const, x: exported.x as string, y: exported.y as string };
  const jkt = createHash("sha256")
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }), "utf8")
    .digest("base64url");
  return { privateKey: pair.privateKey, jwk, jkt };
}

/** A token whose `cnf` carries the session key (slice 04). `n` gives a distinct jti. */
function signingToken(n: number, session: ReturnType<typeof sessionKey>): string {
  const iat = Math.floor(Date.now() / 1000);
  const input = `${TOKEN_HEADER}.${b64({
    iss: "antireverse",
    aud: APP_ID,
    sub: "dev_06c43c0cbc18cb7048ab26a1",
    iat,
    exp: iat + 300,
    jti: n.toString(16).padStart(32, "0"),
    cnf: { jkt: session.jkt, jwk: session.jwk },
    verdict: "trusted",
    risk: 5,
    sig: [],
    pv: 1,
  })}`;
  return `${input}.${sign(null, Buffer.from(input, "ascii"), TOKEN_KEY.privateKey).toString("base64url")}`;
}

const EMPTY_SHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

/** The signed headers of one GET without a body, as Guard sends them, with a fresh 128-bit nonce. */
function signedHeaders(
  target: string,
  token: string,
  n: number,
  session: ReturnType<typeof sessionKey>,
): Record<string, string> {
  const t = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString("base64url");
  const jti = n.toString(16).padStart(32, "0");
  // No body and no content-type: the content-type line is empty (review F1).
  const canonical = `ar-sig-v1\nGET\n${target}\n\n${EMPTY_SHA256}\n${t}\n${nonce}\n${jti}`;
  const s = sign("sha256", Buffer.from(canonical, "utf8"), { key: session.privateKey, dsaEncoding: "ieee-p1363" });
  return {
    "ar-attestation": token,
    "ar-signature": `v1,t=${t},n=${nonce},s=${s.toString("base64url")}`,
    "ar-content-sha256": EMPTY_SHA256,
  };
}

/** Patches in the bundle and conditions in a patch at most (`PATCH_LIMITS` of the protocol). */
const PATCHES = 50;
const CONDITIONS_MAX = 8;
const PATCH_BUDGET_BYTES = 16_384;
/** The query key of the probe patch: a request that carries it is refused, to check that the patches were applied. */
const PROBE_KEY = "__bench_probe__";

/**
 * Conditions that all hold for the first scenario's request (`GET /api/products/42?token=secret` with the Canary
 * run's headers), each a different target and operator; the patch's last condition (`failing`) never holds.
 */
const HOLDING = [
  { target: "path", op: "contains", value: "products" },
  { target: "query_key", op: "equals", value: "token" },
  { target: "query_value", name: "token", op: "starts_with", value: "sec" },
  { target: "header", name: "x-api-key", op: "contains", value: "ak_live_" },
  { target: "header_name", op: "ends_with", value: "-key" },
  { target: "method", op: "equals", value: "GET" },
  { target: "path", op: "length_over", value: "5" },
];
const failing = (i: number) => ({ target: "query_value", op: "contains", value: `no-such-value-${i}` });

/**
 * `count` patches of `conditions` conditions each (all holding but the last), alternately enforce and monitor; with
 * `probe`, the first is replaced by an enforced patch on `PROBE_KEY`.
 */
function benchPatches(count: number, conditions: number, probe: boolean): PatchInput[] {
  return Array.from({ length: count }, (_, i) => {
    const id = `vp_bench_${String(i).padStart(2, "0")}`;
    if (probe && i === 0) {
      return {
        id,
        mode: "enforce",
        conditions: [{ target: "query_key", op: "equals", value: PROBE_KEY }],
        advisory: "CVE-2026-10001",
      } as PatchInput;
    }
    return {
      id,
      mode: i % 2 === 0 ? "enforce" : "monitor",
      conditions: [...HOLDING.slice(0, conditions - 1), failing(i)],
      advisory: "CVE-2026-10001",
    } as PatchInput;
  });
}

/** The most conditions per patch (≤ 8) for which 50 patches fit in the bundle's patch budget. */
const BUNDLE_CONDITIONS = (() => {
  for (let c = CONDITIONS_MAX; c >= 1; c--) {
    if (Buffer.byteLength(JSON.stringify(benchPatches(PATCHES, c, true)), "utf8") <= PATCH_BUDGET_BYTES) return c;
  }
  return 1;
})();

/** What the API would answer for `GET /v1/policy-bundle`: a bundle of 50 Rules, signed with `privateKey`. */
const signing = generateKeyPairSync("ed25519");
function signedBundle(
  withCanaries: boolean,
  withContainment: boolean,
  withAttestation = false,
  withPatches = false,
): string {
  const bundle = JSON.stringify({
    format: 1,
    audience: createHash("sha256").update(KEY, "utf8").digest("hex").slice(0, 32),
    epoch: "0123456789abcdef0123456789abcdef",
    app_id: APP_ID,
    environment: "development",
    version: 1,
    issued_at: new Date().toISOString(),
    not_after: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    rules: fiftyRules(),
    ...(withCanaries ? { canaries: hundredCanaries() } : {}),
    ...(withContainment ? { blocks: hundredFiftyBlocks(), allowlist: hundredCidrs() } : {}),
    ...(withAttestation
      ? { attestation_keys: attestationKeys.map((key) => ({ kid: key.kid, public_key: key.raw })) }
      : {}),
    ...(withPatches ? { patches: benchPatches(PATCHES, BUNDLE_CONDITIONS, true) } : {}),
  });
  const signature = sign(null, Buffer.from(bundle, "utf8"), signing.privateKey).toString("base64url");
  return JSON.stringify({ bundle, signature, key_id: "0123456789abcdef" });
}

type Run = "built-in" | "rules" | "canaries" | "containment" | "attestation" | "patches";

/** Batch bodies handed to the transport, kept only until the Canary check has read them. */
let sentBodies: string[] = [];

function makeShield(run: Run): Shield {
  const withRules = run !== "built-in";
  return createShield({
    key: KEY,
    endpoint: "http://127.0.0.1:9",
    disabled: false,
    actorKey: ACTOR_KEY,
    flushIntervalMs: 50,
    // Batches are built and handed over, nothing is sent; the Policy request is answered from memory.
    transport: async (request) => {
      if (request.method === "GET") {
        const full = run === "containment" || run === "attestation" || run === "patches";
        const attested = run === "attestation" || run === "patches";
        const body = signedBundle(run === "canaries" || full, full, attested, run === "patches");
        return { status: 200, body, etag: '"bench"' };
      }
      if (sentBodies.length < 10) sentBodies.push(request.body ?? "");
      return { status: 202 };
    },
    logger: { warn: () => {} },
    ...(withRules
      ? { policyPublicKey: signing.publicKey.export({ format: "jwk" }).x as string, policyPollIntervalMs: 3_600_000 }
      : {}),
  });
}

const next = (): void => {};

async function measure(
  middleware: ShieldMiddleware,
  scenario: Scenario,
  headers: Record<string, string>,
  /** Headers of iteration `i`, made before its timer starts. Left out: `headers` for every iteration. */
  headersOf?: (i: number) => Record<string, string>,
  iterations = ITERATIONS,
  warmup = WARMUP,
): Promise<{ p50: number; p99: number; max: number; mean: number }> {
  const ITERATIONS = iterations;
  const nanos = new Float64Array(ITERATIONS);
  for (let i = -warmup; i < ITERATIONS; i++) {
    const req = requestDouble(scenario.url, headersOf ? headersOf(i) : headers, scenario.address);
    const res = new ResponseDouble();
    const started = process.hrtime.bigint();
    middleware(req, res as unknown as ServerResponse, next);
    scenario.route(req);
    res.close?.();
    const elapsed = Number(process.hrtime.bigint() - started);
    if (i >= 0) nanos[i] = elapsed;
    if (res.close === undefined) throw new Error("the middleware did not listen for 'close'");
    if (res.statusCode !== 200) throw new Error(`${scenario.name} was answered ${res.statusCode}`);
    if (i % 1_000 === 0) await tick(); // let the flush timer run, as it does between real requests
  }
  let sum = 0;
  for (const value of nanos) sum += value;
  nanos.sort();
  const at = (quantile: number): number =>
    (nanos[Math.min(ITERATIONS - 1, Math.floor(ITERATIONS * quantile))] as number) / 1_000;
  return { p50: at(0.5), p99: at(0.99), max: at(1), mean: sum / ITERATIONS / 1_000 };
}

console.log(`Shield overhead per request: ${ITERATIONS.toLocaleString("en-US")} direct middleware calls per scenario`);
console.log(`node ${process.version}, budget PB-02: p99 <= ${BUDGET_P99_US} µs`);
let worst = 0;
let worstAttested = 0;
let internalErrors = 0;
const attestedResults: string[] = [];
for (const run of ["built-in", "rules", "canaries", "containment", "attestation", "patches"] as const) {
  const withRules = run !== "built-in";
  const shield = makeShield(run);
  if (withRules) {
    await shield.refreshPolicy();
    const applied = shield.stats();
    if (applied.policyRules !== RULES || applied.lastPolicyError !== null) {
      console.error(`FAIL: the Policy of ${RULES} Rules was not applied (${applied.lastPolicyError}).`);
      process.exit(1);
    }
    // None of the Rules may match a benchmark path, or the scenario would measure a block instead of the search.
    for (const scenario of scenarios) {
      const decision = shield.decide({ method: "GET", path: scenario.url });
      if (decision.action !== "allow" || decision.policyVersion !== 1) {
        console.error(`FAIL: a Rule matches ${scenario.url}; the benchmark needs a path that matches none.`);
        process.exit(1);
      }
    }
  }
  const middleware = shield.express();
  if (run === "patches") {
    // The patches must be applied: the probe patch refuses a request that carries its key, and nothing of the
    // request (its query) leaves the process.
    sentBodies = [];
    const res = new ResponseDouble();
    middleware(requestDouble(`/check?${PROBE_KEY}=1`, NO_HEADERS), res as unknown as ServerResponse, next);
    res.close?.();
    await shield.flush();
    const sent = sentBodies.join("\n");
    if (res.statusCode !== 403 || !sent.includes('"patch_id":"vp_bench_00","patch_body":"checked"')) {
      console.error(`FAIL: the ${PATCHES} patches were not applied (the probe was answered ${res.statusCode}).`);
      process.exit(1);
    }
    if (sent.includes(PROBE_KEY)) {
      console.error("FAIL: a query key left the process.");
      process.exit(1);
    }
    sentBodies = [];
    console.log(
      `\nAs the attestation run, plus ${PATCHES} Virtual patches × ${BUNDLE_CONDITIONS} conditions (the most that fit in the ${PATCH_BUDGET_BYTES}-byte patch budget; all but the last hold, none decides); every request carries the Canary run's headers (budget PB-01: p99 <= ${ATTESTED_BUDGET_P99_US} µs)`,
    );
    for (const scenario of scenarios) {
      const result = await measure(middleware, scenario, CANARY_RUN_HEADERS);
      worstAttested = Math.max(worstAttested, result.p99);
      const line = `p50 ${result.p50.toFixed(2)} µs   p99 ${result.p99.toFixed(2)} µs   mean ${result.mean.toFixed(2)} µs   max ${result.max.toFixed(2)} µs`;
      attestedResults.push(`patches, ${scenario.name}: ${line}`);
      console.log(`  ${scenario.name}`);
      console.log(`    ${line}`);
    }
    await shield.close();
    const stats = shield.stats();
    internalErrors += stats.internalErrors;
    console.log(
      `  Events: ${stats.sent.toLocaleString("en-US")} handed to the transport, ${stats.dropped.toLocaleString("en-US")} dropped by the full buffer, ${stats.internalErrors} internal errors`,
    );
    continue;
  }
  if (run === "canaries" || run === "containment" || run === "attestation") {
    // The Canaries must be applied, or the run would measure nothing new: a decoy key must add its signal.
    sentBodies = [];
    const res = new ResponseDouble();
    middleware(requestDouble("/check", { "x-api-key": DECOY_KEY }), res as unknown as ServerResponse, next);
    res.close?.();
    await shield.flush();
    if (!sentBodies.some((body) => body.includes('"canary.touched:cny_000000000000000000000000"'))) {
      console.error(`FAIL: the ${CANARIES} Canaries were not applied.`);
      process.exit(1);
    }
    if (sentBodies.some((body) => body.includes(DECOY_KEY))) {
      console.error("FAIL: a decoy key left the process.");
      process.exit(1);
    }
    sentBodies = [];
  }
  if (run === "attestation") {
    // The keys must be applied: a valid token is recorded as valid, a forged one as invalid, and no token leaves.
    const valid = attestationToken(1);
    const forged = `${valid.slice(0, valid.lastIndexOf("."))}.${attestationToken(2).split(".")[2]}`;
    for (const token of [valid, forged]) {
      const res = new ResponseDouble();
      middleware(requestDouble("/check", { "ar-attestation": token }), res as unknown as ServerResponse, next);
      res.close?.();
    }
    await shield.flush();
    const sent = sentBodies.join("\n");
    if (!sent.includes('"attestation":{"status":"valid","verdict":"suspect","risk":70}')) {
      console.error("FAIL: the attestation keys were not applied (a valid token was not recorded as valid).");
      process.exit(1);
    }
    if (!sent.includes('"attestation":{"status":"invalid","verdict":null,"risk":null}')) {
      console.error("FAIL: a forged token was not recorded as invalid.");
      process.exit(1);
    }
    if (sent.includes(valid.split(".")[2] as string) || sent.includes(TOKEN_HEADER)) {
      console.error("FAIL: a token left the process.");
      process.exit(1);
    }
    sentBodies = [];
  }
  if (run === "containment") {
    // The blocks must be applied: a client an actor block names, and one in a blocked /24, are answered 403.
    for (const address of [BLOCKED_CLIENT, "10.0.1.5"]) {
      const res = new ResponseDouble();
      middleware(requestDouble("/check", NO_HEADERS, address), res as unknown as ServerResponse, next);
      res.close?.();
      if (res.statusCode !== 403) {
        console.error(`FAIL: the ${BLOCKS} blocks were not applied (a blocked client was answered ${res.statusCode}).`);
        process.exit(1);
      }
    }
    await shield.flush();
    if (sentBodies.some((body) => body.includes(BLOCKED_CLIENT) || body.includes("10.0.1.5"))) {
      console.error("FAIL: a client address left the process.");
      process.exit(1);
    }
    sentBodies = [];
  }
  if (run === "attestation") {
    console.log(
      `\nAs the previous run, plus ${attestationKeys.length} attestation keys; every request carries an ar-attestation header (budget PB-01: p99 <= ${ATTESTED_BUDGET_P99_US} µs)`,
    );
    const warmToken = attestationToken(1);
    const validToken = attestationToken(3);
    const forgedToken = `${validToken.slice(0, validToken.lastIndexOf("."))}.${attestationToken(4).split(".")[2]}`;
    let fresh = 1_000_000;
    const attested: [string, (i: number) => Record<string, string>][] = [
      ["valid token, cached (warm)", () => ({ ...CANARY_RUN_HEADERS, "ar-attestation": warmToken })],
      [
        "valid token, first seen (cold)",
        () => ({ ...CANARY_RUN_HEADERS, "ar-attestation": attestationToken(fresh++) }),
      ],
      ["invalid token (forged signature)", () => ({ ...CANARY_RUN_HEADERS, "ar-attestation": forgedToken })],
    ];
    const base = scenarios[0] as Scenario;
    for (const [name, headersOf] of attested) {
      const result = await measure(middleware, base, NO_HEADERS, headersOf);
      worstAttested = Math.max(worstAttested, result.p99);
      const line = `p50 ${result.p50.toFixed(2)} µs   p99 ${result.p99.toFixed(2)} µs   mean ${result.mean.toFixed(2)} µs   max ${result.max.toFixed(2)} µs`;
      attestedResults.push(`${name}: ${line}`);
      console.log(`  ${base.name}, ${name}`);
      console.log(`    ${line}`);
    }

    // Signed requests (slice 04). First check that they are verified: valid, then replayed, and nothing leaks.
    const warmSession = sessionKey();
    const warmSigning = signingToken(7, warmSession);
    await shield.flush(); // the Events of the runs above go first
    sentBodies = [];
    const probe = signedHeaders(base.url, warmSigning, 7, warmSession);
    for (let k = 0; k < 2; k++) {
      const res = new ResponseDouble();
      middleware(requestDouble(base.url, probe), res as unknown as ServerResponse, next);
      res.close?.();
    }
    await shield.flush();
    const sentSigned = sentBodies.join("\n");
    if (
      !sentSigned.includes('"signature":{"status":"valid","body":"none"}') ||
      !sentSigned.includes('"signature":{"status":"replayed","body":"none"}')
    ) {
      console.error("FAIL: a signed request was not recorded valid, or its replay not recorded replayed.");
      console.error(
        sentSigned
          .match(/"signature":\{[^}]*\}/g)
          ?.slice(0, 4)
          .join(" ") ?? "no signature recorded",
      );
      process.exit(1);
    }
    const probeSignature = (probe["ar-signature"] as string).split("s=")[1] as string;
    if (sentSigned.includes(probeSignature) || sentSigned.includes(EMPTY_SHA256)) {
      console.error("FAIL: a signature or a content hash left the process.");
      process.exit(1);
    }
    sentBodies = [];
    console.log(`\n  Signed requests (${SIGNED_ITERATIONS.toLocaleString("en-US")} calls each, budget PB-01)`);
    let coldN = 2_000_000;
    const replay = signedHeaders(base.url, warmSigning, 7, warmSession);
    const signedRuns: [string, (i: number) => Record<string, string>][] = [
      [
        "signed, token and key cached (warm): signature + nonce",
        () => ({ ...CANARY_RUN_HEADERS, ...signedHeaders(base.url, warmSigning, 7, warmSession) }),
      ],
      [
        "signed, token and key first seen (cold): token + key import + signature + nonce",
        () => {
          const session = sessionKey();
          const n = coldN++;
          return { ...CANARY_RUN_HEADERS, ...signedHeaders(base.url, signingToken(n, session), n, session) };
        },
      ],
      ["signed, replayed (same headers every time)", () => ({ ...CANARY_RUN_HEADERS, ...replay })],
    ];
    for (const [name, headersOf] of signedRuns) {
      const result = await measure(middleware, base, NO_HEADERS, headersOf, SIGNED_ITERATIONS, SIGNED_WARMUP);
      worstAttested = Math.max(worstAttested, result.p99);
      const line = `p50 ${result.p50.toFixed(2)} µs   p99 ${result.p99.toFixed(2)} µs   mean ${result.mean.toFixed(2)} µs   max ${result.max.toFixed(2)} µs`;
      attestedResults.push(`${name}: ${line}`);
      console.log(`  ${base.name}, ${name}`);
      console.log(`    ${line}`);
    }
    await shield.close();
    const stats = shield.stats();
    internalErrors += stats.internalErrors;
    console.log(
      `  Events: ${stats.sent.toLocaleString("en-US")} handed to the transport, ${stats.dropped.toLocaleString("en-US")} dropped by the full buffer, ${stats.internalErrors} internal errors`,
    );
    continue;
  }
  console.log(
    run === "containment"
      ? `\nPolicy version 1 with ${RULES} Rules, ${CANARIES} Canaries, ${BLOCKS} blocks and ${ALLOWLIST} allowlist CIDRs applied; no request is blocked`
      : run === "canaries"
        ? `\nPolicy version 1 with ${RULES} Rules and ${CANARIES} Canaries applied; every request carries a bearer token and an x-api-key that are no Canary`
        : withRules
          ? `\nPolicy version 1 with ${RULES} Rules applied, none of which matches`
          : "\nBuilt-in Policy (no Rules)",
  );
  const headers = run === "canaries" || run === "containment" ? CANARY_RUN_HEADERS : NO_HEADERS;
  for (const scenario of run === "containment" ? [...scenarios, allowlisted] : scenarios) {
    const result = await measure(middleware, scenario, headers);
    worst = Math.max(worst, result.p99);
    console.log(`  ${scenario.name}`);
    console.log(
      `    p50 ${result.p50.toFixed(2)} µs   p99 ${result.p99.toFixed(2)} µs   mean ${result.mean.toFixed(2)} µs   max ${result.max.toFixed(2)} µs`,
    );
  }
  await shield.close();
  const stats = shield.stats();
  internalErrors += stats.internalErrors;
  console.log(
    `  Events: ${stats.sent.toLocaleString("en-US")} handed to the transport, ${stats.dropped.toLocaleString("en-US")} dropped by the full buffer, ${stats.internalErrors} internal errors`,
  );
}
// The bound of the cost: 50 patches × 8 conditions, which no bundle can carry within its patch budget, applied in the
// process behind the middleware together with the 50 Rules. Measured against PB-01.
{
  const patches = benchPatches(PATCHES, CONDITIONS_MAX, false).map((patch) => {
    const read = readPatch(patch);
    if (typeof read === "string") throw new Error(`bench patch: ${read}`);
    return read;
  });
  const rules = (fiftyRules() as { id: string; path: string; methods: string[]; mode: "monitor" | "enforce" }[]).map(
    (rule) => {
      const pattern = compilePattern(rule.path);
      if (pattern === null) throw new Error("bench rule");
      return { ...rule, pattern };
    },
  );
  const policy = buildPolicy({
    version: 1,
    issuedAt: Date.now(),
    notAfter: Date.now() + 86_400_000,
    rules,
    patches,
  });
  const checker = createPatchChecker();
  let recorded = 0;
  let errors = 0;
  const middleware = createExpressMiddleware({
    decide: (input) => decide(policy, input),
    patches: (request, method, recordMonitor) => checker.evaluate(policy, request, method, false, recordMonitor),
    routeOf: routeOfDecision,
    record: () => {
      recorded += 1;
    },
    now: Date.now,
    clientAddress: undefined,
    onInternalError: () => {
      errors += 1;
    },
  });
  const base = scenarios[0] as Scenario;
  const result = await measure(middleware, base, CANARY_RUN_HEADERS);
  worstAttested = Math.max(worstAttested, result.p99);
  internalErrors += errors;
  const line = `p50 ${result.p50.toFixed(2)} µs   p99 ${result.p99.toFixed(2)} µs   mean ${result.mean.toFixed(2)} µs   max ${result.max.toFixed(2)} µs`;
  attestedResults.push(`${PATCHES} patches × ${CONDITIONS_MAX} conditions (bound): ${line}`);
  console.log(
    `\n${PATCHES} patches × ${CONDITIONS_MAX} conditions (the cost bound, beyond the bundle budget: applied in the process) and ${RULES} Rules, middleware only (budget PB-01)`,
  );
  console.log(`  ${base.name}`);
  console.log(`    ${line}`);
  console.log(`  Events: ${recorded.toLocaleString("en-US")} recorded, ${errors} internal errors`);
}

// The body side (A6, F8): the first catalog's patches against a 100 KB JSON body, middleware + verifyBody + close.
{
  const CATALOG_PATCHES = [
    { id: "vp_qs_proto_query_key", conditions: [{ target: "query_key", op: "contains", value: "__proto__" }] },
    { id: "vp_qs_proto_form_body", conditions: [{ target: "body", op: "contains", value: "[__proto__]" }] },
    {
      id: "vp_lodash_constructor_prototype",
      conditions: [
        { target: "body", op: "json_key", value: "constructor" },
        { target: "body", op: "json_key", value: "prototype" },
      ],
    },
    {
      id: "vp_lodash_constructor_prototype_query",
      conditions: [{ target: "query_key", op: "contains", value: "constructor[prototype]" }],
    },
    {
      id: "vp_lodash_constructor_prototype_form",
      conditions: [{ target: "body", op: "contains", value: "constructor[prototype]" }],
    },
    {
      id: "vp_lodash_proto_json",
      conditions: [
        { target: "header", name: "content-type", op: "contains", value: "json" },
        { target: "body", op: "json_key", value: "__proto__" },
      ],
    },
    { id: "vp_lodash_proto_path", conditions: [{ target: "body", op: "contains", value: "__proto__." }] },
    {
      id: "vp_lodash_constructor_path",
      conditions: [{ target: "body", op: "contains", value: "constructor.prototype" }],
    },
    { id: "vp_xml2js_proto_element", conditions: [{ target: "body", op: "contains", value: "<__proto__" }] },
  ].map((patch) => ({ ...patch, mode: "enforce", advisory: "CVE-2026-10001" }));
  const bundle = JSON.stringify({
    format: 1,
    audience: createHash("sha256").update(KEY, "utf8").digest("hex").slice(0, 32),
    epoch: "0123456789abcdef0123456789abcdef",
    app_id: APP_ID,
    environment: "development",
    version: 1,
    issued_at: new Date().toISOString(),
    not_after: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    rules: fiftyRules(),
    patches: CATALOG_PATCHES,
  });
  const envelope = JSON.stringify({
    bundle,
    signature: sign(null, Buffer.from(bundle, "utf8"), signing.privateKey).toString("base64url"),
    key_id: "0123456789abcdef",
  });
  const shield = createShield({
    key: KEY,
    endpoint: "http://127.0.0.1:9",
    disabled: false,
    actorKey: ACTOR_KEY,
    flushIntervalMs: 50,
    transport: async (request) =>
      request.method === "GET" ? { status: 200, body: envelope, etag: '"body"' } : { status: 202 },
    logger: { warn: () => {} },
    policyPublicKey: signing.publicKey.export({ format: "jwk" }).x as string,
    policyPollIntervalMs: 3_600_000,
  });
  await shield.refreshPolicy();
  const items: unknown[] = [];
  let json = "";
  for (let i = 0; JSON.stringify({ items }).length < 100 * 1024; i++) {
    items.push({ id: i, name: `item\u00e9 ${i}`, tags: ["a", "b"], price: i * 3 });
  }
  // `é` written as the JSON escape `é`: the body then has a second, JSON-escape-decoded form to scan.
  json = JSON.stringify({ items }).replaceAll("é", "\\u00e9");
  if (!json.includes("\\u00e9")) throw new Error("the bench body has no JSON escape");
  const buffer = Buffer.from(json, "utf8");
  const headers = { "content-type": "application/json", "content-length": String(buffer.length) };
  const middleware = shield.express();
  const ROUNDS = 2_000;
  const nanos = new Float64Array(ROUNDS);
  for (let i = -200; i < ROUNDS; i++) {
    const req = { ...requestDouble("/api/items", headers), method: "POST" } as unknown as Routed;
    const res = new ResponseDouble();
    const started = process.hrtime.bigint();
    middleware(req, res as unknown as ServerResponse, next);
    shield.verifyBody(req, res as unknown as ServerResponse, buffer, "utf8");
    res.close?.();
    const elapsed = Number(process.hrtime.bigint() - started);
    if (i >= 0) nanos[i] = elapsed;
    if (res.statusCode !== 200) throw new Error("the benign 100 KB body was refused");
    if (i % 100 === 0) await tick();
  }
  // The patches must be applied: the same body with a lodash key is refused.
  const probe = Buffer.from(json.replace('"items"', '"constructor":{"prototype":{}},"items"'), "utf8");
  let refused = false;
  try {
    const req = { ...requestDouble("/api/items", headers), method: "POST" } as unknown as Routed;
    middleware(req, new ResponseDouble() as unknown as ServerResponse, next);
    shield.verifyBody(req, new ResponseDouble() as unknown as ServerResponse, probe, "utf8");
  } catch {
    refused = true;
  }
  if (!refused) {
    console.error("FAIL: the catalog patches were not applied to the body.");
    process.exit(1);
  }
  nanos.sort();
  const at = (quantile: number): number =>
    (nanos[Math.min(ROUNDS - 1, Math.floor(ROUNDS * quantile))] as number) / 1_000;
  let sum = 0;
  for (const value of nanos) sum += value;
  console.log(
    `\nThe first catalog's ${CATALOG_PATCHES.length} patches and ${RULES} Rules; a benign ${(buffer.length / 1024).toFixed(1)} KB JSON body with \\u escapes through the middleware and verifyBody (${ROUNDS.toLocaleString("en-US")} calls; budget PB-01: p99 <= ${ATTESTED_BUDGET_P99_US} µs)`,
  );
  console.log(
    `  p50 ${at(0.5).toFixed(2)} µs   p99 ${at(0.99).toFixed(2)} µs   mean ${(sum / ROUNDS / 1_000).toFixed(2)} µs   max ${at(1).toFixed(2)} µs`,
  );
  worstAttested = Math.max(worstAttested, at(0.99));
  await shield.close();
  internalErrors += shield.stats().internalErrors;
}

// Limit Rules (slice 08): 50 limit Rules matched and counted per request, middleware + the 401 of the handler + close.
{
  const LIMIT_RULES = 50;
  /** Above what one counter sees in a measured run, so that no measured request is throttled. */
  const THRESHOLD = 1_000;
  /** Counters one client touches: one per address Rule, two per device Rule (the device and its address). */
  const COUNTERS_PER_CLIENT = LIMIT_RULES / 2 + (LIMIT_RULES / 2) * 2;
  const LIMIT_PATHS = ["/api/products/*", "/api/**", "/**", "/api/products/42", "/api/*/42"];
  const limitRules = Array.from({ length: LIMIT_RULES }, (_, i) => ({
    id: `rul_${(0x100 + i).toString(16).padStart(24, "0")}`,
    path: LIMIT_PATHS[i % LIMIT_PATHS.length],
    methods: i % 3 === 0 ? [] : ["GET"],
    action: "throttle",
    mode: i % 4 < 2 ? "enforce" : "monitor",
    limit: {
      requests: THRESHOLD,
      window_s: 3_600,
      key: i % 2 === 0 ? "ip" : "device",
      count: i % 4 === 0 || i % 4 === 3 ? "requests" : "failures",
    },
  }));
  const bundle = JSON.stringify({
    format: 1,
    audience: createHash("sha256").update(KEY, "utf8").digest("hex").slice(0, 32),
    epoch: "0123456789abcdef0123456789abcdef",
    app_id: APP_ID,
    environment: "development",
    version: 1,
    issued_at: new Date().toISOString(),
    not_after: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    rules: [],
    allowlist: hundredCidrs(),
    attestation_keys: attestationKeys.map((key) => ({ kid: key.kid, public_key: key.raw })),
    limit_rules: limitRules,
  });
  const envelope = JSON.stringify({
    bundle,
    signature: sign(null, Buffer.from(bundle, "utf8"), signing.privateKey).toString("base64url"),
    key_id: "0123456789abcdef",
  });
  let limitBodies: string[] = [];
  const shield = createShield({
    key: KEY,
    endpoint: "http://127.0.0.1:9",
    disabled: false,
    actorKey: ACTOR_KEY,
    flushIntervalMs: 50,
    transport: async (request) => {
      if (request.method === "GET") return { status: 200, body: envelope, etag: '"limits"' };
      if (limitBodies.length < 50) limitBodies.push(request.body ?? "");
      return { status: 202 };
    },
    logger: { warn: () => {} },
    policyPublicKey: signing.publicKey.export({ format: "jwk" }).x as string,
    policyPollIntervalMs: 3_600_000,
  });
  await shield.refreshPolicy();
  const applied = shield.stats();
  if (applied.policyRules !== LIMIT_RULES || applied.lastPolicyError !== null) {
    console.error(`FAIL: the Policy of ${LIMIT_RULES} limit Rules was not applied (${applied.lastPolicyError}).`);
    process.exit(1);
  }
  /** A valid token of device `n`. */
  const deviceToken = (n: number): string => {
    const iat = Math.floor(Date.now() / 1000);
    const input = `${TOKEN_HEADER}.${b64({
      iss: "antireverse",
      aud: APP_ID,
      sub: `dev_${n.toString(16).padStart(24, "0")}`,
      iat,
      exp: iat + 300,
      jti: (0x7000_0000 + n).toString(16).padStart(32, "0"),
      cnf: { jkt: "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s" },
      verdict: "trusted",
      risk: 5,
      sig: [],
      pv: 1,
    })}`;
    return `${input}.${sign(null, Buffer.from(input, "ascii"), TOKEN_KEY.privateKey).toString("base64url")}`;
  };
  const middleware = shield.express();
  const base = scenarios[0] as Scenario;
  const lines: string[] = [];
  console.log(
    `\n${LIMIT_RULES} limit Rules, all matched and counted per request (requests and failures, per address and per attested device, enforce and monitor), ${ALLOWLIST} never-block CIDRs; every request carries a valid cached token and is answered 401 (budget PB-01: p99 <= ${ATTESTED_BUDGET_P99_US} µs)`,
  );
  for (const clients of [1_000, 4_000]) {
    // Tokens are made here, per run, so that none expires while it is measured.
    const tokens = Array.from({ length: clients }, (_, n) => ({
      ...CANARY_RUN_HEADERS,
      "ar-attestation": deviceToken(clients * 10 + n),
    }));
    const nanos = new Float64Array(ITERATIONS);
    for (let i = -WARMUP; i < ITERATIONS; i++) {
      const n = (i + WARMUP) % clients;
      const req = requestDouble(
        base.url,
        tokens[n] as Record<string, string>,
        `10.${clients / 1_000}.${n >> 8}.${n & 255}`,
      );
      const res = new ResponseDouble();
      const started = process.hrtime.bigint();
      middleware(req, res as unknown as ServerResponse, next);
      base.route(req);
      if (res.statusCode === 200) res.statusCode = 401; // the handler refuses the credentials
      res.close?.();
      const elapsed = Number(process.hrtime.bigint() - started);
      if (i >= 0) nanos[i] = elapsed;
      if (res.statusCode !== 401) throw new Error(`a measured request was answered ${res.statusCode}`);
      if (i % 1_000 === 0) await tick();
    }
    let sum = 0;
    for (const value of nanos) sum += value;
    nanos.sort();
    const at = (quantile: number): number =>
      (nanos[Math.min(ITERATIONS - 1, Math.floor(ITERATIONS * quantile))] as number) / 1_000;
    worstAttested = Math.max(worstAttested, at(0.99));
    const line = `p50 ${at(0.5).toFixed(2)} µs   p99 ${at(0.99).toFixed(2)} µs   mean ${(sum / ITERATIONS / 1_000).toFixed(2)} µs   max ${at(1).toFixed(2)} µs`;
    const name =
      clients === 1_000
        ? `${clients.toLocaleString("en-US")} clients (${(clients * COUNTERS_PER_CLIENT).toLocaleString("en-US")} counters, every hit an update)`
        : `${clients.toLocaleString("en-US")} clients (${(clients * COUNTERS_PER_CLIENT).toLocaleString("en-US")} counters wanted, table full: every hit an insert and an eviction)`;
    lines.push(`${LIMIT_RULES} limit Rules, ${name}: ${line}`);
    console.log(`  ${base.name}, ${name}`);
    console.log(`    ${line}`);
  }
  for (const line of lines) attestedResults.push(line);
  // The limits must be applied: a fresh client is served `THRESHOLD` times and then answered 429 with Retry-After.
  await shield.flush();
  limitBodies = [];
  const probeToken = { "ar-attestation": deviceToken(999_999) };
  let served = 0;
  let throttledStatus = 0;
  let retryAfter = "";
  for (let i = 0; i <= THRESHOLD; i++) {
    const res = new ResponseDouble();
    res.setHeader = function (this: ResponseDouble, name?: string, value?: string) {
      if (name === "retry-after") retryAfter = String(value);
      return this;
    } as ResponseDouble["setHeader"];
    middleware(requestDouble(base.url, probeToken, "192.168.77.5"), res as unknown as ServerResponse, next);
    res.close?.();
    if (res.statusCode === 200) served += 1;
    else throttledStatus = res.statusCode;
    if (i % 100 === 0) await tick();
  }
  await shield.flush();
  const sentLimits = limitBodies.join("\n");
  if (served !== THRESHOLD || throttledStatus !== 429 || !/^[1-9][0-9]*$/.test(retryAfter)) {
    console.error(
      `FAIL: the limit Rules were not applied (${served} of ${THRESHOLD + 1} probe requests served, then ${throttledStatus}, Retry-After "${retryAfter}").`,
    );
    process.exit(1);
  }
  if (!sentLimits.includes('"action":"throttle","mode":"enforce"')) {
    console.error("FAIL: the throttled probe request was not recorded as throttle.");
    process.exit(1);
  }
  if (sentLimits.includes("192.168.77.5") || sentLimits.includes("dev_")) {
    console.error("FAIL: a counter key (an address or a device id) left the process.");
    process.exit(1);
  }
  await shield.close();
  const stats = shield.stats();
  internalErrors += stats.internalErrors;
  console.log(
    `  Probe: a fresh client was served ${served.toLocaleString("en-US")} times, then answered 429 with Retry-After ${retryAfter} s. Events: ${stats.sent.toLocaleString("en-US")} handed to the transport, ${stats.dropped.toLocaleString("en-US")} dropped by the full buffer, ${stats.internalErrors} internal errors`,
  );
}

console.log("");
if (internalErrors > 0) {
  console.error("FAIL: Shield reported internal errors during the benchmark.");
  process.exit(1);
}
if (worst > BUDGET_P99_US) {
  console.error(`FAIL: worst p99 ${worst.toFixed(2)} µs exceeds the budget of ${BUDGET_P99_US} µs.`);
  process.exit(1);
}
if (worstAttested > ATTESTED_BUDGET_P99_US) {
  console.error(
    `FAIL: worst attested p99 ${worstAttested.toFixed(2)} µs exceeds the budget of ${ATTESTED_BUDGET_P99_US} µs.`,
  );
  process.exit(1);
}
console.log(`PASS: worst p99 ${worst.toFixed(2)} µs is within the budget of ${BUDGET_P99_US} µs.`);
console.log(
  `PASS: worst attested p99 ${worstAttested.toFixed(2)} µs is within the budget of ${ATTESTED_BUDGET_P99_US} µs (PB-01).`,
);
