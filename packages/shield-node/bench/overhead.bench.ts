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
import { createHash, createHmac, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { setImmediate as tick } from "node:timers/promises";
import { createShield, type Shield, type ShieldMiddleware } from "../src/index.ts";

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

/** What the API would answer for `GET /v1/policy-bundle`: a bundle of 50 Rules, signed with `privateKey`. */
const signing = generateKeyPairSync("ed25519");
function signedBundle(withCanaries: boolean, withContainment: boolean, withAttestation = false): string {
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
  });
  const signature = sign(null, Buffer.from(bundle, "utf8"), signing.privateKey).toString("base64url");
  return JSON.stringify({ bundle, signature, key_id: "0123456789abcdef" });
}

type Run = "built-in" | "rules" | "canaries" | "containment" | "attestation";

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
        const full = run === "containment" || run === "attestation";
        const body = signedBundle(run === "canaries" || full, full, run === "attestation");
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
for (const run of ["built-in", "rules", "canaries", "containment", "attestation"] as const) {
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
