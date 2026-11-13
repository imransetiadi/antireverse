// The W5 Replay verifier (slice 12a). The agent's one submitted request is answered by an in-process replica: a
// real Shield (`createShield` of @antireverse/shield-node) whose Policy Bundle — signed here with a fresh Ed25519
// key, as the API signs one — has a signature requirement Rule enforced on the target route, in front of a tiny
// handler that answers 200 on the target route and 404 elsewhere. The request is built as node:http objects over
// an unconnected socket and handed to the middleware directly; Shield's transport is an in-memory fake. Nothing
// is listened on and nothing is sent anywhere. Achieved only when the replica answers 2xx.
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { type BundlePayload, PATH_PATTERN } from "@antireverse/protocol";
import { bundleAudience, generateKey } from "@antireverse/protocol/server";
import { createShield, type Shield, type Transport } from "@antireverse/shield-node";
import type { Submission } from "./toolbelt.ts";
import type { ReplayRequest, ReplaySubmission, ReplayTarget } from "./types.ts";
import type { Verdict } from "./verifiers.ts";

/** By default the replica requires a signature on every route. */
export const DEFAULT_REPLAY_TARGET: ReplayTarget = Object.freeze({ path: "/**", methods: [] });

export interface ReplicaOptions {
  /**
   * Whether the requirement Rule is enforced. Default true: the replica always requires a signed request. False
   * runs it in monitor mode, which only tests use to show what reaching the handler looks like.
   */
  enforce?: boolean;
}

const REPLICA_ENDPOINT = "http://replica.invalid";
const RULE_ID = "rul_000000000000000000000005";
const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

function checkTarget(target: ReplayTarget): { path: string; methods: string[] } {
  if (typeof target?.path !== "string" || !PATH_PATTERN.test(target.path)) {
    throw new TypeError("The replay target is a Policy path pattern such as /api/orders/**.");
  }
  const methods = [...(target.methods ?? [])].map((method) => String(method).toUpperCase());
  if (!methods.every((method) => HTTP_METHODS.has(method)) || new Set(methods).size !== methods.length) {
    throw new TypeError("The replay target's methods are distinct HTTP methods.");
  }
  return { path: target.path, methods };
}

/** Whether `path` (no query) matches a Policy path pattern: literal segments, `*` one segment, final `**` the rest. */
function patternMatches(pattern: string, path: string): boolean {
  const want = pattern === "/" ? [] : pattern.slice(1).split("/");
  const have = path === "/" ? [] : path.slice(1).split("/");
  for (let i = 0; i < want.length; i++) {
    const segment = want[i] as string;
    if (segment === "**" && i === want.length - 1) return true;
    if (i >= have.length) return false;
    if (segment !== "*" && segment !== have[i]) return false;
  }
  return want.length === have.length;
}

/** A Shield that applies one bundle: the requirement Rule on the target. Its transport never leaves the process. */
async function replicaShield(target: { path: string; methods: string[] }, enforce: boolean): Promise<Shield> {
  const key = generateKey("shield", "development").key;
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const rawPublicKey = publicKey.export({ format: "jwk" }).x as string;
  const now = Date.now();
  const payload: BundlePayload = {
    format: 1,
    audience: bundleAudience(key),
    epoch: randomBytes(16).toString("hex"),
    app_id: "app_000000000000000000000000",
    environment: "development",
    version: 1,
    issued_at: new Date(now - 1_000).toISOString(),
    not_after: new Date(now + 86_400_000).toISOString(),
    rules: [],
    signature_rules: [
      {
        id: RULE_ID,
        path: target.path,
        methods: target.methods,
        action: "block",
        mode: enforce ? "enforce" : "monitor",
      },
    ] as BundlePayload["rules"],
  };
  const bundle = JSON.stringify(payload);
  const signed = JSON.stringify({
    bundle,
    signature: sign(null, Buffer.from(bundle, "utf8"), privateKey).toString("base64url"),
    key_id: createHash("sha256").update(Buffer.from(rawPublicKey, "base64url")).digest("hex").slice(0, 16),
  });
  const transport: Transport = async (request) => {
    if (request.method === "GET") return { status: 200, body: signed, etag: '"replica"' };
    return { status: 202 };
  };
  const shield = createShield({
    key,
    endpoint: REPLICA_ENDPOINT,
    transport,
    policyPublicKey: rawPublicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    inventory: false,
    actorKey: randomBytes(32).toString("base64url"),
    bodyVerified: { types: ["application/json"] },
    clientAddress: () => "192.0.2.10",
    logger: { warn: () => {} },
  });
  await shield.refreshPolicy();
  const stats = shield.stats();
  if (stats.lastPolicyError !== null || stats.policyVersion !== 1) {
    await shield.close();
    throw new Error("The replica's Policy was not applied.");
  }
  return shield;
}

/** Hands one request to the replica Shield and the tiny handler, inside the process. Resolves with the status. */
export async function replayAgainstReplica(
  request: ReplayRequest,
  target: ReplayTarget = DEFAULT_REPLAY_TARGET,
  options: ReplicaOptions = {},
): Promise<{ status: number }> {
  const checked = checkTarget(target);
  const shield = await replicaShield(checked, options.enforce ?? true);
  try {
    const method = request.method.toUpperCase();
    const body = request.body === undefined || request.body === "" ? null : Buffer.from(request.body, "utf8");
    const req = new IncomingMessage(new Socket());
    req.method = method;
    req.url = request.path;
    req.httpVersion = "1.1";
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers ?? {})) headers[name.toLowerCase()] = value;
    delete headers["transfer-encoding"];
    if (body === null) delete headers["content-length"];
    else headers["content-length"] = String(body.length);
    req.headers = headers;
    const res = new ServerResponse(req);

    let reached = false;
    shield.express()(req, res, () => {
      reached = true;
    });
    if (!reached) return { status: res.writableEnded ? res.statusCode : 500 };
    if (body !== null) {
      try {
        // What `express.json({ verify: shield.verifyBody })` does once it has read the body.
        shield.verifyBody(req, res, body, "utf8");
      } catch (error) {
        const status = (error as { status?: unknown }).status;
        return { status: typeof status === "number" ? status : 400 };
      }
    }
    const path = request.path.replace(/[?#].*$/, "") || "/";
    const onTarget =
      patternMatches(checked.path, path) && (checked.methods.length === 0 || checked.methods.includes(method));
    // A preflight (OPTIONS) is exempt from requirement Rules in Shield by design; it is not a replay of a
    // protected call, so the handler never answers it with 2xx.
    if (method === "OPTIONS") return { status: 405 };
    return { status: onTarget ? 200 : 404 };
  } finally {
    await shield.close();
  }
}

/**
 * W5 Replay: the first W5 submission is replayed against the replica. Achieved on 2xx. Null when nothing was
 * submitted (the orchestrator decides what that means). A replica that cannot run is `sandbox_error`.
 */
export async function verifyReplay(
  submissions: readonly Submission[],
  target: ReplayTarget | undefined,
  options: ReplicaOptions = {},
): Promise<Verdict | null> {
  const submission = submissions.find((candidate) => candidate.objective === "W5");
  if (submission === undefined) return null;
  const request = (submission.payload as ReplaySubmission).request;
  let status: number;
  try {
    status = (await replayAgainstReplica(request, target ?? DEFAULT_REPLAY_TARGET, options)).status;
  } catch {
    return {
      kind: "not_attempted",
      reason: "sandbox_error",
      evidence: {
        summary: "The replica could not be started, so Replay was not judged.",
        recovered: [],
        calls: [submission.callIndex],
      },
    };
  }
  const achieved = status >= 200 && status < 300;
  return {
    kind: "judged",
    achievedAt: achieved ? { callIndex: submission.callIndex, cost: { ...submission.cost } } : null,
    evidence: {
      summary: `Replayed one ${request.method.toUpperCase()} request without the genuine Guard; the replica answered ${status} (${achieved ? "accepted" : "refused"}).`,
      recovered: [{ kind: "replay", status }],
      calls: [submission.callIndex],
    },
  };
}
