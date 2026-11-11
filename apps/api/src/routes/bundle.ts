import type { SigningKeyResponse } from "@antireverse/protocol";
import { bundleAudience } from "@antireverse/protocol/server";
import { Hono } from "hono";
import type { AttestationKeys } from "../attestation/keys.ts";
import { type AppEnv, presentedKey, requireKey } from "../auth/authenticate.ts";
import { createBundleIssuer } from "../bundle.ts";
import type { Db } from "../db/db.ts";
import { bundlePatches } from "../patches/activation.ts";
import type { PatchCatalog } from "../patches/catalog.ts";
import { problem } from "../problem.ts";
import type { Signer } from "../signer.ts";
import { allowlistCidrs } from "../stores/allowlist.ts";
import { activeCanaries } from "../stores/canaries.ts";
import { activeBlocks } from "../stores/containments.ts";
import { databaseEpoch } from "../stores/epoch.ts";
import { currentPolicy } from "../stores/policies.ts";

/** True when an `If-None-Match` header names this entity tag (the comparison is weak, as the header asks). */
function matches(header: string | undefined, etag: string): boolean {
  if (header === undefined) return false;
  return header.split(",").some((candidate) => {
    const tag = candidate.trim();
    return tag === "*" || tag === etag || tag === `W/${etag}`;
  });
}

export function bundleRoutes(deps: {
  db: Db;
  signer: Signer;
  attestation: AttestationKeys;
  /** The Virtual patch catalog: the App Environment's active patches travel in the bundle. */
  patches: PatchCatalog;
  now?: () => Date;
}): Hono<AppEnv> {
  const { db, signer } = deps;
  const now = deps.now ?? (() => new Date());
  const issuer = createBundleIssuer({ signer, now });
  const routes = new Hono<AppEnv>();

  // Public by design: the key verifies bundles and can sign nothing.
  routes.get("/v1/signing-key", (c) =>
    c.json({
      key_id: signer.keyId,
      algorithm: "Ed25519",
      public_key: signer.publicKey,
    } satisfies SigningKeyResponse),
  );

  // The signed Policy of the Shield key's own App and Environment. Shield polls this, sending the ETag back.
  routes.get("/v1/policy-bundle", requireKey(db, "shield"), async (c) => {
    // Organization, App and Environment come from the key. Nothing else in the request is read for them.
    const { organizationId, appId, environment } = c.var.principal;
    const key = presentedKey(c);
    if (key === undefined) return problem(c, "unauthorized");

    // Read together: the epoch says which database the version counts in. The Canaries are those of the
    // App and Environment's recent Builds; a change of the set is a new bundle with a new ETag. So are the
    // App and Environment's active blocks (by the clock: an expiry changes them too) and the Organization's
    // allowlist.
    const at = now();
    // So are its active Virtual patches and their modes: a Finding opened, fixed, withdrawn or ignored, or a mode
    // changed, is a new bundle.
    const { epoch, policy, canaries, blocks, allowlist, patches } = await db.tx({ organizationId }, async (q) => ({
      epoch: await databaseEpoch(q),
      policy: await currentPolicy(q, { organizationId, appId, environment }),
      canaries: await activeCanaries(q, { organizationId, appId, environment }),
      blocks: await activeBlocks(q, { organizationId, appId, environment }, at),
      allowlist: await allowlistCidrs(q),
      patches: await bundlePatches(q, deps.patches, { appId, environment }),
    }));
    const { signed, etag } = issuer.issue({
      audience: bundleAudience(key),
      epoch,
      appId,
      environment,
      version: policy.version,
      rules: policy.rules,
      canaries,
      blocks,
      allowlist,
      patches,
      // Read on every request: a rotation that fell due changes the set, so the bundle is issued again.
      attestationKeys: deps.attestation.attestationKeys(),
    });

    if (matches(c.req.header("if-none-match"), etag)) return c.body(null, 304, { ETag: etag });
    return c.json(signed, 200, { ETag: etag });
  });

  return routes;
}
