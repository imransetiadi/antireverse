// Slice 15a, the never-destructive suite: over every catalog variant (both intensities) and every hostile way the
// reference target can answer, the target's own log holds only GET or HEAD requests with empty bodies and no cookie
// or credential, to the catalog's paths only, and its trap routes have no hit. What a hostile answer carries (a
// synthetic key, an email, a card-like number, a session cookie) reaches no Finding, log or report.
import { CAMPAIGN_LIMITS, CampaignReportResponseSchema } from "@antireverse/protocol";
import { STAND_IN_CATALOG } from "@antireverse/prove";
import type { RangeHostile } from "@antireverse/range";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  call,
  findingsOf,
  type Harness,
  type Org,
  requestsOf,
  runCampaign,
  setupOrg,
  startHarness,
} from "./fixtures/campaign-harness.ts";

const CATALOG_PATHS = new Set(STAND_IN_CATALOG.map((check) => check.probe.path));
const HOSTILE: (RangeHostile | undefined)[] = [undefined, "instructions", "large", "secrets", "slow"];
const INTENSITIES = ["passive", "safe-active"] as const;
/** What the range's hostile answers carry (apps/range/src/server.ts): none of it may be kept anywhere. */
const SYNTHETIC = ["SYNTHETICrangeKEY0000000a", "jane.synthetic", "4111 1111 1111 1111", "SYNTHETICsessionVALUE0001"];

describe("never destructive", () => {
  let h: Harness;
  let n = 0;
  let org: Org;
  let used = 3;

  beforeAll(async () => {
    h = await startHarness();
  });
  afterAll(async () => {
    await h?.close();
  });

  for (const intensity of INTENSITIES) {
    for (const hostile of HOSTILE) {
      it(`${intensity}, target answering ${hostile ?? "normally"}: only bodiless GETs to the catalog, no trap hit`, async () => {
        // Three Campaigns per target in 24 hours: a new Organization every three.
        if (used === 3) {
          org = await setupOrg(h, `Careful ${++n}`);
          used = 0;
        }
        used++;
        h.target.reset();
        h.target.token = org.token;
        h.target.serve({ ...(hostile === undefined ? {} : { hostile }), slowMs: 700 });

        const campaign = await runCampaign(h, org, intensity);
        expect(["completed", "failed"]).toContain(campaign.status);
        if (hostile === "slow" && intensity === "safe-active") {
          // No answer within the deadline, five times in a row: the target is left alone.
          expect(campaign).toMatchObject({ status: "failed", end_reason: "target_unhealthy", requests_sent: 6 });
        } else if (hostile === "slow") {
          // The one passive probe got no answer: its check did not run, and the report says so.
          expect(campaign).toMatchObject({ status: "completed", checks: { ran: 0, reported: 0, skipped: 6 } });
        } else expect(campaign).toMatchObject({ status: "completed", end_reason: "checks_complete" });

        // The target's own log.
        const hits = h.target.hits;
        expect(hits.length).toBeGreaterThan(1);
        for (const hit of hits) {
          expect(["GET", "HEAD"]).toContain(hit.method);
          expect(hit.bodyBytes).toBe(0);
          expect(hit.cookie).toBe(false);
          expect(hit.url).not.toMatch(/trap/);
        }
        for (const hit of h.target.probes()) expect(CATALOG_PATHS.has(hit.url.split("?")[0] as string)).toBe(true);
        expect(h.target.range.trapHits()).toEqual([]);
        expect(h.target.range.entries.every((entry) => entry.method === "GET" && entry.bodyBytes === 0)).toBe(true);
        expect(h.target.probes().length).toBeLessThanOrEqual(2 * STAND_IN_CATALOG.length);
        if (intensity === "passive") expect(new Set(h.target.probes().map((hit) => hit.url))).toEqual(new Set(["/"]));

        // What the API kept: bounded, and without anything the hostile answers carried.
        const requests = await requestsOf(h, org, campaign.id);
        const findings = await findingsOf(h, org, campaign.id);
        const report = CampaignReportResponseSchema.parse(
          await (await call(h.api, `/v1/campaigns/${campaign.id}/report`, { key: org.key })).json(),
        );
        // What a row counts is what its connection read: the 64 KB handed on and at most a few socket reads more.
        const readMax = 4 * CAMPAIGN_LIMITS.responseReadBytesMax;
        expect(requests.every((request) => request.bytes <= readMax)).toBe(true);
        expect(campaign.response_bytes).toBeLessThanOrEqual(CAMPAIGN_LIMITS.responseBytesMax);
        const kept = JSON.stringify([campaign, requests, findings, report]);
        for (const secret of SYNTHETIC) expect(kept).not.toContain(secret);
        expect(kept).not.toMatch(/@acme-shop\.io/);
        for (const finding of findings) {
          expect(finding.evidence.excerpt.length).toBeLessThanOrEqual(CAMPAIGN_LIMITS.evidenceWindowMax);
          expect(finding.evidence.headers["set-cookie"] ?? "").not.toMatch(/SYNTHETIC/);
        }
        if (hostile === "secrets" && intensity === "safe-active") {
          // The cookie's name is evidence; its value is not.
          expect(
            findings.some((finding) => finding.evidence.headers["set-cookie"]?.startsWith("session=[redacted]")),
          ).toBe(true);
          expect(kept).toContain("[redacted-key]");
        }
        if (hostile === "large") {
          // (The redirect of RW-06 has no body to cut.)
          expect(findings.filter((f) => f.check_id !== "RW-06").every((finding) => finding.evidence.truncated)).toBe(
            true,
          );
        }
      });
    }
  }
});
