import { type CampaignExchange, type CampaignProbe, campaignRequestTarget } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { type EngineCheck, type EngineFinding, runStandIn } from "../src/index.ts";

// Slice 15a, sixth independent safety review, from its unconfirmed list: redaction can remove the very text a check
// looks for (a `token: …` before `"reports"` on one line is redacted to the end of the line). The check then finds
// nothing — and must not say "ran, nothing reported": it could not tell.

type Ok = Extract<CampaignExchange, { ok: true }>;
const answer = (seq: number, status: number, body: string, extra: Partial<Ok> = {}): Ok => ({
  ok: true,
  seq,
  status,
  headers: {},
  body,
  truncated: false,
  location: null,
  withheld: false,
  ...extra,
});

async function run(respond: (probe: CampaignProbe, seq: number) => CampaignExchange) {
  const checks: EngineCheck[] = [];
  const findings: EngineFinding[] = [];
  let seq = 0;
  await runStandIn({
    intensity: "safe-active",
    request: async (probe) => respond(probe, ++seq),
    check: (check) => checks.push(check),
    finding: (finding) => findings.push(finding),
  });
  return { result: (id: string) => checks.find((check) => check.id === id)?.result, findings };
}

describe("review6: a check whose evidence may have been redacted away is inconclusive", () => {
  it("a body-reading check that finds nothing in a body with a redaction marker could not tell", async () => {
    const { result, findings } = await run((probe, seq) => {
      const target = campaignRequestTarget(probe) ?? "";
      // What the gate hands on of `token: abc {"reports":[…]}`: the value runs to the end of the line.
      if (target === "/api/admin/reports") return answer(seq, 200, "token: [redacted-secret]");
      if (target === "/api/orders/1001") return answer(seq, 200, "note [redacted-email] nothing else");
      if (target.startsWith("/search?")) return answer(seq, 200, "<p>[redacted-number]</p>");
      // A stack trace is looked for only in a 5xx: a 200 is judged by its status, whatever its body.
      if (target === "/api/orders/x") return answer(seq, 200, "ok [redacted-key]");
      return answer(seq, 404, "not found");
    });
    expect(result("RW-03")).toBe("inconclusive");
    expect(result("RW-04")).toBe("inconclusive");
    expect(result("RW-05")).toBe("inconclusive");
    expect(result("RW-02")).toBe("clean");
    expect(findings).toEqual([]);
  });

  it("a body without a marker is judged as before, and a marker beside the evidence does not hide it", async () => {
    const { result, findings } = await run((probe, seq) => {
      const target = campaignRequestTarget(probe) ?? "";
      if (target === "/api/admin/reports") return answer(seq, 200, '{"reports":[{"owner":"[redacted-email]"}]}');
      if (target === "/api/orders/1001") return answer(seq, 200, "no such order");
      if (target === "/api/orders/x") return answer(seq, 500, "Error [redacted-secret] without a trace");
      return answer(seq, 404, "[redacted-secret]");
    });
    expect(result("RW-03")).toBe("reported");
    expect(result("RW-04")).toBe("clean");
    // A 5xx whose trace may have been redacted away: could not tell.
    expect(result("RW-02")).toBe("inconclusive");
    // Not judged by its body at all (a 404): the marker changes nothing.
    expect(result("RW-05")).toBe("clean");
    expect(findings.map((finding) => finding.check_id)).toEqual(["RW-03", "RW-03"]);
  });
});
