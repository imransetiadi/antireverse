// Slice 15a in a real browser: the Console's Campaign screens against the real API, started with AR_PROVE_CAMPAIGNS=1.
//
// The e2e API is a plain process: it has no test-only transport option, and its stand-in resolver never resolves a
// host (fixtures/api-fixture-patches.ts). So no Campaign of this journey ever sends a request, and what the browser
// covers is everything around a run:
//   - the navigation entry, the empty list and the notice of the scripted engine, word for word;
//   - the new Campaign page saying why nothing qualifies (no targets, then no Rules of Engagement);
//   - the form: only the verified targets in scope, the intensity limited to the signed one, the Rules summary, the
//     effect in numbers, the phrase per target, the staging declaration and the reason held back by the browser;
//   - a creation the API refuses (a wrong phrase) shown at its field, nothing created;
//   - a Campaign that is created and then refused at its start checks (the host does not resolve): its page says why,
//     shows no Stop button, an empty request log, and the report downloads through the Console as JSON;
//   - a Campaign that is stopped while it is queued (a `slow-…` host waits in its start checks): Stop is visible,
//     one confirmation step with a required reason, and the stop is final;
//   - the audit log naming the system as the actor of the refusal;
//   - the operator's switches on /ops: suspend and resume this Organization, stop all and enable again, each with a
//     reason, and the tenant list saying so and offering no "New Campaign" meanwhile;
//   - Settings → Usage saying that Campaigns are not metered.
// A Campaign that runs — requests through the gate, Findings with redacted evidence, the request log with refusals, a
// stop of a running Campaign within its deadline, every scope-escape and never-destructive case — is covered by the
// HTTP end-to-end tests (campaign.http.test.ts, campaign-scope.http.test.ts, campaign-never-destructive.http.test.ts),
// which construct the API in code with the test transport, and by the Console's component tests for the rendering.
import { readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import {
  AUDIT_REASON_HEADER,
  CAMPAIGN_STAND_IN_NOTICE,
  CampaignReportResponseSchema,
  CampaignResponseSchema,
  ListAuditResponseSchema,
  ListCampaignsResponseSchema,
  OrganizationResponseSchema,
  ProveOperatorStateSchema,
  TargetResponseSchema,
  VerifyTargetResponseSchema,
} from "@antireverse/protocol";
import { expect, type Page, test } from "@playwright/test";
import { API_URL, FAKE_DNS_FILE, OPS_TOKEN } from "./playwright.config.ts";

const HOST = "staging.campaign-e2e.io";
const SLOW_HOST = "slow-staging.campaign-e2e.io";
const EFFECT =
  "At most 60 GET or HEAD requests, 1 per second, for at most 5 minutes. No request bodies, cookies or credentials. Redirects are never followed.";

/** Publishes one TXT record in the stand-in DNS, keeping the records other journeys may have published. */
function publishTxt(name: string, value: string): void {
  let records: Record<string, string[][]> = {};
  try {
    records = JSON.parse(readFileSync(FAKE_DNS_FILE as string, "utf8")) as Record<string, string[][]>;
  } catch {
    records = {};
  }
  records[name] = [[value]];
  writeFileSync(FAKE_DNS_FILE as string, JSON.stringify(records));
}

async function api(key: string, path: string, init: { method?: string; body?: unknown; reason?: string } = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    method: init.method ?? "GET",
    headers: {
      authorization: `Bearer ${key}`,
      ...(init.body === undefined ? {} : { "content-type": "application/json" }),
      ...(init.reason === undefined ? {} : { [AUDIT_REASON_HEADER]: encodeURIComponent(init.reason) }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
  return { status: response.status, body: (await response.json().catch(() => undefined)) as unknown };
}

/** Adds a host through the API and proves it with a TXT record in the stand-in DNS. Returns the target's id. */
async function verifiedTarget(key: string, host: string): Promise<string> {
  const created = await api(key, "/v1/targets", { method: "POST", body: { host } });
  expect(created.status).toBe(201);
  const { target, verification } = TargetResponseSchema.parse(created.body);
  publishTxt(verification.dns_name, verification.dns_value);
  const verified = await api(key, `/v1/targets/${target.id}/verify`, { method: "POST" });
  expect(VerifyTargetResponseSchema.parse(verified.body).result.verified).toBe(true);
  return target.id;
}

/** Fills the new Campaign form for `host` and launches. */
async function launch(page: Page, host: string, phrase: string, reason: string): Promise<void> {
  await page.getByRole("radio", { name: host, exact: true }).check();
  await page.getByLabel("Type the phrase to authorise").fill(phrase);
  await page.getByRole("checkbox", { name: "This target is a staging or test system" }).check();
  await page.getByLabel("Reason").fill(reason);
  await page.getByTestId("campaign-launch").click();
}

test.afterAll(async () => {
  // Whatever happened above, the kill switch of the shared e2e API is lifted again.
  await api(OPS_TOKEN, "/v1/ops/prove/enable", { method: "POST", body: { reason: "End of the Campaign journey" } });
});

test("campaigns: why nothing qualifies, a refused creation, a Campaign refused at start, a stop while queued, the operator's switches", async ({
  page,
}) => {
  test.setTimeout(180_000);
  expect(FAKE_DNS_FILE).toBeTruthy();

  // 1. A new Organization; its admin key.
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme Campaigns");
  await page.getByRole("button", { name: "Create organization" }).click();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  expect(adminKey).toMatch(/^aro_[A-Za-z0-9_-]{43}$/);
  await page.getByRole("link", { name: "Continue" }).click();
  const { organization } = OrganizationResponseSchema.parse((await api(adminKey, "/v1/organization")).body);

  // 2. Prove → Campaigns: the notice word for word, the engine tag, an empty list.
  await page.getByRole("navigation", { name: "Prove" }).getByRole("link", { name: "Campaigns" }).click();
  await expect(page).toHaveURL(/\/prove\/campaigns$/);
  await expect(page.getByRole("heading", { level: 1, name: "Campaigns" })).toBeVisible();
  await expect(page.getByTestId("campaign-notice-text")).toHaveText(CAMPAIGN_STAND_IN_NOTICE);
  await expect(page.getByTestId("campaign-engine")).toHaveText("stand-in");
  await expect(page.getByTestId("campaigns-empty")).toBeVisible();
  await expect(page.getByTestId("campaigns-disabled")).toHaveCount(0);

  // 3. New Campaign says why nothing qualifies: no targets, then (two verified targets later) no Rules of Engagement.
  await page.getByTestId("campaign-new").click();
  await expect(page).toHaveURL(/\/prove\/campaigns\/new$/);
  await expect(page.getByTestId("campaign-none")).toContainText("There are no targets yet.");
  await expect(page.getByTestId("campaign-launch")).toHaveCount(0);
  const targetId = await verifiedTarget(adminKey, HOST);
  const slowTargetId = await verifiedTarget(adminKey, SLOW_HOST);
  await page.reload();
  await expect(page.getByTestId("campaign-none")).toContainText("No Rules of Engagement are signed.");
  await expect(page.getByTestId("campaign-none").getByRole("link")).toHaveAttribute(
    "href",
    "/prove/rules-of-engagement",
  );

  // Rules of Engagement signed for passive testing only, every day, all day, with one excluded path.
  const signed = await api(adminKey, "/v1/rules-of-engagement", {
    method: "POST",
    reason: "Rules for the Campaign journey",
    body: {
      scope: [targetId, slowTargetId],
      exclusions: ["/admin"],
      intensity: "passive",
      window: { days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], from: "00:00", to: "24:00" },
      contacts: ["security@campaign-e2e.io"],
      confirm: "I authorise passive testing",
    },
  });
  expect(signed.status).toBe(201);

  // 4. The form: the two targets with their phrases, the intensity limited to the signed one, the summary, the effect.
  await page.reload();
  await expect(page.getByRole("radio", { name: HOST, exact: true })).toBeChecked();
  await expect(page.getByRole("radio", { name: SLOW_HOST, exact: true })).toBeVisible();
  await expect(page.getByTestId("campaign-phrase")).toHaveText([
    `I authorise a test of ${HOST}`,
    `I authorise a test of ${SLOW_HOST}`,
  ]);
  const intensity = page.getByRole("group", { name: "Intensity" });
  await expect(intensity.getByRole("radio")).toHaveCount(1);
  await expect(intensity.getByRole("radio", { name: "passive" })).toBeChecked();
  await expect(page.getByTestId("campaign-rules-window")).toHaveText("Mon, Tue, Wed, Thu, Fri, Sat, Sun, all day UTC");
  await expect(page.getByTestId("campaign-rules-exclusion")).toHaveText(["/admin"]);
  await expect(page.getByTestId("campaign-effect")).toHaveText(EFFECT);
  await expect(page.getByTestId("campaign-notice-text")).toHaveText(CAMPAIGN_STAND_IN_NOTICE);

  // The browser holds an incomplete form back: nothing is created.
  await page.getByTestId("campaign-launch").click();
  await expect(page).toHaveURL(/\/prove\/campaigns\/new$/);
  // A wrong phrase reaches the API, which refuses it: the field says so, the choices and the reason are kept.
  await launch(page, HOST, `I authorise a test of ${SLOW_HOST}`, "First launch on staging");
  await expect(page.getByTestId("error-summary")).toBeVisible();
  await expect(page.getByTestId("campaign-confirm-error")).toContainText("Type the phrase of the chosen target");
  await expect(page.getByLabel("Reason")).toHaveValue("First launch on staging");
  await expect(page.getByLabel("Type the phrase to authorise")).toHaveValue("");
  expect(ListCampaignsResponseSchema.parse((await api(adminKey, "/v1/campaigns")).body).campaigns).toHaveLength(0);

  // 5. The exact phrase launches. The host never resolves, so the Campaign is refused at its start checks: the page
  // (which refreshes itself while the Campaign is active) says why, in words, and offers no Stop.
  await launch(page, HOST, `I authorise a test of ${HOST}`, "First launch on staging");
  await page.waitForURL(/\/prove\/campaigns\/cmp_[0-9a-f]{24}$/);
  const refusedId = page.url().split("/").at(-1) as string;
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(`Campaign against ${HOST}`);
  await expect(page.getByTestId("campaign-status")).toHaveAttribute("data-status", "refused", { timeout: 20_000 });
  await expect(page.getByTestId("campaign-status")).toHaveText("Refused");
  await expect(page.getByTestId("campaign-why")).toHaveText(
    "The host did not resolve, or an address it resolves to is not public. No request was sent.",
  );
  await expect(page.getByTestId("campaign-stop")).toHaveCount(0);
  await expect(page.getByTestId("campaign-requests")).toHaveText("0 sent, 0 refused");
  await expect(page.getByTestId("campaign-checks")).toHaveText("No check ran.");
  await expect(page.getByTestId("campaign-requests-empty")).toBeVisible();
  await expect(page.getByTestId("campaign-notice-text").first()).toHaveText(CAMPAIGN_STAND_IN_NOTICE);
  await expect(page.getByTestId("campaign-staging")).toContainText("Declared a staging or test system by key_");
  const refusedCampaign = CampaignResponseSchema.parse(
    (await api(adminKey, `/v1/campaigns/${refusedId}`)).body,
  ).campaign;
  expect(refusedCampaign).toMatchObject({ status: "refused", end_reason: "target_not_reachable", requests_sent: 0 });

  // The report downloads through the Console: the API's report as JSON, with the notice and the engine tag.
  const downloading = page.waitForEvent("download");
  await page.getByTestId("campaign-report-download").click();
  const download = await downloading;
  expect(download.suggestedFilename()).toBe(`airverse-campaign-${refusedId}.json`);
  const { report } = CampaignReportResponseSchema.parse(JSON.parse(await readFile(await download.path(), "utf8")));
  expect(report.notice).toBe(CAMPAIGN_STAND_IN_NOTICE);
  expect(report.engine.name).toBe("stand-in");
  expect(report.campaign.id).toBe(refusedId);
  expect(report.findings).toEqual([]);
  await expect(page).toHaveURL(new RegExp(`/prove/campaigns/${refusedId}$`));

  // 6. The list: the Campaign with its status, its target, its intensity and the engine tag.
  await page.getByRole("link", { name: "All Campaigns" }).click();
  await expect(page).toHaveURL(/\/prove\/campaigns$/);
  const row = page.locator(`[data-testid="campaign-row"][data-campaign-id="${refusedId}"]`);
  await expect(row.getByTestId("campaign-status")).toHaveText("Refused");
  await expect(row.getByTestId("campaign-host")).toHaveText(HOST);
  await expect(row.getByTestId("campaign-intensity")).toHaveText("passive");
  await expect(row.getByTestId("campaign-engine")).toHaveText("stand-in");
  await expect(row.getByTestId("campaign-checks")).toHaveText("None ran");

  // 7. A Campaign against the slow host waits in its start checks: Stop is visible, asks for a reason once, and is
  // final. The wait is the runner's 5 s start deadline; if a stop comes after it, the page says the Campaign had
  // already ended, and the journey launches one more.
  let stoppedId = "";
  for (let attempt = 0; attempt < 3 && stoppedId === ""; attempt++) {
    await page.goto("/prove/campaigns/new");
    await launch(page, SLOW_HOST, `I authorise a test of ${SLOW_HOST}`, "Stop journey");
    await page.waitForURL(/\/prove\/campaigns\/cmp_[0-9a-f]{24}$/);
    const id = page.url().split("/").at(-1) as string;
    const stop = page.getByTestId("campaign-stop");
    if (!(await stop.isVisible().catch(() => false))) continue;
    await expect(page.getByTestId("campaign-status")).toHaveAttribute("data-status", "queued");
    await stop.click();
    const step = page.getByTestId("campaign-confirm");
    await expect(step.getByTestId("confirm-question")).toHaveText(
      `Stop the Campaign against ${SLOW_HOST}? No further request is sent.`,
    );
    await expect(step.getByLabel("Reason")).toHaveAttribute("required", "");
    await step.getByLabel("Reason").fill("The staging system is being deployed to");
    await step.getByTestId("confirm-submit").click();
    await page.waitForURL(new RegExp(`/prove/campaigns/${id}(\\?notice=ended)?$`));
    if (!page.url().includes("notice=ended")) stoppedId = id;
  }
  expect(stoppedId).not.toBe("");
  await expect(page.getByTestId("campaign-status")).toHaveAttribute("data-status", "stopped");
  await expect(page.getByTestId("campaign-why")).toHaveText("Stopped with an admin key of this Organization.");
  await expect(page.getByTestId("campaign-stop-request")).toContainText("The staging system is being deployed to");
  await expect(page.getByTestId("campaign-stop")).toHaveCount(0);
  await expect(page.getByTestId("campaign-confirm")).toHaveCount(0);
  const stopped = CampaignResponseSchema.parse((await api(adminKey, `/v1/campaigns/${stoppedId}`)).body).campaign;
  expect(stopped).toMatchObject({ status: "stopped", end_reason: "owner_stop", requests_sent: 0 });
  // Final: a second stop of the same Campaign is refused by the API.
  expect((await api(adminKey, `/v1/campaigns/${stoppedId}/stop`, { method: "POST", reason: "Again" })).status).toBe(
    409,
  );

  // 8. The audit log: the creation by the admin key with its reason, the refusal by the system, the stop.
  await page.getByTestId("nav-audit").click();
  await expect(page).toHaveURL(/\/settings\/audit$/);
  const refusal = page.getByTestId("audit-row").filter({ hasText: "Campaign refused" }).first();
  await expect(refusal.getByTestId("audit-actor")).toHaveText("System");
  await expect(refusal.getByTestId("audit-target")).toContainText("Campaign");
  await expect(page.getByTestId("audit-row").filter({ hasText: "Campaign stopped" }).first()).toContainText(
    "The staging system is being deployed to",
  );
  await expect(
    page
      .getByTestId("audit-row")
      .filter({ hasText: "Campaign created" })
      .filter({ hasText: "First launch on staging" }),
  ).toHaveCount(1);
  const audit = ListAuditResponseSchema.parse((await api(adminKey, "/v1/audit?action=campaign.refuse")).body);
  expect(audit.entries[0]?.actor).toEqual({ kind: "system" });

  // 9. Settings → Usage: Campaigns are not metered in this version.
  await page.getByTestId("nav-usage").click();
  await expect(page.getByTestId("usage-campaigns")).toHaveText("Campaigns are not metered in this version.");

  // 10. The operator's switches on /ops, with the operator session.
  await page.goto("/ops");
  await expect(page).toHaveURL(/\/ops\/sign-in$/);
  await page.getByLabel("Operator token").fill(OPS_TOKEN);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/ops$/);
  const switches = page.getByTestId("ops-prove");
  await expect(switches.getByRole("heading", { name: "Pentest Campaigns" })).toBeVisible();
  await expect(switches.getByTestId("prove-enabled")).toHaveText("On");
  await expect(switches.getByTestId("prove-killed")).toHaveAttribute("data-killed", "false");

  // Suspend this Organization: a reason is required; the tenant list says so and offers no "New Campaign".
  const organizationForm = switches.getByTestId("prove-organization-form");
  await organizationForm.getByLabel("Organization id").fill(organization.id);
  await organizationForm.getByRole("button", { name: "Suspend" }).click();
  await expect(page).toHaveURL(/\/ops$/);
  await organizationForm.getByLabel("Reason").fill("Abuse report under review");
  await organizationForm.getByRole("button", { name: "Suspend" }).click();
  await expect(page).toHaveURL(/\/ops\?prove=suspend&stopped=0$/);
  await expect(page.getByTestId("prove-done")).toHaveText(
    "The Organization is suspended. 0 of its Campaigns were ended.",
  );
  await expect(page.getByTestId("prove-suspended-organization")).toContainText(organization.id);
  await page.goto("/prove/campaigns");
  await expect(page.getByTestId("campaigns-blocked")).toHaveAttribute("data-blocked", "organization_suspended");
  await expect(page.getByTestId("campaign-new")).toHaveCount(0);
  await expect(page.locator('[data-testid="campaign-row"]').first()).toBeVisible();
  await page.goto("/prove/campaigns/new");
  await expect(page.getByTestId("campaigns-blocked")).toBeVisible();
  await expect(page.getByTestId("campaign-launch")).toHaveCount(0);

  // Resume it.
  await page.goto("/ops");
  await page.getByTestId("prove-organization-form").getByLabel("Organization id").fill(organization.id);
  await page.getByTestId("prove-organization-form").getByLabel("Reason").fill("Report closed");
  await page.getByTestId("prove-organization-form").getByRole("button", { name: "Resume" }).click();
  await expect(page).toHaveURL(/\/ops\?prove=resume$/);
  await expect(page.getByTestId("prove-done")).toHaveText("The suspension is lifted.");
  await expect(page.getByTestId("prove-suspended")).toHaveText("None");

  // Stop all Campaigns, then enable them again.
  const globalForm = page.getByTestId("prove-global-form");
  await globalForm.getByLabel("Reason").fill("Drill of the kill switch");
  await globalForm.getByRole("button", { name: "Stop all Campaigns" }).click();
  await expect(page).toHaveURL(/\/ops\?prove=kill&stopped=\d+$/);
  await expect(page.getByTestId("prove-killed")).toHaveAttribute("data-killed", "true");
  expect(ProveOperatorStateSchema.parse((await api(OPS_TOKEN, "/v1/ops/prove")).body).killed).toBe(true);
  await page.goto("/prove/campaigns");
  await expect(page.getByTestId("campaigns-blocked")).toHaveAttribute("data-blocked", "operator_kill");
  await expect(page.getByTestId("campaign-new")).toHaveCount(0);
  await page.goto("/ops");
  await page.getByTestId("prove-global-form").getByLabel("Reason").fill("Drill finished");
  await page.getByTestId("prove-global-form").getByRole("button", { name: "Enable Campaigns" }).click();
  await expect(page).toHaveURL(/\/ops\?prove=enable$/);
  await expect(page.getByTestId("prove-done")).toHaveText("Campaigns are enabled again.");
  await expect(page.getByTestId("prove-killed")).toHaveAttribute("data-killed", "false");
  await page.goto("/prove/campaigns");
  await expect(page.getByTestId("campaigns-blocked")).toHaveCount(0);
  await expect(page.getByTestId("campaign-new")).toBeVisible();
});
