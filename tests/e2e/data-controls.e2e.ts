// Ticket 18b in a real browser: Settings → Data controls. Export the Organization (signed NDJSON through the Console),
// export and erase an end user's records by actor hash with a reason, request the Organization's deletion (typed
// name and reason) — then the banner shows on Data controls, every other page sends the person there with the pending
// message, and the API refuses the key — and cancel it, after which everything works again.
import { readFile } from "node:fs/promises";
import { ExportLineSchema, ListAuditResponseSchema, ProblemSchema } from "@antireverse/protocol";
import { expect, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

const IP_HASH = "iph_0123456789abcdef0123456789abcdef";
// A name with every character a pattern could misread (review 18b): the typed confirmation must still accept it.
const NAME = "Acme (EU) [x] {y} a.b*c+d?e^f$g|h\\i/j";
const ERASE_REASON = "Erasure request #42 from the end user, identity checked";
const DELETE_REASON = "Trial ended — the customer asked us to delete everything";
const CANCEL_REASON = "Customer changed their mind and renewed";

async function lines(path: string) {
  return (await readFile(path, "utf8"))
    .trimEnd()
    .split("\n")
    .map((line) => ExportLineSchema.parse(JSON.parse(line)));
}

test("data controls: export, erase a subject with a reason, request and cancel the Organization's deletion", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByLabel("Organization name").fill(NAME);
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByTestId("organization-created")).toBeVisible();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  await page.getByRole("link", { name: "Continue" }).click();
  const auth = { authorization: `Bearer ${adminKey}` };

  // 1. Settings → Data controls.
  await page.getByTestId("nav-data").click();
  await expect(page).toHaveURL(/\/settings\/data$/);
  await expect(page.getByTestId("nav-data")).toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("heading", { level: 1, name: "Data controls" })).toBeVisible();
  await expect(page.getByTestId("deletion-banner")).toHaveCount(0);

  // 2. Export: a manifest first, a signed end line last, through the Console.
  const [orgExport] = await Promise.all([page.waitForEvent("download"), page.getByTestId("data-export").click()]);
  expect(orgExport.suggestedFilename()).toMatch(/^airverse-org_[0-9a-f]{24}-\d{4}-\d{2}-\d{2}\.ndjson$/);
  const exported = await lines(await orgExport.path());
  expect(exported[0]?.kind).toBe("manifest");
  const end = exported.at(-1);
  expect(end?.kind).toBe("end");
  expect(exported.some((line) => line.kind === "row" && line.table === "organizations")).toBe(true);

  // 3. An end user's request: the hash is checked by the browser, then exported and erased.
  const hash = page.getByLabel("Actor hash");
  await expect(page.getByTestId("subject-help")).toContainText("actorHash");
  await hash.fill("203.0.113.7");
  await page.getByTestId("subject-erase").click();
  // Checked in the browser: the field says what is wrong and no confirmation step opens.
  await expect(page.getByTestId("subject-input-error")).toBeVisible();
  await expect(page.getByTestId("subject-confirm")).toHaveCount(0);
  await hash.fill(IP_HASH);
  const [subjectExport] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("subject-export").click(),
  ]);
  const subjectLines = await lines(await subjectExport.path());
  const manifest = subjectLines[0];
  expect(manifest?.kind === "manifest" && manifest.subject?.ip_hash).toBe(IP_HASH);

  // The confirmation opens in place: the actor hash never enters an address.
  await page.getByTestId("subject-erase").click();
  await expect(page).toHaveURL(/\/settings\/data$/);
  const eraseStep = page.getByTestId("subject-confirm");
  await expect(eraseStep).toBeFocused();
  const eraseReason = eraseStep.getByLabel("Reason");
  await expect(eraseReason).toHaveAttribute("required", "");
  await eraseStep.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("subject-report")).toHaveCount(0);
  await eraseReason.fill(ERASE_REASON);
  await eraseStep.getByTestId("confirm-submit").click();
  const report = page.getByTestId("subject-report");
  await expect(report).toBeVisible();
  await expect(report).toBeFocused();
  await expect(report).toContainText(`Records erased for ${IP_HASH}`);
  await expect(report).toContainText("0 Events erased");
  await expect(report).toContainText("No active blocks.");
  await expect(page.getByTestId("subject-confirm")).toHaveCount(0);
  const erased = ListAuditResponseSchema.parse(
    await (await fetch(`${API_URL}/v1/audit?action=subject.erase`, { headers: auth })).json(),
  );
  expect(erased.entries[0]?.reason).toBe(ERASE_REASON);

  // 4. Delete Organization: what happens, then the typed name and a reason.
  await page.goto("/settings/data");
  const danger = page.getByTestId("delete-organization");
  await expect(danger).toContainText("stops working at once");
  await expect(danger).toContainText("Export the data first");
  await page.getByTestId("delete-start").click();
  const deleteStep = page.getByTestId("delete-confirm");
  await expect(deleteStep).toBeFocused();
  const typed = deleteStep.getByTestId("confirm-typed");
  await typed.fill(NAME);
  expect(await typed.evaluate((input) => (input as unknown as { validity: { valid: boolean } }).validity.valid)).toBe(
    true,
  );
  await deleteStep.getByLabel("Reason").fill(DELETE_REASON);
  await deleteStep.getByTestId("confirm-submit").click();
  await expect(page).toHaveURL(/\/settings\/data\?done=requested$/);
  await expect(page.getByTestId("data-done")).toBeFocused();
  const banner = page.getByTestId("deletion-banner");
  await expect(banner).toContainText("This Organization is scheduled for deletion");
  const status = (await (await fetch(`${API_URL}/v1/organization/deletion`, { headers: auth })).json()) as {
    deletion: { id: string; purge_after: string };
  };
  const erasedAfter = `${status.deletion.purge_after.slice(0, 10)} ${status.deletion.purge_after.slice(11, 19)} UTC`;
  await expect(banner).toContainText(`erased after ${erasedAfter}`);
  await expect(page.getByTestId("deletion-id")).toHaveText(status.deletion.id);

  // The API refuses the key everywhere else; every other page of the Console says why, on Data controls.
  const refused = await fetch(`${API_URL}/v1/apps`, { headers: auth });
  expect(refused.status).toBe(403);
  expect(ProblemSchema.parse(await refused.json()).type).toMatch(/\/organization-deletion-pending$/);
  for (const path of ["/", "/apps", "/settings/audit", "/incidents"]) {
    await page.goto(path);
    await expect(page).toHaveURL(/\/settings\/data\?blocked=1$/);
    await expect(page.getByTestId("data-blocked")).toContainText(
      "Other Console pages are unavailable while the deletion is pending",
    );
    await expect(page.getByTestId("deletion-banner")).toContainText(`erased after ${erasedAfter}`);
  }

  // 5. Cancel deletion, with a reason: everything works again.
  await page.getByTestId("deletion-cancel").click();
  const cancelStep = page.getByTestId("cancel-confirm");
  await expect(cancelStep).toBeFocused();
  await cancelStep.getByLabel("Reason").fill(CANCEL_REASON);
  await cancelStep.getByTestId("confirm-submit").click();
  await expect(page).toHaveURL(/\/settings\/data\?done=cancelled$/);
  await expect(page.getByTestId("data-done")).toContainText("Deletion cancelled");
  // An old address no longer claims a pending deletion.
  await page.goto("/settings/data?blocked=1");
  await expect(page.getByTestId("data-blocked")).toHaveCount(0);
  await expect(page.getByTestId("deletion-banner")).toHaveCount(0);
  expect((await fetch(`${API_URL}/v1/apps`, { headers: auth })).status).toBe(200);
  await page.goto("/apps");
  await expect(page).toHaveURL(/\/apps$/);
  await expect(page.getByTestId("deletion-banner")).toHaveCount(0);
  const cancelled = ListAuditResponseSchema.parse(
    await (await fetch(`${API_URL}/v1/audit?action=organization.deletion.cancel`, { headers: auth })).json(),
  );
  expect(cancelled.entries[0]?.reason).toBe(CANCEL_REASON);
});
