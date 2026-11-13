// Slice 14 in a real browser: an admin adds a host in the Console, sees the two ways to prove it with copy buttons,
// publishes the TXT record (in the e2e API's stand-in DNS, a JSON file the API's resolver reads: see
// fixtures/api-fixture-patches.ts) and verifies it; then writes and signs Rules of Engagement with the typed phrase,
// sees the current version, and uses "Check a test" for one allowed and one refused case.
import { readFileSync, writeFileSync } from "node:fs";
import { CurrentRulesOfEngagementResponseSchema } from "@antireverse/protocol";
import { expect, test } from "@playwright/test";
import { API_URL, FAKE_DNS_FILE } from "./playwright.config.ts";

const HOST = "www.acme-shop.io";

/** Reads the page's clipboard (this workspace's TypeScript has no DOM library, hence the narrow type). */
const readClipboard = (): Promise<string> =>
  (
    globalThis as unknown as { navigator: { clipboard: { readText(): Promise<string> } } }
  ).navigator.clipboard.readText();

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

test("a host is added and verified, Rules of Engagement are signed, and a test is checked", async ({
  page,
  context,
}) => {
  expect(FAKE_DNS_FILE).toBeTruthy();
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);

  // 1. Create the Organization; capture the admin key.
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByRole("button", { name: "Create organization" }).click();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  expect(adminKey).toMatch(/^aro_[A-Za-z0-9_-]{43}$/);
  await page.getByRole("link", { name: "Continue" }).click();

  // 2. Prove → Targets: add the host.
  await page.getByRole("link", { name: "Targets" }).first().click();
  await expect(page).toHaveURL(/\/prove\/targets$/);
  await expect(page.getByTestId("targets-empty")).toBeVisible();
  await page.getByTestId("target-host-input").fill(HOST);
  await page.getByTestId("target-add").click();
  await page.waitForURL(/\/prove\/targets\/tgt_[0-9a-f]{24}$/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText(HOST);
  await expect(page.getByTestId("target-status")).toHaveAttribute("data-status", "pending");

  // 3. The two instructions, each value with a copy button.
  const dns = page.getByTestId("prove-dns");
  const file = page.getByTestId("prove-file");
  await expect(page.getByTestId("prove-dns-name")).toHaveText(`_airverse-challenge.${HOST}`);
  await expect(page.getByTestId("prove-dns-type")).toHaveText("TXT");
  const dnsValue = (await page.getByTestId("prove-dns-value").textContent()) ?? "";
  expect(dnsValue).toMatch(/^airverse-verification=[A-Za-z0-9_-]{43}$/);
  await expect(page.getByTestId("prove-file-url")).toHaveText(`https://${HOST}/.well-known/airverse-verification.txt`);
  const token = (await page.getByTestId("prove-file-content").textContent()) ?? "";
  expect(dnsValue).toBe(`airverse-verification=${token}`);
  await expect(dns.getByRole("button", { name: "Copy" })).toHaveCount(2);
  await expect(file.getByRole("button", { name: "Copy" })).toHaveCount(2);
  // Copying the record value puts exactly that value on the clipboard.
  const copyValue = page.locator('button[aria-describedby="prove-dns-value-label"]');
  await copyValue.click();
  await expect(copyValue).toHaveText("Copied");
  expect(await page.evaluate(readClipboard)).toBe(dnsValue);

  // 4. Verify before the record exists: not verified, and why.
  await page.getByTestId("target-verify").click();
  await expect(page.getByTestId("verify-headline")).toContainText("Not verified");
  await expect(page.getByTestId("target-status")).toHaveAttribute("data-status", "pending");

  // 5. Publish the record (the value copied from the page) and verify: verified by the DNS record.
  publishTxt(`_airverse-challenge.${HOST}`, await page.evaluate(readClipboard));
  await page.getByTestId("target-verify").click();
  await expect(page.getByTestId("verify-result")).toContainText("Verified through the DNS record");
  await expect(page.getByTestId("target-status")).toHaveAttribute("data-status", "verified");

  // 6. Rules of Engagement: none yet; write a new version.
  await page.getByRole("link", { name: "Rules of Engagement" }).first().click();
  await expect(page).toHaveURL(/\/prove\/rules-of-engagement$/);
  await expect(page.getByTestId("roe-none")).toBeVisible();
  await page.getByTestId("roe-new").first().click();
  await expect(page).toHaveURL(/\/prove\/rules-of-engagement\/new$/);

  await page.getByRole("checkbox", { name: HOST }).check();
  await page.locator("#roe-exclusions").fill("/admin");
  await page.getByRole("radio", { name: "safe-active" }).check();
  await expect(page.getByTestId("roe-phrase")).toHaveText("I authorise safe-active testing");
  for (const day of await page.locator('input[name="days"]').all()) await day.check();
  await page.getByRole("checkbox", { name: "All day" }).check();
  await page.locator("#roe-contacts").fill("security@acme-shop.io");

  // A wrong phrase is refused and nothing is signed.
  await page.locator("#roe-confirm").fill("I authorise full testing");
  await page.getByTestId("roe-sign").click();
  await expect(page.getByTestId("error-summary")).toBeVisible();
  await expect(page.locator("#roe-confirm")).toHaveAttribute("aria-invalid", "true");
  await expect(page).toHaveURL(/\/prove\/rules-of-engagement\/new$/);

  // The exact phrase signs. Everything but the phrase was kept by the refusal.
  await expect(page.locator("#roe-exclusions")).toHaveValue("/admin");
  await page.locator("#roe-confirm").fill((await page.getByTestId("roe-phrase").textContent()) ?? "");
  // Slice 18a: signing is a sensitive change, recorded in the audit log with its reason.
  await page.getByTestId("roe-reason").fill("Quarterly test window agreed with the shop owner");
  await page.getByTestId("roe-sign").click();
  await page.waitForURL(/\/prove\/rules-of-engagement$/);

  // 7. The current version: what was signed, by which key, with its content hash.
  const current = page.getByTestId("roe-current");
  await expect(current).toBeVisible();
  await expect(current.getByTestId("roe-scope-host")).toHaveText([HOST]);
  await expect(current.getByTestId("roe-exclusion")).toHaveText(["/admin"]);
  await expect(current.getByTestId("roe-intensity")).toHaveText("safe-active");
  await expect(current.getByTestId("roe-contact")).toHaveText(["security@acme-shop.io"]);
  await expect(current.getByTestId("roe-immutable")).toBeVisible();
  const signed = CurrentRulesOfEngagementResponseSchema.parse(
    await (
      await fetch(`${API_URL}/v1/rules-of-engagement/current`, { headers: { authorization: `Bearer ${adminKey}` } })
    ).json(),
  ).version;
  expect(signed).not.toBeNull();
  await expect(current).toHaveAttribute("data-roe-id", signed?.id as string);
  await expect(current.getByTestId("roe-signed-by")).toHaveAttribute("title", signed?.signed_by as string);
  await expect(current.getByTestId("roe-hash")).toHaveAttribute("title", signed?.content_sha256 as string);

  // 8. Check a test (now, which the all-day, every-day window contains): allowed, then refused on the excluded path.
  await page.locator("#check-host").fill(HOST);
  await page.locator("#check-path").fill("/products/1");
  await page.locator("#check-intensity").selectOption("passive");
  await page.getByTestId("check-submit").click();
  const result = page.getByTestId("check-result");
  await expect(result).toHaveAttribute("data-allowed", "true");
  await expect(result).toContainText(`Allowed. The current Rules of Engagement (${signed?.id})`);

  await page.locator("#check-path").fill("/Admin/users");
  await page.getByTestId("check-submit").click();
  await expect(result).toHaveAttribute("data-allowed", "false");
  await expect(result).toContainText("Refused. This path is excluded by the current Rules of Engagement.");
});
