// Ticket 18a in a real browser: promote a Rule with a reason in the Console, then find the change in Settings → Audit
// log with the actor's key id, the reason and a verified chain; the entry's details show its place in the chain; the
// export downloads the NDJSON with the signed head first.
import { readFile } from "node:fs/promises";
import {
  type AuditEntry,
  AuditEntrySchema,
  AuditExportHeadLineSchema,
  ListAuditResponseSchema,
} from "@antireverse/protocol";
import { expect, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

const REASON = "Credential stuffing on /login since 08:40 — 100 % of it from one network";

test("a Rule promoted with a reason appears in the audit log with its actor, its reason and a verified chain", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByTestId("organization-created")).toBeVisible();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  await page.getByRole("link", { name: "Continue" }).click();
  await page.getByRole("link", { name: "New App" }).first().click();
  await page.getByLabel("App name").fill("shop-web");
  await page.getByRole("button", { name: "Create App" }).click();
  await expect(page.getByTestId("app-created")).toHaveText("shop-web is ready");

  // 1. A Rule in Monitor mode, then the promotion: the step asks for a reason and refuses to send without one.
  await page.getByTestId("policy-link").click();
  await page.getByLabel("Rule name").fill("Login");
  await page.getByLabel("Path pattern").fill("/login");
  await page.getByRole("button", { name: "Add Rule" }).click();
  const row = page.getByTestId("rule-row").filter({ hasText: "/login" });
  await expect(row).toHaveAttribute("data-mode", "monitor");
  await row.getByTestId("rule-promote").click();
  const dialog = page.getByTestId("policy-confirm");
  const reason = dialog.getByLabel("Reason");
  await expect(reason).toHaveAttribute("required", "");
  await dialog.getByTestId("confirm-submit").click();
  // The browser holds the form back: nothing is published.
  await expect(page.getByTestId("policy-version")).toHaveText("Version 1");
  await expect(row).toHaveAttribute("data-mode", "monitor");
  await reason.fill(REASON);
  await dialog.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("policy-confirm")).toHaveCount(0);
  await expect(row).toHaveAttribute("data-mode", "enforce");
  await expect(page.getByTestId("policy-version")).toHaveText("Version 2");

  // The actor is the admin key of this session: its id, as the API records it.
  const listed = ListAuditResponseSchema.parse(
    await (
      await fetch(`${API_URL}/v1/audit?action=policy.rule.promote`, {
        headers: { authorization: `Bearer ${adminKey}` },
      })
    ).json(),
  );
  const promoted = listed.entries[0] as AuditEntry;
  expect(promoted.reason).toBe(REASON);
  const keyId = promoted.actor.key_id ?? "";

  // 2. Settings → Audit log: the entry, newest first, in words, with the actor, the reason and the chain verified.
  await page.getByTestId("nav-audit").click();
  await expect(page).toHaveURL(/\/settings\/audit$/);
  await expect(page.getByTestId("nav-audit")).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("audit-chain")).toHaveAttribute("data-valid", "true");
  await expect(page.getByTestId("audit-chain")).toHaveText(/^Chain verified: \d+ entries$/);
  // Beside it, the signed head; below, the audit public key an auditor checks an export with.
  const auditKey = (await (await fetch(`${API_URL}/v1/audit/public-key`)).json()) as {
    key_id: string;
    public_key: string;
  };
  await expect(page.getByTestId("audit-signed-head")).toHaveText(
    new RegExp(`^Head signed at entry \\d+ with audit key ${auditKey.key_id}$`),
  );
  await expect(page.getByTestId("audit-key-id")).toHaveText(auditKey.key_id);
  await expect(page.getByTestId("audit-public-key")).toHaveText(auditKey.public_key);
  const rows = page.getByTestId("audit-row");
  const first = rows.first();
  await expect(first).toHaveAttribute("data-action", "policy.rule.promote");
  await expect(first.getByTestId("audit-action")).toHaveText("Rule promoted to enforce");
  await expect(first.getByTestId("audit-app")).toHaveText("shop-web");
  await expect(first.getByTestId("audit-actor")).toHaveText(keyId);
  await expect(first.getByTestId("audit-reason")).toHaveText(REASON);
  await expect(first.getByTestId("audit-summary")).toContainText(promoted.summary);
  // The Rule's creation and the App and Organization before it, each by the same key.
  await expect(page.locator('[data-testid="audit-row"][data-action="organization.create"]')).toHaveCount(1);
  for (const actor of await page.getByTestId("audit-actor").allTextContents()) expect(actor).toBe(keyId);

  // 3. The entry's details: its sequence and hash.
  await first.getByRole("button", { name: "Show details" }).click();
  const details = page.getByTestId("audit-details");
  await expect(details.getByTestId("audit-detail-seq")).toHaveText(String(promoted.seq));
  await expect(details.getByTestId("audit-detail-hash")).toHaveText(promoted.hash);

  // 4. A filter narrows the list to the action.
  await page.getByLabel("Action").selectOption("app.create");
  await page.getByRole("button", { name: "Apply filters" }).click();
  // A GET form of the page: the empty filters travel too and are ignored.
  await expect(page).toHaveURL(/\/settings\/audit\?action=app\.create(?:&|$)/);
  await expect(page.getByTestId("audit-row")).toHaveCount(1);
  await expect(page.getByTestId("audit-row").first()).toHaveAttribute("data-action", "app.create");

  // A filtered view does not check the chain on its own (the API's limit is shared with Export): it offers the check.
  await expect(page.getByTestId("audit-chain")).toHaveCount(0);
  await page.getByTestId("audit-verify").click();
  await expect(page.getByTestId("audit-chain")).toHaveAttribute("data-valid", "true");

  // A day the API cannot take (before 2000) is dropped from the filters: the page still lists the log (review F1).
  await page.goto("/settings/audit?from=1999-12-31");
  await expect(page.getByTestId("audit-row").first()).toBeVisible();

  // 5. Export: the signed head, then every entry with its hash, through the Console.
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByTestId("audit-export").click()]);
  const path = await download.path();
  const lines = (await readFile(path, "utf8")).trimEnd().split("\n");
  AuditExportHeadLineSchema.parse(JSON.parse(lines[0] ?? ""));
  const exported = lines.slice(1).map((line) => AuditEntrySchema.parse(JSON.parse(line)));
  expect(exported.find((entry) => entry.id === promoted.id)?.hash).toBe(promoted.hash);
});
