// Ticket 18d in a real browser: the operator dashboard /ops against the real API, started with AR_OPS_TOKEN. Without the
// operator cookie /ops sends to operator sign-in; a wrong token is refused; the right one opens ten SLO panels in catalog
// order. Policy-distribution fetches made meanwhile move SLO-03's totals after Refresh, once the API's read cache
// (up to 15 s) has expired. Sign-out ends the session.
import { SLO_CATALOG } from "@antireverse/protocol";
import { expect, type Page, test } from "@playwright/test";
import { API_URL, OPS_TOKEN } from "./playwright.config.ts";

/** The `good` and `total` of an SLO panel, read from its "N good of M" line. */
async function countsOf(page: Page, id: string): Promise<{ good: number; total: number }> {
  const text =
    (await page.locator(`[data-testid="slo-panel"][data-slo-id="${id}"] [data-testid="slo-counts"]`).textContent()) ??
    "";
  const match = /^([\d,]+) good of ([\d,]+)$/.exec(text.trim());
  if (match === null) throw new Error(`unexpected counts: ${text}`);
  return { good: Number(match[1]?.replaceAll(",", "")), total: Number(match[2]?.replaceAll(",", "")) };
}

test("ops: operator sign-in, ten SLO panels, totals that move, sign-out", async ({ page, context }) => {
  await page.goto("/ops");
  await expect(page).toHaveURL(/\/ops\/sign-in$/);
  await expect(page.getByRole("heading", { level: 1, name: "Sign in as an operator" })).toBeVisible();

  // A wrong token of the right shape is refused by the API; nothing is stored.
  await page.getByLabel("Operator token").fill("not-the-operator-token-".padEnd(48, "x"));
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("That token was not accepted.")).toBeVisible();
  expect((await context.cookies()).some((cookie) => cookie.name === "ar_ops")).toBe(false);

  await page.getByLabel("Operator token").fill(OPS_TOKEN);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/ops$/);
  expect(page.url()).not.toContain(OPS_TOKEN);
  const cookie = (await context.cookies()).find((entry) => entry.name === "ar_ops");
  expect(cookie).toMatchObject({ httpOnly: true, sameSite: "Strict", path: "/ops" });

  const panels = page.getByTestId("slo-panel");
  await expect(panels).toHaveCount(10);
  expect(
    await panels.evaluateAll((elements) => elements.map((element) => element.getAttribute("data-slo-id"))),
  ).toEqual(SLO_CATALOG.map((def) => def.id));
  await expect(page.getByTestId("ops-scope")).toContainText("this API instance");
  await expect(page.getByTestId("ops-count-not-measured")).toHaveText("2");
  await expect(page.locator('[data-slo-id="SLO-06"] [data-testid="slo-not-measured"]')).toBeVisible();
  await expect(page.locator('[data-slo-id="SLO-08"] [data-testid="slo-status"]')).toHaveText("Not measured");

  // A little traffic: three key-set fetches feed SLO-03 (policy distribution), good and total alike. Other specs'
  // Shields share this API and may fetch the bundle or the key set meanwhile, so the totals rise by at least three,
  // and every request counted in between was good.
  const before = await countsOf(page, "SLO-03");
  for (let i = 0; i < 3; i++) expect((await fetch(`${API_URL}/v1/signing-key`)).status).toBe(200);
  // The API serves reads from an aggregate up to 15 s old (readCacheMs), and sign-in filled it: Refresh again until
  // the next aggregate shows the fetches, for longer than the cache lives.
  await expect
    .poll(
      async () => {
        await page.getByTestId("ops-refresh").click();
        await page.waitForLoadState("load");
        const now = await countsOf(page, "SLO-03");
        const added = now.total - before.total;
        return { atLeastThree: added >= 3, allGood: now.good - before.good === added };
      },
      { timeout: 30_000, intervals: [2_000] },
    )
    .toEqual({ atLeastThree: true, allGood: true });
  await expect(page.locator('[data-slo-id="SLO-03"]')).toHaveAttribute("data-state", "ok");
  await expect(page.locator('[data-slo-id="SLO-03"] [data-testid="slo-attainment"]')).toHaveText("100.000 %");

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/ops\/sign-in$/);
  expect((await context.cookies()).some((entry) => entry.name === "ar_ops")).toBe(false);
  await page.goto("/ops");
  await expect(page).toHaveURL(/\/ops\/sign-in$/);
});
