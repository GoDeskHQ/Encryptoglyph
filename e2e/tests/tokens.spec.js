const { test, expect } = require("@playwright/test");

test("user creates, uses, and revokes a scoped API token from the console", async ({ page, request }) => {
  await page.goto("/");
  await page.locator("#nav-links").getByRole("button", { name: "Tokens", exact: true }).click();
  await expect(page.locator("#view-tokens")).toBeVisible();
  await page.getByTestId("token-name").fill("n8n");
  await page.getByTestId("token-days").fill("3");
  await page.getByRole("button", { name: "Create token" }).click();
  await expect(page.getByTestId("token-status")).toContainText("Created n8n");
  const token = await page.getByTestId("token-once").innerText();
  expect(token).toMatch(/^egt_/);
  await expect(page.getByTestId("token-list")).toContainText("n8n");
  await expect(page.getByTestId("token-list")).not.toContainText(token);

  const keys = await request.get("/v1/keys", { headers: { authorization: `Bearer ${token}` } });
  expect(keys.status()).toBe(200);

  await page.getByTestId("token-list").getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByTestId("token-status")).toContainText("Revoked n8n");
  const after = await request.get("/v1/keys", { headers: { authorization: `Bearer ${token}` } });
  expect(after.status()).toBe(401);
});
