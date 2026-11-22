const { test, expect } = require("@playwright/test");
const fs = require("fs");
const path = require("path");

const shots = path.join(__dirname, "..", "screenshots");

test.beforeAll(() => {
  fs.mkdirSync(shots, { recursive: true });
});

test("console flows seal, navigate, and refuse secrets", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");
  await expect(page.getByTestId("hero")).toContainText("Seal the field");
  const hero = await page.getByTestId("hero").innerText();
  for (const brand of ["Komboe", "GitGoat", "RailYard", "Portkyl", "Cerebro", "restic", "age"]) {
    expect(hero).not.toMatch(new RegExp(`\\b${brand}\\b`, "i"));
  }
  await expect(page.getByTestId("feature-cards")).toContainText("Komboe");
  await expect(page.getByRole("link", { name: "Komboe" })).toHaveAttribute("href", "https://komboe.com");

  await page.screenshot({ path: path.join(shots, "desktop-1440.png"), fullPage: true });

  await page.getByRole("button", { name: "Seal a field" }).click();
  await expect(page.locator("#view-seal")).toBeVisible();
  await page.locator("#plaintext").fill("ada@example.com");
  await page.locator("#seal-form").getByRole("button", { name: "Seal", exact: true }).click();
  await expect(page.getByTestId("seal-status")).toContainText("Sealed");
  const ciphertext = await page.getByTestId("ciphertext").inputValue();
  expect(ciphertext.length).toBeGreaterThan(20);
  await expect(page.getByTestId("transcript")).toHaveText("");

  await page.getByRole("button", { name: "Open", exact: true }).click();
  await expect(page.getByTestId("opened")).toHaveText("ada@example.com");

  await page.getByRole("button", { name: "Keys", exact: true }).click();
  await page.getByRole("button", { name: "New key" }).click();
  await expect(page.getByTestId("key-status")).toContainText("Fingerprint");
  await page.locator("#nav-links").getByRole("button", { name: "Seal", exact: true }).click();
  await page.getByRole("button", { name: "Rewrap" }).click();
  await expect(page.getByTestId("seal-status")).toContainText("Rewrap");
  await page.getByRole("button", { name: "Keys", exact: true }).click();
  const retired = page.locator(".key", { has: page.getByRole("button", { name: "Shred" }) });
  await expect(retired).toContainText("retired");
  await expect(retired).toContainText("retained for opening and rewrap");
  await expect(page.locator(".key").filter({ hasText: "current" })).toContainText("No scheduled rotation policy");
  const fingerprint = await retired.locator("code").innerText();
  await page.getByTestId("shred-confirm").fill(fingerprint);
  await retired.getByRole("button", { name: "Shred" }).click();
  await expect(page.getByTestId("key-status")).toContainText("Shredded");

  await page.getByRole("button", { name: "Custody", exact: true }).click();
  await expect(page.getByTestId("custody-status")).toContainText("not-connected");
  await expect(page.getByTestId("custody-status")).toContainText("Backup health");
  await expect(page.getByTestId("custody-status")).toContainText("Restore tests");
  await expect(page.getByTestId("custody-status")).toContainText("Escrow two-person approvals");
  await expect(page.getByTestId("custody-status")).toContainText("not-implemented");
  await page.getByRole("button", { name: "Download sealed inventory" }).click();
  await expect(page.getByTestId("backup-status")).toContainText("Sealed inventory");

  await page.getByRole("button", { name: "Agent", exact: true }).click();
  await page.getByRole("button", { name: "Health" }).click();
  await expect(page.getByTestId("transcript")).toContainText("Health is ok");
  await page.getByRole("button", { name: "What can you do" }).click();
  await expect(page.getByTestId("transcript")).toContainText("Seal form");

  await page.getByTestId("agent-input").fill("password=hunter2-secret");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.getByTestId("transcript")).toContainText("stays out of the assistant");
  await expect(page.getByTestId("transcript")).not.toContainText("hunter2-secret");
  await expect(page.getByTestId("agent-input")).toHaveValue("");

  await page.getByRole("button", { name: "Adopt", exact: true }).click();
  await expect(page.getByTestId("snippet-python")).toContainText("eg_crypto");

  await page.getByRole("button", { name: "Overview", exact: true }).click();
  await page.getByRole("button", { name: "Check for updates" }).click();
  await expect(page.getByTestId("update-status")).toContainText("0.2.0");
  await page.screenshot({ path: path.join(shots, "desktop-1440.png"), fullPage: true });
});

test("mobile nav and reduced motion", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-motion", "reduce");
  await expect(page.getByRole("button", { name: "Menu" })).toBeVisible();
  await page.getByRole("button", { name: "Menu" }).click();
  await page.locator("#nav-links").getByRole("button", { name: "Seal", exact: true }).click();
  await expect(page.locator("#view-seal")).toBeVisible();
  await page.locator("#plaintext").fill("mobile");
  await page.locator("#seal-form").getByRole("button", { name: "Seal", exact: true }).click();
  await expect(page.getByTestId("seal-status")).toContainText("Sealed");
  await page.getByRole("button", { name: "Menu" }).click();
  await page.locator("#nav-links").getByRole("button", { name: "Inventory", exact: true }).click();
  await expect(page.locator("#view-inventory")).toBeVisible();
  await expect(page.locator("#tenant-list")).toContainText("No tenant records");
  await page.screenshot({ path: path.join(shots, "inventory-mobile-390.png"), fullPage: true });
  await page.getByRole("button", { name: "Menu" }).click();
  await page.locator("#nav-links").getByRole("button", { name: "Overview", exact: true }).click();
  await page.screenshot({ path: path.join(shots, "mobile-390.png"), fullPage: true });
});

test("inventory creates and shows the tenant site device hierarchy", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Inventory", exact: true }).click();
  await expect(page.locator("#view-inventory")).toContainText("disappear on restart");
  await expect(page.locator("#tenant-list")).toContainText("No tenant records");
  const create = async (kind, id, name) => {
    await page.locator(`#inventory-${kind}-id`).fill(id);
    await page.locator(`#inventory-${kind}-name`).fill(name);
    await page.getByRole("button", { name: `Create ${kind}`, exact: true }).click();
    await expect(page.locator("#inventory-status")).toHaveText(`Created ${kind} metadata ${id}.`);
  };
  await create("tenant", "acme", "Acme MSP");
  await page.locator("#inventory-site-tenant").selectOption("acme");
  await create("site", "phoenix", "Phoenix office");
  await page.locator("#inventory-device-site").selectOption("phoenix");
  await create("device", "host-1", "Local host");
  await expect(page.locator("#inventory-detail")).toContainText("phoenix");
  await page.locator("#tenant-list").getByRole("button", { name: "Acme MSP (acme)" }).click();
  await expect(page.locator("#inventory-detail")).toContainText("Acme MSP");
  await page.locator("#site-list").getByRole("button", { name: "Phoenix office (phoenix)" }).click();
  await expect(page.locator("#inventory-detail")).toContainText("tenant_id");
  await expect(page.locator("#inventory-detail")).toContainText("acme");
  await page.screenshot({ path: path.join(shots, "inventory-desktop.png"), fullPage: true });

  await page.reload();
  await page.getByRole("button", { name: "Inventory", exact: true }).click();
  await expect(page.locator("#device-list")).toContainText("Local host (host-1)");
  await page.locator("#inventory-tenant-id").fill("acme");
  await page.locator("#inventory-tenant-name").fill("Duplicate");
  await page.getByRole("button", { name: "Create tenant", exact: true }).click();
  await expect(page.locator("#inventory-status")).not.toHaveText("");
  await expect(page.locator("#tenant-list button")).toHaveCount(1);
  await page.evaluate(() => sessionStorage.setItem("eg.session", "expired-test-session"));
  await page.reload();
  await page.getByRole("button", { name: "Inventory", exact: true }).click();
  await expect(page.locator("#tenant-list")).toContainText("No tenant records");
  await expect(page.locator("#site-list")).toContainText("No site records");
  await expect(page.locator("#device-list")).toContainText("No device records");
  await expect(page.locator("#inventory-detail")).toContainText("Select a record");
});
