import { expect, test, type Page } from "@playwright/test";
import { registerSocMocks } from "./support/mockSocApi";

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill("demo.admin@aisoc.dev");
  await page.getByLabel("Password").fill("DemoAdmin123!");
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByTestId("dashboard-page")).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await registerSocMocks(page);
});

test("login flow works", async ({ page }) => {
  await login(page);
  await expect(page).toHaveURL(/\/dashboard$/);
});

test("dashboard loads", async ({ page }) => {
  await login(page);
  await expect(page.getByText("SOC Overview")).toBeVisible();
  await expect(page.getByText("Total alerts")).toBeVisible();
  await expect(page.getByText("Recent alerts")).toBeVisible();
});

test("collector creation works", async ({ page }) => {
  await login(page);
  await page.goto("/collectors");
  await page.getByLabel("Collector name").fill("Browser Collector");
  await page.getByLabel("Collector type").selectOption("windows");
  await page.getByTestId("create-collector-button").click();

  await expect(page.getByText(/One-time token/)).toBeVisible();
  await expect(page.getByText("Browser Collector")).toBeVisible();
});

test("detection rule creation works", async ({ page }) => {
  await login(page);
  await page.goto("/rules");
  await page.getByTestId("new-rule-button").click();
  await page.getByTestId("rule-editor").getByLabel("Name").fill("Browser Test Rule");
  await page.getByTestId("save-rule-button").click();

  await expect(page.getByText("Browser Test Rule")).toBeVisible();
});

test("rule pack page loads", async ({ page }) => {
  await login(page);
  await page.goto("/packs");

  await expect(page.getByTestId("packs-page")).toBeVisible();
  await expect(page.getByText("Authentication Starter")).toBeVisible();
  await expect(page.getByText("Starter packs")).toBeVisible();
});

test("alert list loads", async ({ page }) => {
  await login(page);
  await page.goto("/alerts");

  await expect(page.getByTestId("alerts-page")).toBeVisible();
  await expect(page.getByText("SSH brute force detected")).toBeVisible();
});

test("incident detail loads", async ({ page }) => {
  await login(page);
  await page.goto("/incidents");
  await page.getByRole("button", { name: "Investigate" }).first().click();

  await expect(page.getByTestId("incident-detail-page")).toBeVisible();
  await expect(page.getByText("Attack graph")).toBeVisible();
  await expect(page.getByText("Credential access incident")).toBeVisible();
});

test("soar page loads", async ({ page }) => {
  await login(page);
  await page.goto("/soar");

  await expect(page.getByTestId("soar-page")).toBeVisible();
  await expect(page.getByText("Blocked IPs")).toBeVisible();
  await expect(page.getByText("ssh attack")).toBeVisible();
});
