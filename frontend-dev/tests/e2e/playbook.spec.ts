import { test, expect, Page } from "@playwright/test";

/**
 * Cross-browser E2E tests for the Sentinel Dashboard.
 *
 * Runs against the LIVE dev server (localhost:5173) with the real
 * backend API (localhost:8000). No page.route() mocks are used here
 * because the Vite dev-server Proxy forwards /api/ at the server level
 * and browser-level mocks are skipped when the backend serves data.
 *
 * Tested: Chromium, Firefox, Microsoft Edge.
 */

async function navigateToPlaybooksList(page: Page) {
  await page.goto("http://localhost:5173/sentinel");
  // Wait for React to hydrate (h1 confirms JS loaded)
  await page.waitForSelector("h1", { timeout: 20000 });
  // Click Playbooks List tab for consistent start state
  const tabBtn = page.locator(".nav-tab-btn", { hasText: "Playbooks List" });
  await tabBtn.waitFor({ state: "visible", timeout: 10000 });
  await tabBtn.click();
  // Wait for either playbook cards, empty state, or loading skeletons to appear
  await page.waitForSelector(".sentinel-tabs-container", { timeout: 15000 });
}

test.describe("Sentinel Cross-Browser Validation", () => {
  test.beforeEach(async ({ page }) => {
    await navigateToPlaybooksList(page);
  });

  // Layout Tests
  test("should render dashboard with heading and nav tabs", async ({ page }) => {
    await expect(page.locator("h1")).toBeVisible();
    await expect(page.locator("h1")).toContainText("Sentinel");
    await expect(page.locator(".sentinel-nav-tabs")).toBeVisible();
    await expect(page.locator(".nav-tab-btn", { hasText: "Playbooks List" })).toBeVisible();
    await expect(page.locator(".nav-tab-btn", { hasText: "ATT&CK Coverage" })).toBeVisible();
  });

  test("should show filter tabs in the playbooks view", async ({ page }) => {
    const tabs = page.locator(".sentinel-tabs-container");
    await expect(tabs).toBeVisible();
    await expect(tabs.locator("button", { hasText: /All/ })).toBeVisible();
    await expect(tabs.locator("button", { hasText: /Draft/ })).toBeVisible();
    await expect(tabs.locator("button", { hasText: /Approved/ })).toBeVisible();
  });

  test("should show search and filter controls", async ({ page }) => {
    await expect(page.locator(".hud-search-input")).toBeVisible();
    await expect(page.locator(".hud-filter-select").first()).toBeVisible();
  });

  test("should switch to ATT&CK Coverage tab and render matrix", async ({ page }) => {
    await page.locator(".nav-tab-btn", { hasText: "ATT&CK Coverage" }).click();
    await expect(
      page.locator(".mitre-matrix-container, .sentinel-mitre-grid")
    ).toBeVisible({ timeout: 12000 });
  });

  test("should display playbook cards or a valid empty/loading state", async ({ page }) => {
    const cards = await page.locator(".playbook-card").count();
    const empty = await page.locator(".sentinel-empty-state").count();
    const loading = await page.locator(".playbook-skeleton-card").count();
    expect(cards + empty + loading).toBeGreaterThan(0);
  });

  test("should open and close the playbook viewer modal", async ({ page }) => {
    const cards = page.locator(".playbook-card");
    if ((await cards.count()) === 0) { test.skip(); return; }

    await cards.first().click();
    const modal = page.locator(".playbook-viewer-panel");
    await expect(modal).toBeVisible({ timeout: 10000 });
    await expect(page.locator(".pbv-title")).toBeVisible();

    await page.locator(".pbv-close-btn").click();
    await expect(modal).not.toBeVisible({ timeout: 5000 });
  });

  test("should render viewer tabs and download bar when modal opens", async ({ page }) => {
    const cards = page.locator(".playbook-card");
    if ((await cards.count()) === 0) { test.skip(); return; }

    await cards.first().click();
    await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
    await expect(page.locator(".pbv-tab-bar")).toBeVisible();
    await expect(page.locator(".pbv-download-bar")).toBeVisible();
    await expect(page.locator("#playbook-viewer-export-btn")).toBeVisible();
  });

  // PDF download via export dropdown
  test("should trigger PDF download via export dropdown", async ({ page }) => {
    const cards = page.locator(".playbook-card");
    if ((await cards.count()) === 0) { test.skip(); return; }

    await cards.first().click();
    await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
    await expect(page.locator(".pbv-download-bar")).toBeVisible();

    await page.locator("#playbook-viewer-export-btn").click();
    await expect(page.locator(".pbv-export-menu")).toBeVisible({ timeout: 5000 });

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 15000 }),
      page.locator(".pbv-export-item").filter({ hasText: "PDF" }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/\.pdf$/i);
  });

  // Markdown download from download bar
  test("should trigger Markdown download from download bar", async ({ page }) => {
    const cards = page.locator(".playbook-card");
    if ((await cards.count()) === 0) { test.skip(); return; }

    await cards.first().click();
    await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
    await expect(page.locator(".pbv-download-bar")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 15000 }),
      page.locator(".pbv-download-btn").filter({ hasText: "Markdown" }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/\.md$/i);
  });

  // JSON download from download bar
  test("should trigger JSON download from download bar", async ({ page }) => {
    const cards = page.locator(".playbook-card");
    if ((await cards.count()) === 0) { test.skip(); return; }

    await cards.first().click();
    await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
    await expect(page.locator(".pbv-download-bar")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 15000 }),
      page.locator(".pbv-download-btn").filter({ hasText: "JSON" }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/\.json$/i);
  });

  // STIX download from download bar
  test("should trigger STIX Bundle download from download bar", async ({ page }) => {
    const cards = page.locator(".playbook-card");
    if ((await cards.count()) === 0) { test.skip(); return; }

    await cards.first().click();
    await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });
    await expect(page.locator(".pbv-download-bar")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 15000 }),
      page.locator(".pbv-download-btn").filter({ hasText: "STIX Bundle" }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/stix\.json$/i);
  });

  // Flexbox layout validation
  test("should have correct flex layout for viewer header (no overflow)", async ({ page }) => {
    const cards = page.locator(".playbook-card");
    if ((await cards.count()) === 0) { test.skip(); return; }

    await cards.first().click();
    await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });

    const headerBox = await page.locator(".pbv-header").boundingBox();
    expect(headerBox).not.toBeNull();
    // Header must be row-direction (height < 100px), not column-stacked
    expect(headerBox!.height).toBeLessThan(100);

    await expect(page.locator(".pbv-title")).toBeVisible();
  });

  test("should have correct flex layout for download bar (no overflow)", async ({ page }) => {
    const cards = page.locator(".playbook-card");
    if ((await cards.count()) === 0) { test.skip(); return; }

    await cards.first().click();
    await expect(page.locator(".playbook-viewer-panel")).toBeVisible({ timeout: 10000 });

    const barBox = await page.locator(".pbv-download-bar").boundingBox();
    expect(barBox).not.toBeNull();
    // Bar width must be greater than 0 (not collapsed)
    expect(barBox!.width).toBeGreaterThan(100);
  });
});
