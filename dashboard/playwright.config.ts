import { defineConfig, devices } from "@playwright/test";

/**
 * Parcours de bout en bout (S4-14) contre une pile réelle : collecteur en mémoire et
 * tableau de bord Vite, démarrés par scripts/e2e.sh. Fichiers *.e2e.ts, distincts
 * des tests unitaires Vitest.
 */
export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.e2e.ts",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
