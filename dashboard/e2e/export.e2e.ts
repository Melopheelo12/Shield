import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import { ingest, login } from "./helpers";

test("parcours 4 — exporter en pseudonymisé", async ({ page, request }) => {
  await ingest(request, { service: "ftp", username: "e2e-export", password: "secret-a-retirer", source_ip: "192.0.2.123" });

  await login(page, "/#/defense");
  await expect(page.getByLabel("Pseudonymiser")).toBeChecked();
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Exporter" }).click()]);

  // US-47 : le mode réel est annoncé à l'écran et dans le nom du fichier.
  await expect(page.getByText(/^Export pseudonymisé/)).toBeVisible();
  expect(download.suggestedFilename()).toMatch(/-pseudonymise\.csv$/);

  const csv = await readFile(await download.path(), "utf8");
  const header = csv.split("\n")[0];
  expect(header).not.toContain("password");
  expect(csv).toContain("192.0.2.0");
  expect(csv).not.toContain("192.0.2.123");
  expect(csv).not.toContain("secret-a-retirer");
});
