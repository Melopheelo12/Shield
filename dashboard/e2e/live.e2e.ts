import { expect, test } from "@playwright/test";
import { ingest, login } from "./helpers";

test("parcours 1 — se connecter et voir une attaque arriver en direct", async ({ page, request }) => {
  await login(page);
  await expect(page.getByText("Temps réel : connecté")).toBeVisible();

  const username = `e2e-direct-${Date.now()}`;
  await ingest(request, { service: "ssh", username, password: "123456" });

  // US-20 / S3-11 : visible en moins de 5 s, sans recharger la page.
  await expect(page.locator(".feed").getByText(username)).toBeVisible({ timeout: 5000 });
});
