import { expect, test } from "@playwright/test";
import { login } from "./helpers";

test("parcours 3 — régler un seuil d'alerte et le tester", async ({ page }) => {
  await login(page, "/#/defense");
  const threshold = page.getByLabel("Seuil du seuil 1");
  await expect(threshold).toBeVisible();

  // Une valeur invalide est refusée sur le champ, avant tout envoi.
  await threshold.fill("0");
  await expect(page.getByText("Le seuil doit être positif.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Enregistrer" })).toBeDisabled();

  const value = String(150 + (Date.now() % 100));
  await threshold.fill(value);
  await page.getByRole("button", { name: "Enregistrer" }).click();
  await expect(page.getByText("Seuils enregistrés.")).toBeVisible();

  await page.reload();
  await expect(page.getByLabel("Seuil du seuil 1")).toHaveValue(value);

  // Le collecteur de scripts/e2e.sh a un canal Discord pointé vers un faux webhook local.
  await page.getByRole("button", { name: "Tester les canaux" }).click();
  await expect(page.getByLabel("Résultat du test")).toContainText("discord");
  await expect(page.getByLabel("Résultat du test")).toContainText("envoyée ✓");
});
