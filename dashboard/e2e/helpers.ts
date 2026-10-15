import { expect, type APIRequestContext, type Page } from "@playwright/test";

export const ADMIN = { username: "admin", password: process.env.E2E_ADMIN_PASSWORD ?? "dev-admin" };
const INGEST_TOKEN = process.env.E2E_INGEST_TOKEN ?? "dev-token";

/** Se connecte depuis l'écran de connexion et attend la coquille de l'application. */
export async function login(page: Page, path = "/#/") {
  await page.goto(path);
  await page.getByLabel("Identifiant", { exact: true }).fill(ADMIN.username);
  await page.getByLabel("Mot de passe").fill(ADMIN.password);
  await page.getByRole("button", { name: "Se connecter" }).click();
  await expect(page.getByRole("button", { name: "Se déconnecter" })).toBeVisible();
}

let port = 40000;

/**
 * Injecte une tentative comme le ferait un leurre (route d'ingestion, jeton partagé).
 * Adresses de documentation (RFC 5737) uniquement.
 */
export async function ingest(
  request: APIRequestContext,
  event: { service: "ssh" | "http" | "ftp"; username: string; password?: string; payload?: string; source_ip?: string },
) {
  const response = await request.post("/api/v1/ingest", {
    headers: { "X-Ingest-Token": INGEST_TOKEN },
    data: {
      service: event.service,
      source_ip: event.source_ip ?? "203.0.113.77",
      source_port: port++,
      dest_port: { ssh: 22, http: 80, ftp: 21 }[event.service],
      username: event.username,
      password: event.password ?? "",
      payload: Buffer.from(event.payload ?? "").toString("base64"),
    },
  });
  expect(response.status(), await response.text()).toBe(202);
}
