/**
 * Jeton d'accès du tableau de bord (US-19, S3-01).
 *
 * Le jeton vit en `sessionStorage` : il disparaît avec l'onglet, et un autre site ne
 * peut pas le lire. Le stockage peut être indisponible (navigation privée, données
 * bloquées) : chaque accès est protégé, le tableau de bord redemande alors la connexion.
 */

const STORAGE_KEY = "shield.token";

/** Émis sur `window` quand le jeton disparaît : déconnexion ou réponse 401. */
export const LOGOUT_EVENT = "shield:logout";

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, token);
  } catch {
    // Stockage indisponible : la session durera le temps de la page.
  }
}

export function clearToken(): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Rien à effacer.
  }
}

/** `expired` : le collecteur a refusé le jeton ; `manual` : l'exploitant s'est déconnecté. */
export type LogoutReason = "expired" | "manual";

/** Efface le jeton et prévient toute l'application de revenir à l'écran de connexion. */
export function logout(reason: LogoutReason = "expired"): void {
  clearToken();
  window.dispatchEvent(new CustomEvent<LogoutReason>(LOGOUT_EVENT, { detail: reason }));
}

export type LoginFailure =
  | { kind: "invalid" }
  | { kind: "throttled"; retryAfter: number }
  | { kind: "unavailable"; status: number };

export class LoginError extends Error {
  constructor(readonly failure: LoginFailure) {
    super(failure.kind);
  }
}

/** Secondes d'attente annoncées par `Retry-After` ; 60 si l'en-tête est absent ou illisible. */
export function parseRetryAfter(header: string | null): number {
  const seconds = Number(header);
  return Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds) : 60;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

/** Échange identifiant et mot de passe contre un jeton, et le conserve. */
export async function login(username: string, password: string): Promise<void> {
  const response = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (response.status === 401) throw new LoginError({ kind: "invalid" });
  if (response.status === 429) {
    throw new LoginError({ kind: "throttled", retryAfter: parseRetryAfter(response.headers.get("Retry-After")) });
  }
  if (!response.ok) throw new LoginError({ kind: "unavailable", status: response.status });
  const body = (await response.json()) as TokenResponse;
  setToken(body.access_token);
}

/** Adresse du flux temps réel, jeton compris : un navigateur ne peut pas poser d'en-tête sur un WebSocket. */
export function streamUrl(path = "/ws/events"): string {
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const token = getToken();
  const query = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${scheme}://${window.location.host}${path}${query}`;
}
