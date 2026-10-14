import { getToken, logout } from "./auth";

export type QueryParams = Record<string, string | number | null | undefined>;

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Construit `path?a=1&b=2` en ignorant les paramètres vides. */
export function buildUrl(path: string, params: QueryParams = {}): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === "") continue;
    query.set(key, String(value));
  }
  const qs = query.toString();
  return qs ? `${path}?${qs}` : path;
}

/**
 * GET typé vers l'API du collecteur, jeton d'accès compris. Toute réponse non 2xx lève
 * une `ApiError` ; un 401 (jeton absent, expiré ou révoqué) déconnecte en plus.
 */
export async function getJson<T>(path: string, params?: QueryParams, signal?: AbortSignal): Promise<T> {
  const token = getToken();
  const response = await fetch(buildUrl(path, params), {
    headers: { Accept: "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    signal,
  });
  if (response.status === 401) logout();
  if (!response.ok) throw new ApiError(response.status, `HTTP ${response.status}`);
  return (await response.json()) as T;
}
