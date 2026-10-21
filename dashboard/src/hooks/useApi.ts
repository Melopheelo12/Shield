import { useCallback, useEffect, useState } from "react";
import { ApiError, getJson } from "../api/client";

export type LoadState<T> =
  | { status: "loading" }
  | { status: "empty" }
  | { status: "ready"; data: T }
  | { status: "error"; message: string };

/**
 * Appels typés vers l'API du collecteur.
 *
 * Les quatre états (chargement, vide, prêt, erreur) sont explicites et non
 * optionnels : ils sont fréquents au démarrage d'une instance neuve et doivent être
 * maquettés, pas improvisés (§ 1.7.2 de la documentation technique).
 *
 * Passe par `getJson` : le jeton d'accès est ajouté, et un 401 ramène à la connexion.
 */
export function useApi<T>(path: string, intervalMs = 0): LoadState<T> & { reload: () => void } {
  const [state, setState] = useState<LoadState<T>>({ status: "loading" });

  const load = useCallback(async () => {
    try {
      setState({ status: "ready", data: await getJson<T>(path) });
    } catch (error) {
      setState({ status: "error", message: error instanceof ApiError ? error.message : String(error) });
    }
  }, [path]);

  useEffect(() => {
    void load();
    if (intervalMs <= 0) return;
    const timer = setInterval(() => void load(), intervalMs);
    return () => clearInterval(timer);
  }, [load, intervalMs]);

  return { ...state, reload: () => void load() };
}
