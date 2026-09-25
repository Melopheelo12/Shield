import { useCallback, useEffect, useState } from "react";

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
 */
export function useApi<T>(path: string, intervalMs = 0): LoadState<T> & { reload: () => void } {
  const [state, setState] = useState<LoadState<T>>({ status: "loading" });

  const load = useCallback(async () => {
    try {
      const response = await fetch(path, { headers: { Accept: "application/json" } });
      if (!response.ok) {
        setState({ status: "error", message: `HTTP ${response.status}` });
        return;
      }
      const data = (await response.json()) as T;
      setState({ status: "ready", data });
    } catch (error) {
      setState({ status: "error", message: String(error) });
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
