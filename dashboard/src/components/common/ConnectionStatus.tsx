import { useApi } from "../../hooks/useApi";

/**
 * État du collecteur, sondé toutes les 10 s sur `/api/v1/health`.
 *
 * Un tableau de bord qui affiche des chiffres figés sans le dire est pire qu'un
 * tableau vide : l'opérateur doit voir immédiatement que la collecte ne répond plus.
 */
export function ConnectionStatus() {
  const health = useApi<{ status: string }>("/api/v1/health", 10_000);
  const state =
    health.status === "ready" && health.data.status === "ok"
      ? { tone: "ok", label: "Collecteur en ligne" }
      : health.status === "loading"
        ? { tone: "pending", label: "Connexion…" }
        : { tone: "down", label: "Collecteur injoignable" };

  return (
    <span className={`status status--${state.tone}`} role="status" aria-live="polite">
      <span className="status__dot" aria-hidden="true" />
      {state.label}
    </span>
  );
}
