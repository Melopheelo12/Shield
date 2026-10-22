import { useApi } from "../../hooks/useApi";
import { useEventStream } from "../../hooks/useEventStream";
import type { ConnectionState } from "../../hooks/useWebSocket";

const STREAM: Record<ConnectionState, { tone: string; label: string }> = {
  connecting: { tone: "pending", label: "Temps réel : connexion…" },
  open: { tone: "ok", label: "Temps réel : connecté" },
  reconnecting: { tone: "pending", label: "Temps réel : reconnexion…" },
  down: { tone: "down", label: "Temps réel : coupé" },
};

/**
 * État du collecteur (sonde `/api/v1/health` toutes les 10 s) et du flux temps réel.
 *
 * Un tableau de bord qui affiche des chiffres figés sans le dire est pire qu'un
 * tableau vide : l'opérateur doit voir immédiatement que la collecte ne répond plus,
 * ou que le direct est coupé alors que l'API répond encore.
 */
export function ConnectionStatus() {
  const health = useApi<{ status: string }>("/api/v1/health", 10_000);
  const stream = STREAM[useEventStream().connection];
  const collector =
    health.status === "ready" && health.data.status === "ok"
      ? { tone: "ok", label: "Collecteur en ligne" }
      : health.status === "loading"
        ? { tone: "pending", label: "Connexion…" }
        : { tone: "down", label: "Collecteur injoignable" };

  return (
    <span className="statuses" role="status" aria-live="polite">
      {[collector, stream].map((state) => (
        <span key={state.label} className={`status status--${state.tone}`}>
          <span className="status__dot" aria-hidden="true" />
          {state.label}
        </span>
      ))}
    </span>
  );
}
