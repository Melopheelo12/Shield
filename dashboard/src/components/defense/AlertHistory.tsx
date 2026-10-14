import { ALERTS, type AlertRecord } from "../../api/alerts";
import { useApi } from "../../hooks/useApi";
import { formatTimestamp } from "../../utils/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

const STATUS: Record<AlertRecord["status"], string> = {
  sent: "envoyée",
  failed: "échec d'envoi",
  logged: "tracée (aucun canal)",
};

/** Historique des franchissements de seuil, avec le résultat par canal (US-30). */
export function AlertHistory() {
  const history = useApi<{ items: AlertRecord[] }>(ALERTS.history, 15_000);
  if (history.status === "loading") return <LoadingState />;
  if (history.status === "error") return <ErrorState message={history.message} onRetry={history.reload} />;
  const items = history.status === "ready" ? history.data.items : [];
  if (items.length === 0) return <EmptyState title="Aucun seuil franchi pour l'instant." />;

  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Date</th>
            <th scope="col">Seuil</th>
            <th scope="col" className="num">
              Valeur / seuil
            </th>
            <th scope="col">Statut</th>
            <th scope="col">Canaux</th>
          </tr>
        </thead>
        <tbody>
          {items.map((alert) => (
            <tr key={`${alert.threshold_id}-${alert.triggered_at}`}>
              <td>{formatTimestamp(alert.triggered_at)}</td>
              <td className="mono">{alert.threshold_id}</td>
              <td className="num">
                {alert.value.toLocaleString("fr-FR")} / {alert.threshold.toLocaleString("fr-FR")}
              </td>
              <td className={alert.status === "failed" ? "export-result--warn" : undefined}>{STATUS[alert.status]}</td>
              <td>
                {Object.entries(alert.channels)
                  .map(([channel, result]) => `${channel} ${result === "sent" ? "✓" : "✕"}`)
                  .join(", ") || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
