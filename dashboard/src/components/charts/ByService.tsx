import { STATS, type ByServiceItem } from "../../api/stats";
import { useApi } from "../../hooks/useApi";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { BarList } from "./BarList";

/** Répartition des tentatives par leurre (US-25). */
export function ByService() {
  const stats = useApi<{ items: ByServiceItem[] }>(STATS.byService, 10_000);
  if (stats.status === "loading") return <LoadingState />;
  if (stats.status === "error") return <ErrorState message={stats.message} onRetry={stats.reload} />;
  const items = stats.status === "ready" ? stats.data.items : [];
  if (items.length === 0) return <EmptyState title="Aucune tentative." />;

  return (
    <BarList
      label="Tentatives par service"
      items={[...items]
        .sort((a, b) => b.count - a.count)
        .map((item) => ({
          key: item.service,
          label: <span className={`service service--${item.service}`}>{item.service.toUpperCase()}</span>,
          value: item.count,
          detail: `${item.count.toLocaleString("fr-FR")} · ${item.percentage.toLocaleString("fr-FR")} %`,
          color: `var(--svc-${item.service})`,
        }))}
    />
  );
}
