import { STATS, type ByServiceItem } from "../../api/stats";
import { useApi } from "../../hooks/useApi";
import type { ServiceName } from "../../types/events";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

/** Ce que chaque leurre attire, en une ligne. */
const DECOYS: Record<ServiceName, { label: string; detail: string }> = {
  ssh: { label: "SSH", detail: "Force brute, identifiants par défaut" },
  http: { label: "HTTP · WordPress", detail: "Scans de chemins, connexions, exploits" },
  ftp: { label: "FTP", detail: "Connexions anonymes, identifiants" },
};

const number = new Intl.NumberFormat("fr-FR");

/** Répartition des tentatives par leurre (US-25) : barre empilée et détail. */
export function ByService() {
  const stats = useApi<{ items: ByServiceItem[] }>(STATS.byService, 10_000);
  if (stats.status === "loading") return <LoadingState />;
  if (stats.status === "error") return <ErrorState message={stats.message} onRetry={stats.reload} />;
  const items = [...(stats.status === "ready" ? stats.data.items : [])].sort((a, b) => b.count - a.count);
  if (items.length === 0) return <EmptyState title="Aucune tentative." />;

  return (
    <div className="split">
      <div className="split__bar" aria-hidden="true">
        {items.map((item) => (
          <span key={item.service} style={{ width: `${item.percentage}%`, background: `var(--svc-${item.service})` }} />
        ))}
      </div>
      <ul className="split__list" aria-label="Tentatives par leurre">
        {items.map((item) => (
          <li key={item.service}>
            <span className="split__swatch" style={{ background: `var(--svc-${item.service})` }} aria-hidden="true" />
            <span className="split__label">
              <strong>{DECOYS[item.service]?.label ?? item.service.toUpperCase()}</strong>
              <span className="muted">{DECOYS[item.service]?.detail}</span>
            </span>
            <span className="mono" title={`${item.percentage.toLocaleString("fr-FR")} %`}>
              {number.format(item.count)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
