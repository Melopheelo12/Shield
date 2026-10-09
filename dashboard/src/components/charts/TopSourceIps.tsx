import { STATS, type TopIpItem } from "../../api/stats";
import { useApi } from "../../hooks/useApi";
import { formatCountry } from "../../utils/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { ThreatScore, threatLevel } from "../common/ThreatScore";
import { BarList } from "./BarList";

/** Les adresses les plus actives (US-23) : les premières candidates au blocage. */
export function TopSourceIps({ limit = 8 }: { limit?: number }) {
  const stats = useApi<{ items: TopIpItem[] }>(STATS.topIps(limit), 10_000);
  if (stats.status === "loading") return <LoadingState />;
  if (stats.status === "error") return <ErrorState message={stats.message} onRetry={stats.reload} />;
  const items = stats.status === "ready" ? stats.data.items : [];
  if (items.length === 0) return <EmptyState title="Aucune adresse pour l'instant." />;

  return (
    <BarList
      label="Adresses IP les plus actives"
      items={items.map((item) => ({
        key: item.source_ip,
        label: (
          <>
            <span className="mono">{item.source_ip}</span>
            {item.country_code && <span className="muted"> {formatCountry(item.country_code)}</span>}
          </>
        ),
        value: item.events,
        detail: (
          <>
            {item.events.toLocaleString("fr-FR")} <ThreatScore score={item.threat_score} />
          </>
        ),
        color: `var(--sev-${threatLevel(item.threat_score)})`,
      }))}
    />
  );
}
