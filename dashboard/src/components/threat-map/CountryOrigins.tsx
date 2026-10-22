import { useMemo } from "react";
import { STATS, type CountryCount } from "../../api/stats";
import { useApi } from "../../hooks/useApi";
import { fromCountryCounts } from "../../utils/geo";
import { BarList } from "../charts/BarList";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

const number = new Intl.NumberFormat("fr-FR");

/** Les pays d'où viennent le plus de tentatives, et la part encore non située. */
export function CountryOrigins({ limit = 6 }: { limit?: number }) {
  const stats = useApi<{ items: CountryCount[] }>(STATS.byCountry, 15_000);
  const items = stats.status === "ready" ? stats.data.items : null;
  const { countries, unlocated } = useMemo(() => fromCountryCounts(items ?? []), [items]);

  if (stats.status === "loading") return <LoadingState />;
  if (stats.status === "error") return <ErrorState message={stats.message} onRetry={stats.reload} />;
  if (countries.length === 0 && unlocated === 0) return <EmptyState title="Aucune tentative." />;

  return (
    <>
      {countries.length > 0 ? (
        <BarList
          label="Tentatives par pays d'origine"
          items={countries.slice(0, limit).map((country) => ({
            key: country.code,
            label: country.name,
            value: country.events,
            color: "var(--svc-http)",
          }))}
        />
      ) : (
        <p className="muted">Aucun pays identifié : bases GeoLite2 absentes du collecteur.</p>
      )}
      {unlocated > 0 && (
        <p className="stat__hint">
          {number.format(unlocated)} tentative{unlocated > 1 ? "s" : ""} non située{unlocated > 1 ? "s" : ""} ·{" "}
          <a href="#/carte">voir la carte</a>
        </p>
      )}
    </>
  );
}
