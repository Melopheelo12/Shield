import { useMemo, useState } from "react";
import { EmptyState } from "../components/common/EmptyState";
import { ErrorState } from "../components/common/ErrorState";
import { LoadingState } from "../components/common/LoadingState";
import { AttackMap } from "../components/threat-map/AttackMap";
import { CountryPanel } from "../components/threat-map/CountryPanel";
import { MapLegend } from "../components/threat-map/MapLegend";
import { STATS, type CountryCount } from "../api/stats";
import { useApi } from "../hooks/useApi";
import { fromCountryCounts } from "../utils/geo";

/** Carte des origines : d'où viennent les attaques, pour savoir quoi contrer. */
export function ThreatMap() {
  const stats = useApi<{ items: CountryCount[] }>(STATS.byCountry, 15_000);
  const items = stats.status === "ready" ? stats.data.items : null;
  const { countries, unlocated } = useMemo(() => fromCountryCounts(items ?? []), [items]);
  const located = countries.reduce((sum, country) => sum + country.events, 0);
  const [selected, setSelected] = useState<string | null>(null);

  if (stats.status === "loading") return <LoadingState />;
  if (stats.status === "error") return <ErrorState message={stats.message} onRetry={stats.reload} />;

  return (
    <>
      {unlocated > 0 && (
        <p className="notice" role="note">
          {unlocated.toLocaleString("fr-FR")} tentative{unlocated > 1 ? "s" : ""} sur{" "}
          {(unlocated + located).toLocaleString("fr-FR")} n'ont pas de pays : base GeoLite2 absente du
          collecteur, ou adresse inconnue. Elles n'apparaissent pas sur la carte.
        </p>
      )}

      <div className="grid map-layout">
        <section className="panel" aria-labelledby="map-title">
          <div className="panel__head">
            <h2 id="map-title">Origine des tentatives</h2>
            <span className="panel__hint">{located.toLocaleString("fr-FR")} tentatives situées</span>
          </div>
          <AttackMap countries={countries} selected={selected} onSelect={setSelected} />
          {countries.length > 0 && <MapLegend max={countries[0].events} />}
        </section>

        <section className="panel" aria-labelledby="countries-title">
          <div className="panel__head">
            <h2 id="countries-title">Pays les plus actifs</h2>
          </div>
          {countries.length === 0 ? (
            <EmptyState title="Aucun pays identifié pour l'instant." />
          ) : (
            <CountryPanel countries={countries} selected={selected} onSelect={setSelected} />
          )}
        </section>
      </div>
    </>
  );
}
