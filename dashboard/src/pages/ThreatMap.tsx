import { useMemo, useState } from "react";
import { EmptyState } from "../components/common/EmptyState";
import { ErrorState } from "../components/common/ErrorState";
import { LoadingState } from "../components/common/LoadingState";
import { AttackMap } from "../components/threat-map/AttackMap";
import { CountryPanel } from "../components/threat-map/CountryPanel";
import { MapLegend } from "../components/threat-map/MapLegend";
import { useApi } from "../hooks/useApi";
import type { NormalizedEvent } from "../types/events";
import { aggregateByCountry } from "../utils/geo";

const SAMPLE = 500;

/** Carte des origines : d'où viennent les attaques, pour savoir quoi contrer. */
export function ThreatMap() {
  const events = useApi<{ items: NormalizedEvent[] }>(`/api/v1/events?limit=${SAMPLE}`, 10_000);
  const items = events.status === "ready" ? events.data.items : null;
  const { countries, unlocated } = useMemo(() => aggregateByCountry(items ?? []), [items]);
  const [selected, setSelected] = useState<string | null>(null);

  if (events.status === "loading") return <LoadingState />;
  if (events.status === "error") return <ErrorState message={events.message} onRetry={events.reload} />;

  return (
    <>
      {unlocated > 0 && (
        <p className="notice" role="note">
          {unlocated.toLocaleString("fr-FR")} des {items?.length.toLocaleString("fr-FR")} dernières
          tentatives n'ont pas de pays : la géolocalisation GeoIP (US-07) n'est pas encore active
          côté collecteur. Elles n'apparaissent pas sur la carte.
        </p>
      )}

      <div className="grid map-layout">
        <section className="panel" aria-labelledby="map-title">
          <div className="panel__head">
            <h2 id="map-title">Origine des tentatives</h2>
            <span className="panel__hint">{SAMPLE} dernières tentatives</span>
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
