import { useCallback, useEffect, useState } from "react";
import type { ServiceName } from "../types/events";
import { DEFAULT_PERIOD, PERIODS, SERVICES, type PeriodKey } from "../utils/constants";

export interface EventFilters {
  period: PeriodKey;
  service: ServiceName | "";
  /** Code pays ISO 3166-1 alpha-2, en majuscules ; vide = tous. */
  country: string;
  /** Score de menace minimal : 0 (tous), 30 ou 60 (seuil d'alerte). */
  minScore: MinScore;
}

/** Paliers du filtre de score, ceux des badges : bleu < 30 ≤ ambre < 60 ≤ rouge. */
export const MIN_SCORES = [0, 30, 60] as const;
export type MinScore = (typeof MIN_SCORES)[number];

export const DEFAULT_FILTERS: EventFilters = { period: DEFAULT_PERIOD, service: "", country: "", minScore: 0 };

/** Lit les filtres depuis la query string. Toute valeur inconnue retombe sur le défaut. */
export function parseFilters(search: string): EventFilters {
  const params = new URLSearchParams(search);
  const period = params.get("periode");
  const service = params.get("service");
  const country = (params.get("pays") ?? "").toUpperCase();
  const minScore = Number(params.get("score"));
  return {
    period: period && period in PERIODS ? (period as PeriodKey) : DEFAULT_FILTERS.period,
    service: SERVICES.includes(service as ServiceName) ? (service as ServiceName) : "",
    country: /^[A-Z]{2}$/.test(country) ? country : "",
    minScore: MIN_SCORES.includes(minScore as MinScore) ? (minScore as MinScore) : 0,
  };
}

/** Écrit les filtres dans la query string en conservant les autres paramètres. */
export function serializeFilters(filters: EventFilters, search = ""): string {
  const params = new URLSearchParams(search);
  const entries: [string, string][] = [
    ["periode", filters.period === DEFAULT_FILTERS.period ? "" : filters.period],
    ["service", filters.service],
    ["pays", filters.country],
    ["score", filters.minScore ? String(filters.minScore) : ""],
  ];
  for (const [key, value] of entries) {
    if (value) params.set(key, value);
    else params.delete(key);
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/**
 * Filtres du tableau d'événements, synchronisés avec l'URL : une vue filtrée se
 * partage par simple copier-coller du lien (c'est aussi ce que vise le lien des
 * alertes). Le bouton « précédent » du navigateur restaure les filtres.
 */
export function useFilters(): [EventFilters, (next: Partial<EventFilters>) => void, () => void] {
  const [filters, setFilters] = useState<EventFilters>(() => parseFilters(window.location.search));

  useEffect(() => {
    const onPopState = () => setFilters(parseFilters(window.location.search));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const apply = useCallback((next: EventFilters) => {
    setFilters(next);
    const url = `${window.location.pathname}${serializeFilters(next, window.location.search)}`;
    window.history.pushState(null, "", url);
  }, []);

  const update = useCallback(
    (patch: Partial<EventFilters>) => apply({ ...parseFilters(window.location.search), ...patch }),
    [apply],
  );
  const reset = useCallback(() => apply(DEFAULT_FILTERS), [apply]);

  return [filters, update, reset];
}
