import type { NormalizedEvent } from "../types/events";
import { PERIODS } from "../utils/constants";
import type { EventFilters } from "../hooks/useFilters";
import { getJson } from "./client";

/**
 * Réponse de `GET /api/v1/events`.
 *
 * `next_cursor` fait partie du contrat de pagination par curseur (US-27) : absent
 * ou `null`, il signifie « dernière page ». Tant que le collecteur ne le renvoie
 * pas, le tableau affiche une seule page — sans erreur.
 */
interface EventsResponse {
  items: NormalizedEvent[];
  count: number;
  next_cursor?: string | null;
}

export interface EventsPage {
  items: NormalizedEvent[];
  nextCursor: string | null;
}

/** Borne basse de la période, en ISO 8601 ; `null` pour « Tout ». */
export function periodStart(period: EventFilters["period"], now = Date.now()): string | null {
  const seconds = PERIODS[period].seconds;
  return seconds === null ? null : new Date(now - seconds * 1000).toISOString();
}

export async function fetchEventsPage(
  filters: EventFilters,
  cursor: string | null,
  limit: number,
  signal?: AbortSignal,
): Promise<EventsPage> {
  const since = periodStart(filters.period);
  const body = await getJson<EventsResponse>(
    "/api/v1/events",
    {
      service: filters.service,
      country: filters.country,
      since,
      cursor,
      limit,
    },
    signal,
  );

  // Garde côté client : si le collecteur ignore `since`, la période reste respectée.
  const sinceMs = since ? Date.parse(since) : null;
  const items =
    sinceMs === null ? body.items : body.items.filter((event) => Date.parse(event.occurred_at) >= sinceMs);
  return { items, nextCursor: body.next_cursor ?? null };
}
