import type { NormalizedEvent } from "../types/events";

/**
 * Fusionne deux listes d'événements, les plus récents d'abord, sans doublon.
 *
 * Le flux temps réel et le premier chargement REST se recouvrent : un événement
 * arrivé par les deux chemins ne doit apparaître qu'une fois.
 */
export function mergeFeed(newer: NormalizedEvent[], older: NormalizedEvent[], limit: number): NormalizedEvent[] {
  const seen = new Set<string>();
  const merged: NormalizedEvent[] = [];
  for (const event of [...newer, ...older]) {
    if (seen.has(event.event_id)) continue;
    seen.add(event.event_id);
    merged.push(event);
  }
  return merged
    .sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at))
    .slice(0, limit);
}
