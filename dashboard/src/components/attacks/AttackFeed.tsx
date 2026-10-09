import { useEffect, useRef } from "react";
import { useApi } from "../../hooks/useApi";
import type { NormalizedEvent } from "../../types/events";
import { formatAttackerText } from "../../utils/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { ThreatScore } from "../common/ThreatScore";

const timeFormat = new Intl.DateTimeFormat("fr-FR", { timeStyle: "medium" });

/**
 * Les dernières tentatives, rafraîchies toutes les 3 s.
 *
 * Sondage plutôt que WebSocket tant que le point d'entrée `/ws` (S3-02) n'existe
 * pas : à 3 s, l'objectif de latence d'affichage (< 5 s, US-20) reste tenu.
 */
export function AttackFeed({ limit = 12 }: { limit?: number }) {
  const feed = useApi<{ items: NormalizedEvent[] }>(`/api/v1/events?limit=${limit}`, 3000);
  const items = feed.status === "ready" ? feed.data.items : [];
  const ids = items.map((event) => event.event_id).join(",");

  // Identifiants déjà affichés : mis à jour APRÈS le rendu, pour que seules les
  // nouvelles arrivées clignotent (et rien au premier affichage).
  const seen = useRef<Set<string> | null>(null);
  useEffect(() => {
    seen.current = new Set(ids ? ids.split(",") : []);
  }, [ids]);

  if (feed.status === "loading") return <LoadingState />;
  if (feed.status === "error") return <ErrorState message={feed.message} onRetry={feed.reload} />;
  if (items.length === 0) {
    return <EmptyState title="Aucune tentative pour l'instant." />;
  }
  const previous = seen.current;

  return (
    <ul className="feed" aria-live="polite">
      {items.map((event) => (
        <li key={event.event_id} className={previous && !previous.has(event.event_id) ? "feed__new" : undefined}>
          <time className="mono muted" dateTime={event.occurred_at}>
            {timeFormat.format(new Date(event.occurred_at))}
          </time>
          <span className={`service service--${event.service}`}>{event.service.toUpperCase()}</span>
          <span className="truncate">
            <span className="mono">{event.source_ip}</span>
            {event.username && <span className="muted"> · {formatAttackerText(event.username, 24)}</span>}
          </span>
          <ThreatScore score={event.threat_score} />
        </li>
      ))}
    </ul>
  );
}
