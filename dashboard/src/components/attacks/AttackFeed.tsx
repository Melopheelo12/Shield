import { useEffect, useRef } from "react";
import { useApi } from "../../hooks/useApi";
import { useEventStream } from "../../hooks/useEventStream";
import type { NormalizedEvent } from "../../types/events";
import { mergeFeed } from "../../utils/feed";
import { formatAttackerText } from "../../utils/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { ThreatScore } from "../common/ThreatScore";

const timeFormat = new Intl.DateTimeFormat("fr-FR", { timeStyle: "medium" });

/**
 * Les dernières tentatives, en direct (US-20, S3-06).
 *
 * Un premier chargement par l'API REST remplit la liste, puis chaque trame du
 * WebSocket s'ajoute en tête : une attaque apparaît sans attendre de sondage.
 */
export function AttackFeed({ limit = 12 }: { limit?: number }) {
  const feed = useApi<{ items: NormalizedEvent[] }>(`/api/v1/events?limit=${limit}`);
  const stream = useEventStream();
  const items = mergeFeed(stream.events, feed.status === "ready" ? feed.data.items : [], limit);
  const ids = items.map((event) => event.event_id).join(",");

  // Identifiants déjà affichés : mis à jour APRÈS le rendu, pour que seules les
  // nouvelles arrivées clignotent (et rien au premier affichage).
  const seen = useRef<Set<string> | null>(null);
  useEffect(() => {
    seen.current = new Set(ids ? ids.split(",") : []);
  }, [ids]);

  if (feed.status === "loading" && items.length === 0) return <LoadingState />;
  if (feed.status === "error" && items.length === 0) return <ErrorState message={feed.message} onRetry={feed.reload} />;
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
