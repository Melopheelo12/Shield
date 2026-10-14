import type { NormalizedEvent } from "../../types/events";
import type { LoadState } from "../../hooks/useApi";
import type { CursorPagination } from "../../hooks/useEventsPage";
import { formatAttackerText, formatCountry, formatTimestamp } from "../../utils/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { ThreatScore } from "../common/ThreatScore";

type Props = LoadState<NormalizedEvent[]> &
  CursorPagination & {
    reload: () => void;
    onSelect?: (event: NormalizedEvent) => void;
  };

/**
 * Journal des tentatives (US-27).
 *
 * Tout ce qui vient de l'attaquant (IP, identifiant) est rendu comme texte par
 * React — jamais via `dangerouslySetInnerHTML` : une charge XSS reste une chaîne.
 */
export function EventTable(props: Props) {
  return (
    <section className="event-table" aria-label="Journal des événements">
      {renderBody(props)}
      <Pagination {...props} />
    </section>
  );
}

function renderBody(props: Props) {
  switch (props.status) {
    case "loading":
      return <LoadingState label="Chargement des événements…" />;
    case "error":
      return <ErrorState message={props.message} onRetry={props.reload} />;
    case "empty":
      return (
        <EmptyState title="Aucun événement pour ces filtres.">
          <p>Élargissez la période ou retirez un filtre.</p>
        </EmptyState>
      );
    case "ready":
      return (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th scope="col">Horodatage</th>
                <th scope="col">Service</th>
                <th scope="col">IP source</th>
                <th scope="col">Pays</th>
                <th scope="col">Identifiant</th>
                <th scope="col">Technique</th>
                <th scope="col" className="num">
                  Score
                </th>
              </tr>
            </thead>
            <tbody>
              {props.data.map((event) => (
                <tr
                  key={event.event_id}
                  onClick={props.onSelect ? () => props.onSelect?.(event) : undefined}
                  className={props.onSelect ? "clickable" : undefined}
                >
                  <td>
                    <time dateTime={event.occurred_at}>{formatTimestamp(event.occurred_at)}</time>
                  </td>
                  <td>
                    <span className={`service service--${event.service}`}>{event.service.toUpperCase()}</span>
                  </td>
                  <td className="mono">{event.source_ip}</td>
                  <td>{formatCountry(event.country_code)}</td>
                  <td className="mono" title={event.username || undefined}>
                    {formatAttackerText(event.username)}
                  </td>
                  <td className="mono">{event.technique_id ?? "—"}</td>
                  <td className="num">
                    <ThreatScore score={event.threat_score} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
  }
}

function Pagination({ page, hasPrevious, hasNext, previous, next }: CursorPagination) {
  if (!hasPrevious && !hasNext) return null;
  return (
    <nav className="pagination" aria-label="Pagination">
      <button type="button" onClick={previous} disabled={!hasPrevious}>
        ← Plus récents
      </button>
      <span>Page {page + 1}</span>
      <button type="button" onClick={next} disabled={!hasNext}>
        Plus anciens →
      </button>
    </nav>
  );
}
