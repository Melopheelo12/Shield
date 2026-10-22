import type { NormalizedEvent } from "../../types/events";
import type { LoadState } from "../../hooks/useApi";
import type { CursorPagination } from "../../hooks/useEventsPage";
import { attemptSummary, formatAttackerText } from "../../utils/format";
import { EmptyState } from "../common/EmptyState";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { ThreatScore } from "../common/ThreatScore";

const timeFormat = new Intl.DateTimeFormat("fr-FR", { timeStyle: "medium" });
const dateFormat = new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short" });

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
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Horodatage</th>
                <th scope="col">Source</th>
                <th scope="col">Opérateur</th>
                <th scope="col">Leurre</th>
                <th scope="col">Tentative</th>
                <th scope="col">ATT&amp;CK</th>
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
                  onKeyDown={
                    props.onSelect
                      ? (key) => (key.key === "Enter" || key.key === " ") && props.onSelect?.(event)
                      : undefined
                  }
                  tabIndex={props.onSelect ? 0 : undefined}
                  className={props.onSelect ? "clickable" : undefined}
                >
                  <td>
                    <time className="stamp" dateTime={event.occurred_at}>
                      <span className="mono">{timeFormat.format(new Date(event.occurred_at))}</span>
                      <span className="muted">{dateFormat.format(new Date(event.occurred_at))}</span>
                    </time>
                  </td>
                  <td>
                    {event.country_code && <span className="cc">{event.country_code}</span>}
                    <span className="mono">{event.source_ip}</span>
                  </td>
                  <td className="muted truncate" title={event.as_org ?? undefined}>
                    {event.asn ? `AS${event.asn}${event.as_org ? ` · ${event.as_org}` : ""}` : "—"}
                  </td>
                  <td>
                    <span className={`service service--${event.service}`}>{event.service.toUpperCase()}</span>
                  </td>
                  <td className="mono feed__attempt" title={attemptSummary(event)}>
                    {formatAttackerText(attemptSummary(event), 48)}
                  </td>
                  <td className="mono muted">{event.technique_id ?? "—"}</td>
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
