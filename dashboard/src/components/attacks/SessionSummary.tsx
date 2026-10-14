import { formatDuration, heaviestFirst, sessionPath, type SessionDetail } from "../../api/sessions";
import { useApi } from "../../hooks/useApi";
import { PROFILES } from "../../utils/constants";
import { formatTimestamp } from "../../utils/format";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";
import { ThreatScore } from "../common/ThreatScore";

/**
 * Toute la session d'une tentative (US-26) : un attaquant essaie rarement une seule
 * fois. Les règles sont agrégées sur la session, la plus lourde d'abord.
 */
export function SessionSummary({ sessionId }: { sessionId: string }) {
  const session = useApi<SessionDetail>(sessionPath(sessionId));
  if (session.status === "loading") return <LoadingState />;
  if (session.status === "error") return <ErrorState message={session.message} onRetry={session.reload} />;
  if (session.status !== "ready") return null;

  const detail = session.data;
  const rules = heaviestFirst(detail.rules);

  return (
    <>
      <dl className="fields">
        <div className="field">
          <dt>Tentatives</dt>
          <dd className="num">{detail.event_count.toLocaleString("fr-FR")}</dd>
        </div>
        <div className="field">
          <dt>Durée</dt>
          <dd>
            {formatDuration(detail.started_at, detail.ended_at)}
            <span className="muted"> · {detail.closed ? "terminée" : "en cours"}</span>
          </dd>
        </div>
        <div className="field">
          <dt>Début</dt>
          <dd>{formatTimestamp(detail.started_at)}</dd>
        </div>
        <div className="field">
          <dt>Pire verdict</dt>
          <dd>
            <ThreatScore score={detail.threat_score} />{" "}
            {PROFILES[detail.attacker_profile] ?? detail.attacker_profile}
          </dd>
        </div>
      </dl>

      {rules.length === 0 ? (
        <p className="muted">Aucune règle déclenchée sur la session.</p>
      ) : (
        <ol className="rules__list">
          {rules.map((rule) => (
            <li key={rule.rule_id}>
              <div className="rules__head">
                <span>
                  <span className={`badge badge--${rule.severity}`}>{rule.severity}</span> <strong>{rule.name}</strong>{" "}
                  <span className="muted mono">{rule.rule_id}</span>
                </span>
                <span className="num rules__points">
                  ×{rule.matches} · +{rule.total_contribution}
                </span>
              </div>
            </li>
          ))}
        </ol>
      )}
    </>
  );
}
