import { useState } from "react";
import { useApi } from "../../hooks/useApi";
import { loadGameStart, reportVerdict, saveGameStart, type SandboxReport } from "../../utils/scorecard";
import { formatTimestamp } from "../../utils/format";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

function Report({ since }: { since: string }) {
  const report = useApi<SandboxReport>(`/api/v1/sandbox/report?since=${encodeURIComponent(since)}`, 5000);
  if (report.status === "loading") return <LoadingState />;
  if (report.status === "error") return <ErrorState message={report.message} onRetry={report.reload} />;
  if (report.status !== "ready") return null;

  const data = report.data;
  const verdict = reportVerdict(data);
  return (
    <>
      <div className="grid grid--stats">
        <div className="stat">
          <span className="stat__label">Tentatives reçues</span>
          <span className="stat__value">{data.events.toLocaleString("fr-FR")}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Détectées (score &gt; 0)</span>
          <span className="stat__value">{data.detected.toLocaleString("fr-FR")}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Taux de détection</span>
          <span className="stat__value">{data.detection_rate === null ? "—" : `${data.detection_rate} %`}</span>
        </div>
      </div>
      <p className={`status status--${verdict.tone}`} role="status">
        <span className="status__dot" aria-hidden="true" />
        {verdict.text}
      </p>
      {data.missed_by_technique.length > 0 && (
        <>
          <h3 className="panel__sub">Techniques manquées par l'agent</h3>
          <ul className="ip-list">
            {data.missed_by_technique.map((item) => (
              <li key={item.technique}>
                <span>{item.technique}</span>
                <span className="muted num">{item.events} tent.</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

/**
 * Mesure objective d'une partie (US-37) : le collecteur compte, depuis le début de la
 * partie, les tentatives reçues et celles que l'agent a détectées. La grille, elle,
 * reste le relevé humain de ce qui a été tenté.
 */
export function GameMeasure() {
  const [since, setSince] = useState<string | null>(loadGameStart);
  const start = (value: string | null) => {
    saveGameStart(value);
    setSince(value);
  };

  return (
    <div className="grid">
      <div className="filter-bar">
        <button type="button" onClick={() => start(new Date().toISOString())}>
          {since ? "Nouvelle partie" : "Démarrer la partie"}
        </button>
        {since && (
          <>
            <span className="muted">depuis le {formatTimestamp(since)}</span>
            <button type="button" onClick={() => start(null)}>
              Arrêter la mesure
            </button>
          </>
        )}
      </div>
      {since ? <Report since={since} /> : <p className="muted">Démarrez la partie au moment où l'attaquant commence.</p>}
    </div>
  );
}
