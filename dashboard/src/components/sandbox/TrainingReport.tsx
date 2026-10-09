import { useEffect, useState } from "react";
import { useApi } from "../../hooks/useApi";
import { loadScorecard, saveScorecard, summarize, type RuleMark, type Scorecard } from "../../utils/scorecard";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

interface Rule {
  id: string;
  name: string;
  description: string;
}

const EMPTY: RuleMark = { attempted: false, detected: false };

/**
 * Grille de partie (US-36) : l'attaquant coche ce qu'il a tenté, le défenseur ce que
 * l'agent a vu dans le journal. Le bilan dit objectivement ce que l'agent a manqué.
 */
export function TrainingReport() {
  const rules = useApi<{ items: Rule[] }>("/api/v1/rules");
  const [card, setCard] = useState<Scorecard>(loadScorecard);
  useEffect(() => saveScorecard(card), [card]);

  if (rules.status === "loading") return <LoadingState />;
  if (rules.status === "error") return <ErrorState message={rules.message} onRetry={rules.reload} />;
  const items = rules.status === "ready" ? rules.data.items : [];
  const summary = summarize(card);

  const toggle = (id: string, field: keyof RuleMark) =>
    setCard((current) => {
      const mark = current[id] ?? EMPTY;
      return { ...current, [id]: { ...mark, [field]: !mark[field] } };
    });

  return (
    <div className="grid">
      <div className="grid grid--stats">
        <div className="stat">
          <span className="stat__label">Techniques tentées</span>
          <span className="stat__value">{summary.attempted}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Détectées par l'agent</span>
          <span className="stat__value">{summary.detected}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Taux de détection</span>
          <span className="stat__value">{summary.rate === null ? "—" : `${summary.rate} %`}</span>
        </div>
      </div>
      {summary.missed.length > 0 && (
        <p className="state--error">Manquées par l'agent : {summary.missed.join(", ")}</p>
      )}

      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Règle</th>
              <th scope="col">Tentée</th>
              <th scope="col">Détectée</th>
            </tr>
          </thead>
          <tbody>
            {items.map((rule) => {
              const mark = card[rule.id] ?? EMPTY;
              return (
                <tr key={rule.id} title={rule.description}>
                  <td>
                    <span className="mono muted">{rule.id}</span> {rule.name}
                  </td>
                  <td>
                    <input
                      type="checkbox"
                      checked={mark.attempted}
                      onChange={() => toggle(rule.id, "attempted")}
                      aria-label={`${rule.name} tentée par l'attaquant`}
                    />
                  </td>
                  <td>
                    <input
                      type="checkbox"
                      checked={mark.detected}
                      onChange={() => toggle(rule.id, "detected")}
                      aria-label={`${rule.name} détectée par l'agent`}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div>
        <button type="button" onClick={() => setCard({})} disabled={summary.attempted === 0 && Object.keys(card).length === 0}>
          Nouvelle partie
        </button>
      </div>
    </div>
  );
}
