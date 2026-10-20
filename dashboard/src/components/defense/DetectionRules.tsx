import { useApi } from "../../hooks/useApi";
import type { Severity } from "../../types/events";
import { ErrorState } from "../common/ErrorState";
import { LoadingState } from "../common/LoadingState";

interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  weight: number;
  window_seconds: number;
  enabled: boolean;
}

/** Les règles de l'agent défenseur, telles que chargées depuis `rules/detection_rules.yaml`. */
export function DetectionRules() {
  const rules = useApi<{ items: Rule[] }>("/api/v1/rules");
  if (rules.status === "loading") return <LoadingState />;
  if (rules.status === "error") return <ErrorState message={rules.message} onRetry={rules.reload} />;
  const items = rules.status === "ready" ? rules.data.items : [];

  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">Règle</th>
            <th scope="col">Gravité</th>
            <th scope="col" className="num">
              Poids
            </th>
            <th scope="col">Fenêtre</th>
            <th scope="col">État</th>
          </tr>
        </thead>
        <tbody>
          {items.map((rule) => (
            <tr key={rule.id} title={rule.description}>
              <td>
                <span className="mono muted">{rule.id}</span> {rule.name}
              </td>
              <td>
                <span className={`badge badge--${rule.severity}`}>{rule.severity}</span>
              </td>
              <td className="num">{rule.weight}</td>
              <td>{rule.window_seconds ? `${rule.window_seconds} s` : "—"}</td>
              <td>{rule.enabled ? "active" : <span className="muted">désactivée</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
