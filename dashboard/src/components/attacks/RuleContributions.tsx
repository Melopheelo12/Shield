import type { Verdict } from "../../types/events";
import { ThreatScore } from "../common/ThreatScore";

/**
 * Pourquoi ce score (US-13) : chaque règle déclenchée et sa contribution.
 *
 * La somme est recalculée ici et comparée au score : c'est l'invariant 2 du projet,
 * et un écart doit se voir à l'écran plutôt que passer inaperçu.
 */
export function RuleContributions({ verdict }: { verdict: Verdict }) {
  const total = verdict.matches.reduce((sum, match) => sum + match.contribution, 0);
  const consistent = total === verdict.threat_score;

  if (verdict.matches.length === 0) {
    return <p className="muted">Aucune règle déclenchée : score de {verdict.threat_score}.</p>;
  }

  return (
    <div className="rules">
      <ol className="rules__list">
        {verdict.matches.map((match) => (
          <li key={match.rule_id}>
            <div className="rules__head">
              <span>
                <span className={`badge badge--${match.severity}`}>{match.severity}</span>{" "}
                <strong>{match.name}</strong> <span className="muted mono">{match.rule_id}</span>
              </span>
              <span className="num rules__points">+{match.contribution}</span>
            </div>
            <p className="muted">{match.description}</p>
          </li>
        ))}
      </ol>
      <div className={`rules__total${consistent ? "" : " rules__total--broken"}`}>
        <span>Somme des contributions</span>
        <span className="num">
          {total} {consistent ? "=" : "≠"} <ThreatScore score={verdict.threat_score} />
        </span>
      </div>
      {!consistent && (
        <p className="state--error" role="alert">
          La somme ne correspond pas au score : le verdict n'est pas explicable (invariant 2).
        </p>
      )}
    </div>
  );
}
