import type { Verdict } from "../../types/events";

/**
 * Pourquoi ce score (US-13) : chaque règle déclenchée et sa contribution, comme dans
 * le design — barre empilée, puis le détail règle par règle.
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
      <p className="muted">
        Chaque point du score provient d'une règle nommée. La somme des contributions doit être égale au score.
      </p>
      <div className="rules__stack" aria-hidden="true">
        {verdict.matches.map((match) => (
          <span
            key={match.rule_id}
            className={`rules__segment rules__segment--${match.severity}`}
            style={{ width: `${match.contribution}%` }}
          >
            {match.contribution >= 12 ? `${match.contribution} · ${match.name}` : match.contribution}
          </span>
        ))}
      </div>
      <div className="rules__scale" aria-hidden="true">
        <span>0</span>
        <span>50</span>
        <span>100</span>
      </div>

      <ol className="rules__list">
        {verdict.matches.map((match) => (
          <li key={match.rule_id}>
            <div className="rules__head">
              <span>
                <span className={`rules__swatch rules__segment--${match.severity}`} aria-hidden="true" />
                <span className="mono muted">{match.rule_id}</span> <strong className="mono">{match.name}</strong>{" "}
                <span className={`badge badge--${match.severity}`}>{match.severity}</span>
              </span>
              <span className="num rules__points mono" title={`poids ${match.weight}`}>
                +{match.contribution}
              </span>
            </div>
            <p className="muted">{match.description}</p>
          </li>
        ))}
      </ol>

      <div className={`rules__total${consistent ? "" : " rules__total--broken"}`}>
        <span>{consistent ? "Verdict cohérent — somme des contributions égale au score" : "Somme des contributions ≠ score"}</span>
        <span className="mono">
          {verdict.matches.map((match) => match.contribution).join(" + ")} {consistent ? "=" : "≠"} {verdict.threat_score}
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
