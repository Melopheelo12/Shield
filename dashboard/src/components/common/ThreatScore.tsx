/** Palier de gravité d'un score 0–100, aligné sur les sévérités des règles. */
export function threatLevel(score: number): "low" | "medium" | "high" | "critical" {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export function ThreatScore({ score }: { score: number }) {
  return (
    <span className={`score score--${threatLevel(score)}`} title={`Score de menace : ${score}/100`}>
      {score}
    </span>
  );
}
