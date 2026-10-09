export interface RuleMark {
  attempted: boolean;
  detected: boolean;
}

export type Scorecard = Record<string, RuleMark>;

export interface ScorecardSummary {
  attempted: number;
  detected: number;
  /** Règles tentées par l'attaquant mais non détectées : ce que l'agent a manqué. */
  missed: string[];
  /** Taux de détection en pourcentage, `null` tant que rien n'a été tenté. */
  rate: number | null;
}

/**
 * Bilan d'une partie de sandbox (US-36) : on ne compte une détection que si la
 * technique a réellement été tentée — une règle déclenchée par hasard ne doit pas
 * gonfler le score de l'agent.
 */
export function summarize(card: Scorecard): ScorecardSummary {
  const attempted = Object.entries(card).filter(([, mark]) => mark.attempted);
  const detected = attempted.filter(([, mark]) => mark.detected);
  return {
    attempted: attempted.length,
    detected: detected.length,
    missed: attempted.filter(([, mark]) => !mark.detected).map(([rule]) => rule).sort(),
    rate: attempted.length ? Math.round((detected.length / attempted.length) * 100) : null,
  };
}

const STORAGE_KEY = "shield.sandbox.grille";

/** Grille sauvegardée dans le navigateur ; vide si le stockage est indisponible ou illisible. */
export function loadScorecard(): Scorecard {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? (parsed as Scorecard) : {};
  } catch {
    return {};
  }
}

export function saveScorecard(card: Scorecard): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(card));
  } catch {
    // Navigation privée ou stockage plein : la grille reste valable pour la session.
  }
}
