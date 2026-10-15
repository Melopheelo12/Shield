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

const START_KEY = "shield.sandbox.debut";

/** Début de la partie en cours (ISO 8601), ou `null` si aucune mesure n'est lancée. */
export function loadGameStart(): string | null {
  try {
    const value = window.localStorage.getItem(START_KEY);
    return value && Number.isFinite(Date.parse(value)) ? value : null;
  } catch {
    return null;
  }
}

export function saveGameStart(start: string | null): void {
  try {
    if (start) window.localStorage.setItem(START_KEY, start);
    else window.localStorage.removeItem(START_KEY);
  } catch {
    // Stockage indisponible : la mesure vaut pour cette page seulement.
  }
}

/** Réponse de `GET /api/v1/sandbox/report` (US-37). */
export interface SandboxReport {
  since: string | null;
  events: number;
  detected: number;
  detection_rate: number | null;
  target: number;
  target_met: boolean;
  by_service: Record<string, number>;
  missed_by_technique: { technique: string; events: number }[];
}

/** Verdict d'une partie face à l'objectif de détection (80 %). */
export function reportVerdict(report: SandboxReport): { tone: "ok" | "down" | "pending"; text: string } {
  if (report.detection_rate === null) return { tone: "pending", text: "Aucune tentative depuis le début de la partie." };
  if (report.target_met) {
    return { tone: "ok", text: `Objectif atteint : ${report.detection_rate} % détectées (objectif ${report.target} %).` };
  }
  return {
    tone: "down",
    text: `Objectif manqué : ${report.detection_rate} % détectées, il en faut ${report.target} %.`,
  };
}
