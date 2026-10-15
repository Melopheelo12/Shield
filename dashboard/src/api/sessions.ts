import type { AttackerProfile, NormalizedEvent, ServiceName, Severity } from "../types/events";

/**
 * Réponse de `GET /api/v1/sessions/{session_id}` (US-26).
 *
 * Écrite à la main, comme `api/stats.ts` : #82 ajoute ces types au contrat généré
 * (`types/events.ts`), à reprendre une fois #82 fusionnée.
 */
export interface SessionRule {
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  weight: number;
  matches: number;
  total_contribution: number;
}

export interface SessionDetail {
  session_id: string;
  source_ip: string;
  service: ServiceName;
  started_at: string;
  ended_at: string | null;
  event_count: number;
  threat_score: number;
  attacker_profile: AttackerProfile;
  closed: boolean;
  events: NormalizedEvent[];
  rules: SessionRule[];
}

export const sessionPath = (sessionId: string) => `/api/v1/sessions/${encodeURIComponent(sessionId)}`;

/** Règles de la session, la plus lourde d'abord ; à poids égal, la plus fréquente. */
export function heaviestFirst(rules: SessionRule[]): SessionRule[] {
  return [...rules].sort(
    (a, b) => b.total_contribution - a.total_contribution || b.matches - a.matches || a.rule_id.localeCompare(b.rule_id),
  );
}

/** Durée lisible d'une session : « 42 s », « 3 min 05 s », « 2 h 10 min ». */
export function formatDuration(startIso: string, endIso: string | null): string {
  const start = Date.parse(startIso);
  const end = endIso ? Date.parse(endIso) : start;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return "—";
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ${String(seconds % 60).padStart(2, "0")} s`;
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, "0")} min`;
}
