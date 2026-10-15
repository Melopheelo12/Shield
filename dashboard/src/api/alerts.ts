/**
 * Alertes (US-30, US-31) : routes `/api/v1/alerts*` de #82. Formes écrites à la main,
 * elles ne font pas partie du contrat d'événement généré.
 */

export type Metric = "events" | "unique_ips" | "max_threat_score";

export const METRICS: Record<Metric, string> = {
  events: "Tentatives reçues",
  unique_ips: "Adresses distinctes",
  max_threat_score: "Score de menace maximal",
};

export interface Threshold {
  id: string;
  metric: Metric;
  threshold: number;
  window_seconds: number;
  silence_seconds: number;
  enabled: boolean;
}

export interface ThresholdsResponse {
  items: Threshold[];
  channels: string[];
}

export type ChannelResult = "sent" | "failed";

export interface AlertRecord {
  threshold_id: string;
  triggered_at: string;
  value: number;
  threshold: number;
  status: "sent" | "failed" | "logged";
  channels: Record<string, ChannelResult>;
}

export const ALERTS = {
  history: "/api/v1/alerts?limit=50",
  thresholds: "/api/v1/alerts/thresholds",
  test: "/api/v1/alerts/test",
} as const;

export type ThresholdField = "id" | "metric" | "threshold" | "window_seconds" | "silence_seconds";
export type FieldErrors = Partial<Record<ThresholdField, string>>;

/**
 * Mêmes règles que le collecteur (`Threshold.__post_init__`, `AlertService.configure`) :
 * l'erreur s'affiche sur le champ avant même l'envoi.
 */
export function validateThresholds(items: Threshold[]): FieldErrors[] {
  const counts = new Map<string, number>();
  for (const item of items) counts.set(item.id.trim(), (counts.get(item.id.trim()) ?? 0) + 1);

  return items.map((item) => {
    const errors: FieldErrors = {};
    const id = item.id.trim();
    if (!id) errors.id = "Identifiant obligatoire.";
    else if ((counts.get(id) ?? 0) > 1) errors.id = "Identifiant en double.";
    if (!(item.metric in METRICS)) errors.metric = "Mesure inconnue.";
    if (!Number.isFinite(item.threshold) || item.threshold <= 0) errors.threshold = "Le seuil doit être positif.";
    if (!Number.isInteger(item.window_seconds) || item.window_seconds < 1 || item.window_seconds > 86_400) {
      errors.window_seconds = "Fenêtre entre 1 s et 24 h (86 400 s).";
    }
    if (!Number.isInteger(item.silence_seconds) || item.silence_seconds < 0 || item.silence_seconds > 7 * 86_400) {
      errors.silence_seconds = "Silence entre 0 et 7 jours (604 800 s).";
    }
    return errors;
  });
}

/** Champ visé par un refus 422 du collecteur (`invalid threshold: …`), si on le reconnaît. */
export function fieldFromServerError(detail: string | undefined): ThresholdField | null {
  if (!detail) return null;
  if (/double|'id'/.test(detail)) return "id";
  if (/seuil|'threshold'/.test(detail)) return "threshold";
  if (/fenêtre|window/.test(detail)) return "window_seconds";
  if (/silence/.test(detail)) return "silence_seconds";
  if (/metric|Metric/.test(detail)) return "metric";
  return null;
}
