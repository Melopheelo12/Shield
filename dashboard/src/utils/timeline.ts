import type { TimelinePoint } from "../api/stats";

export interface TimelineSlot {
  /** Début de la tranche, en millisecondes depuis l'époque Unix. */
  start: number;
  events: number;
  maxScore: number;
}

/** Périodes proposées : au plus quelques dizaines de tranches, sous le plafond de 1 000 de l'API. */
export const PERIODS = [
  { key: "1h", label: "1 h", hours: 1, bucketMinutes: 5 },
  { key: "24h", label: "24 h", hours: 24, bucketMinutes: 60 },
  { key: "7d", label: "7 j", hours: 24 * 7, bucketMinutes: 6 * 60 },
  { key: "30d", label: "30 j", hours: 24 * 30, bucketMinutes: 24 * 60 },
] as const;

export type PeriodKey = (typeof PERIODS)[number]["key"];

/**
 * Complète la chronologie de l'API par des tranches vides.
 *
 * Le collecteur ne renvoie que les tranches qui contiennent des tentatives : sans ce
 * remplissage, une accalmie disparaîtrait de la courbe et deux pics éloignés
 * sembleraient voisins. Les tranches sont calées sur celles de l'API, de la tranche
 * qui contient `since` jusqu'à celle qui contient `now`.
 */
export function fillTimeline(points: TimelinePoint[], since: number, stepMs: number, now: number): TimelineSlot[] {
  const valid = points
    .map((point) => ({ start: Date.parse(point.bucket), point }))
    .filter((item) => Number.isFinite(item.start));
  const anchor = valid.length > 0 ? valid[0].start : Math.floor(since / stepMs) * stepMs;
  const first = anchor - Math.ceil((anchor - since) / stepMs) * stepMs;
  const count = Math.max(0, Math.floor((now - first) / stepMs) + 1);

  const slots: TimelineSlot[] = Array.from({ length: count }, (_, index) => ({
    start: first + index * stepMs,
    events: 0,
    maxScore: 0,
  }));
  for (const { start, point } of valid) {
    const slot = slots[Math.round((start - first) / stepMs)];
    if (!slot) continue;
    slot.events += point.events;
    slot.maxScore = Math.max(slot.maxScore, point.max_threat_score);
  }
  return slots;
}
