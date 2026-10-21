import type { ServiceName } from "../types/events";

export interface TimelineBucket {
  /** Début de la tranche, en millisecondes depuis l'époque Unix. */
  start: number;
  ssh: number;
  http: number;
  ftp: number;
}

/** Pas proposés, du plus fin au plus large : on prend le premier qui donne ≤ 60 tranches. */
const STEPS_MS = [60_000, 5 * 60_000, 15 * 60_000, 3_600_000, 6 * 3_600_000, 86_400_000];

/**
 * Regroupe des événements en tranches régulières, par service.
 *
 * Calculé côté navigateur tant que le collecteur n'expose pas de point d'entrée
 * `timeline` (S3-03) : la courbe porte donc sur les derniers événements chargés,
 * pas sur tout l'historique. Les tranches vides sont conservées, sans quoi une
 * accalmie disparaîtrait de la courbe.
 */
export function bucketize(
  events: { occurred_at: string; service: ServiceName }[],
): { step: number; buckets: TimelineBucket[] } {
  // Une date par événement, à la même position : NaN pour un horodatage illisible.
  const parsed = events.map((event) => Date.parse(event.occurred_at));
  const times = parsed.filter(Number.isFinite);
  if (times.length === 0) return { step: STEPS_MS[0], buckets: [] };

  const min = Math.min(...times);
  const max = Math.max(...times);
  const step = STEPS_MS.find((ms) => (max - min) / ms <= 60) ?? STEPS_MS[STEPS_MS.length - 1];
  const first = Math.floor(min / step) * step;
  const count = Math.floor((max - first) / step) + 1;

  const buckets: TimelineBucket[] = Array.from({ length: count }, (_, index) => ({
    start: first + index * step,
    ssh: 0,
    http: 0,
    ftp: 0,
  }));
  events.forEach((event, index) => {
    const time = parsed[index];
    if (!Number.isFinite(time)) return;
    buckets[Math.floor((time - first) / step)][event.service] += 1;
  });
  return { step, buckets };
}
