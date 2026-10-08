import type { ServiceName } from "../types/events";

export const SERVICES: readonly ServiceName[] = ["ssh", "http", "ftp"];

export const PERIODS = {
  "1h": { label: "Dernière heure", seconds: 3_600 },
  "24h": { label: "24 heures", seconds: 86_400 },
  "7d": { label: "7 jours", seconds: 7 * 86_400 },
  "30d": { label: "30 jours", seconds: 30 * 86_400 },
  all: { label: "Tout", seconds: null },
} as const;

export type PeriodKey = keyof typeof PERIODS;

export const DEFAULT_PERIOD: PeriodKey = "24h";

/** Taille de page du tableau d'événements (l'API plafonne `limit` à 500). */
export const EVENTS_PAGE_SIZE = 50;
