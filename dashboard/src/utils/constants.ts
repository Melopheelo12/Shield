import type { AttackerProfile, ServiceName } from "../types/events";

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

/** Libellés des profils d'attaquant établis par l'agent défenseur. */
export const PROFILES: Record<AttackerProfile, string> = {
  balayage_opportuniste: "Balayage opportuniste",
  force_brute_ciblee: "Force brute ciblée",
  tentative_exploitation: "Tentative d'exploitation",
  indetermine: "Indéterminé",
};

/** Libellés des techniques ATT&CK attribuées par le collecteur (même table que mitre.py). */
export const TECHNIQUES: Record<string, string> = {
  "T1110.001": "Brute Force: Password Guessing",
  "T1110.003": "Brute Force: Password Spraying",
  T1046: "Network Service Discovery",
  T1190: "Exploit Public-Facing Application",
  T1083: "File and Directory Discovery",
  T1059: "Command and Scripting Interpreter",
  T1078: "Valid Accounts",
};
