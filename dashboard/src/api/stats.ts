import type { ServiceName } from "../types/events";

/**
 * Réponses des points d'entrée `/api/v1/stats/*`.
 *
 * Écrites à la main : ces formes ne font pas partie du contrat d'événement généré
 * (`types/events.ts`). À aligner si le collecteur les modifie.
 */
export interface ByServiceItem {
  service: ServiceName;
  count: number;
  percentage: number;
}

export interface TopIpItem {
  source_ip: string;
  events: number;
  threat_score: number;
  country_code: string | null;
}

export interface CredentialItem {
  value: string;
  count: number;
}

export interface TopCredentials {
  usernames: CredentialItem[];
  passwords: CredentialItem[];
}

export const STATS = {
  byService: "/api/v1/stats/by-service",
  topIps: (limit = 8) => `/api/v1/stats/top-ips?limit=${limit}`,
  topCredentials: (limit = 8) => `/api/v1/stats/top-credentials?limit=${limit}`,
} as const;
