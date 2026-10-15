import type { ServiceName } from "../types/events";

/**
 * Réponses des points d'entrée `/api/v1/stats/*`.
 *
 * Écrites à la main : ces formes ne font pas partie du contrat d'événement généré
 * (`types/events.ts`). À aligner si le collecteur les modifie. `TimelinePoint` et
 * `CountryCount` reprennent les types que #82 ajoute au contrat généré : à remplacer
 * par ceux-ci une fois #82 fusionnée.
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

export interface TimelinePoint {
  bucket: string; // début de la tranche, ISO 8601
  events: number;
  max_threat_score: number;
}

export interface TimelineResponse {
  since: string;
  bucket_minutes: number;
  items: TimelinePoint[];
}

export interface CountryCount {
  country_code: string | null; // null : adresse non située
  events: number;
  unique_ips: number;
}

export const STATS = {
  byService: "/api/v1/stats/by-service",
  byCountry: "/api/v1/stats/by-country",
  timeline: (hours: number, bucketMinutes: number) =>
    `/api/v1/stats/timeline?hours=${hours}&bucket_minutes=${bucketMinutes}`,
  topIps: (limit = 8) => `/api/v1/stats/top-ips?limit=${limit}`,
  topCredentials: (limit = 8) => `/api/v1/stats/top-credentials?limit=${limit}`,
} as const;
