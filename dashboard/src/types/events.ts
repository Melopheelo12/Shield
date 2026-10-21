// ---------------------------------------------------------------------------
// FICHIER GÉNÉRÉ — ne pas modifier à la main.
// Source : src/shield/common/schema.py
// Régénérer avec : make types
// ---------------------------------------------------------------------------

export type ServiceName = "ssh" | "http" | "ftp";
export type EnrichmentStatus = "pending" | "done" | "partial";
export type AttackerProfile = "balayage_opportuniste" | "force_brute_ciblee" | "tentative_exploitation" | "indetermine";
export type Severity = "low" | "medium" | "high" | "critical";

export interface RawEvent {
  event_id: string;
  occurred_at: string;
  service: ServiceName;
  source_ip: string;
  source_port: number;
  dest_port: number;
  username: string;
  password: string;
  payload: string; // base64
  payload_truncated: boolean;
  payload_sha256: string | null; // empreinte de la charge complète, avant troncature
}

export interface NormalizedEvent extends RawEvent {
  session_id: string | null;
  country_code: string | null;
  asn: number | null;
  as_org: string | null;
  reputation_score: number | null;
  technique_id: string | null;
  enrichment_status: EnrichmentStatus;
  threat_score: number;
}

export interface RuleMatch {
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  weight: number;
  contribution: number;
}

export interface Verdict {
  event_id: string;
  session_id: string | null;
  threat_score: number;
  profile: AttackerProfile;
  matches: RuleMatch[];
}

export interface Overview {
  events: number;
  unique_ips: number;
  sessions: number;
  max_threat_score: number;
  rejected: number;
}

export interface TimelinePoint {
  bucket: string; // début de la tranche, ISO 8601
  events: number;
  max_threat_score: number;
}

export interface CountryCount {
  country_code: string | null; // null : adresse non située
  events: number;
  unique_ips: number;
}

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

export type StreamFrame = { type: "event"; data: NormalizedEvent } | { type: "ping" };
