"""Génère les types TypeScript du tableau de bord à partir des modèles Pydantic.

C'est le mécanisme qui garantit que la lane back-end et la lane front-end partagent
exactement le même contrat (§ 7.2 de la documentation technique). La CI lance ce
script puis vérifie que le fichier produit est identique à celui du dépôt : si Ryan
renomme un champ sans régénérer, la CI échoue avant que le front ne casse en démo.

    python -m shield.tools.gen_ts_types --check   # vérification (CI)
    python -m shield.tools.gen_ts_types           # régénération
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shield.common.schema import (
    AttackerProfile,
    EnrichmentStatus,
    ServiceName,
    Severity,
)

TARGET = Path("dashboard/src/types/events.ts")

HEADER = """// ---------------------------------------------------------------------------
// FICHIER GÉNÉRÉ — ne pas modifier à la main.
// Source : src/shield/common/schema.py
// Régénérer avec : make types
// ---------------------------------------------------------------------------
"""


def _union(enum: type) -> str:
    return " | ".join(f'"{member.value}"' for member in enum)


def render() -> str:
    return f"""{HEADER}
export type ServiceName = {_union(ServiceName)};
export type EnrichmentStatus = {_union(EnrichmentStatus)};
export type AttackerProfile = {_union(AttackerProfile)};
export type Severity = {_union(Severity)};

export interface RawEvent {{
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
}}

export interface NormalizedEvent extends RawEvent {{
  session_id: string | null;
  country_code: string | null;
  asn: number | null;
  as_org: string | null;
  reputation_score: number | null;
  technique_id: string | null;
  enrichment_status: EnrichmentStatus;
  threat_score: number;
}}

export interface RuleMatch {{
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  weight: number;
  contribution: number;
}}

export interface Verdict {{
  event_id: string;
  session_id: string | null;
  threat_score: number;
  profile: AttackerProfile;
  matches: RuleMatch[];
}}

export interface Overview {{
  events: number;
  unique_ips: number;
  sessions: number;
  max_threat_score: number;
  rejected: number;
}}
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="échoue si le fichier est périmé")
    args = parser.parse_args()

    content = render()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != content:
            print(
                "Les types TypeScript sont périmés. Lancez `make types` et committez " f"{TARGET}.",
                file=sys.stderr,
            )
            return 1
        print("types à jour")
        return 0

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(content, encoding="utf-8")
    print(f"écrit : {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
