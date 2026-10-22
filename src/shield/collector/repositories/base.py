"""Contrat de persistance du collecteur.

Les routes de l'API ne connaissent que ce protocole. Deux implémentations le
respectent :

* ``PostgresEventRepository`` — la production (S1-06) ;
* ``InMemoryEventRepository`` — les tests unitaires et le développement sans base.

Toutes les méthodes sont asynchrones, y compris celles de l'implémentation en
mémoire : c'est le prix d'un seul contrat pour les deux.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from shield.collector.defender import Rule
from shield.collector.ingest.session_tracker import ResumedSession
from shield.common.schema import NormalizedEvent, RawEvent, RuleMatch, ServiceName, Verdict

#: Taille maximale du corps conservé pour un événement rejeté (même plafond que US-06).
MAX_REJECTED_BODY_BYTES = 4096


class EventRepository(Protocol):
    """Ce que le collecteur attend de son stockage."""

    async def prepare(self, rules: list[Rule]) -> None:
        """Au démarrage : synchronise le référentiel des règles et les tables de référence."""

    async def maintain(self) -> None:
        """Chaque jour : prépare le stockage des semaines à venir."""

    async def close(self) -> None:
        """À l'arrêt : libère les connexions."""

    # -- écriture ---------------------------------------------------------------

    async def save(self, event: NormalizedEvent, verdict: Verdict) -> None:
        """Écrit l'événement, sa session, son adresse et ses règles déclenchées, atomiquement."""

    async def record_rejected(self, reason: str, raw_body: bytes) -> None:
        """Trace un événement malformé : rejeté, mais jamais perdu (§ 4.1)."""

    # -- cycle de vie des sessions -----------------------------------------------

    async def close_idle_sessions(self, before: datetime) -> int:
        """Ferme les sessions sans activité depuis ``before``. Retourne leur nombre."""

    async def open_sessions(self) -> list[ResumedSession]:
        """Les sessions encore ouvertes, que le collecteur reprend à son démarrage (#58)."""

    # -- enrichissement différé (ADR 007, US-10) ---------------------------------

    async def pending_reputation(self, limit: int) -> list[str]:
        """Adresses dont des événements attendent leur réputation, les plus récentes d'abord."""

    async def apply_reputation(self, ip: str, score: int | None) -> None:
        """Enregistre la réputation d'une adresse et clôt l'enrichissement de ses événements."""

    # -- export, liste de blocage, conservation (US-42, US-43, US-46) -------------

    async def export_page(
        self,
        since: datetime | None,
        until: datetime | None,
        cursor: tuple[datetime, UUID] | None,
        limit: int,
    ) -> list[NormalizedEvent]:
        """Une page d'export, ordre croissant (``occurred_at``, ``event_id``), après ``cursor``."""

    async def hostile_ips(self, min_score: int, since: datetime) -> list[str]:
        """Adresses dont le pire score depuis ``since`` atteint ``min_score``, pires d'abord."""

    async def purge(self, cutoff: datetime) -> dict[str, int]:
        """Supprime tout ce qui précède ``cutoff``. Retourne le nombre de lignes par table."""

    async def lighten_payloads(self, before: datetime) -> int:
        """Efface la charge utile des événements antérieurs à ``before`` ; l'empreinte reste."""

    async def archive_partitions(self, before: date, directory: Path) -> list[dict[str, Any]]:
        """Archive en fichier puis supprime les mois entièrement antérieurs à ``before``."""

    async def storage_usage(self) -> list[dict[str, Any]]:
        """Taille des tables, pour décider des seuils de conservation sur des chiffres réels."""

    # -- veille (US-39, US-40) ---------------------------------------------------

    async def upsert_watch(self, entries: list[dict[str, Any]]) -> None:
        """Ajoute ou met à jour les CVE suivies, sans toucher à leurs corrélations."""

    async def watch_entries(self, limit: int = 100) -> list[dict[str, Any]]:
        """Les CVE suivies : observées chez nous d'abord, puis les plus récentes."""

    async def count_payload_matches(self, marker: bytes) -> tuple[int, datetime | None]:
        """Nombre d'événements dont la charge utile contient ``marker``, et le dernier."""

    async def record_watch_matches(
        self, cve_id: str, count: int, last: datetime | None
    ) -> None: ...

    async def events_with_payload(self, marker: bytes, limit: int) -> list[NormalizedEvent]:
        """Les événements concernés par une CVE, les plus récents d'abord."""

    # -- alertes (US-30, US-31) ---------------------------------------------------

    async def load_alert_thresholds(self) -> list[dict[str, Any]]:
        """Les seuils enregistrés ; liste vide si l'instance n'a jamais été configurée."""

    async def save_alert_thresholds(self, thresholds: list[dict[str, Any]]) -> None:
        """Remplace tous les seuils, atomiquement."""

    async def record_alert(self, alert: dict[str, Any]) -> None:
        """Trace un franchissement : seuil, valeur, statut et résultat par canal."""

    async def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Les alertes les plus récentes d'abord."""

    # -- compteurs de fenêtre glissante (Redis au sprint 2, S2-07) ---------------

    async def counters(self, event: RawEvent) -> dict[str, int]:
        """Compteurs par adresse, l'événement courant inclus."""

    # -- lecture ----------------------------------------------------------------

    async def query(
        self,
        *,
        service: ServiceName | None = None,
        country: str | None = None,
        min_score: int = 0,
        limit: int = 50,
        session_id: UUID | None = None,
    ) -> list[NormalizedEvent]:
        """Les événements les plus récents d'abord."""

    async def get_verdict(self, event_id: UUID) -> Verdict | None: ...

    async def session_detail(self, session_id: UUID) -> dict[str, object] | None:
        """La session, ses événements et ses règles déclenchées, agrégées (US-26)."""

    async def timeline(self, since: datetime, bucket: timedelta) -> list[dict[str, object]]:
        """Événements par tranche de temps depuis ``since`` (US-22). Tranches vides omises."""

    async def by_country(self) -> list[dict[str, object]]:
        """Événements et adresses par pays, pour la carte (US-21)."""

    async def overview(self) -> dict[str, int]: ...

    async def top_ips(self, limit: int = 10) -> list[dict[str, object]]: ...

    async def top_credentials(self, limit: int = 10) -> dict[str, list[dict[str, object]]]: ...

    async def by_service(self) -> list[dict[str, object]]: ...


#: Origine commune des tranches de la chronologie : les deux implémentations
#: découpent le temps aux mêmes instants (``date_bin`` côté PostgreSQL).
TIMELINE_ORIGIN = datetime(2000, 1, 1, tzinfo=UTC)

#: Événements renvoyés au plus dans le détail d'une session.
MAX_SESSION_EVENTS = 200


def bucket_start(moment: datetime, bucket: timedelta) -> datetime:
    """Début de la tranche qui contient ``moment``."""
    return TIMELINE_ORIGIN + ((moment - TIMELINE_ORIGIN) // bucket) * bucket


def rule_summary(match: RuleMatch, hits: int, total_contribution: int) -> dict[str, Any]:
    """Une règle déclenchée dans une session : combien de fois, pour combien de points."""
    return {
        "rule_id": match.rule_id,
        "name": match.name,
        "description": match.description,
        "severity": match.severity.value,
        "weight": match.weight,
        "matches": hits,
        "total_contribution": total_contribution,
    }


def session_payload(
    *,
    session_id: UUID,
    source_ip: str,
    service: str,
    started_at: datetime,
    ended_at: datetime | None,
    event_count: int,
    threat_score: int,
    attacker_profile: str,
    closed: bool,
    events: list[NormalizedEvent],
    rules: list[dict[str, Any]],
) -> dict[str, object]:
    """Forme commune du détail de session. Règles : la plus lourde d'abord."""
    ranked = sorted(rules, key=lambda rule: (-rule["total_contribution"], rule["rule_id"]))
    return {
        "session_id": str(session_id),
        "source_ip": source_ip,
        "service": service,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat() if ended_at else None,
        "event_count": event_count,
        "threat_score": threat_score,
        "attacker_profile": attacker_profile,
        "closed": closed,
        "events": [event.model_dump(mode="json") for event in events],
        "rules": ranked,
    }


def country_ranking(rows: list[tuple[str | None, int, int]]) -> list[dict[str, object]]:
    """(pays, événements, adresses) → liste triée, le plus actif d'abord ; pays inconnu inclus."""
    ordered = sorted(rows, key=lambda row: (-row[1], row[0] or "~"))
    return [
        {"country_code": country, "events": events, "unique_ips": addresses}
        for country, events, addresses in ordered
    ]


def service_percentages(counts: dict[str, int]) -> list[dict[str, object]]:
    """Répartition par service, triée par nom. Partagée par les deux implémentations."""
    total = sum(counts.values()) or 1
    return [
        {"service": name, "count": count, "percentage": round(100 * count / total, 1)}
        for name, count in sorted(counts.items())
    ]
