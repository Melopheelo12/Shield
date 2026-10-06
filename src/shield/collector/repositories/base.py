"""Contrat de persistance du collecteur.

Les routes de l'API ne connaissent que ce protocole. Deux implémentations le
respectent :

* ``PostgresEventRepository`` — la production (S1-06) ;
* ``InMemoryEventRepository`` — les tests unitaires et le développement sans base.

Toutes les méthodes sont asynchrones, y compris celles de l'implémentation en
mémoire : c'est le prix d'un seul contrat pour les deux.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from shield.collector.defender import Rule
from shield.common.schema import NormalizedEvent, RawEvent, ServiceName, Verdict

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
    ) -> list[NormalizedEvent]:
        """Les événements les plus récents d'abord."""

    async def get_verdict(self, event_id: UUID) -> Verdict | None: ...

    async def overview(self) -> dict[str, int]: ...

    async def top_ips(self, limit: int = 10) -> list[dict[str, object]]: ...

    async def top_credentials(self, limit: int = 10) -> dict[str, list[dict[str, object]]]: ...

    async def by_service(self) -> list[dict[str, object]]: ...


def service_percentages(counts: dict[str, int]) -> list[dict[str, object]]:
    """Répartition par service, triée par nom. Partagée par les deux implémentations."""
    total = sum(counts.values()) or 1
    return [
        {"service": name, "count": count, "percentage": round(100 * count / total, 1)}
        for name, count in sorted(counts.items())
    ]
