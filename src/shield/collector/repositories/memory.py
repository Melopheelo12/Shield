"""Entrepôt en mémoire, borné.

C'était le stockage du bootstrap (sprint 0). Il reste l'implémentation de
référence pour les tests unitaires et pour développer sans PostgreSQL
(``SHIELD_STORAGE=memory``). Rien n'y survit à un redémarrage.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from uuid import UUID

from shield.collector.defender import Rule
from shield.collector.ingest.session_tracker import ResumedSession
from shield.collector.repositories.base import MAX_REJECTED_BODY_BYTES, service_percentages
from shield.common.schema import NormalizedEvent, RawEvent, ServiceName, Verdict

MAX_EVENTS_IN_MEMORY = 50_000


class InMemoryEventRepository:
    """Implémentation en mémoire d'``EventRepository``."""

    def __init__(self, maxlen: int = MAX_EVENTS_IN_MEMORY) -> None:
        self.events: deque[NormalizedEvent] = deque(maxlen=maxlen)
        self.verdicts: dict[UUID, Verdict] = {}
        self.rejected: list[tuple[str, bytes]] = []

    async def prepare(self, rules: list[Rule]) -> None:
        return None

    async def maintain(self) -> None:
        return None

    async def close(self) -> None:
        return None

    # -- écriture ---------------------------------------------------------------

    async def save(self, event: NormalizedEvent, verdict: Verdict) -> None:
        self.events.append(event)
        self.verdicts[event.event_id] = verdict

    async def record_rejected(self, reason: str, raw_body: bytes) -> None:
        self.rejected.append((reason, raw_body[:MAX_REJECTED_BODY_BYTES]))

    # -- compteurs de fenêtre glissante -----------------------------------------

    async def close_idle_sessions(self, before: datetime) -> int:
        return 0

    async def open_sessions(self) -> list[ResumedSession]:
        return []

    async def counters(self, event: RawEvent) -> dict[str, int]:
        now = event.occurred_at
        window_5m = now - timedelta(seconds=300)
        window_24h = now - timedelta(seconds=86_400)
        ip = str(event.source_ip)

        auth_attempts = 0
        services: set[ServiceName] = set()
        events_24h = 0
        for stored in self.events:
            if str(stored.source_ip) != ip:
                continue
            if stored.occurred_at >= window_24h:
                events_24h += 1
            if stored.occurred_at >= window_5m:
                services.add(stored.service)
                if stored.username or stored.password:
                    auth_attempts += 1
        return {
            "auth_attempts_by_ip": auth_attempts + 1,
            "distinct_services_by_ip": len(services | {event.service}),
            "events_by_ip_24h": events_24h + 1,
        }

    # -- lecture ----------------------------------------------------------------

    async def query(
        self,
        *,
        service: ServiceName | None = None,
        country: str | None = None,
        min_score: int = 0,
        limit: int = 50,
    ) -> list[NormalizedEvent]:
        result = []
        for stored in reversed(self.events):
            if service and stored.service != service:
                continue
            if country and stored.country_code != country:
                continue
            if stored.threat_score < min_score:
                continue
            result.append(stored)
            if len(result) >= limit:
                break
        return result

    async def get_verdict(self, event_id: UUID) -> Verdict | None:
        return self.verdicts.get(event_id)

    async def overview(self) -> dict[str, int]:
        unique_ips = {str(event.source_ip) for event in self.events}
        sessions = {event.session_id for event in self.events if event.session_id}
        scores = [event.threat_score for event in self.events] or [0]
        return {
            "events": len(self.events),
            "unique_ips": len(unique_ips),
            "sessions": len(sessions),
            "max_threat_score": max(scores),
            "rejected": len(self.rejected),
        }

    async def top_ips(self, limit: int = 10) -> list[dict[str, object]]:
        counter: dict[str, int] = defaultdict(int)
        best_score: dict[str, int] = defaultdict(int)
        country: dict[str, str | None] = {}
        for event in self.events:
            ip = str(event.source_ip)
            counter[ip] += 1
            best_score[ip] = max(best_score[ip], event.threat_score)
            country.setdefault(ip, event.country_code)
        ranked = sorted(counter.items(), key=lambda item: item[1], reverse=True)[:limit]
        return [
            {
                "source_ip": ip,
                "events": count,
                "threat_score": best_score[ip],
                "country_code": country.get(ip),
            }
            for ip, count in ranked
        ]

    async def top_credentials(self, limit: int = 10) -> dict[str, list[dict[str, object]]]:
        users: dict[str, int] = defaultdict(int)
        passwords: dict[str, int] = defaultdict(int)
        for event in self.events:
            if event.username:
                users[event.username] += 1
            if event.password:
                passwords[event.password] += 1

        def rank(source: dict[str, int]) -> list[dict[str, object]]:
            top = sorted(source.items(), key=lambda item: item[1], reverse=True)[:limit]
            return [{"value": value, "count": count} for value, count in top]

        return {"usernames": rank(users), "passwords": rank(passwords)}

    async def by_service(self) -> list[dict[str, object]]:
        counter: dict[str, int] = defaultdict(int)
        for event in self.events:
            counter[event.service.value] += 1
        return service_percentages(counter)
