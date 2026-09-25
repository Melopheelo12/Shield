"""API du collecteur SHIELD.

État du bootstrap (sprint 0) : l'ingestion, l'enrichissement hors ligne, l'agent
défenseur et les lectures sont fonctionnels sur un **entrepôt en mémoire**. Le
branchement sur PostgreSQL et Redis est la première tâche du sprint 1 (voir
``docs/SPRINT_PLAN.md``, tâches S1-05 et S1-06) : seule l'implémentation de
``EventStore`` change, aucune route ni aucun schéma ne bouge.
"""

from __future__ import annotations

import os
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel

from shield.collector.defender import DefenderAgent, RuleEngine
from shield.collector.enrichment.mitre import MitreMapper
from shield.collector.ingest.session_tracker import SessionTracker
from shield.common.schema import (
    EnrichmentStatus,
    NormalizedEvent,
    RawEvent,
    ServiceName,
    Verdict,
)

RULES_PATH = Path(os.getenv("RULES_PATH", "rules/detection_rules.yaml"))
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "change-me-ingest-token")
MAX_EVENTS_IN_MEMORY = 50_000


class EventStore:
    """Entrepôt en mémoire, borné. Remplacé par PostgreSQL au sprint 1."""

    def __init__(self, maxlen: int = MAX_EVENTS_IN_MEMORY) -> None:
        self.events: deque[NormalizedEvent] = deque(maxlen=maxlen)
        self.verdicts: dict[UUID, Verdict] = {}
        self.rejected: int = 0

    # -- écriture ---------------------------------------------------------------

    def add(self, event: NormalizedEvent, verdict: Verdict) -> None:
        self.events.append(event)
        self.verdicts[event.event_id] = verdict

    # -- compteurs de fenêtre glissante (Redis au sprint 2) ---------------------

    def counters(self, event: RawEvent) -> dict[str, int]:
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

    def query(
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

    def overview(self) -> dict[str, int | str]:
        unique_ips = {str(event.source_ip) for event in self.events}
        sessions = {event.session_id for event in self.events if event.session_id}
        scores = [event.threat_score for event in self.events] or [0]
        return {
            "events": len(self.events),
            "unique_ips": len(unique_ips),
            "sessions": len(sessions),
            "max_threat_score": max(scores),
            "rejected": self.rejected,
        }

    def top_ips(self, limit: int = 10) -> list[dict[str, object]]:
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

    def top_credentials(self, limit: int = 10) -> dict[str, list[dict[str, object]]]:
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

    def by_service(self) -> list[dict[str, object]]:
        counter: dict[str, int] = defaultdict(int)
        for event in self.events:
            counter[event.service.value] += 1
        total = sum(counter.values()) or 1
        return [
            {"service": name, "count": count, "percentage": round(100 * count / total, 1)}
            for name, count in sorted(counter.items())
        ]


# --------------------------------------------------------------------------- état

store = EventStore()
tracker = SessionTracker()
mapper = MitreMapper()
agent = DefenderAgent(engine=RuleEngine.from_file(RULES_PATH))

app = FastAPI(
    title="SHIELD Collector API",
    version="0.1.0",
    docs_url="/api/docs" if os.getenv("SHIELD_ENV", "dev") != "prod" else None,
    redoc_url=None,
)


def require_ingest_token(x_ingest_token: Annotated[str | None, Header()] = None) -> None:
    """Les leurres ne sont pas des utilisateurs : ils ont leur propre secret partagé."""
    if x_ingest_token != INGEST_TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid ingest token")


class IngestAck(BaseModel):
    event_id: UUID
    session_id: UUID
    threat_score: int
    profile: str


@app.post(
    "/api/v1/ingest",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_ingest_token)],
    response_model=IngestAck,
    tags=["ingestion"],
)
async def ingest(raw: RawEvent) -> IngestAck:
    """Valide, rattache à une session, enrichit hors ligne, évalue, stocke.

    L'ordre est volontaire : rien de ce qui dépend du réseau n'est sur ce chemin.
    L'enrichissement en ligne (réputation) est différé — un événement non enrichi
    est une donnée incomplète, un événement perdu est une donnée absente.
    """
    raw = raw.truncated()
    session_id = tracker.attach(raw)
    counters = store.counters(raw)

    event = NormalizedEvent(
        **raw.model_dump(exclude={"payload"}),
        payload=raw.payload,
        session_id=session_id,
        technique_id=mapper.map(raw),
        enrichment_status=EnrichmentStatus.PARTIAL,
    )

    verdict = agent.evaluate(event, counters)
    event = event.model_copy(update={"threat_score": verdict.threat_score})
    store.add(event, verdict)

    return IngestAck(
        event_id=event.event_id,
        session_id=session_id,
        threat_score=verdict.threat_score,
        profile=verdict.profile.value,
    )


@app.get("/api/v1/events", tags=["consultation"])
async def list_events(
    service: ServiceName | None = None,
    country: str | None = Query(default=None, min_length=2, max_length=2),
    min_score: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, object]:
    items = store.query(service=service, country=country, min_score=min_score, limit=limit)
    return {"items": [item.model_dump(mode="json") for item in items], "count": len(items)}


@app.get("/api/v1/events/{event_id}/verdict", tags=["agent défenseur"])
async def get_verdict(event_id: UUID) -> Verdict:
    """Le verdict explicable : la somme des contributions égale le score (US-13)."""
    verdict = store.verdicts.get(event_id)
    if verdict is None:
        raise HTTPException(status_code=404, detail="unknown event")
    return verdict


@app.get("/api/v1/rules", tags=["agent défenseur"])
async def list_rules() -> dict[str, object]:
    return {
        "items": [
            {
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity.value,
                "weight": rule.weight,
                "window_seconds": rule.window_seconds,
                "enabled": rule.enabled,
                "version": rule.version,
            }
            for rule in agent.engine.rules
        ],
        "count": len(agent.engine.rules),
    }


@app.get("/api/v1/stats/overview", tags=["statistiques"])
async def stats_overview() -> dict[str, object]:
    return store.overview()


@app.get("/api/v1/stats/top-ips", tags=["statistiques"])
async def stats_top_ips(limit: int = Query(default=10, ge=1, le=100)) -> dict[str, object]:
    return {"items": store.top_ips(limit)}


@app.get("/api/v1/stats/top-credentials", tags=["statistiques"])
async def stats_top_credentials(limit: int = Query(default=10, ge=1, le=100)) -> dict[str, object]:
    return store.top_credentials(limit)


@app.get("/api/v1/stats/by-service", tags=["statistiques"])
async def stats_by_service() -> dict[str, object]:
    return {"items": store.by_service()}


@app.get("/api/v1/health", tags=["exploitation"])
async def health() -> dict[str, object]:
    """Sonde de vivacité : aucune information métier, aucune authentification."""
    return {"status": "ok", "time": datetime.now(UTC).isoformat()}
