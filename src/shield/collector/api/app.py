"""API du collecteur SHIELD.

Les routes ne connaissent que le protocole ``EventRepository`` : le stockage est
PostgreSQL en production (S1-06) et en mémoire pour les tests ou le
développement sans base (``SHIELD_STORAGE=memory``). Il est créé au démarrage
de l'application et rangé dans ``app.state.repository``.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from shield.collector.defender import DefenderAgent, RuleEngine
from shield.collector.enrichment.mitre import MitreMapper
from shield.collector.ingest.session_tracker import SessionTracker
from shield.collector.repositories import EventRepository, build_repository
from shield.common.schema import (
    EnrichmentStatus,
    NormalizedEvent,
    RawEvent,
    ServiceName,
    Verdict,
)

RULES_PATH = Path(os.getenv("RULES_PATH", "rules/detection_rules.yaml"))
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "change-me-ingest-token")
INGEST_PATH = "/api/v1/ingest"
MAX_REJECTION_REASON_CHARS = 1000

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- état

tracker = SessionTracker()
mapper = MitreMapper()
agent = DefenderAgent(engine=RuleEngine.from_file(RULES_PATH))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Ouvre le stockage et y synchronise les règles avant d'accepter la moindre requête."""
    repository = build_repository()
    await repository.prepare(agent.engine.rules)
    app.state.repository = repository
    try:
        yield
    finally:
        await repository.close()


def get_repository(request: Request) -> EventRepository:
    repository: EventRepository = request.app.state.repository
    return repository


Repository = Annotated[EventRepository, Depends(get_repository)]

app = FastAPI(
    title="SHIELD Collector API",
    version="0.1.0",
    docs_url="/api/docs" if os.getenv("SHIELD_ENV", "dev") != "prod" else None,
    redoc_url=None,
    lifespan=lifespan,
)


def require_ingest_token(x_ingest_token: Annotated[str | None, Header()] = None) -> None:
    """Les leurres ne sont pas des utilisateurs : ils ont leur propre secret partagé."""
    if x_ingest_token != INGEST_TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid ingest token")


@app.exception_handler(RequestValidationError)
async def trace_rejected_event(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Un événement malformé est rejeté (422) mais tracé dans ``event_rejected`` (§ 4.1).

    Le jeton est vérifié avant le corps : seul un leurre authentifié peut écrire ici.
    Un échec de traçage est journalisé, jamais propagé — la réponse au leurre ne change pas.
    """
    if request.url.path == INGEST_PATH:
        reason = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )[:MAX_REJECTION_REASON_CHARS]
        body = exc.body
        raw_body = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        try:
            await request.app.state.repository.record_rejected(reason, raw_body)
        except Exception:
            logger.exception("événement rejeté non tracé")
    return await request_validation_exception_handler(request, exc)


class IngestAck(BaseModel):
    event_id: UUID
    session_id: UUID
    threat_score: int
    profile: str


@app.post(
    INGEST_PATH,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_ingest_token)],
    response_model=IngestAck,
    tags=["ingestion"],
)
async def ingest(raw: RawEvent, repository: Repository) -> IngestAck:
    """Valide, rattache à une session, enrichit hors ligne, évalue, stocke.

    L'ordre est volontaire : rien de ce qui dépend du réseau n'est sur ce chemin.
    L'enrichissement en ligne (réputation) est différé — un événement non enrichi
    est une donnée incomplète, un événement perdu est une donnée absente.
    """
    raw = raw.truncated()
    session_id = tracker.attach(raw)
    counters = await repository.counters(raw)

    event = NormalizedEvent(
        **raw.model_dump(exclude={"payload"}),
        payload=raw.payload,
        session_id=session_id,
        technique_id=mapper.map(raw),
        enrichment_status=EnrichmentStatus.PARTIAL,
    )

    verdict = agent.evaluate(event, counters)
    event = event.model_copy(update={"threat_score": verdict.threat_score})
    await repository.save(event, verdict)

    return IngestAck(
        event_id=event.event_id,
        session_id=session_id,
        threat_score=verdict.threat_score,
        profile=verdict.profile.value,
    )


@app.get("/api/v1/events", tags=["consultation"])
async def list_events(
    repository: Repository,
    service: ServiceName | None = None,
    country: str | None = Query(default=None, min_length=2, max_length=2),
    min_score: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, object]:
    items = await repository.query(
        service=service, country=country, min_score=min_score, limit=limit
    )
    return {"items": [item.model_dump(mode="json") for item in items], "count": len(items)}


@app.get("/api/v1/events/{event_id}/verdict", tags=["agent défenseur"])
async def get_verdict(event_id: UUID, repository: Repository) -> Verdict:
    """Le verdict explicable : la somme des contributions égale le score (US-13)."""
    verdict = await repository.get_verdict(event_id)
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
async def stats_overview(repository: Repository) -> dict[str, object]:
    return dict(await repository.overview())


@app.get("/api/v1/stats/top-ips", tags=["statistiques"])
async def stats_top_ips(
    repository: Repository, limit: int = Query(default=10, ge=1, le=100)
) -> dict[str, object]:
    return {"items": await repository.top_ips(limit)}


@app.get("/api/v1/stats/top-credentials", tags=["statistiques"])
async def stats_top_credentials(
    repository: Repository, limit: int = Query(default=10, ge=1, le=100)
) -> dict[str, object]:
    return dict(await repository.top_credentials(limit))


@app.get("/api/v1/stats/by-service", tags=["statistiques"])
async def stats_by_service(repository: Repository) -> dict[str, object]:
    return {"items": await repository.by_service()}


@app.get("/api/v1/health", tags=["exploitation"])
async def health() -> dict[str, object]:
    """Sonde de vivacité : aucune information métier, aucune authentification."""
    return {"status": "ok", "time": datetime.now(UTC).isoformat()}
