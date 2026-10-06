"""API du collecteur SHIELD.

Les routes ne connaissent que le protocole ``EventRepository`` : le stockage est
PostgreSQL en production (S1-06) et en mémoire pour les tests ou le
développement sans base (``SHIELD_STORAGE=memory``). Il est créé au démarrage
de l'application et rangé dans ``app.state.repository``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
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
MAINTENANCE_INTERVAL_SECONDS = 86_400
SESSION_CLOSING_INTERVAL_SECONDS = 60

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- état

tracker = SessionTracker()
mapper = MitreMapper()
agent = DefenderAgent(engine=RuleEngine.from_file(RULES_PATH))


async def run_periodically(job: Callable[[], Awaitable[object]], interval: float) -> None:
    """Lance ``job`` à intervalle fixe, jusqu'à l'arrêt.

    Un échec est journalisé puis retenté au tour suivant : une tâche de fond ne doit
    jamais faire tomber l'ingestion.
    """
    while True:
        await asyncio.sleep(interval)
        try:
            await job()
        except Exception:
            logger.exception("tâche périodique %s en échec", getattr(job, "__name__", job))


async def close_idle_sessions(repository: EventRepository, tracker: SessionTracker) -> None:
    """Ferme les sessions inactives, en mémoire et en base."""
    now = datetime.now(UTC)
    tracker.close_expired(now)
    await repository.close_idle_sessions(now - timedelta(seconds=tracker.window_seconds))


async def resume_sessions(repository: EventRepository, tracker: SessionTracker) -> None:
    """Au démarrage : ferme les sessions expirées pendant l'arrêt, reprend les autres (#58)."""
    await close_idle_sessions(repository, tracker)
    tracker.restore(await repository.open_sessions())


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Ouvre le stockage et y synchronise les règles avant d'accepter la moindre requête."""
    repository = build_repository()
    await repository.prepare(agent.engine.rules)
    await resume_sessions(repository, tracker)
    app.state.repository = repository
    background = [
        asyncio.create_task(run_periodically(repository.maintain, MAINTENANCE_INTERVAL_SECONDS)),
        asyncio.create_task(
            run_periodically(
                lambda: close_idle_sessions(repository, tracker),
                SESSION_CLOSING_INTERVAL_SECONDS,
            )
        ),
    ]
    try:
        yield
    finally:
        for task in background:
            task.cancel()
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


UNAUTHORIZED_DETAIL = "invalid ingest token"


def is_valid_ingest_token(token: str | None) -> bool:
    """Comparaison à temps constant : la durée de réponse ne trahit pas le jeton."""
    return token is not None and secrets.compare_digest(
        token.encode("utf-8"), INGEST_TOKEN.encode("utf-8")
    )


def require_ingest_token(x_ingest_token: Annotated[str | None, Header()] = None) -> None:
    """Les leurres ne sont pas des utilisateurs : ils ont leur propre secret partagé."""
    if not is_valid_ingest_token(x_ingest_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=UNAUTHORIZED_DETAIL)


@app.exception_handler(RequestValidationError)
async def trace_rejected_event(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Un événement malformé est rejeté (422) mais tracé dans ``event_rejected`` (§ 4.1).

    Seul un leurre authentifié peut écrire ici. FastAPI décode le corps **avant** de
    résoudre les dépendances : pour un JSON illisible, ``require_ingest_token`` n'a
    pas encore tourné quand on arrive ici. Le jeton est donc revérifié, et une requête
    sans le bon jeton reçoit le même 401 qu'avec un corps valide, sans rien écrire (#63).

    Un échec de traçage est journalisé, jamais propagé — la réponse au leurre ne change pas.
    """
    if request.url.path == INGEST_PATH:
        if not is_valid_ingest_token(request.headers.get("x-ingest-token")):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": UNAUTHORIZED_DETAIL},
            )
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
