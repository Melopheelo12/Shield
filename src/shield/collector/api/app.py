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
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from shield.collector.alerts import AlertService, Threshold
from shield.collector.api.auth import (
    check_production_secrets,
    decode_access_token,
    require_user,
    require_user_query,
)
from shield.collector.api.auth import router as auth_router
from shield.collector.defender import DefenderAgent, RuleEngine, RuleReloader
from shield.collector.enrichment.geoip import GeoIpEnricher
from shield.collector.enrichment.mitre import MitreMapper
from shield.collector.enrichment.reputation import ReputationEnricher, enrich_pending
from shield.collector.exports import csv_stream, json_stream
from shield.collector.ingest.session_tracker import SessionTracker
from shield.collector.realtime import Broadcaster, next_frame
from shield.collector.repositories import EventRepository, build_repository
from shield.collector.sandbox import sandbox_report
from shield.collector.watch import fetch_kev, refresh, run_daily, signature_for
from shield.common.schema import (
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
ENRICHMENT_INTERVAL_SECONDS = 30
RULES_RELOAD_INTERVAL_SECONDS = 10
MAX_TIMELINE_BUCKETS = 1000
ALERT_REARM_INTERVAL_SECONDS = 15

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- état

tracker = SessionTracker()
mapper = MitreMapper()
geoip = GeoIpEnricher.from_env()
reputation = ReputationEnricher.from_env()
broadcaster = Broadcaster.from_env()
alerts = AlertService.from_env()
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


async def first_watch(repository: EventRepository) -> None:
    """Instance neuve : une veille tout de suite plutôt qu'au premier 4 h du matin."""
    try:
        if not await repository.watch_entries(limit=1):
            await refresh(repository, fetch_kev)
    except Exception:
        logger.exception("première veille en échec")


async def resume_sessions(repository: EventRepository, tracker: SessionTracker) -> None:
    """Au démarrage : ferme les sessions expirées pendant l'arrêt, reprend les autres (#58)."""
    await close_idle_sessions(repository, tracker)
    tracker.restore(await repository.open_sessions())


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Ouvre le stockage et y synchronise les règles avant d'accepter la moindre requête."""
    check_production_secrets()
    repository = build_repository()
    await repository.prepare(agent.engine.rules)
    await resume_sessions(repository, tracker)
    await alerts.load(repository)
    app.state.repository = repository
    background = [
        asyncio.create_task(alerts.run(repository)),
        asyncio.create_task(run_periodically(alerts.rearm, ALERT_REARM_INTERVAL_SECONDS)),
        asyncio.create_task(run_periodically(repository.maintain, MAINTENANCE_INTERVAL_SECONDS)),
        asyncio.create_task(
            run_periodically(lambda: purge_expired(repository), MAINTENANCE_INTERVAL_SECONDS)
        ),
        asyncio.create_task(
            run_periodically(
                lambda: close_idle_sessions(repository, tracker),
                SESSION_CLOSING_INTERVAL_SECONDS,
            )
        ),
        asyncio.create_task(
            run_periodically(
                lambda: enrich_pending(repository, reputation),
                ENRICHMENT_INTERVAL_SECONDS,
            )
        ),
        asyncio.create_task(
            run_periodically(
                RuleReloader(agent, RULES_PATH, on_reload=repository.prepare).reload_if_changed,
                RULES_RELOAD_INTERVAL_SECONDS,
            )
        ),
    ]
    # La sandbox n'a aucune sortie réseau, et les tests n'en veulent pas.
    if os.getenv("WATCH_ENABLED", "true").lower() != "false":
        background += [
            asyncio.create_task(first_watch(repository)),
            asyncio.create_task(run_daily(lambda: refresh(repository, fetch_kev))),
        ]
    try:
        yield
    finally:
        for task in background:
            task.cancel()
        await repository.close()
        await reputation.close()
        await broadcaster.close()
        geoip.close()


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
app.include_router(auth_router)

#: Toute route de consultation exige un jeton d'exploitant (US-19).
AUTHENTICATED = [Depends(require_user)]


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
    GeoLite2 est un fichier local (S2-01) : il passe avant le verdict, pour que les
    règles sur le pays et l'ASN s'appliquent. La réputation n'est lue que dans le
    cache (S2-02) ; une adresse inconnue est marquée ``pending`` et complétée par la
    tâche de fond — un événement non enrichi est une donnée incomplète, un événement
    perdu est une donnée absente.
    """
    raw = raw.truncated()
    session_id = tracker.attach(raw)
    counters = await repository.counters(raw)
    reputation_score = await reputation.cached(raw.source_ip)

    event = NormalizedEvent(
        **raw.model_dump(exclude={"payload"}),
        payload=raw.payload,
        session_id=session_id,
        technique_id=mapper.map(raw),
        reputation_score=reputation_score,
        enrichment_status=reputation.status_for(raw.source_ip, reputation_score),
        **geoip.lookup(raw.source_ip).as_update(),
    )

    verdict = agent.evaluate(event, counters)
    event = event.model_copy(update={"threat_score": verdict.threat_score})
    await repository.save(event, verdict)
    # Après l'écriture seulement : on n'affiche ni n'alerte sur un événement absent de la base.
    await broadcaster.publish({"type": "event", "data": event.model_dump(mode="json")})
    alerts.observe(event)

    return IngestAck(
        event_id=event.event_id,
        session_id=session_id,
        threat_score=verdict.threat_score,
        profile=verdict.profile.value,
    )


@app.get("/api/v1/events", tags=["consultation"], dependencies=AUTHENTICATED)
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


@app.get("/api/v1/events/{event_id}/verdict", tags=["agent défenseur"], dependencies=AUTHENTICATED)
async def get_verdict(event_id: UUID, repository: Repository) -> Verdict:
    """Le verdict explicable : la somme des contributions égale le score (US-13)."""
    verdict = await repository.get_verdict(event_id)
    if verdict is None:
        raise HTTPException(status_code=404, detail="unknown event")
    return verdict


@app.get("/api/v1/rules", tags=["agent défenseur"], dependencies=AUTHENTICATED)
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


@app.get("/api/v1/stats/overview", tags=["statistiques"], dependencies=AUTHENTICATED)
async def stats_overview(repository: Repository) -> dict[str, object]:
    return dict(await repository.overview())


@app.get("/api/v1/stats/top-ips", tags=["statistiques"], dependencies=AUTHENTICATED)
async def stats_top_ips(
    repository: Repository, limit: int = Query(default=10, ge=1, le=100)
) -> dict[str, object]:
    return {"items": await repository.top_ips(limit)}


@app.get("/api/v1/stats/top-credentials", tags=["statistiques"], dependencies=AUTHENTICATED)
async def stats_top_credentials(
    repository: Repository, limit: int = Query(default=10, ge=1, le=100)
) -> dict[str, object]:
    return dict(await repository.top_credentials(limit))


@app.get("/api/v1/stats/by-service", tags=["statistiques"], dependencies=AUTHENTICATED)
async def stats_by_service(repository: Repository) -> dict[str, object]:
    return {"items": await repository.by_service()}


@app.get("/api/v1/stats/timeline", tags=["statistiques"], dependencies=AUTHENTICATED)
async def stats_timeline(
    repository: Repository,
    hours: int = Query(default=24, ge=1, le=24 * 30),
    bucket_minutes: int = Query(default=60, ge=1, le=24 * 60),
) -> dict[str, object]:
    """Chronologie (US-22). Au plus ``MAX_TIMELINE_BUCKETS`` tranches par requête."""
    if hours * 60 // bucket_minutes > MAX_TIMELINE_BUCKETS:
        raise HTTPException(status_code=422, detail="too many buckets, widen bucket_minutes")
    since = datetime.now(UTC) - timedelta(hours=hours)
    items = await repository.timeline(since, timedelta(minutes=bucket_minutes))
    return {"since": since.isoformat(), "bucket_minutes": bucket_minutes, "items": items}


@app.get("/api/v1/stats/by-country", tags=["statistiques"], dependencies=AUTHENTICATED)
async def stats_by_country(repository: Repository) -> dict[str, object]:
    """Pour la carte (US-21). ``country_code`` vaut ``null`` pour les adresses non situées."""
    return {"items": await repository.by_country()}


@app.get("/api/v1/sessions/{session_id}", tags=["consultation"], dependencies=AUTHENTICATED)
async def get_session(session_id: UUID, repository: Repository) -> dict[str, object]:
    """Détail d'une session et de ses règles déclenchées (US-26)."""
    detail = await repository.session_detail(session_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="unknown session")
    return detail


class ExportFormat(StrEnum):
    CSV = "csv"
    JSON = "json"


@app.get("/api/v1/export", tags=["export"], dependencies=AUTHENTICATED)
async def export_events(
    repository: Repository,
    format: ExportFormat = ExportFormat.CSV,  # noqa: A002 - nom public de l'API
    since: datetime | None = None,
    until: datetime | None = None,
    pseudonymize: bool | None = None,
) -> StreamingResponse:
    """Export par lots, en flux (US-42). Pseudonymisé par défaut si ``PSEUDONYMIZE_EXPORTS``."""
    if pseudonymize is None:
        pseudonymize = os.getenv("PSEUDONYMIZE_EXPORTS", "false").lower() == "true"

    async def fetch_page(cursor: tuple | None, limit: int) -> list[NormalizedEvent]:
        return await repository.export_page(since, until, cursor, limit)

    stream = csv_stream if format is ExportFormat.CSV else json_stream
    media_type = "text/csv" if format is ExportFormat.CSV else "application/json"
    # US-47 : le mode n'est jamais silencieux — il se lit dans le nom et dans l'en-tête.
    mode = "-pseudonymise" if pseudonymize else ""
    filename = f"shield-export-{datetime.now(UTC):%Y%m%d-%H%M%S}{mode}.{format.value}"
    return StreamingResponse(
        stream(fetch_page, pseudonymize),
        media_type=f"{media_type}; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Shield-Pseudonymized": "true" if pseudonymize else "false",
        },
    )


def require_blocklist_access(
    request: Request, x_blocklist_token: Annotated[str | None, Header()] = None
) -> None:
    """Un pare-feu ne se connecte pas : il présente ``BLOCKLIST_TOKEN``. Sinon, un JWT."""
    expected = os.getenv("BLOCKLIST_TOKEN", "")
    if expected and x_blocklist_token is not None:
        if secrets.compare_digest(x_blocklist_token.encode(), expected.encode()):
            return
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or decode_access_token(token) is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")


@app.get(
    "/api/v1/blocklist",
    tags=["export"],
    dependencies=[Depends(require_blocklist_access)],
    response_class=PlainTextResponse,
)
async def blocklist(
    repository: Repository,
    min_score: int = Query(default=60, ge=1, le=100),
    days: int = Query(default=7, ge=1, le=90),
) -> str:
    """Une adresse par ligne, prête pour un pare-feu (US-43). Les pires d'abord."""
    since = datetime.now(UTC) - timedelta(days=days)
    ips = await repository.hostile_ips(min_score, since)
    return "".join(f"{ip}\n" for ip in ips)


@app.get("/api/v1/watch", tags=["veille"], dependencies=AUTHENTICATED)
async def list_watch(
    repository: Repository, limit: int = Query(default=100, ge=1, le=500)
) -> dict[str, object]:
    """Vulnérabilités activement exploitées ; ``observed`` : vue chez vous (US-39, US-40)."""
    items = await repository.watch_entries(limit)
    for item in items:
        item["observed"] = item["matched_events"] > 0
        item["has_signature"] = signature_for(item["cve_id"]) is not None
    return {"items": items}


@app.get("/api/v1/watch/{cve_id}/events", tags=["veille"], dependencies=AUTHENTICATED)
async def watch_events(
    cve_id: str, repository: Repository, limit: int = Query(default=50, ge=1, le=500)
) -> dict[str, object]:
    """Les événements dont la charge utile porte la signature de cette CVE (US-40)."""
    signature = signature_for(cve_id)
    if signature is None:
        raise HTTPException(status_code=404, detail="no signature for this CVE")
    items = await repository.events_with_payload(signature.marker, limit)
    return {"items": [item.model_dump(mode="json") for item in items], "count": len(items)}


@app.get("/api/v1/sandbox/report", tags=["sandbox"], dependencies=AUTHENTICATED)
async def get_sandbox_report(
    repository: Repository, since: datetime | None = None
) -> dict[str, object]:
    """Taux de détection d'une partie d'entraînement (US-37). ``since`` : début de partie."""
    return await sandbox_report(repository, since)


async def purge_expired(repository: EventRepository) -> dict[str, int]:
    """Purge quotidienne RGPD (US-46) : ``RETENTION_DAYS`` jours, 365 par défaut."""
    days = int(os.getenv("RETENTION_DAYS", "365"))
    return await repository.purge(datetime.now(UTC) - timedelta(days=days))


class ThresholdsUpdate(BaseModel):
    items: list[dict[str, object]]


@app.get("/api/v1/alerts", tags=["alertes"], dependencies=AUTHENTICATED)
async def list_alerts(
    repository: Repository, limit: int = Query(default=50, ge=1, le=500)
) -> dict[str, object]:
    """Historique des franchissements, avec le résultat par canal."""
    return {"items": await repository.recent_alerts(limit)}


@app.get("/api/v1/alerts/thresholds", tags=["alertes"], dependencies=AUTHENTICATED)
async def get_thresholds() -> dict[str, object]:
    return {
        "items": [threshold.to_dict() for threshold in alerts.manager.thresholds],
        "channels": [channel.name for channel in alerts.notifier.channels],
    }


@app.put("/api/v1/alerts/thresholds", tags=["alertes"], dependencies=AUTHENTICATED)
async def put_thresholds(update: ThresholdsUpdate, repository: Repository) -> dict[str, object]:
    """Seuil, fenêtre et période de silence modifiables depuis l'interface (US-31)."""
    try:
        thresholds = [Threshold.from_dict(item) for item in update.items]
        await alerts.configure(repository, thresholds)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"invalid threshold: {exc}") from exc
    return await get_thresholds()


@app.post("/api/v1/alerts/test", tags=["alertes"], dependencies=AUTHENTICATED)
async def test_alert() -> dict[str, object]:
    """Bouton « tester » (US-31) : une notification factice sur chaque canal."""
    results = await alerts.send_test()
    return {"channels": results}


@app.websocket("/ws/events")
async def events_stream(
    websocket: WebSocket, username: Annotated[str | None, Depends(require_user_query)]
) -> None:
    """Flux temps réel (US-20). Jeton en paramètre ``token`` : un navigateur ne peut pas
    poser d'en-tête ``Authorization`` sur un WebSocket."""
    if username is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    async with broadcaster.subscribe() as queue:
        try:
            while True:
                await websocket.send_json(await next_frame(queue))
        except (WebSocketDisconnect, RuntimeError):
            return


@app.get("/api/v1/health", tags=["exploitation"])
async def health() -> dict[str, object]:
    """Sonde de vivacité : aucune information métier, aucune authentification."""
    return {"status": "ok", "time": datetime.now(UTC).isoformat()}
