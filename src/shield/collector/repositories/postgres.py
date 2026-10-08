"""Stockage PostgreSQL du collecteur (S1-06).

Une ingestion = **une transaction**, dans cet ordre imposé par les clés étrangères :

1. ``ip_intel``   — l'adresse existe (créée ou ``last_seen`` / ``total_events`` mis à jour) ;
2. ``session``    — la session existe (créée ou compteur, score max et profil mis à jour) ;
3. ``event``      — l'événement est inséré dans sa partition mensuelle ;
4. ``rule_match`` — une ligne par règle déclenchée, ce qui rend le score explicable (US-13).

Si la base refuse l'écriture, l'exception remonte : le collecteur répond 5xx et le
leurre réessaie. Un échec bruyant vaut mieux qu'un événement perdu en silence.

Les compteurs de fenêtre glissante sont calculés ici en SQL (index
``event_source_ip_idx``) en attendant leur passage dans Redis au sprint 2 (S2-07).
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta
from ipaddress import ip_address
from uuid import UUID

from sqlalchemy import and_, case, distinct, func, insert, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql import ColumnElement

from shield.collector.defender import Rule
from shield.collector.ingest.session_tracker import ResumedSession
from shield.collector.models import (
    DecoyService,
    DetectionRule,
    Event,
    EventRejected,
    IpIntel,
    dispose_engine,
    get_engine,
)
from shield.collector.models import RuleMatch as RuleMatchRow
from shield.collector.models import Session as SessionRow
from shield.collector.repositories.base import MAX_REJECTED_BODY_BYTES, service_percentages
from shield.common.schema import (
    AttackerProfile,
    EnrichmentStatus,
    NormalizedEvent,
    RawEvent,
    RuleMatch,
    ServiceName,
    Severity,
    Verdict,
)

logger = logging.getLogger(__name__)

#: Partitions mensuelles d'``event`` créées d'avance, en plus de celle du mois courant.
PARTITION_MONTHS_AHEAD = 2

_RULE_COLUMNS = (
    "name",
    "description",
    "condition",
    "weight",
    "severity",
    "window_seconds",
    "profile_hint",
    "enabled",
    "version",
)


def _pg_text(value: str) -> str:
    """Rend une chaîne fournie par un attaquant acceptable pour une colonne texte.

    PostgreSQL refuse l'octet nul dans ``VARCHAR`` / ``TEXT``, et des robots en
    envoient dans leurs identifiants. On le remplace par U+FFFD plutôt que de laisser
    l'insertion échouer — et le leurre réessayer sans fin. (L'UTF-8 invalide, lui,
    est déjà refusé par le contrat Pydantic.)
    """
    return value.replace("\x00", "\ufffd")


class PostgresEventRepository:
    """Implémentation PostgreSQL d'``EventRepository``."""

    def __init__(self, engine: AsyncEngine | None = None) -> None:
        self._owns_default_engine = engine is None
        self._engine = engine or get_engine()
        self._sessions = async_sessionmaker(self._engine, expire_on_commit=False)
        self._service_ids: dict[ServiceName, int] = {}
        self._rule_ids: dict[str, int] = {}

    # -- cycle de vie -----------------------------------------------------------

    async def prepare(self, rules: list[Rule]) -> None:
        """Charge les identifiants des leurres et synchronise ``detection_rule`` depuis le YAML.

        Le fichier de règles fait foi : une règle modifiée est mise à jour, une règle
        retirée du fichier reste en base pour que l'historique de ``rule_match`` garde
        son sens.
        """
        async with self._sessions.begin() as db:
            rows = await db.execute(select(DecoyService.name, DecoyService.id))
            known = {service.value for service in ServiceName}
            service_ids = {ServiceName(name): id_ for name, id_ in rows if name in known}
            missing = set(ServiceName) - service_ids.keys()
            if missing:
                raise RuntimeError(
                    f"decoy_service incomplet, leurres absents : {sorted(missing)} — "
                    "le schéma deploy/initdb a-t-il été appliqué ?"
                )

            rule_ids: dict[str, int] = {}
            for rule in rules:
                stmt = pg_insert(DetectionRule).values(
                    rule_key=rule.id,
                    name=rule.name,
                    description=rule.description,
                    condition=rule.condition,
                    weight=rule.weight,
                    severity=rule.severity.value,
                    window_seconds=rule.window_seconds,
                    profile_hint=rule.profile_hint.value if rule.profile_hint else None,
                    enabled=rule.enabled,
                    version=rule.version,
                )
                upsert = stmt.on_conflict_do_update(
                    index_elements=[DetectionRule.rule_key],
                    set_={column: stmt.excluded[column] for column in _RULE_COLUMNS},
                ).returning(DetectionRule.id)
                rule_ids[rule.id] = (await db.execute(upsert)).scalar_one()

        self._service_ids = service_ids
        self._rule_ids = rule_ids
        await self.maintain()

    async def maintain(self, today: date | None = None) -> None:
        """Crée les partitions du mois courant et des ``PARTITION_MONTHS_AHEAD`` suivants.

        Un événement sans partition tombe dans ``event_default`` ; PostgreSQL refuse
        alors de créer la partition de son mois, et la purge RGPD par ``DROP`` de
        partition devient impossible (#62). La partition doit donc exister **avant**
        le premier événement du mois : appelée au démarrage puis chaque jour, cette
        méthode garde deux mois d'avance. ``create_event_partition`` est idempotente.
        """
        first = (today or datetime.now(UTC).date()).replace(day=1)
        async with self._sessions.begin() as db:
            for offset in range(PARTITION_MONTHS_AHEAD + 1):
                years, month = divmod(first.month - 1 + offset, 12)
                target = first.replace(year=first.year + years, month=month + 1)
                result = await db.execute(
                    text("SELECT create_event_partition(:target)"), {"target": target}
                )
                logger.debug("partition %s", result.scalar_one())

    async def close(self) -> None:
        if self._owns_default_engine:
            await dispose_engine()
        else:
            await self._engine.dispose()

    # -- écriture ---------------------------------------------------------------

    async def save(self, event: NormalizedEvent, verdict: Verdict) -> None:
        service_id = self._service_ids[event.service]
        ip = str(event.source_ip)
        seen_at = event.occurred_at

        async with self._sessions.begin() as db:
            intel = pg_insert(IpIntel).values(
                ip=ip, first_seen=seen_at, last_seen=seen_at, total_events=1
            )
            await db.execute(
                intel.on_conflict_do_update(
                    index_elements=[IpIntel.ip],
                    set_={
                        "first_seen": func.least(IpIntel.first_seen, intel.excluded.first_seen),
                        "last_seen": func.greatest(IpIntel.last_seen, intel.excluded.last_seen),
                        "total_events": IpIntel.total_events + 1,
                    },
                )
            )

            if event.session_id is not None:
                session = pg_insert(SessionRow).values(
                    id=event.session_id,
                    source_ip=ip,
                    service_id=service_id,
                    started_at=seen_at,
                    ended_at=seen_at,
                    event_count=1,
                    threat_score=verdict.threat_score,
                    attacker_profile=verdict.profile.value,
                )
                # La session porte le score et le profil de son pire événement.
                worse = session.excluded.threat_score > SessionRow.threat_score
                await db.execute(
                    session.on_conflict_do_update(
                        index_elements=[SessionRow.id],
                        set_={
                            "started_at": func.least(
                                SessionRow.started_at, session.excluded.started_at
                            ),
                            # ended_at = dernière activité, tant que la session est ouverte.
                            "ended_at": func.greatest(
                                SessionRow.ended_at, session.excluded.ended_at
                            ),
                            # Un événement tardif rouvre une session fermée de justesse.
                            "closed": False,
                            "event_count": SessionRow.event_count + 1,
                            "threat_score": func.greatest(
                                SessionRow.threat_score, session.excluded.threat_score
                            ),
                            "attacker_profile": case(
                                (worse, session.excluded.attacker_profile),
                                else_=SessionRow.attacker_profile,
                            ),
                        },
                    )
                )

            row_id = (
                await db.execute(
                    insert(Event)
                    .values(
                        event_uid=event.event_id,
                        occurred_at=seen_at,
                        received_at=datetime.now(UTC),
                        service_id=service_id,
                        session_id=event.session_id,
                        source_ip=ip,
                        source_port=event.source_port,
                        dest_port=event.dest_port,
                        username=_pg_text(event.username),
                        password=_pg_text(event.password),
                        payload_excerpt=event.payload or None,
                        payload_truncated=event.payload_truncated,
                        payload_sha256=event.payload_sha256,
                        technique_id=event.technique_id,
                        threat_score=verdict.threat_score,
                        attacker_profile=verdict.profile.value,
                        enrichment_status=event.enrichment_status.value,
                    )
                    .returning(Event.id)
                )
            ).scalar_one()

            if event.session_id is not None:
                matches = []
                for match in verdict.matches:
                    rule_id = self._rule_ids.get(match.rule_id)
                    if rule_id is None:
                        # Ne doit pas arriver : prepare() synchronise toutes les règles du moteur.
                        # On garde l'événement plutôt que de le perdre pour une ligne d'explication.
                        logger.warning("règle %s absente de detection_rule", match.rule_id)
                        continue
                    matches.append(
                        {
                            "rule_id": rule_id,
                            "session_id": event.session_id,
                            "event_id": row_id,
                            "matched_at": seen_at,
                            "contributed_score": match.contribution,
                        }
                    )
                if matches:
                    await db.execute(insert(RuleMatchRow), matches)

    async def record_rejected(self, reason: str, raw_body: bytes) -> None:
        async with self._sessions.begin() as db:
            await db.execute(
                insert(EventRejected).values(
                    received_at=datetime.now(UTC),
                    reason=_pg_text(reason),
                    raw_body=raw_body[:MAX_REJECTED_BODY_BYTES],
                )
            )

    # -- cycle de vie des sessions -----------------------------------------------

    @staticmethod
    def _last_activity() -> ColumnElement[datetime]:
        """Dernière activité d'une session.

        ``ended_at`` n'est tenu à jour que depuis #58 : pour une session plus ancienne,
        on la retrouve dans ``event`` (index ``event_session_id_idx``).
        """
        last_event = (
            select(func.max(Event.occurred_at))
            .where(Event.session_id == SessionRow.id)
            .scalar_subquery()
        )
        return func.coalesce(SessionRow.ended_at, last_event, SessionRow.started_at)

    async def close_idle_sessions(self, before: datetime) -> int:
        last_activity = self._last_activity()
        async with self._sessions.begin() as db:
            result = await db.execute(
                update(SessionRow)
                .where(SessionRow.closed.is_(False), last_activity < before)
                .values(closed=True, ended_at=last_activity)
                .execution_options(synchronize_session=False)
            )
        closed: int = result.rowcount  # type: ignore[attr-defined]
        return closed

    async def open_sessions(self) -> list[ResumedSession]:
        stmt = (
            select(
                SessionRow.id,
                SessionRow.source_ip,
                DecoyService.name,
                SessionRow.started_at,
                self._last_activity(),
                SessionRow.event_count,
            )
            .join(DecoyService, DecoyService.id == SessionRow.service_id)
            .where(SessionRow.closed.is_(False))
        )
        async with self._sessions() as db:
            rows = (await db.execute(stmt)).all()
        return [
            ResumedSession(
                session_id=session_id,
                source_ip=str(source_ip),
                service=ServiceName(service),
                started_at=started_at,
                last_seen_at=last_seen_at,
                event_count=event_count,
            )
            for session_id, source_ip, service, started_at, last_seen_at, event_count in rows
        ]

    # -- compteurs de fenêtre glissante -----------------------------------------

    async def counters(self, event: RawEvent) -> dict[str, int]:
        window_5m = event.occurred_at - timedelta(seconds=300)
        window_24h = event.occurred_at - timedelta(seconds=86_400)
        recent = Event.occurred_at >= window_5m

        stmt = select(
            func.count().filter(and_(recent, or_(Event.username != "", Event.password != ""))),
            func.array_agg(distinct(Event.service_id)).filter(recent),
            func.count(),
        ).where(Event.source_ip == str(event.source_ip), Event.occurred_at >= window_24h)

        async with self._sessions() as db:
            auth_attempts, recent_services, events_24h = (await db.execute(stmt)).one()

        services = set(recent_services or ()) | {self._service_ids[event.service]}
        return {
            "auth_attempts_by_ip": auth_attempts + 1,
            "distinct_services_by_ip": len(services),
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
        stmt = (
            select(
                Event,
                DecoyService.name,
                IpIntel.country_code,
                IpIntel.asn,
                IpIntel.as_org,
                IpIntel.reputation_score,
            )
            .join(DecoyService, DecoyService.id == Event.service_id)
            .outerjoin(IpIntel, IpIntel.ip == Event.source_ip)
            .where(Event.threat_score >= min_score)
            .order_by(Event.occurred_at.desc(), Event.id.desc())
            .limit(limit)
        )
        if service is not None:
            stmt = stmt.where(Event.service_id == self._service_ids[service])
        if country is not None:
            stmt = stmt.where(IpIntel.country_code == country)

        async with self._sessions() as db:
            rows = (await db.execute(stmt)).all()

        return [
            NormalizedEvent(
                event_id=stored.event_uid,
                occurred_at=stored.occurred_at,
                service=ServiceName(service_name),
                source_ip=ip_address(str(stored.source_ip)),
                source_port=stored.source_port,
                dest_port=stored.dest_port,
                username=stored.username,
                password=stored.password,
                payload=stored.payload_excerpt or b"",
                payload_truncated=stored.payload_truncated,
                payload_sha256=stored.payload_sha256,
                session_id=stored.session_id,
                country_code=country_code,
                asn=asn,
                as_org=as_org,
                reputation_score=reputation_score,
                technique_id=stored.technique_id,
                enrichment_status=EnrichmentStatus(stored.enrichment_status),
                threat_score=stored.threat_score,
            )
            for stored, service_name, country_code, asn, as_org, reputation_score in rows
        ]

    async def get_verdict(self, event_id: UUID) -> Verdict | None:
        async with self._sessions() as db:
            found = (
                await db.execute(
                    select(Event.id, Event.session_id, Event.threat_score, Event.attacker_profile)
                    .where(Event.event_uid == event_id)
                    .limit(1)
                )
            ).first()
            if found is None:
                return None

            matches: list[RuleMatch] = []
            if found.session_id is not None:
                # Filtrer d'abord par session sert l'index rule_match_session_idx.
                rows = await db.execute(
                    select(
                        RuleMatchRow.contributed_score,
                        DetectionRule.rule_key,
                        DetectionRule.name,
                        DetectionRule.description,
                        DetectionRule.severity,
                        DetectionRule.weight,
                    )
                    .join(DetectionRule, DetectionRule.id == RuleMatchRow.rule_id)
                    .where(
                        RuleMatchRow.session_id == found.session_id,
                        RuleMatchRow.event_id == found.id,
                    )
                    .order_by(RuleMatchRow.id)
                )
                matches = [
                    RuleMatch(
                        rule_id=row.rule_key,
                        name=row.name,
                        description=row.description,
                        severity=Severity(row.severity),
                        weight=row.weight,
                        contribution=row.contributed_score,
                    )
                    for row in rows
                ]

        return Verdict(
            event_id=event_id,
            session_id=found.session_id,
            threat_score=found.threat_score,
            profile=AttackerProfile(found.attacker_profile),
            matches=matches,
        )

    async def overview(self) -> dict[str, int]:
        async with self._sessions() as db:
            events, unique_ips, sessions, max_score = (
                await db.execute(
                    select(
                        func.count(),
                        func.count(distinct(Event.source_ip)),
                        func.count(distinct(Event.session_id)),
                        func.coalesce(func.max(Event.threat_score), 0),
                    ).select_from(Event)
                )
            ).one()
            rejected = (
                await db.execute(select(func.count()).select_from(EventRejected))
            ).scalar_one()
        return {
            "events": events,
            "unique_ips": unique_ips,
            "sessions": sessions,
            "max_threat_score": max_score,
            "rejected": rejected,
        }

    async def top_ips(self, limit: int = 10) -> list[dict[str, object]]:
        events = func.count().label("events")
        stmt = (
            select(
                Event.source_ip,
                events,
                func.max(Event.threat_score).label("threat_score"),
                IpIntel.country_code,
            )
            .select_from(Event)
            .outerjoin(IpIntel, IpIntel.ip == Event.source_ip)
            .group_by(Event.source_ip, IpIntel.country_code)
            .order_by(events.desc(), Event.source_ip)
            .limit(limit)
        )
        async with self._sessions() as db:
            rows = (await db.execute(stmt)).all()
        return [
            {
                "source_ip": str(row.source_ip),
                "events": row.events,
                "threat_score": row.threat_score,
                "country_code": row.country_code,
            }
            for row in rows
        ]

    async def top_credentials(self, limit: int = 10) -> dict[str, list[dict[str, object]]]:
        async with self._sessions() as db:
            return {
                "usernames": await self._rank(db, Event.username, limit),
                "passwords": await self._rank(db, Event.password, limit),
            }

    @staticmethod
    async def _rank(
        db: AsyncSession, column: InstrumentedAttribute[str], limit: int
    ) -> list[dict[str, object]]:
        count = func.count().label("count")
        stmt = (
            select(column, count)
            .where(column != "")
            .group_by(column)
            .order_by(count.desc(), column)
            .limit(limit)
        )
        return [{"value": value, "count": total} for value, total in await db.execute(stmt)]

    async def by_service(self) -> list[dict[str, object]]:
        stmt = (
            select(DecoyService.name, func.count())
            .select_from(Event)
            .join(DecoyService, DecoyService.id == Event.service_id)
            .group_by(DecoyService.name)
        )
        async with self._sessions() as db:
            rows = (await db.execute(stmt)).all()
        return service_percentages({name: count for name, count in rows})
