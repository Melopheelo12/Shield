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

import gzip
import hashlib
import json
import logging
import os
import re
from datetime import UTC, date, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Select,
    and_,
    case,
    delete,
    distinct,
    func,
    insert,
    or_,
    select,
    text,
    tuple_,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql import ColumnElement

from shield.collector.defender import Rule
from shield.collector.ingest.session_tracker import ResumedSession
from shield.collector.models import (
    Alert,
    AlertThreshold,
    CveWatch,
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
from shield.collector.repositories.base import (
    MAX_REJECTED_BODY_BYTES,
    MAX_SESSION_EVENTS,
    TIMELINE_ORIGIN,
    country_ranking,
    rule_summary,
    service_percentages,
    session_payload,
)
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

#: Nom des partitions créées par ``create_event_partition`` : event_AAAA_MM.
_PARTITION_NAME = re.compile(r"event_(\d{4})_(\d{2})")

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
                ip=ip,
                first_seen=seen_at,
                last_seen=seen_at,
                total_events=1,
                country_code=event.country_code,
                asn=event.asn,
                as_org=_pg_text(event.as_org) if event.as_org else None,
            )
            await db.execute(
                intel.on_conflict_do_update(
                    index_elements=[IpIntel.ip],
                    set_={
                        "first_seen": func.least(IpIntel.first_seen, intel.excluded.first_seen),
                        "last_seen": func.greatest(IpIntel.last_seen, intel.excluded.last_seen),
                        "total_events": IpIntel.total_events + 1,
                        # Une base GeoLite2 plus récente corrige ; une base absente n'efface rien.
                        **{
                            column: func.coalesce(intel.excluded[column], getattr(IpIntel, column))
                            for column in ("country_code", "asn", "as_org")
                        },
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

    # -- enrichissement différé -------------------------------------------------

    async def pending_reputation(self, limit: int) -> list[str]:
        """Index partiel ``event_enrichment_pending_idx`` (003_enrichment.sql)."""
        latest = func.max(Event.occurred_at)
        stmt = (
            select(Event.source_ip)
            .where(Event.enrichment_status != EnrichmentStatus.DONE.value)
            .group_by(Event.source_ip)
            .order_by(latest.desc())
            .limit(limit)
        )
        async with self._sessions() as db:
            return [str(ip) for ip in (await db.execute(stmt)).scalars()]

    async def apply_reputation(self, ip: str, score: int | None) -> None:
        async with self._sessions.begin() as db:
            if score is not None:
                await db.execute(
                    update(IpIntel)
                    .where(IpIntel.ip == ip)
                    .values(reputation_score=score, reputation_checked_at=datetime.now(UTC))
                )
            await db.execute(
                update(Event)
                .where(
                    Event.source_ip == ip,
                    Event.enrichment_status != EnrichmentStatus.DONE.value,
                )
                .values(enrichment_status=EnrichmentStatus.DONE.value)
                .execution_options(synchronize_session=False)
            )

    # -- liste de blocage et conservation ---------------------------------------

    async def hostile_ips(self, min_score: int, since: datetime) -> list[str]:
        worst = func.max(Event.threat_score)
        stmt = (
            select(Event.source_ip)
            .where(Event.occurred_at >= since)
            .group_by(Event.source_ip)
            .having(worst >= min_score)
            .order_by(worst.desc(), Event.source_ip)
        )
        async with self._sessions() as db:
            return [str(ip) for ip in (await db.execute(stmt)).scalars()]

    async def purge(self, cutoff: datetime) -> dict[str, int]:
        """US-46 : supprime tout ce qui précède ``cutoff``, et le journalise.

        Une partition mensuelle entièrement expirée part en un ``DROP`` instantané —
        c'est la raison du partitionnement. Le reste (mois partiellement expiré,
        ``event_default``) passe par un ``DELETE`` ciblé.
        """
        summary: dict[str, int] = {}
        async with self._sessions.begin() as db:
            for name, _, first_day_after in await self._event_partitions(db):
                if first_day_after > cutoff.date():
                    continue
                # Nom vérifié par l'expression régulière : aucune donnée externe ici.
                count_sql = f'SELECT count(*) FROM "{name}"'  # noqa: S608  # nosec B608
                rows = (await db.execute(text(count_sql))).scalar_one()
                await db.execute(text(f'DROP TABLE "{name}"'))
                await self._log_retention(db, cutoff, name, rows)
                summary[name] = rows

            result = await db.execute(delete(Event).where(Event.occurred_at < cutoff))
            deleted: int = result.rowcount  # type: ignore[attr-defined]
            await self._log_retention(db, cutoff, None, deleted)
            summary["event"] = deleted

            last_activity = func.coalesce(SessionRow.ended_at, SessionRow.started_at)
            rejected_before = EventRejected.received_at < cutoff
            for label, stmt in (
                ("session", delete(SessionRow).where(last_activity < cutoff)),
                ("ip_intel", delete(IpIntel).where(IpIntel.last_seen < cutoff)),
                ("event_rejected", delete(EventRejected).where(rejected_before)),
                ("alert", delete(Alert).where(Alert.triggered_at < cutoff)),
            ):
                result = await db.execute(stmt)
                summary[label] = result.rowcount  # type: ignore[attr-defined]
        logger.info("purge RGPD avant %s : %s", cutoff.date(), summary)
        return summary

    @staticmethod
    async def _event_partitions(db: AsyncSession) -> list[tuple[str, date, date]]:
        """Partitions mensuelles d'``event`` : (nom, premier jour, premier jour suivant).

        ``event_default`` et tout nom inattendu sont ignorés : seul un nom vérifié par
        ``_PARTITION_NAME`` peut ensuite apparaître dans une requête.
        """
        children = await db.execute(
            text(
                "SELECT c.relname FROM pg_inherits i "
                "JOIN pg_class c ON c.oid = i.inhrelid "
                "WHERE i.inhparent = 'event'::regclass"
            )
        )
        partitions = []
        for name in sorted(children.scalars()):
            found = _PARTITION_NAME.fullmatch(name)
            if found is None:
                continue
            year, month = int(found[1]), int(found[2])
            first_day = date(year, month, 1)
            partitions.append((name, first_day, date(year + month // 12, month % 12 + 1, 1)))
        return partitions

    async def lighten_payloads(self, before: datetime) -> int:
        """Efface la charge utile des événements antérieurs à ``before``. L'empreinte reste."""
        async with self._sessions.begin() as db:
            result = await db.execute(
                update(Event)
                .where(Event.occurred_at < before, Event.payload_excerpt.is_not(None))
                .values(payload_excerpt=None)
                .execution_options(synchronize_session=False)
            )
        lightened: int = result.rowcount  # type: ignore[attr-defined]
        return lightened

    async def archive_partitions(self, before: date, directory: Path) -> list[dict[str, Any]]:
        """Archive puis supprime chaque partition mensuelle entièrement antérieure à ``before``.

        Ordre de sûreté : le fichier est écrit sous un nom temporaire, puis renommé ; le
        nombre de lignes copiées est comparé à celui de la partition **dans la même
        transaction que le DROP**. Au moindre écart, rien n'est supprimé.
        """
        async with self._sessions() as db:
            eligible = [name for name, _, end in await self._event_partitions(db) if end <= before]
        archived = []
        for name in eligible:
            path = directory / f"{name}.csv.gz"
            copied, digest = await self._copy_partition(name, path)
            async with self._sessions.begin() as db:
                count_sql = f'SELECT count(*) FROM "{name}"'  # noqa: S608  # nosec B608
                rows = (await db.execute(text(count_sql))).scalar_one()
                if rows != copied:
                    logger.error(
                        "archive %s : %s lignes copiées, %s en base — rien supprimé",
                        name,
                        copied,
                        rows,
                    )
                    continue
                await db.execute(text(f'DROP TABLE "{name}"'))
                await self._log_retention(
                    db, datetime.combine(before, datetime.min.time(), UTC), f"archive:{name}", rows
                )
            manifest = {
                "partition": name,
                "rows": rows,
                "sha256": digest,
                "archived_at": datetime.now(UTC).isoformat(),
                "file": path.name,
            }
            (directory / f"{name}.json").write_text(json.dumps(manifest, indent=2), "utf-8")
            archived.append(manifest)
            logger.info("partition %s archivée : %s lignes → %s", name, rows, path)
        return archived

    async def _copy_partition(self, name: str, path: Path) -> tuple[int, str]:
        """``COPY … TO STDOUT`` en CSV compressé. Retourne (lignes copiées, SHA-256 du fichier)."""
        temporary = path.with_name(path.name + ".tmp")
        digest = hashlib.sha256()
        # Nom vérifié par _PARTITION_NAME. Le service est joint : l'archive se lit seule.
        query = (
            f'SELECT e.*, s.name AS service FROM "{name}" e '  # noqa: S608  # nosec B608
            "JOIN decoy_service s ON s.id = e.service_id ORDER BY e.occurred_at, e.id"
        )
        async with self._engine.connect() as conn:
            raw = await conn.get_raw_connection()
            with gzip.open(temporary, "wb") as archive:

                async def sink(chunk: bytes) -> None:
                    archive.write(chunk)

                status = await raw.driver_connection.copy_from_query(
                    query, output=sink, format="csv", header=True
                )
        with temporary.open("rb") as written:
            for block in iter(lambda: written.read(1 << 20), b""):
                digest.update(block)
        os.replace(temporary, path)
        return int(str(status).split()[-1]), digest.hexdigest()

    async def storage_usage(self) -> list[dict[str, Any]]:
        """Taille sur disque des tables, index compris, les plus lourdes d'abord."""
        async with self._sessions() as db:
            rows = await db.execute(
                text(
                    "SELECT c.relname, pg_total_relation_size(c.oid) "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE c.relkind = 'r' AND n.nspname = current_schema() "
                    "ORDER BY 2 DESC"
                )
            )
            return [{"table": name, "bytes": size} for name, size in rows]

    @staticmethod
    async def _log_retention(
        db: AsyncSession, cutoff: datetime, partition: str | None, rows: int
    ) -> None:
        await db.execute(
            text(
                "INSERT INTO retention_job (cutoff_date, partition, deleted_rows) "
                "VALUES (:cutoff, :partition, :rows)"
            ),
            {"cutoff": cutoff.date(), "partition": partition, "rows": rows},
        )

    # -- veille (US-39, US-40) ---------------------------------------------------

    async def upsert_watch(self, entries: list[dict[str, Any]]) -> None:
        if not entries:
            return
        stmt = pg_insert(CveWatch).values(entries)
        async with self._sessions.begin() as db:
            await db.execute(
                stmt.on_conflict_do_update(
                    index_elements=[CveWatch.cve_id],
                    set_={
                        "published_at": stmt.excluded.published_at,
                        "summary": stmt.excluded.summary,
                        "kev_flag": stmt.excluded.kev_flag,
                    },
                )
            )

    async def watch_entries(self, limit: int = 100) -> list[dict[str, Any]]:
        stmt = (
            select(
                CveWatch.cve_id,
                CveWatch.published_at,
                CveWatch.summary,
                CveWatch.kev_flag,
                CveWatch.matched_events,
                CveWatch.last_matched_at,
            )
            .order_by(
                CveWatch.matched_events.desc(),
                CveWatch.published_at.desc().nulls_last(),
                CveWatch.cve_id,
            )
            .limit(limit)
        )
        async with self._sessions() as db:
            return [dict(row._mapping) for row in await db.execute(stmt)]

    _PAYLOAD_CONTAINS = "position(CAST(:marker AS bytea) IN event.payload_excerpt) > 0"

    async def count_payload_matches(self, marker: bytes) -> tuple[int, datetime | None]:
        stmt = select(func.count(), func.max(Event.occurred_at)).where(
            text(self._PAYLOAD_CONTAINS).bindparams(marker=marker)
        )
        async with self._sessions() as db:
            count, last = (await db.execute(stmt)).one()
        return count, last

    async def record_watch_matches(self, cve_id: str, count: int, last: datetime | None) -> None:
        async with self._sessions.begin() as db:
            await db.execute(
                update(CveWatch)
                .where(CveWatch.cve_id == cve_id)
                .values(matched_events=count, last_matched_at=last)
            )

    async def events_with_payload(self, marker: bytes, limit: int) -> list[NormalizedEvent]:
        stmt = (
            self._event_select()
            .where(text(self._PAYLOAD_CONTAINS).bindparams(marker=marker))
            .order_by(Event.occurred_at.desc(), Event.id.desc())
            .limit(limit)
        )
        return await self._fetch_events(stmt)

    # -- alertes ----------------------------------------------------------------

    _THRESHOLD_COLUMNS = (
        "id",
        "metric",
        "threshold",
        "window_seconds",
        "silence_seconds",
        "enabled",
    )

    async def load_alert_thresholds(self) -> list[dict[str, Any]]:
        columns = [getattr(AlertThreshold, name) for name in self._THRESHOLD_COLUMNS]
        async with self._sessions() as db:
            rows = (await db.execute(select(*columns).order_by(AlertThreshold.id))).all()
        return [
            {**dict(zip(self._THRESHOLD_COLUMNS, row, strict=True)), "threshold": float(row[2])}
            for row in rows
        ]

    async def save_alert_thresholds(self, thresholds: list[dict[str, Any]]) -> None:
        async with self._sessions.begin() as db:
            await db.execute(delete(AlertThreshold))
            if thresholds:
                await db.execute(
                    insert(AlertThreshold),
                    [{name: item[name] for name in self._THRESHOLD_COLUMNS} for item in thresholds],
                )

    async def record_alert(self, alert: dict[str, Any]) -> None:
        async with self._sessions.begin() as db:
            await db.execute(
                insert(Alert).values(
                    threshold_key=alert["threshold_id"],
                    triggered_at=alert["triggered_at"],
                    metric_value=alert["value"],
                    threshold=alert["threshold"],
                    status=alert["status"],
                    channels=alert["channels"],
                )
            )

    async def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        stmt = (
            select(
                Alert.threshold_key,
                Alert.triggered_at,
                Alert.metric_value,
                Alert.threshold,
                Alert.status,
                Alert.channels,
            )
            .order_by(Alert.triggered_at.desc(), Alert.id.desc())
            .limit(limit)
        )
        async with self._sessions() as db:
            rows = (await db.execute(stmt)).all()
        return [
            {
                "threshold_id": row.threshold_key,
                "triggered_at": row.triggered_at,
                "value": float(row.metric_value) if row.metric_value is not None else None,
                "threshold": float(row.threshold) if row.threshold is not None else None,
                "status": row.status,
                "channels": row.channels,
            }
            for row in rows
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
        session_id: UUID | None = None,
    ) -> list[NormalizedEvent]:
        stmt = (
            self._event_select()
            .where(Event.threat_score >= min_score)
            .order_by(Event.occurred_at.desc(), Event.id.desc())
            .limit(limit)
        )
        if service is not None:
            stmt = stmt.where(Event.service_id == self._service_ids[service])
        if country is not None:
            stmt = stmt.where(IpIntel.country_code == country)
        if session_id is not None:
            stmt = stmt.where(Event.session_id == session_id)
        return await self._fetch_events(stmt)

    async def export_page(
        self,
        since: datetime | None,
        until: datetime | None,
        cursor: tuple[datetime, UUID] | None,
        limit: int,
    ) -> list[NormalizedEvent]:
        stmt = self._event_select().order_by(Event.occurred_at, Event.event_uid).limit(limit)
        if since is not None:
            stmt = stmt.where(Event.occurred_at >= since)
        if until is not None:
            stmt = stmt.where(Event.occurred_at < until)
        if cursor is not None:
            stmt = stmt.where(tuple_(Event.occurred_at, Event.event_uid) > tuple_(*cursor))
        return await self._fetch_events(stmt)

    @staticmethod
    def _event_select() -> Select[Any]:
        return (
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
        )

    async def _fetch_events(self, stmt: Select[Any]) -> list[NormalizedEvent]:
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

    async def session_detail(self, session_id: UUID) -> dict[str, object] | None:
        async with self._sessions() as db:
            # Colonnes explicites : charger l'entité tirerait ses relations « selectin ».
            session = (
                await db.execute(
                    select(
                        SessionRow.source_ip,
                        DecoyService.name.label("service"),
                        SessionRow.started_at,
                        SessionRow.ended_at,
                        SessionRow.event_count,
                        SessionRow.threat_score,
                        SessionRow.attacker_profile,
                        SessionRow.closed,
                    )
                    .join(DecoyService, DecoyService.id == SessionRow.service_id)
                    .where(SessionRow.id == session_id)
                )
            ).first()
            if session is None:
                return None

            # Filtrer par session sert l'index rule_match_session_idx.
            total = func.sum(RuleMatchRow.contributed_score)
            rows = await db.execute(
                select(
                    DetectionRule.rule_key,
                    DetectionRule.name,
                    DetectionRule.description,
                    DetectionRule.severity,
                    DetectionRule.weight,
                    func.count(),
                    total,
                )
                .join(DetectionRule, DetectionRule.id == RuleMatchRow.rule_id)
                .where(RuleMatchRow.session_id == session_id)
                .group_by(DetectionRule.id)
            )
            rules = [
                rule_summary(
                    RuleMatch(
                        rule_id=rule_key,
                        name=name,
                        description=description,
                        severity=Severity(severity),
                        weight=weight,
                        contribution=0,
                    ),
                    hits,
                    int(contributed),
                )
                for rule_key, name, description, severity, weight, hits, contributed in rows
            ]

        return session_payload(
            session_id=session_id,
            source_ip=str(session.source_ip),
            service=session.service,
            started_at=session.started_at,
            ended_at=session.ended_at,
            event_count=session.event_count,
            threat_score=session.threat_score,
            attacker_profile=session.attacker_profile,
            closed=session.closed,
            events=await self.query(session_id=session_id, limit=MAX_SESSION_EVENTS),
            rules=rules,
        )

    async def timeline(self, since: datetime, bucket: timedelta) -> list[dict[str, object]]:
        # GROUP BY / ORDER BY par position : la même expression écrite deux fois
        # porterait des paramètres distincts, que PostgreSQL ne reconnaît pas égaux.
        start = func.date_bin(bucket, Event.occurred_at, TIMELINE_ORIGIN)
        stmt = (
            select(start, func.count(), func.max(Event.threat_score))
            .where(Event.occurred_at >= since)
            .group_by(text("1"))
            .order_by(text("1"))
        )
        async with self._sessions() as db:
            rows = (await db.execute(stmt)).all()
        return [
            {"bucket": moment.isoformat(), "events": count, "max_threat_score": worst}
            for moment, count, worst in rows
        ]

    async def by_country(self) -> list[dict[str, object]]:
        stmt = (
            select(IpIntel.country_code, func.count(), func.count(distinct(Event.source_ip)))
            .select_from(Event)
            .outerjoin(IpIntel, IpIntel.ip == Event.source_ip)
            .group_by(IpIntel.country_code)
        )
        async with self._sessions() as db:
            rows = (await db.execute(stmt)).all()
        return country_ranking([(country, events, ips) for country, events, ips in rows])

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
