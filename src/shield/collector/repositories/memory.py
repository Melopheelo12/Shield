"""Entrepôt en mémoire, borné.

C'était le stockage du bootstrap (sprint 0). Il reste l'implémentation de
référence pour les tests unitaires et pour développer sans PostgreSQL
(``SHIELD_STORAGE=memory``). Rien n'y survit à un redémarrage.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from shield.collector.defender import Rule
from shield.collector.ingest.session_tracker import ResumedSession
from shield.collector.repositories.base import (
    MAX_REJECTED_BODY_BYTES,
    MAX_SESSION_EVENTS,
    bucket_start,
    country_ranking,
    rule_summary,
    service_percentages,
    session_payload,
)
from shield.common.schema import (
    EnrichmentStatus,
    NormalizedEvent,
    RawEvent,
    RuleMatch,
    ServiceName,
    Verdict,
)

MAX_EVENTS_IN_MEMORY = 50_000


class InMemoryEventRepository:
    """Implémentation en mémoire d'``EventRepository``."""

    def __init__(self, maxlen: int = MAX_EVENTS_IN_MEMORY) -> None:
        self.events: deque[NormalizedEvent] = deque(maxlen=maxlen)
        self.verdicts: dict[UUID, Verdict] = {}
        self.rejected: list[tuple[str, bytes]] = []
        self.alert_thresholds: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.watch: dict[str, dict[str, Any]] = {}

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

    # -- enrichissement différé -------------------------------------------------

    async def pending_reputation(self, limit: int) -> list[str]:
        pending: list[str] = []
        for stored in reversed(self.events):
            ip = str(stored.source_ip)
            if stored.enrichment_status != EnrichmentStatus.DONE and ip not in pending:
                pending.append(ip)
                if len(pending) >= limit:
                    break
        return pending

    async def apply_reputation(self, ip: str, score: int | None) -> None:
        update = {"reputation_score": score, "enrichment_status": EnrichmentStatus.DONE}
        for index in range(len(self.events)):
            if str(self.events[index].source_ip) == ip:
                self.events[index] = self.events[index].model_copy(update=update)

    # -- export, liste de blocage, conservation ----------------------------------

    async def export_page(
        self,
        since: datetime | None,
        until: datetime | None,
        cursor: tuple[datetime, UUID] | None,
        limit: int,
    ) -> list[NormalizedEvent]:
        ordered = sorted(self.events, key=lambda event: (event.occurred_at, event.event_id))
        page: list[NormalizedEvent] = []
        for event in ordered:
            if since is not None and event.occurred_at < since:
                continue
            if until is not None and event.occurred_at >= until:
                continue
            if cursor is not None and (event.occurred_at, event.event_id) <= cursor:
                continue
            page.append(event)
            if len(page) >= limit:
                break
        return page

    async def hostile_ips(self, min_score: int, since: datetime) -> list[str]:
        worst: dict[str, int] = {}
        for event in self.events:
            if event.occurred_at >= since:
                ip = str(event.source_ip)
                worst[ip] = max(worst.get(ip, 0), event.threat_score)
        ranked = sorted(worst.items(), key=lambda item: (-item[1], item[0]))
        return [ip for ip, score in ranked if score >= min_score]

    async def lighten_payloads(self, before: datetime) -> int:
        lightened = 0
        for index in range(len(self.events)):
            event = self.events[index]
            if event.occurred_at < before and event.payload:
                self.events[index] = event.model_copy(update={"payload": b""})
                lightened += 1
        return lightened

    async def archive_partitions(self, before: date, directory: Path) -> list[dict[str, Any]]:
        return []  # pas de partitions en mémoire : rien à archiver

    async def storage_usage(self) -> list[dict[str, Any]]:
        return [{"table": "event (mémoire)", "bytes": sum(len(e.payload) for e in self.events)}]

    async def purge(self, cutoff: datetime) -> dict[str, int]:
        kept = [event for event in self.events if event.occurred_at >= cutoff]
        removed = len(self.events) - len(kept)
        for event in self.events:
            if event.occurred_at < cutoff:
                self.verdicts.pop(event.event_id, None)
        self.events = deque(kept, maxlen=self.events.maxlen)
        return {"event": removed}

    # -- veille -----------------------------------------------------------------

    async def upsert_watch(self, entries: list[dict[str, Any]]) -> None:
        for entry in entries:
            current = self.watch.setdefault(
                entry["cve_id"], {"matched_events": 0, "last_matched_at": None}
            )
            current.update(entry)

    async def watch_entries(self, limit: int = 100) -> list[dict[str, Any]]:
        ranked = sorted(
            self.watch.values(),
            key=lambda entry: (
                -entry["matched_events"],
                -(entry["published_at"].timestamp() if entry["published_at"] else 0),
                entry["cve_id"],
            ),
        )
        return [dict(entry) for entry in ranked[:limit]]

    def _with_payload(self, marker: bytes) -> list[NormalizedEvent]:
        return [event for event in self.events if marker in event.payload]

    async def count_payload_matches(self, marker: bytes) -> tuple[int, datetime | None]:
        matches = self._with_payload(marker)
        return len(matches), max((event.occurred_at for event in matches), default=None)

    async def record_watch_matches(self, cve_id: str, count: int, last: datetime | None) -> None:
        if cve_id in self.watch:
            self.watch[cve_id].update(matched_events=count, last_matched_at=last)

    async def events_with_payload(self, marker: bytes, limit: int) -> list[NormalizedEvent]:
        matches = sorted(self._with_payload(marker), key=lambda e: e.occurred_at, reverse=True)
        return matches[:limit]

    # -- alertes ----------------------------------------------------------------

    async def load_alert_thresholds(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self.alert_thresholds]

    async def save_alert_thresholds(self, thresholds: list[dict[str, Any]]) -> None:
        self.alert_thresholds = [dict(item) for item in thresholds]

    async def record_alert(self, alert: dict[str, Any]) -> None:
        self.alerts.append(dict(alert))

    async def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        return [dict(item) for item in reversed(self.alerts[-limit:])]

    # -- cycle de vie des sessions -----------------------------------------------

    async def close_idle_sessions(self, before: datetime) -> int:
        return 0

    async def open_sessions(self) -> list[ResumedSession]:
        return []

    # -- compteurs de fenêtre glissante -----------------------------------------

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
        session_id: UUID | None = None,
    ) -> list[NormalizedEvent]:
        result = []
        for stored in reversed(self.events):
            if session_id and stored.session_id != session_id:
                continue
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

    async def session_detail(self, session_id: UUID) -> dict[str, object] | None:
        events = [event for event in self.events if event.session_id == session_id]
        if not events:
            return None
        verdicts = [self.verdicts[event.event_id] for event in events]
        worst = max(verdicts, key=lambda verdict: verdict.threat_score)

        first_match: dict[str, RuleMatch] = {}
        hits: dict[str, int] = defaultdict(int)
        contributions: dict[str, int] = defaultdict(int)
        for verdict in verdicts:
            for match in verdict.matches:
                first_match.setdefault(match.rule_id, match)
                hits[match.rule_id] += 1
                contributions[match.rule_id] += match.contribution
        rules = [
            rule_summary(match, hits[rule_id], contributions[rule_id])
            for rule_id, match in first_match.items()
        ]

        recent = sorted(events, key=lambda event: event.occurred_at, reverse=True)
        return session_payload(
            session_id=session_id,
            source_ip=str(events[0].source_ip),
            service=events[0].service.value,
            started_at=min(event.occurred_at for event in events),
            ended_at=max(event.occurred_at for event in events),
            event_count=len(events),
            threat_score=worst.threat_score,
            attacker_profile=worst.profile.value,
            closed=False,
            events=recent[:MAX_SESSION_EVENTS],
            rules=rules,
        )

    async def timeline(self, since: datetime, bucket: timedelta) -> list[dict[str, object]]:
        counts: dict[datetime, int] = defaultdict(int)
        worst: dict[datetime, int] = defaultdict(int)
        for event in self.events:
            if event.occurred_at < since:
                continue
            start = bucket_start(event.occurred_at, bucket)
            counts[start] += 1
            worst[start] = max(worst[start], event.threat_score)
        return [
            {"bucket": start.isoformat(), "events": counts[start], "max_threat_score": worst[start]}
            for start in sorted(counts)
        ]

    async def by_country(self) -> list[dict[str, object]]:
        events: dict[str | None, int] = defaultdict(int)
        addresses: dict[str | None, set[str]] = defaultdict(set)
        for event in self.events:
            events[event.country_code] += 1
            addresses[event.country_code].add(str(event.source_ip))
        return country_ranking(
            [(country, count, len(addresses[country])) for country, count in events.items()]
        )

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
