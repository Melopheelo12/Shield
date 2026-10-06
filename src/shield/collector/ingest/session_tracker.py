"""Regroupement des événements en sessions (US-04).

Une session = les événements d'une même adresse sur un même service, séparés de
moins de ``window_seconds``. Le suivi est volontairement en mémoire : il est
déterministe et testable sans base. Pour qu'une session survive à un redémarrage
du collecteur, les sessions encore ouvertes en base lui sont rendues au démarrage
par ``restore`` (#58). ``RedisSessionTracker`` prendra le relais au sprint 2.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID, uuid4

from shield.common.schema import RawEvent, ServiceName

DEFAULT_WINDOW_SECONDS = 300


@dataclass
class _OpenSession:
    session_id: UUID
    started_at: datetime
    last_seen_at: datetime
    event_count: int = 0


@dataclass(frozen=True)
class ResumedSession:
    """Une session encore ouverte en base, à reprendre après un redémarrage."""

    session_id: UUID
    source_ip: str
    service: ServiceName
    started_at: datetime
    last_seen_at: datetime
    event_count: int


@dataclass
class SessionTracker:
    """Attache un ``session_id`` à chaque événement, en ouvrant une session si besoin."""

    window_seconds: int = DEFAULT_WINDOW_SECONDS
    _open: dict[tuple[str, ServiceName], _OpenSession] = field(default_factory=dict)

    def _key(
        self, source_ip: IPv4Address | IPv6Address, service: ServiceName
    ) -> tuple[str, ServiceName]:
        return (str(source_ip), service)

    def attach(self, event: RawEvent) -> UUID:
        key = self._key(event.source_ip, event.service)
        window = timedelta(seconds=self.window_seconds)
        current = self._open.get(key)

        if current is not None and event.occurred_at - current.last_seen_at <= window:
            current.last_seen_at = event.occurred_at
            current.event_count += 1
            return current.session_id

        session = _OpenSession(
            session_id=uuid4(),
            started_at=event.occurred_at,
            last_seen_at=event.occurred_at,
            event_count=1,
        )
        self._open[key] = session
        return session.session_id

    def restore(self, sessions: Iterable[ResumedSession]) -> None:
        """Reprend des sessions ouvertes ; pour une même clé, la plus récente l'emporte."""
        for resumed in sessions:
            key = (resumed.source_ip, resumed.service)
            current = self._open.get(key)
            if current is not None and current.last_seen_at >= resumed.last_seen_at:
                continue
            self._open[key] = _OpenSession(
                session_id=resumed.session_id,
                started_at=resumed.started_at,
                last_seen_at=resumed.last_seen_at,
                event_count=resumed.event_count,
            )

    def close_expired(self, now: datetime) -> list[UUID]:
        """Ferme les sessions inactives. Retourne les identifiants fermés."""
        window = timedelta(seconds=self.window_seconds)
        expired = [
            (key, session)
            for key, session in self._open.items()
            if now - session.last_seen_at > window
        ]
        for key, _ in expired:
            del self._open[key]
        return [session.session_id for _, session in expired]

    @property
    def open_count(self) -> int:
        return len(self._open)
