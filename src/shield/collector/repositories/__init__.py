"""Persistance du collecteur. Le stockage est choisi par ``SHIELD_STORAGE``.

* ``postgres`` (défaut) — la production ; lit ``DATABASE_URL`` ;
* ``memory`` — développement et tests, sans base, rien ne survit à un redémarrage.
"""

from __future__ import annotations

import os

from shield.collector.repositories.base import EventRepository
from shield.collector.repositories.memory import InMemoryEventRepository
from shield.collector.repositories.postgres import PostgresEventRepository


def build_repository() -> EventRepository:
    storage = os.getenv("SHIELD_STORAGE", "postgres").lower()
    if storage == "postgres":
        return PostgresEventRepository()
    if storage == "memory":
        return InMemoryEventRepository()
    raise ValueError(f"SHIELD_STORAGE inconnu : {storage!r} (attendu : postgres ou memory)")


__all__ = [
    "EventRepository",
    "InMemoryEventRepository",
    "PostgresEventRepository",
    "build_repository",
]
