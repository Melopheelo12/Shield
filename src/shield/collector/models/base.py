"""Connexion à la base et base déclarative SQLAlchemy.

Le moteur est **asynchrone** (asyncpg) : le collecteur est une application
`asyncio`, et une session bloquante sur le chemin d'ingestion ferait tomber
l'objectif « aucune perte jusqu'à 50 événements par seconde » (US-01).

Le schéma lui-même n'est PAS créé par SQLAlchemy : il vit dans
``deploy/initdb/001_schema.sql``, exécuté par PostgreSQL au premier démarrage.
Les modèles se contentent de s'y mapper. C'est délibéré — le partitionnement
déclaratif s'exprime mal à travers un ORM, et on veut un schéma identique en
local, en CI et en production.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://shield:shield@localhost:5432/shield",
)


class Base(DeclarativeBase):
    """Base déclarative commune à tous les modèles."""


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Moteur unique, créé paresseusement.

    ``pool_pre_ping`` évite les erreurs « connection closed » quand PostgreSQL
    redémarre : la connexion est testée avant d'être prêtée.
    """
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            DATABASE_URL,
            pool_size=10,
            max_overflow=5,
            pool_pre_ping=True,
            echo=os.getenv("SQL_ECHO", "").lower() == "true",
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _session_factory


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Une session, une transaction. Commit si tout va bien, rollback sinon."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    """À appeler à l'arrêt de l'application."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
