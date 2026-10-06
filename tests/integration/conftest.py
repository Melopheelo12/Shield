"""Une vraie base PostgreSQL, isolée dans un schéma jetable par test.

Chaque test reçoit un schéma neuf, construit à partir des scripts de
``deploy/initdb`` — les mêmes qu'en production — puis supprimé. La base visée
(``DATABASE_URL``) n'est jamais modifiée en dehors de ce schéma : on peut lancer
ces tests contre sa base de développement sans rien y perdre.

Sans PostgreSQL joignable, les tests sont ignorés — sauf si ``SHIELD_REQUIRE_DB``
est défini (en CI), auquel cas ils échouent.
"""

import os
import uuid
from pathlib import Path

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from shield.collector.models.base import DATABASE_URL

INITDB_SCRIPTS = sorted(Path("deploy/initdb").glob("*.sql"))


@pytest.fixture
async def pg_engine():
    schema = f"shield_it_{uuid.uuid4().hex[:12]}"
    dsn = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
    try:
        admin = await asyncpg.connect(dsn, timeout=5)
    except (OSError, asyncpg.PostgresError) as exc:
        if os.getenv("SHIELD_REQUIRE_DB"):
            raise
        pytest.skip(f"PostgreSQL indisponible : {exc}")

    try:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
        await admin.execute(f'SET search_path TO "{schema}"')
        for script in INITDB_SCRIPTS:
            await admin.execute(script.read_text(encoding="utf-8"))

        engine = create_async_engine(
            DATABASE_URL, connect_args={"server_settings": {"search_path": schema}}
        )
        try:
            yield engine
        finally:
            await engine.dispose()
    finally:
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await admin.close()
