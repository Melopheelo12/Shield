"""Diffusion temps réel des événements (US-20, S3-02).

Objectif : une attaque capturée apparaît à l'écran en moins de cinq secondes.

* Chaque client WebSocket a sa file, **bornée** : un onglet lent ou en arrière-plan
  perd ses trames les plus anciennes, il ne ralentit jamais l'ingestion.
* La publication Redis (canal ``shield:events``) est un plus pour d'autres consommateurs
  — jamais une condition : Redis absent, les clients WebSocket reçoivent quand même.

Trames : ``{"type": "event", "data": NormalizedEvent}`` et ``{"type": "ping"}`` toutes
les 25 s, qui garde la connexion ouverte à travers nginx et révèle un client parti.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

logger = logging.getLogger(__name__)

CHANNEL = "shield:events"
QUEUE_SIZE = 100
PING_INTERVAL_SECONDS = 25.0

Frame = dict[str, Any]


class Broadcaster:
    """Répartit chaque trame vers toutes les files abonnées."""

    def __init__(self, redis: Any = None) -> None:
        self._subscribers: set[asyncio.Queue[Frame]] = set()
        self._redis = redis

    @classmethod
    def from_env(cls) -> Broadcaster:
        url = os.getenv("REDIS_URL")
        if not url:
            return cls()
        import redis.asyncio as redis

        return cls(redis.from_url(url, socket_timeout=0.2, socket_connect_timeout=0.2))

    @property
    def subscribers(self) -> int:
        return len(self._subscribers)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[Frame]]:
        queue: asyncio.Queue[Frame] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)

    async def publish(self, frame: Frame) -> None:
        """Ne lève jamais, ne bloque jamais : appelée sur le chemin d'ingestion."""
        for queue in self._subscribers:
            if queue.full():
                queue.get_nowait()  # le plus ancien cède sa place
            queue.put_nowait(frame)
        if self._redis is not None:
            try:
                await self._redis.publish(CHANNEL, json.dumps(frame, default=str))
            except Exception:  # noqa: BLE001 - Redis est un plus, pas une condition
                logger.debug("publication Redis impossible", exc_info=True)

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:  # noqa: BLE001
                logger.debug("fermeture Redis", exc_info=True)


async def next_frame(queue: asyncio.Queue[Frame], timeout: float = PING_INTERVAL_SECONDS) -> Frame:
    """La prochaine trame, ou un ping si rien n'arrive pendant ``timeout`` secondes."""
    try:
        return await asyncio.wait_for(queue.get(), timeout)
    except TimeoutError:
        return {"type": "ping"}
