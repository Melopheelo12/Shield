"""Contrat commun à tous les leurres.

INVARIANT DE SÉCURITÉ — vérifié en revue à chaque pull request touchant ce paquet :

    Aucune méthode de ce module ni de ses sous-classes n'appelle ``eval``, ``exec``,
    ``subprocess``, ``os.system``, n'écrit dans le système de fichiers, ni n'interprète
    le contenu reçu. La charge utile est une séquence d'octets opaque, transportée
    telle quelle jusqu'au collecteur.

C'est la différence entre la faible interaction et la forte interaction, et c'est la
mitigation principale du risque R1 (« le honeypot sert de rebond vers un tiers »).
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from ipaddress import ip_address

import httpx

from shield.common.schema import MAX_PAYLOAD_BYTES, RawEvent, ServiceName

logger = logging.getLogger(__name__)

#: Au-delà, on arrête de lire : un attaquant ne doit pas pouvoir saturer la mémoire.
READ_LIMIT_BYTES = 64 * 1024

#: Un client qui ne parle pas est déconnecté : les sockets ouverts sont une ressource.
IDLE_TIMEOUT_SECONDS = 10.0


class DecoyService(ABC):
    """Écouter, dialoguer le strict minimum, journaliser, refuser."""

    service: ServiceName

    def __init__(
        self,
        port: int,
        ingest_url: str,
        ingest_token: str,
        *,
        banner: str = "",
        max_connections: int = 200,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.port = port
        self.banner = banner
        self.ingest_url = ingest_url
        self.ingest_token = ingest_token
        self._semaphore = asyncio.Semaphore(max_connections)
        self._server: asyncio.AbstractServer | None = None
        self._client = client

    # ------------------------------------------------------------------ cycle de vie

    async def start(self) -> None:
        self._client = self._client or httpx.AsyncClient(timeout=5.0)
        self._server = await asyncio.start_server(
            self._guarded_connection, host="0.0.0.0", port=self.port  # noqa: S104
        )
        logger.info("decoy %s listening on port %s", self.service.value, self.port)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        if self._client is not None:
            await self._client.aclose()
        logger.info("decoy %s stopped", self.service.value)

    # ------------------------------------------------------------------ connexions

    async def _guarded_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Un échec sur une connexion ne doit jamais arrêter le service (US-01)."""
        async with self._semaphore:
            try:
                await asyncio.wait_for(
                    self.handle_connection(reader, writer), timeout=IDLE_TIMEOUT_SECONDS * 3
                )
            except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                pass
            except Exception:  # noqa: BLE001 - résilience volontaire
                logger.exception("decoy %s: unhandled error", self.service.value)
            finally:
                with_suppress = (ConnectionError, RuntimeError)
                try:
                    writer.close()
                    await writer.wait_closed()
                except with_suppress:
                    pass

    @abstractmethod
    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Dialogue propre au protocole. Ne doit jamais exécuter le contenu reçu."""

    # ------------------------------------------------------------------ utilitaires

    @staticmethod
    async def read_some(reader: asyncio.StreamReader, limit: int = READ_LIMIT_BYTES) -> bytes:
        """Lit ce qui vient, avec un plafond et un délai. Ne lève jamais sur un client muet."""
        try:
            return await asyncio.wait_for(reader.read(limit), timeout=IDLE_TIMEOUT_SECONDS)
        except (TimeoutError, ConnectionError):
            return b""

    def build_raw_event(
        self,
        *,
        writer: asyncio.StreamWriter,
        username: str = "",
        password: str = "",
        payload: bytes = b"",
    ) -> RawEvent:
        """Construit un événement conforme au contrat, charge utile déjà plafonnée."""
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)  # noqa: S104
        source_ip, source_port = peer[0], peer[1]
        event = RawEvent(
            service=self.service,
            source_ip=ip_address(source_ip),
            source_port=int(source_port),
            dest_port=self.port,
            username=username,
            password=password,
            payload=payload[: MAX_PAYLOAD_BYTES * 2],
            payload_truncated=len(payload) > MAX_PAYLOAD_BYTES,
        )
        return event.truncated()

    async def emit(self, event: RawEvent) -> None:
        """Pousse l'événement vers le collecteur.

        Un seul réessai : si le collecteur est indisponible, le leurre continue
        d'accepter des connexions plutôt que de se bloquer sur un envoi.
        """
        if self._client is None:  # pragma: no cover - garde de sûreté
            return
        headers = {"X-Ingest-Token": self.ingest_token}
        body = event.model_dump(mode="json")
        for attempt in (1, 2):
            try:
                response = await self._client.post(self.ingest_url, json=body, headers=headers)
                if response.status_code < 500:
                    return
            except httpx.HTTPError:
                if attempt == 2:
                    logger.warning("decoy %s: collector unreachable", self.service.value)
                await asyncio.sleep(0.2)
