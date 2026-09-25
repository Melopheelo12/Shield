"""Leurre SSH — présente une bannière, lit une tentative d'authentification, refuse.

Aucune négociation cryptographique réelle n'est faite : un client SSH légitime
échouera, ce qui est sans importance puisque personne n'a de raison légitime de se
connecter ici. Les robots d'attaque, eux, envoient leur bannière et leurs identifiants
avant toute vérification — c'est exactement ce que nous voulons enregistrer.
"""

from __future__ import annotations

import asyncio
import re

from shield.common.schema import ServiceName
from shield.decoys.base import DecoyService

_CLIENT_BANNER = re.compile(rb"^SSH-\d+\.\d+-([^\r\n]*)")
# Beaucoup de robots envoient directement "user:password" ou des chaînes lisibles.
_CREDENTIAL_HINT = re.compile(rb"([\w.\-]{1,64})[:/\s]([^\s\r\n]{1,64})")


class SSHDecoy(DecoyService):
    service = ServiceName.SSH

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(self.negotiate_version().encode())
        await writer.drain()

        payload = await self.read_some(reader)
        username, password = self.read_auth_attempt(payload)

        # Refus explicite : aucun shell, aucun binaire, aucune commande.
        writer.write(b"Permission denied, please try again.\r\n")
        await writer.drain()

        event = self.build_raw_event(
            writer=writer, username=username, password=password, payload=payload
        )
        await self.emit(event)

    def negotiate_version(self) -> str:
        """Bannière annoncée. Versionnée et configurable (US-02)."""
        return f"{self.banner}\r\n"

    @staticmethod
    def read_auth_attempt(payload: bytes) -> tuple[str, str]:
        """Extrait un couple identifiant / mot de passe d'une tentative brute.

        Retourne des chaînes vides plutôt que de lever : un paquet illisible reste
        un événement valide, seulement moins renseigné.
        """
        if not payload:
            return "", ""
        if _CLIENT_BANNER.match(payload):
            # Le client s'est seulement annoncé : pas encore d'identifiants.
            return "", ""
        match = _CREDENTIAL_HINT.search(payload)
        if not match:
            return "", ""
        user = match.group(1).decode("utf-8", errors="replace")
        pwd = match.group(2).decode("utf-8", errors="replace")
        return user, pwd
