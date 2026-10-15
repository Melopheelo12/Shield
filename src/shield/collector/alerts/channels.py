"""Canaux de notification : webhook Discord (US-30) et courriel (US-32, S4-10).

L'échec d'un canal est journalisé et **ne bloque pas les autres** : ``Notifier``
envoie à chaque canal indépendamment et rend le résultat de chacun.

Les envois partent d'une tâche de fond, jamais du chemin d'ingestion : un webhook
lent ne retarde pas la capture d'un événement.
"""

from __future__ import annotations

import asyncio
import logging
import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

import httpx

from shield.collector.alerts.manager import AlertNotice

logger = logging.getLogger(__name__)

SEND_TIMEOUT_SECONDS = 10.0
#: Discord tronque au-delà ; on reste en dessous avec de la marge.
DISCORD_MAX_CHARS = 1900


class Channel(Protocol):
    name: str

    async def send(self, notice: AlertNotice) -> None:
        """Lève en cas d'échec : c'est ``Notifier`` qui isole les canaux."""


@dataclass
class DiscordChannel:
    webhook_url: str
    dashboard_url: str
    http: httpx.AsyncClient | None = None
    name: str = "discord"

    async def send(self, notice: AlertNotice) -> None:
        content = f"**{notice.title}**\n{notice.body(self.dashboard_url)}"[:DISCORD_MAX_CHARS]
        payload = {"content": content, "allowed_mentions": {"parse": []}}
        if self.http is not None:
            response = await self.http.post(self.webhook_url, json=payload)
        else:
            async with httpx.AsyncClient(timeout=SEND_TIMEOUT_SECONDS) as http:
                response = await http.post(self.webhook_url, json=payload)
        response.raise_for_status()


@dataclass
class EmailChannel:
    host: str
    port: int
    sender: str
    recipient: str
    dashboard_url: str
    username: str = ""
    password: str = ""
    name: str = "email"

    def _message(self, notice: AlertNotice) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = notice.title
        message["From"] = self.sender
        message["To"] = self.recipient
        message.set_content(notice.body(self.dashboard_url))
        return message

    def _send_sync(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self.host, self.port, timeout=SEND_TIMEOUT_SECONDS) as smtp:
            smtp.starttls()
            if self.username:
                smtp.login(self.username, self.password)
            smtp.send_message(message)

    async def send(self, notice: AlertNotice) -> None:
        # smtplib est bloquant : un fil dédié, pour ne pas geler la boucle.
        await asyncio.to_thread(self._send_sync, self._message(notice))


class Notifier:
    """Envoie une alerte à tous les canaux, chacun isolé des pannes des autres."""

    def __init__(self, channels: list[Channel]) -> None:
        self.channels = channels

    @classmethod
    def from_env(cls) -> Notifier:
        dashboard = os.getenv("DASHBOARD_URL", "https://localhost:8443")
        channels: list[Channel] = []
        webhook = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
        if webhook:
            channels.append(DiscordChannel(webhook, dashboard))
        smtp_host = os.getenv("SMTP_HOST", "").strip()
        recipient = os.getenv("ALERT_EMAIL_TO", "").strip()
        if smtp_host and recipient:
            user = os.getenv("SMTP_USER", "")
            channels.append(
                EmailChannel(
                    host=smtp_host,
                    port=int(os.getenv("SMTP_PORT", "587")),
                    sender=os.getenv("ALERT_EMAIL_FROM", user or recipient),
                    recipient=recipient,
                    dashboard_url=dashboard,
                    username=user,
                    password=os.getenv("SMTP_PASSWORD", ""),
                )
            )
        if not channels:
            logger.warning("aucun canal d'alerte configuré — les alertes sont seulement tracées")
        return cls(channels)

    async def send(self, notice: AlertNotice) -> dict[str, str]:
        """Résultat par canal : ``sent`` ou ``failed``. Ne lève jamais."""
        results: dict[str, str] = {}
        for channel in self.channels:
            try:
                await channel.send(notice)
            except Exception:  # noqa: BLE001 - un canal en panne n'arrête pas les autres
                logger.exception(
                    "alerte « %s » non envoyée sur %s", notice.threshold.id, channel.name
                )
                results[channel.name] = "failed"
            else:
                results[channel.name] = "sent"
        return results


def overall_status(results: dict[str, str]) -> str:
    """Statut d'une alerte : envoyée si au moins un canal l'a délivrée."""
    if not results:
        return "logged"
    return "sent" if "sent" in results.values() else "failed"
