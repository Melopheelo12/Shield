"""Orchestration des alertes : ingestion → gestionnaire → file → canaux → trace.

``observe`` est appelée sur le chemin d'ingestion : elle ne fait que des calculs en
mémoire et dépose les alertes dans une file. ``run`` les envoie depuis une tâche de
fond et trace chaque franchissement en base, quel que soit le sort des canaux.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from shield.collector.alerts.channels import Notifier, overall_status
from shield.collector.alerts.manager import (
    DEFAULT_THRESHOLDS,
    AlertManager,
    AlertNotice,
    Threshold,
)
from shield.common.schema import NormalizedEvent

logger = logging.getLogger(__name__)


class AlertService:
    def __init__(self, manager: AlertManager, notifier: Notifier) -> None:
        self.manager = manager
        self.notifier = notifier
        self.queue: asyncio.Queue[AlertNotice] = asyncio.Queue()

    @classmethod
    def from_env(cls) -> AlertService:
        return cls(AlertManager(), Notifier.from_env())

    async def load(self, repository: Any) -> None:
        """Au démarrage : seuils enregistrés, ou seuils par défaut sur une instance neuve."""
        stored = await repository.load_alert_thresholds()
        if stored:
            self.manager.configure([Threshold.from_dict(item) for item in stored])
        else:
            await repository.save_alert_thresholds([t.to_dict() for t in DEFAULT_THRESHOLDS])
            self.manager.configure(list(DEFAULT_THRESHOLDS))

    async def configure(self, repository: Any, thresholds: list[Threshold]) -> None:
        """Enregistrer d'abord, appliquer ensuite : l'interface ne ment jamais."""
        ids = [threshold.id for threshold in thresholds]
        if len(ids) != len(set(ids)):
            raise ValueError("identifiants de seuil en double")
        await repository.save_alert_thresholds([t.to_dict() for t in thresholds])
        self.manager.configure(thresholds)

    def observe(self, event: NormalizedEvent) -> None:
        """Chemin d'ingestion : calcul en mémoire, ne lève jamais."""
        try:
            for notice in self.manager.observe(event):
                self.queue.put_nowait(notice)
        except Exception:  # noqa: BLE001 - une alerte ratée ne coûte jamais un événement
            logger.exception("évaluation des seuils d'alerte en échec")

    async def rearm(self) -> None:
        """Tâche périodique : réévalue, ce qui réarme les seuils redescendus."""
        for notice in self.manager.evaluate():
            self.queue.put_nowait(notice)

    async def deliver(self, repository: Any, notice: AlertNotice) -> dict[str, Any]:
        results = await self.notifier.send(notice)
        alert = {
            "threshold_id": notice.threshold.id,
            "triggered_at": datetime.now(UTC),
            "value": notice.value,
            "threshold": notice.threshold.threshold,
            "status": overall_status(results),
            "channels": results,
        }
        await repository.record_alert(alert)
        return alert

    async def run(self, repository: Any) -> None:
        """Boucle de fond : envoie chaque alerte de la file, une par une, sans jamais s'arrêter.

        La file est recréée ici : une ``asyncio.Queue`` se lie à la boucle qui l'attend,
        et le cycle de vie peut tourner dans plusieurs boucles successives (tests).
        """
        pending: list[AlertNotice] = []
        while not self.queue.empty():
            pending.append(self.queue.get_nowait())
        self.queue = asyncio.Queue()
        for notice in pending:
            self.queue.put_nowait(notice)
        while True:
            notice = await self.queue.get()
            try:
                await self.deliver(repository, notice)
            except Exception:  # noqa: BLE001
                logger.exception("alerte « %s » non tracée", notice.threshold.id)

    async def send_test(self) -> dict[str, str]:
        """Bouton « tester » (US-31) : notification factice, non tracée comme alerte."""
        return await self.notifier.send(self.manager.test_notice())
