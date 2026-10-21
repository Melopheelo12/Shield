"""Rechargement à chaud des règles de détection (US-16, S2-06).

Modifier ``rules/detection_rules.yaml`` suffit : le collecteur relit le fichier au
tour suivant, sans redémarrage et sans perdre un événement.

Un fichier invalide n'est **jamais** appliqué : les règles en place restent actives,
l'erreur est journalisée, et elle n'est pas rejouée tant que le fichier ne change pas.
On ne remplace pas un moteur qui marche par un moteur cassé.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from shield.collector.defender.engine import DefenderAgent, Rule, RuleEngine, RuleError

logger = logging.getLogger(__name__)


class RuleReloader:
    """Surveille la date de modification du fichier de règles."""

    def __init__(
        self,
        agent: DefenderAgent,
        path: str | Path,
        on_reload: Callable[[list[Rule]], Awaitable[object]] | None = None,
    ) -> None:
        self.agent = agent
        self.path = Path(path)
        self._on_reload = on_reload
        self._signature = self._current_signature()
        self.last_error: str | None = None

    def _current_signature(self) -> tuple[int, int] | None:
        try:
            stat = self.path.stat()
        except OSError:
            return None
        return stat.st_mtime_ns, stat.st_size

    async def reload_if_changed(self) -> bool:
        """``True`` si de nouvelles règles sont en place."""
        signature = self._current_signature()
        if signature is None or signature == self._signature:
            return False
        previous, self._signature = self._signature, signature
        try:
            engine = RuleEngine.from_file(self.path)
        except (RuleError, OSError) as exc:
            self.last_error = str(exc)
            logger.error("règles non rechargées, les précédentes restent actives : %s", exc)
            return False
        # Synchroniser d'abord le référentiel (detection_rule), basculer ensuite :
        # un rule_match ne doit jamais pointer vers une règle inconnue en base.
        if self._on_reload is not None:
            try:
                await self._on_reload(engine.rules)
            except Exception:
                # Base indisponible : on réessaiera au tour suivant, fichier inchangé ou non.
                self._signature = previous
                raise
        self.agent.engine = engine
        self.last_error = None
        logger.info("règles rechargées : %d règles actives", len(engine.rules))
        return True
