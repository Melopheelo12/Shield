"""Gestionnaire d'alertes (US-30, US-31, S4-01).

Une alerte part **exactement une fois par franchissement** de seuil :

* chaque seuil est une petite machine à états : *armé* → franchissement → alerte →
  *déclenché* ; il ne se **réarme** que lorsque la mesure repasse sous le seuil ;
* une **période de silence** s'ajoute : même réarmé, un seuil ne réalerte pas avant
  ``silence_seconds`` — une activité qui oscille autour du seuil ne spamme pas.

Les mesures sont tenues en mémoire sur des fenêtres glissantes alimentées à
l'ingestion : aucune requête en base, et le calcul est déterministe (horloge injectée),
donc testable. Contrepartie assumée : un redémarrage du collecteur vide les fenêtres
et réarme les seuils.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from typing import Any

from shield.common.schema import NormalizedEvent


class Metric(StrEnum):
    """Mesures disponibles. Liste fermée, décrite en clair pour l'interface."""

    EVENTS = "events"
    UNIQUE_IPS = "unique_ips"
    MAX_THREAT_SCORE = "max_threat_score"


METRIC_LABELS = {
    Metric.EVENTS: "tentatives reçues",
    Metric.UNIQUE_IPS: "adresses distinctes",
    Metric.MAX_THREAT_SCORE: "score de menace maximal",
}


@dataclass(frozen=True)
class Threshold:
    """Un seuil configurable (US-31)."""

    id: str
    metric: Metric
    threshold: float
    window_seconds: int = 300
    silence_seconds: int = 3600
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.threshold <= 0:
            raise ValueError("le seuil doit être positif")
        if not 1 <= self.window_seconds <= 86_400:
            raise ValueError("fenêtre entre 1 s et 24 h")
        if not 0 <= self.silence_seconds <= 7 * 86_400:
            raise ValueError("silence entre 0 et 7 jours")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Threshold:
        return cls(
            id=str(data["id"]),
            metric=Metric(data["metric"]),
            threshold=float(data["threshold"]),
            window_seconds=int(data.get("window_seconds", 300)),
            silence_seconds=int(data.get("silence_seconds", 3600)),
            enabled=bool(data.get("enabled", True)),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["metric"] = self.metric.value
        return data


#: Seuils par défaut d'une instance neuve. Modifiables depuis l'interface.
DEFAULT_THRESHOLDS = (
    Threshold("volume", Metric.EVENTS, threshold=200, window_seconds=300),
    Threshold("critique", Metric.MAX_THREAT_SCORE, threshold=80, window_seconds=300),
)


@dataclass(frozen=True)
class AlertNotice:
    """Ce que reçoivent les canaux : la règle, la valeur observée, le lien (US-30)."""

    threshold: Threshold
    value: float
    triggered_at: float  # horloge du gestionnaire
    test: bool = False

    @property
    def title(self) -> str:
        prefix = "[TEST] " if self.test else ""
        return f"{prefix}SHIELD — seuil « {self.threshold.id} » franchi"

    def body(self, dashboard_url: str) -> str:
        label = METRIC_LABELS[self.threshold.metric]
        minutes = max(self.threshold.window_seconds // 60, 1)
        link = filtered_view_url(dashboard_url, self.threshold)
        return (
            f"{label.capitalize()} : {self.value:g} sur les {minutes} dernières minutes "
            f"(seuil : {self.threshold.threshold:g}).\n"
            f"Voir les événements concernés : {link}"
        )


def filtered_view_url(dashboard_url: str, threshold: Threshold) -> str:
    """Lien vers la vue déjà filtrée : les événements de la fenêtre, les plus graves d'abord."""
    base = dashboard_url.rstrip("/")
    query = f"since_seconds={threshold.window_seconds}"
    if threshold.metric is Metric.MAX_THREAT_SCORE:
        query += f"&min_score={int(threshold.threshold)}"
    return f"{base}/?{query}"


@dataclass
class _Observation:
    at: float
    ip: str
    score: int


@dataclass
class _State:
    armed: bool = True
    last_alert_at: float | None = None


@dataclass
class AlertManager:
    """Observe les événements, évalue les seuils, produit les alertes à envoyer."""

    thresholds: list[Threshold] = field(default_factory=lambda: list(DEFAULT_THRESHOLDS))
    clock: Callable[[], float] = time.monotonic
    _window: deque[_Observation] = field(default_factory=deque, init=False)
    _states: dict[str, _State] = field(default_factory=dict, init=False)

    @property
    def horizon(self) -> int:
        return max((t.window_seconds for t in self.thresholds), default=0)

    def configure(self, thresholds: list[Threshold]) -> None:
        """Nouveaux seuils. Un seuil dont la définition change repart armé."""
        previous = {t.id: t for t in self.thresholds}
        self.thresholds = list(thresholds)
        self._states = {
            t.id: self._states[t.id]
            for t in thresholds
            if t.id in self._states and previous.get(t.id) == t
        }

    def observe(self, event: NormalizedEvent) -> list[AlertNotice]:
        """Appelée à chaque ingestion. Retourne les alertes déclenchées par cet événement."""
        self._window.append(_Observation(self.clock(), str(event.source_ip), event.threat_score))
        return self.evaluate()

    def measure(self, metric: Metric, window_seconds: int) -> float:
        since = self.clock() - window_seconds
        recent = [obs for obs in self._window if obs.at > since]
        if metric is Metric.EVENTS:
            return float(len(recent))
        if metric is Metric.UNIQUE_IPS:
            return float(len({obs.ip for obs in recent}))
        return float(max((obs.score for obs in recent), default=0))

    def evaluate(self) -> list[AlertNotice]:
        """À appeler aussi périodiquement : c'est ce qui réarme un seuil redescendu."""
        self._forget_old()
        now = self.clock()
        notices = []
        for threshold in self.thresholds:
            if not threshold.enabled:
                continue
            state = self._states.setdefault(threshold.id, _State())
            value = self.measure(threshold.metric, threshold.window_seconds)
            if value < threshold.threshold:
                state.armed = True
                continue
            if not state.armed:
                continue  # toujours au-dessus : même franchissement, pas de nouvelle alerte
            state.armed = False
            silenced = (
                state.last_alert_at is not None
                and now - state.last_alert_at < threshold.silence_seconds
            )
            if silenced:
                continue
            state.last_alert_at = now
            notices.append(AlertNotice(threshold, value, now))
        return notices

    def _forget_old(self) -> None:
        horizon = self.clock() - self.horizon
        while self._window and self._window[0].at <= horizon:
            self._window.popleft()

    def test_notice(self, threshold: Threshold | None = None) -> AlertNotice:
        """Notification factice pour le bouton « tester » (US-31)."""
        sample = threshold or replace(DEFAULT_THRESHOLDS[0], id="test")
        return AlertNotice(sample, sample.threshold, self.clock(), test=True)
