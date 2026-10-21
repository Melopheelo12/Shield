"""Rapport de fin de partie de la sandbox (US-37, S4-09).

Dans la sandbox, **tout** événement vient du joueur attaquant : il n'y a pas de bruit
de fond. Le taux de détection se mesure donc sans ambiguïté :

    détecté = au moins une règle déclenchée (score de menace > 0)

Le rapport dit aussi ce que l'agent a **manqué**, par technique ATT&CK : c'est la liste
des règles à écrire. Objectif SMART du projet : ≥ 80 %.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from shield.collector.enrichment.mitre import MitreMapper
from shield.collector.exports import iterate_events

TARGET_DETECTION_RATE = 80


async def sandbox_report(repository: Any, since: datetime | None) -> dict[str, object]:
    async def fetch_page(cursor: tuple | None, limit: int) -> list[Any]:
        return list(await repository.export_page(since, None, cursor, limit))

    total = detected = 0
    missed: Counter[str] = Counter()
    by_service: Counter[str] = Counter()
    async for event in iterate_events(fetch_page):
        total += 1
        by_service[event.service.value] += 1
        if event.threat_score > 0:
            detected += 1
        else:
            missed[MitreMapper.label(event.technique_id)] += 1

    rate = round(100 * detected / total) if total else None
    return {
        "since": since.isoformat() if since else None,
        "events": total,
        "detected": detected,
        "detection_rate": rate,
        "target": TARGET_DETECTION_RATE,
        "target_met": rate is not None and rate >= TARGET_DETECTION_RATE,
        "by_service": dict(sorted(by_service.items())),
        # Tri explicite : à égalité, l'ordre ne doit pas dépendre de l'ordre de lecture.
        "missed_by_technique": [
            {"technique": technique, "events": count}
            for technique, count in sorted(missed.items(), key=lambda item: (-item[1], item[0]))
        ],
    }
