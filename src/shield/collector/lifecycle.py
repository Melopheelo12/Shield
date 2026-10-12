"""Cycle de vie des données : allègement, archivage, purge (US-46, au-delà).

Trois paliers, pour que la base ne grossisse pas sans fin sans perdre ce qui sert :

1. **0 → 30 jours** : tout est en base, charge utile comprise.
2. **Au-delà de ``PAYLOAD_RETENTION_DAYS``** (30) : la charge utile — de loin la colonne
   la plus lourde — est effacée. L'empreinte SHA-256, la technique ATT&CK, le score et
   les règles déclenchées restent : le verdict reste explicable.
3. **Au-delà de ``ARCHIVE_AFTER_MONTHS``** (3) : chaque mois complet est exporté dans un
   fichier CSV compressé (``ARCHIVE_DIR``), vérifié ligne à ligne, puis sa partition
   est supprimée d'un bloc.

Et la **conservation RGPD** (``RETENTION_DAYS``, 12 mois) s'applique aussi aux archives :
une archive n'est pas une exemption, sinon on garderait des adresses plus longtemps
que ce que l'on déclare.

Chaque palier se désactive en mettant sa variable à 0.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Fichiers produits par l'archivage : event_AAAA_MM.csv.gz et son manifeste.
ARCHIVE_NAME = re.compile(r"event_(\d{4})_(\d{2})\.(csv\.gz|json)")


@dataclass(frozen=True)
class LifecycleSettings:
    payload_retention_days: int = 30
    archive_after_months: int = 3
    retention_days: int = 365
    archive_dir: Path | None = None

    @classmethod
    def from_env(cls) -> LifecycleSettings:
        directory = os.getenv("ARCHIVE_DIR", "").strip()
        return cls(
            payload_retention_days=int(os.getenv("PAYLOAD_RETENTION_DAYS", "30")),
            archive_after_months=int(os.getenv("ARCHIVE_AFTER_MONTHS", "3")),
            retention_days=int(os.getenv("RETENTION_DAYS", "365")),
            archive_dir=Path(directory) if directory else None,
        )


def first_day_months_ago(today: date, months: int) -> date:
    """Premier jour du mois, ``months`` mois avant celui de ``today``."""
    index = today.year * 12 + today.month - 1 - months
    return date(index // 12, index % 12 + 1, 1)


def archive_month_end(name: str) -> date | None:
    """Premier jour du mois suivant celui que couvre un fichier d'archive."""
    found = ARCHIVE_NAME.fullmatch(name)
    if found is None:
        return None
    year, month = int(found[1]), int(found[2])
    return date(year + month // 12, month % 12 + 1, 1)


def purge_archives(directory: Path, cutoff: date) -> list[str]:
    """Supprime les archives entièrement antérieures à ``cutoff``. Retourne leurs noms."""
    removed: list[str] = []
    if not directory.is_dir():
        return removed
    for path in sorted(directory.iterdir()):
        end = archive_month_end(path.name)
        if end is not None and end <= cutoff:
            path.unlink()
            removed.append(path.name)
    return removed


def archive_directory_ready(directory: Path | None) -> bool:
    """Un archivage vers un dossier absent ou en lecture seule serait une perte : on s'abstient."""
    if directory is None:
        return False
    if not directory.is_dir() or not os.access(directory, os.W_OK):
        logger.warning("ARCHIVE_DIR %s absent ou non inscriptible : archivage suspendu", directory)
        return False
    return True


async def run_lifecycle(
    repository: Any, settings: LifecycleSettings, now: datetime | None = None
) -> dict[str, Any]:
    """Passage quotidien : allège, archive, puis purge base et archives."""
    now = now or datetime.now(UTC)
    report: dict[str, Any] = {}

    if settings.payload_retention_days > 0:
        before = now - timedelta(days=settings.payload_retention_days)
        report["payloads_lightened"] = await repository.lighten_payloads(before)

    if settings.archive_after_months > 0 and archive_directory_ready(settings.archive_dir):
        assert settings.archive_dir is not None
        before_month = first_day_months_ago(now.date(), settings.archive_after_months)
        report["archived"] = await repository.archive_partitions(before_month, settings.archive_dir)

    if settings.retention_days > 0:
        cutoff = now - timedelta(days=settings.retention_days)
        report["purged"] = await repository.purge(cutoff)
        if settings.archive_dir is not None:
            report["archives_purged"] = purge_archives(settings.archive_dir, cutoff.date())

    logger.info("cycle de vie des données : %s", report)
    return report
