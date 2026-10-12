"""Agent de veille : vulnérabilités activement exploitées, corrélées aux observations.

US-39, US-40, US-41 (S4-11).

* **Source** — le catalogue CISA KEV (*Known Exploited Vulnerabilities*) : un fichier
  JSON public, sans clé ni quota. Une requête par jour, vers 4 h UTC, hors des heures
  de forte activité. Un échec est journalisé et n'a d'effet sur rien d'autre.
* **Corrélation** — chaque entrée de ``SIGNATURES`` associe une CVE à un motif de
  charge utile caractéristique de son exploitation. Une CVE dont le motif apparaît
  dans nos événements est marquée « observée chez vous », avec le nombre d'événements.
  La table est courte et revue à la main : mieux vaut peu de signatures sûres qu'une
  corrélation approximative.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FETCH_TIMEOUT_SECONDS = 30.0
RECENT_DAYS = 30
RUN_HOUR_UTC = 4


@dataclass(frozen=True)
class Signature:
    cve_id: str
    marker: bytes
    summary: str


SIGNATURES = (
    Signature("CVE-2021-44228", b"${jndi:", "Apache Log4j — exécution de code (Log4Shell)"),
    Signature("CVE-2014-6271", b"() { :;};", "Bash — exécution de code (Shellshock)"),
    Signature("CVE-2021-41773", b"/.%2e/", "Apache HTTP Server 2.4.49 — traversée de chemin"),
    Signature("CVE-2017-9841", b"eval-stdin.php", "PHPUnit — exécution de code"),
    Signature("CVE-2018-13379", b"fgt_lang", "Fortinet FortiOS SSL VPN — lecture de fichiers"),
    Signature("CVE-2022-1388", b"/mgmt/tm/util/bash", "F5 BIG-IP iControl REST — contournement"),
    Signature("CVE-2019-19781", b"/vpn/../vpns/", "Citrix ADC — traversée de chemin"),
    Signature("CVE-2023-1389", b"/cgi-bin/luci/;stok=/locale", "TP-Link Archer AX21 — injection"),
    Signature("CVE-2020-25213", b"connector.minimal.php", "WordPress File Manager — envoi"),
)


async def fetch_kev(http: httpx.AsyncClient | None = None) -> list[dict[str, Any]]:
    """Le catalogue KEV. Lève en cas d'échec : c'est ``refresh`` qui isole la panne."""
    if http is None:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT_SECONDS) as client:
            return await fetch_kev(client)
    response = await http.get(KEV_URL, headers={"Accept": "application/json"})
    response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("catalogue KEV illisible")
    return [item for item in vulnerabilities if isinstance(item, dict) and item.get("cveID")]


def _parse_date(value: object) -> datetime | None:
    try:
        return datetime.combine(date.fromisoformat(str(value)), datetime.min.time(), UTC)
    except ValueError:
        return None


def build_entries(kev: list[dict[str, Any]], today: date) -> list[dict[str, Any]]:
    """Entrées de veille : nos signatures, plus les ajouts récents au catalogue KEV."""
    catalog = {str(item["cveID"]): item for item in kev}
    horizon = today - timedelta(days=RECENT_DAYS)
    entries: dict[str, dict[str, Any]] = {}

    for item in kev:
        added = _parse_date(item.get("dateAdded"))
        if added is not None and added.date() >= horizon:
            entries[str(item["cveID"])] = _entry(item, added)

    for signature in SIGNATURES:
        known = catalog.get(signature.cve_id)
        if known is not None:
            entries[signature.cve_id] = _entry(known, _parse_date(known.get("dateAdded")))
        else:
            entries.setdefault(
                signature.cve_id,
                {
                    "cve_id": signature.cve_id,
                    "published_at": None,
                    "summary": signature.summary,
                    "kev_flag": False,
                },
            )
    return sorted(entries.values(), key=lambda entry: entry["cve_id"])


def _entry(item: dict[str, Any], added: datetime | None) -> dict[str, Any]:
    name = str(item.get("vulnerabilityName") or "").strip()
    description = str(item.get("shortDescription") or "").strip()
    summary = f"{name} — {description}" if name and description else name or description
    return {
        "cve_id": str(item["cveID"]),
        "published_at": added,
        "summary": summary[:1000],
        "kev_flag": True,
    }


async def refresh(repository: Any, fetch: Callable[[], Awaitable[list[dict[str, Any]]]]) -> int:
    """Passage quotidien : catalogue KEV puis corrélation. Retourne les CVE observées."""
    try:
        kev = await fetch()
    except Exception:  # noqa: BLE001 - US-41 : sans effet sur les autres composants
        logger.exception("catalogue KEV indisponible — corrélation sur les données connues")
        kev = []
    if kev:
        await repository.upsert_watch(build_entries(kev, datetime.now(UTC).date()))
    elif not await repository.watch_entries(limit=1):
        # Première exécution hors ligne : les signatures restent consultables.
        await repository.upsert_watch(build_entries([], datetime.now(UTC).date()))
    return await correlate(repository)


async def correlate(repository: Any) -> int:
    """Recompte les événements portant chaque signature. Local, sans réseau ni quota :
    il tourne toutes les heures, pour qu'une attaque d'aujourd'hui ne soit pas signalée
    seulement demain. Retourne le nombre de CVE observées chez nous."""
    observed = 0
    for signature in SIGNATURES:
        count, last = await repository.count_payload_matches(signature.marker)
        await repository.record_watch_matches(signature.cve_id, count, last)
        observed += count > 0
    return observed


def seconds_until(hour: int, now: datetime) -> float:
    """Délai jusqu'à la prochaine occurrence de ``hour``:00 UTC."""
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


async def run_daily(job: Callable[[], Awaitable[object]], hour: int = RUN_HOUR_UTC) -> None:
    while True:
        await asyncio.sleep(seconds_until(hour, datetime.now(UTC)))
        try:
            await job()
        except Exception:  # noqa: BLE001
            logger.exception("agent de veille en échec")


def signature_for(cve_id: str) -> Signature | None:
    return next((s for s in SIGNATURES if s.cve_id == cve_id), None)
