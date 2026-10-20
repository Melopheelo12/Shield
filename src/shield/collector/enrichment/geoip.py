"""Enrichissement géographique hors ligne : pays et opérateur réseau (US-07, S2-01).

Les bases GeoLite2 (City et ASN) sont des fichiers locaux : la recherche ne sort
jamais de la machine et prend quelques microsecondes. C'est ce qui l'autorise sur le
chemin d'ingestion, avant le verdict, contrairement à la réputation (ADR 007).

Trois propriétés, testées unitairement :

1. **Ne lève jamais.** Base absente, illisible, adresse inconnue ou privée : le
   résultat est simplement vide. Un événement non géolocalisé reste un événement.
2. **Dégradation indépendante.** Les deux bases sont optionnelles l'une par rapport à
   l'autre : sans la base ASN, le pays est toujours renseigné, et inversement.
3. **Conforme au contrat.** Le pays est un code ISO à deux lettres ou ``None`` ;
   l'organisation tient dans la colonne ``ip_intel.as_org``.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)

#: Largeur de la colonne ``ip_intel.as_org``.
MAX_AS_ORG_CHARS = 128

DEFAULT_CITY_PATH = "/data/geolite2/GeoLite2-City.mmdb"
DEFAULT_ASN_PATH = "/data/geolite2/GeoLite2-ASN.mmdb"


@dataclass(frozen=True)
class GeoInfo:
    """Ce que GeoLite2 sait d'une adresse. Tous les champs peuvent manquer."""

    country_code: str | None = None
    asn: int | None = None
    as_org: str | None = None

    def as_update(self) -> dict[str, object]:
        """Champs à reporter sur un ``NormalizedEvent`` (``model_copy(update=...)``)."""
        return {"country_code": self.country_code, "asn": self.asn, "as_org": self.as_org}


EMPTY = GeoInfo()


class GeoReader(Protocol):
    """Le sous-ensemble de ``geoip2.database.Reader`` utilisé ici — remplaçable en test."""

    def city(self, ip_address: str) -> Any: ...

    def asn(self, ip_address: str) -> Any: ...

    def close(self) -> None: ...


def _country_code(record: Any) -> str | None:
    code = getattr(getattr(record, "country", None), "iso_code", None)
    if isinstance(code, str) and len(code) == 2 and code.isascii() and code.isalpha():
        return code.upper()
    return None


def _asn_number(record: Any) -> int | None:
    number = getattr(record, "autonomous_system_number", None)
    if isinstance(number, bool) or not isinstance(number, int) or number < 0:
        return None
    return number


def _asn_org(record: Any) -> str | None:
    org = getattr(record, "autonomous_system_organization", None)
    if not isinstance(org, str) or not org.strip():
        return None
    return org.strip()[:MAX_AS_ORG_CHARS]


def _open(path: str | Path | None) -> GeoReader | None:
    """Ouvre une base GeoLite2, ou renvoie ``None`` en le journalisant."""
    if not path:
        return None
    if not Path(path).is_file():
        logger.warning("base GeoLite2 absente : %s — enrichissement géographique partiel", path)
        return None
    try:
        import geoip2.database

        reader: GeoReader = geoip2.database.Reader(str(path))
    except Exception:
        logger.exception("base GeoLite2 illisible : %s", path)
        return None
    return reader


class GeoIpEnricher:
    """Pays (base City) et ASN (base ASN) d'une adresse source."""

    def __init__(self, city: GeoReader | None = None, asn: GeoReader | None = None) -> None:
        self._city = city
        self._asn = asn

    @classmethod
    def from_paths(cls, city_path: str | Path | None, asn_path: str | Path | None) -> GeoIpEnricher:
        return cls(city=_open(city_path), asn=_open(asn_path))

    @classmethod
    def from_env(cls) -> GeoIpEnricher:
        return cls.from_paths(
            os.getenv("GEOLITE2_CITY_PATH", DEFAULT_CITY_PATH),
            os.getenv("GEOLITE2_ASN_PATH", DEFAULT_ASN_PATH),
        )

    @property
    def available(self) -> bool:
        return self._city is not None or self._asn is not None

    def lookup(self, ip: IPv4Address | IPv6Address) -> GeoInfo:
        """Ne lève jamais : une adresse privée ou inconnue donne un résultat vide."""
        if not ip.is_global or not self.available:
            return EMPTY
        address = str(ip)
        city = self._safe(self._city, "city", address)
        asn = self._safe(self._asn, "asn", address)
        return GeoInfo(
            country_code=_country_code(city),
            asn=_asn_number(asn),
            as_org=_asn_org(asn),
        )

    @staticmethod
    def _safe(reader: GeoReader | None, method: str, address: str) -> Any:
        """Une adresse absente de la base est le cas courant, pas une erreur."""
        if reader is None:
            return None
        try:
            return getattr(reader, method)(address)
        except Exception as exc:  # noqa: BLE001 - AddressNotFoundError, base corrompue…
            if type(exc).__name__ != "AddressNotFoundError":
                logger.warning("recherche GeoLite2 %s en échec pour %s : %r", method, address, exc)
            return None

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()
        self._city = self._asn = None
