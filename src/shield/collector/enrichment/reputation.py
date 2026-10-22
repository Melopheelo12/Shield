"""Réputation des adresses source : AbuseIPDB, cache 24 h, dégradation gracieuse.

US-08 (S2-02), US-10 (S2-03), US-11 (S2-05). Deux chemins, deux règles :

* **Ingestion** — ``cached()`` ne consulte que le cache. Jamais d'appel réseau
  externe, jamais d'exception : une adresse inconnue du cache est marquée ``pending``.
* **Tâche de fond** — ``fetch()`` interroge AbuseIPDB pour les adresses en attente.
  Quota épuisé, délai dépassé, panne : le service est **suspendu** (coupe-circuit),
  les événements restent ``pending`` et sont repris au tour suivant.

AbuseIPDB gratuit = 1 000 requêtes par jour. Le cache de 24 h n'est donc pas une
optimisation mais une condition de fonctionnement : un robot revient des dizaines de
fois par jour, on ne paie qu'une requête.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Protocol

import httpx

from shield.common.schema import EnrichmentStatus

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_CACHE_TTL_SECONDS = 86_400
REQUEST_TIMEOUT_SECONDS = 5.0
#: Ancienneté maximale des signalements pris en compte par AbuseIPDB.
MAX_AGE_IN_DAYS = 90
#: Suspension après une panne : doublée à chaque échec consécutif, plafonnée.
INITIAL_BACKOFF_SECONDS = 60.0
MAX_BACKOFF_SECONDS = 1_800.0
#: Suspension par défaut quand le quota est épuisé sans ``Retry-After``.
QUOTA_BACKOFF_SECONDS = 3_600.0

IpAddress = IPv4Address | IPv6Address


class ReputationUnavailable(Exception):
    """AbuseIPDB ne peut pas répondre maintenant. ``retry_after`` : délai conseillé."""

    def __init__(self, reason: str, retry_after: float | None = None) -> None:
        super().__init__(reason)
        self.retry_after = retry_after


# --------------------------------------------------------------------------- client


class ReputationSource(Protocol):
    async def check(self, ip: str) -> int: ...

    async def close(self) -> None: ...


class AbuseIpDbClient:
    """Client minimal de l'API ``check``. Renvoie l'``abuseConfidenceScore`` (0–100)."""

    def __init__(self, api_key: str, http: httpx.AsyncClient | None = None) -> None:
        self._api_key = api_key
        self._http = http or httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)

    async def check(self, ip: str) -> int:
        try:
            response = await self._http.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_IN_DAYS},
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ReputationUnavailable(f"réseau : {exc!r}") from exc

        if response.status_code == 429:
            raise ReputationUnavailable("quota épuisé", _retry_after(response))
        if response.status_code >= 400:
            raise ReputationUnavailable(f"HTTP {response.status_code}")
        try:
            score = response.json()["data"]["abuseConfidenceScore"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ReputationUnavailable("réponse illisible") from exc
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            raise ReputationUnavailable(f"score hors bornes : {score!r}")
        return score

    async def close(self) -> None:
        await self._http.aclose()


def _retry_after(response: httpx.Response) -> float:
    """``Retry-After`` en secondes, sinon le défaut prudent d'une heure."""
    try:
        return max(float(response.headers.get("Retry-After", "")), 1.0)
    except ValueError:
        return QUOTA_BACKOFF_SECONDS


# --------------------------------------------------------------------------- cache


class ReputationCache(Protocol):
    async def get(self, ip: str) -> int | None: ...

    async def set(self, ip: str, score: int) -> None: ...

    async def close(self) -> None: ...


class InMemoryReputationCache:
    """Cache du développement sans Redis et des tests. Rien ne survit à un redémarrage."""

    def __init__(
        self,
        ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._entries: dict[str, tuple[int, float]] = {}

    async def get(self, ip: str) -> int | None:
        entry = self._entries.get(ip)
        if entry is None:
            return None
        score, expires_at = entry
        if self._clock() >= expires_at:
            del self._entries[ip]
            return None
        return score

    async def set(self, ip: str, score: int) -> None:
        self._entries[ip] = (score, self._clock() + self._ttl)

    async def close(self) -> None:
        self._entries.clear()


class RedisReputationCache:
    """Cache partagé dans Redis, expiration native (``SET … EX``).

    Redis est sur le chemin d'ingestion : un Redis lent ou absent doit se comporter
    comme un cache vide, jamais comme une erreur. D'où le délai court et les
    exceptions avalées (journalisées).
    """

    PREFIX = "shield:reputation:"

    def __init__(self, client: Any, ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS) -> None:
        self._redis = client
        self._ttl = ttl_seconds

    @classmethod
    def from_url(
        cls, url: str, ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS
    ) -> RedisReputationCache:
        import redis.asyncio as redis

        client = redis.from_url(url, socket_timeout=0.2, socket_connect_timeout=0.2)
        return cls(client, ttl_seconds)

    async def get(self, ip: str) -> int | None:
        try:
            value = await self._redis.get(self.PREFIX + ip)
        except Exception:  # noqa: BLE001 - Redis indisponible = cache vide
            logger.warning("cache de réputation indisponible (lecture)", exc_info=True)
            return None
        if value is None:
            return None
        try:
            score = int(value)
        except (TypeError, ValueError):
            return None
        return score if 0 <= score <= 100 else None

    async def set(self, ip: str, score: int) -> None:
        try:
            await self._redis.set(self.PREFIX + ip, score, ex=self._ttl)
        except Exception:  # noqa: BLE001
            logger.warning("cache de réputation indisponible (écriture)", exc_info=True)

    async def close(self) -> None:
        try:
            await self._redis.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("fermeture du cache Redis", exc_info=True)


# --------------------------------------------------------------------------- façade


class ReputationEnricher:
    """Cache d'abord, AbuseIPDB ensuite, coupe-circuit en cas de panne."""

    def __init__(
        self,
        cache: ReputationCache,
        source: ReputationSource | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cache = cache
        self._source = source
        self._clock = clock
        self._suspended_until = 0.0
        self._backoff = INITIAL_BACKOFF_SECONDS

    @classmethod
    def from_env(cls) -> ReputationEnricher:
        ttl = int(os.getenv("ABUSEIPDB_CACHE_TTL_SECONDS", str(DEFAULT_CACHE_TTL_SECONDS)))
        redis_url = os.getenv("REDIS_URL")
        cache: ReputationCache = (
            RedisReputationCache.from_url(redis_url, ttl)
            if redis_url
            else InMemoryReputationCache(ttl)
        )
        api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        if not api_key:
            logger.warning("ABUSEIPDB_API_KEY absente — réputation désactivée")
        return cls(cache, AbuseIpDbClient(api_key) if api_key else None)

    @property
    def enabled(self) -> bool:
        return self._source is not None

    @property
    def suspended(self) -> bool:
        return self._clock() < self._suspended_until

    # -- chemin d'ingestion -----------------------------------------------------

    async def cached(self, ip: IpAddress) -> int | None:
        """Lecture seule du cache : rapide, locale, ne lève jamais."""
        if not ip.is_global:
            return None
        return await self.cache.get(str(ip))

    def status_for(self, ip: IpAddress, score: int | None) -> EnrichmentStatus:
        """``done`` si tout est connu, ``pending`` si la tâche de fond s'en chargera.

        ``partial`` : rien de plus ne viendra (pas de clé AbuseIPDB configurée).
        """
        if score is not None or not ip.is_global:
            return EnrichmentStatus.DONE
        return EnrichmentStatus.PENDING if self.enabled else EnrichmentStatus.PARTIAL

    # -- tâche de fond ----------------------------------------------------------

    async def fetch(self, ip: str) -> int | None:
        """Score de l'adresse, ou ``None`` si AbuseIPDB est indisponible (à reprendre)."""
        cached = await self.cache.get(ip)
        if cached is not None:
            return cached
        if self._source is None or self.suspended:
            return None
        try:
            score = await self._source.check(ip)
        except ReputationUnavailable as exc:
            self._suspend(exc)
            return None
        self._backoff = INITIAL_BACKOFF_SECONDS
        await self.cache.set(ip, score)
        return score

    def _suspend(self, exc: ReputationUnavailable) -> None:
        delay = exc.retry_after if exc.retry_after is not None else self._backoff
        if exc.retry_after is None:
            self._backoff = min(self._backoff * 2, MAX_BACKOFF_SECONDS)
        self._suspended_until = self._clock() + delay
        logger.warning("AbuseIPDB suspendu %.0f s : %s", delay, exc)

    async def close(self) -> None:
        await self.cache.close()
        if self._source is not None:
            await self._source.close()


async def enrich_pending(repository: Any, enricher: ReputationEnricher, batch: int = 50) -> int:
    """Un tour de la tâche de fond : complète la réputation des adresses en attente.

    S'arrête au premier refus d'AbuseIPDB : le reste attend le tour suivant, rien
    n'est perdu. Retourne le nombre d'adresses complétées.
    """
    if not enricher.enabled:
        return 0
    done = 0
    for ip in await repository.pending_reputation(batch):
        if not ip_address(ip).is_global:
            await repository.apply_reputation(ip, None)
            continue
        score = await enricher.fetch(ip)
        if score is None:
            break
        await repository.apply_reputation(ip, score)
        done += 1
    return done
