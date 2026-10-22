"""Réputation (S2-02) et dégradation gracieuse (S2-03, S2-11) : rien ne se perd, tout se reprend."""

from ipaddress import ip_address

import httpx
import pytest

from shield.collector.enrichment.reputation import (
    INITIAL_BACKOFF_SECONDS,
    AbuseIpDbClient,
    InMemoryReputationCache,
    RedisReputationCache,
    ReputationEnricher,
    ReputationUnavailable,
    enrich_pending,
)
from shield.collector.repositories import InMemoryEventRepository
from shield.common.schema import EnrichmentStatus, NormalizedEvent, ServiceName, Verdict

PUBLIC = "8.8.8.8"


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


class FakeSource:
    """Tient lieu d'AbuseIPDB : un score par adresse, ou une panne programmée."""

    def __init__(self, scores=None, failure: ReputationUnavailable | None = None):
        self.scores = scores or {}
        self.failure = failure
        self.calls: list[str] = []

    async def check(self, ip):
        self.calls.append(ip)
        if self.failure is not None:
            raise self.failure
        return self.scores.get(ip, 0)

    async def close(self):
        pass


@pytest.fixture
def clock():
    return Clock()


def enricher_with(source, clock):
    return ReputationEnricher(InMemoryReputationCache(clock=clock), source, clock=clock)


# --------------------------------------------------------------------------- client


def client_answering(handler) -> AbuseIpDbClient:
    return AbuseIpDbClient("cle", http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


async def test_le_client_lit_le_score_de_confiance():
    def handler(request):
        assert request.headers["Key"] == "cle"
        assert request.url.params["ipAddress"] == PUBLIC
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 87}})

    assert await client_answering(handler).check(PUBLIC) == 87


async def test_quota_epuise_avec_retry_after():
    client = client_answering(lambda r: httpx.Response(429, headers={"Retry-After": "120"}))
    with pytest.raises(ReputationUnavailable) as exc:
        await client.check(PUBLIC)
    assert exc.value.retry_after == 120


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(401),
        httpx.Response(200, content=b"<html>"),
        httpx.Response(200, json={"data": {}}),
        httpx.Response(200, json={"data": {"abuseConfidenceScore": 250}}),
        httpx.Response(200, json={"data": {"abuseConfidenceScore": "87"}}),
    ],
)
async def test_toute_reponse_anormale_est_une_indisponibilite(response):
    with pytest.raises(ReputationUnavailable):
        await client_answering(lambda r: response).check(PUBLIC)


async def test_un_delai_depasse_est_une_indisponibilite():
    def handler(request):
        raise httpx.ReadTimeout("trop lent", request=request)

    with pytest.raises(ReputationUnavailable):
        await client_answering(handler).check(PUBLIC)


# --------------------------------------------------------------------------- cache


async def test_le_cache_expire_apres_son_ttl(clock):
    cache = InMemoryReputationCache(ttl_seconds=86_400, clock=clock)
    await cache.set(PUBLIC, 42)
    clock.now += 86_399
    assert await cache.get(PUBLIC) == 42
    clock.now += 1
    assert await cache.get(PUBLIC) is None


class BrokenRedis:
    async def get(self, key):
        raise ConnectionError("redis absent")

    async def set(self, key, value, ex):
        raise ConnectionError("redis absent")

    async def aclose(self):
        raise ConnectionError("redis absent")


async def test_redis_absent_se_comporte_comme_un_cache_vide():
    cache = RedisReputationCache(BrokenRedis())
    await cache.set(PUBLIC, 10)
    assert await cache.get(PUBLIC) is None
    await cache.close()


class DictRedis:
    def __init__(self):
        self.store = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex):
        assert ex == 86_400
        self.store[key] = str(value).encode()


@pytest.mark.parametrize("stored,expected", [(b"55", 55), (b"abc", None), (b"900", None)])
async def test_redis_valeurs_relues(stored, expected):
    redis = DictRedis()
    redis.store[RedisReputationCache.PREFIX + PUBLIC] = stored
    assert await RedisReputationCache(redis).get(PUBLIC) == expected


# --------------------------------------------------------------------------- façade


async def test_une_seule_requete_par_adresse_grace_au_cache(clock):
    source = FakeSource({PUBLIC: 90})
    enricher = enricher_with(source, clock)
    assert await enricher.fetch(PUBLIC) == 90
    assert await enricher.fetch(PUBLIC) == 90
    assert await enricher.cached(ip_address(PUBLIC)) == 90
    assert source.calls == [PUBLIC]


async def test_l_ingestion_ne_lit_que_le_cache(clock):
    source = FakeSource({PUBLIC: 90})
    enricher = enricher_with(source, clock)
    assert await enricher.cached(ip_address(PUBLIC)) is None
    assert source.calls == []


def test_statut_d_enrichissement(clock):
    enabled = enricher_with(FakeSource(), clock)
    disabled = ReputationEnricher(InMemoryReputationCache(clock=clock))
    public, private = ip_address(PUBLIC), ip_address("10.0.0.1")

    assert enabled.status_for(public, 12) == EnrichmentStatus.DONE
    assert enabled.status_for(public, None) == EnrichmentStatus.PENDING
    assert enabled.status_for(private, None) == EnrichmentStatus.DONE
    assert disabled.status_for(public, None) == EnrichmentStatus.PARTIAL


async def test_coupe_circuit_apres_une_panne_puis_reprise(clock):
    source = FakeSource({PUBLIC: 33}, failure=ReputationUnavailable("HTTP 503"))
    enricher = enricher_with(source, clock)

    assert await enricher.fetch(PUBLIC) is None
    assert enricher.suspended
    assert await enricher.fetch(PUBLIC) is None
    assert len(source.calls) == 1, "suspendu : AbuseIPDB n'est plus sollicité"

    source.failure = None
    clock.now += INITIAL_BACKOFF_SECONDS
    assert await enricher.fetch(PUBLIC) == 33


async def test_les_pannes_successives_allongent_la_suspension(clock):
    enricher = enricher_with(FakeSource(failure=ReputationUnavailable("timeout")), clock)
    await enricher.fetch(PUBLIC)
    clock.now += INITIAL_BACKOFF_SECONDS
    await enricher.fetch(PUBLIC)
    clock.now += INITIAL_BACKOFF_SECONDS
    assert enricher.suspended, "la deuxième suspension dure deux fois plus longtemps"


async def test_le_quota_suspend_le_temps_demande(clock):
    enricher = enricher_with(FakeSource(failure=ReputationUnavailable("quota", 600)), clock)
    await enricher.fetch(PUBLIC)
    clock.now += 599
    assert enricher.suspended
    clock.now += 1
    assert not enricher.suspended


# --------------------------------------------------------------------------- tâche de fond


async def stored_event(repo, ip, status=EnrichmentStatus.PENDING):
    event = NormalizedEvent(
        service=ServiceName.SSH,
        source_ip=ip_address(ip),
        source_port=1,
        dest_port=22,
        enrichment_status=status,
    )
    verdict = Verdict(
        event_id=event.event_id, session_id=None, threat_score=0, profile="indetermine"
    )
    await repo.save(event, verdict)
    return event


async def test_la_tache_de_fond_complete_les_evenements_en_attente(clock):
    repo = InMemoryEventRepository()
    await stored_event(repo, PUBLIC)
    await stored_event(repo, PUBLIC)
    await stored_event(repo, "1.1.1.1", status=EnrichmentStatus.DONE)
    enricher = enricher_with(FakeSource({PUBLIC: 77}), clock)

    assert await enrich_pending(repo, enricher) == 1
    enriched = [e for e in repo.events if str(e.source_ip) == PUBLIC]
    assert {(e.reputation_score, e.enrichment_status) for e in enriched} == {
        (77, EnrichmentStatus.DONE)
    }
    assert await repo.pending_reputation(10) == []


async def test_panne_pendant_la_tache_de_fond_rien_n_est_perdu(clock):
    """S2-11 : AbuseIPDB en panne → tout reste pending, puis est repris."""
    repo = InMemoryEventRepository()
    await stored_event(repo, PUBLIC)
    await stored_event(repo, "9.9.9.9")
    source = FakeSource({PUBLIC: 5, "9.9.9.9": 60}, failure=ReputationUnavailable("HTTP 502"))
    enricher = enricher_with(source, clock)

    assert await enrich_pending(repo, enricher) == 0
    assert len(source.calls) == 1, "on s'arrête au premier refus"
    assert set(await repo.pending_reputation(10)) == {PUBLIC, "9.9.9.9"}

    source.failure = None
    clock.now += INITIAL_BACKOFF_SECONDS
    assert await enrich_pending(repo, enricher) == 2
    assert await repo.pending_reputation(10) == []


async def test_sans_cle_la_tache_de_fond_ne_fait_rien(clock):
    repo = InMemoryEventRepository()
    await stored_event(repo, PUBLIC)
    assert await enrich_pending(repo, ReputationEnricher(InMemoryReputationCache())) == 0
