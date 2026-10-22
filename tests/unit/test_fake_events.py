"""Le générateur doit être reproductible : c'est ce qui permet de rejouer un scénario."""

import asyncio
import random
import time
from datetime import UTC, datetime
from ipaddress import IPv4Address

import httpx

from shield.common.schema import RawEvent
from shield.tools.fake_events import make_burst, make_event, send_paced


def test_meme_graine_meme_sequence():
    a = [make_event(random.Random(42)) for _ in range(5)]
    b = [make_event(random.Random(42)) for _ in range(5)]
    assert [e.service for e in a] == [e.service for e in b]
    assert [e.username for e in a] == [e.username for e in b]


def test_les_evenements_produits_sont_valides():
    rng = random.Random(7)
    for _ in range(200):
        event = make_event(rng)
        assert isinstance(event, RawEvent)
        RawEvent.model_validate(event.model_dump(mode="json"))


def test_les_adresses_restent_dans_les_plages_documentaires():
    """Aucune vraie adresse dans un jeu de test (RFC 5737)."""
    rng = random.Random(3)
    for _ in range(200):
        ip = str(make_event(rng).source_ip)
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_une_rafale_vient_bien_dune_seule_adresse():
    events = make_burst(
        random.Random(1),
        count=30,
        source_ip=IPv4Address("203.0.113.7"),
        start=datetime(2026, 9, 25, tzinfo=UTC),
    )
    assert len({str(e.source_ip) for e in events}) == 1
    assert len(events) == 30


async def test_la_cadence_ne_depend_pas_de_la_latence_du_collecteur():
    """#55 : la latence s'ajoutait à chaque envoi ; 3 000 à 50/s prenaient 82 s."""
    received: list[float] = []

    async def slow_collector(request: httpx.Request) -> httpx.Response:
        received.append(time.perf_counter())
        await asyncio.sleep(0.1)  # bien plus que l'intervalle de 10 ms
        return httpx.Response(202)

    rng = random.Random(1)
    events = (make_event(rng) for _ in range(30))
    start = time.perf_counter()
    sent, failed = await send_paced(
        "http://collecteur/api/v1/ingest",
        "t",
        events,
        rate=100,
        transport=httpx.MockTransport(slow_collector),
    )
    elapsed = time.perf_counter() - start

    assert (sent, failed) == (30, 0)
    # Cadencé : ~0,29 s d'injection + 0,1 s pour le dernier. En série : 30 × 0,11 s ≈ 3,3 s.
    assert elapsed < 1.0
    assert received[-1] - received[0] < 0.6


async def test_un_collecteur_injoignable_compte_des_echecs():
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refusé")

    rng = random.Random(1)
    sent, failed = await send_paced(
        "http://collecteur/api/v1/ingest",
        "t",
        (make_event(rng) for _ in range(5)),
        rate=0,
        transport=httpx.MockTransport(down),
    )
    assert (sent, failed) == (0, 5)
